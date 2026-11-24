"""Owner-only Builder Studio extension for the pinned, unmodified Collab Hub.

:class:`BuilderHubExtension` is an outer ASGI wrapper around the Hub app that
``collab_hub_api.core.make_app(Config.parse())`` returns. Every request outside
``/builder`` is delegated to the Hub unchanged (scope, receive and send are
passed through as they arrived). Every request on ``/builder`` is answered here
and never reaches the Hub router:

* The Host must name the configured ``BUILDER_PUBLIC_ORIGIN``.
* The request must carry a **live** Hub web session, decided by the Hub's own
  ``collab_hub_api.web.authz.get_web_session`` against the Hub's ``app.state``
  (signature, expiry and the ended-session lookup). A lookup that fails is a
  503, never "signed in".
* The session subject must equal ``BUILDER_OWNER_SUB`` exactly.
* Only a fixed allowlist of method and path pairs is served; WebSockets are
  refused.
* Writes require the exact public Origin, a same-origin fetch, a JSON body and
  the Studio's ``X-Cog-Workbench`` page token.
* The request is proxied to ``BUILDER_WORKSPACE_URL`` with the ``/builder``
  prefix removed, carrying only fixed headers and the internal bearer
  ``BUILDER_WORKSPACE_TOKEN``. Browser cookies, authorization and forwarding
  headers are never sent; upstream headers other than the content type are
  never returned.

Run with ``python -m builder_hub.hub_extension``: it configures Hub logging and
serves the wrapped app with the Hub's own ``server`` configuration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

logger = logging.getLogger("builder_hub.extension")

PREFIX = "/builder"
STUDIO_PATH = "/builder/studio"
SIGNIN_PATH = "/web/signin"
HOME_PATH = "/web/home"
SIGNIN_REDIRECT = f"{SIGNIN_PATH}?{urlencode({'next': STUDIO_PATH})}"

MAX_REQUEST_BODY = 4 * 1024 * 1024
MAX_RESPONSE_BODY = 16 * 1024 * 1024
MAX_QUERY_BYTES = 2048
MIN_TOKEN_LENGTH = 32

# (method, public path) -> (upstream path, forwards query, kind)
ROUTES: dict[tuple[str, str], tuple[str, bool, str]] = {
    ("GET", "/builder/studio"): ("/studio", False, "page"),
    ("GET", "/builder/api/suite/catalog"): ("/api/suite/catalog", False, "api"),
    ("GET", "/builder/api/suite/builds"): ("/api/suite/builds", False, "api"),
    ("GET", "/builder/api/suite/build"): ("/api/suite/build", True, "api"),
    ("GET", "/builder/api/suite/job"): ("/api/suite/job", True, "api"),
    ("POST", "/builder/api/suite/action"): ("/api/suite/action", False, "api"),
}
PAGE_PATHS = frozenset({PREFIX, STUDIO_PATH})
KNOWN_PATHS = frozenset({PREFIX, *(path for _, path in ROUTES)})

WORKBENCH_TOKEN_HEADER = "x-cog-workbench"
WORKBENCH_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
JSON_CONTENT_TYPES = frozenset({"application/json", "application/json; charset=utf-8"})

SECURITY_HEADERS: dict[str, str] = {
    "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
    "pragma": "no-cache",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}
API_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
STUDIO_CSP = (
    "default-src 'none'; script-src {scripts}; style-src {styles}; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)

OWNER_BANNER = (
    '<style>.builder-nav{display:flex;gap:1em;align-items:center;padding:8px 5%;'
    'background:#193b37;color:#f2f5ee;font:14px/1.4 system-ui}'
    '.builder-nav a{color:#f2f5ee;font-weight:600}</style>'
    '<nav aria-label="Collab Hub" class="builder-nav">'
    '<a href="/web/home">&larr; Back to Collab Hub</a>'
    "<span>Owner preview: Builder Studio. Unavailable actions are refused by the server.</span></nav>"
)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
SessionChecker = Callable[[Any], Awaitable[Any]]


class BuilderConfigError(ValueError):
    """The Builder environment is missing or unsafe; the process must not start."""


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int

    @property
    def serialized(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")


def _is_literal_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS


def _parse_origin_url(name: str, value: str, *, allow_path: bool) -> tuple[Origin, str]:
    if not value or value != value.strip() or any(ord(c) < 0x21 or ord(c) > 0x7E for c in value):
        raise BuilderConfigError(f"{name} must be a non-empty URL without whitespace")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise BuilderConfigError(f"{name} is not a valid URL") from exc
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise BuilderConfigError(f"{name} must be an absolute https URL")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise BuilderConfigError(f"{name} must not embed credentials")
    if parts.query or parts.fragment or "?" in value or "#" in value or ";" in parts.path:
        raise BuilderConfigError(f"{name} must not carry a query, fragment or parameters")
    host = parts.hostname.lower()
    if parts.scheme == "http" and not _is_literal_loopback(host):
        raise BuilderConfigError(f"{name} must use https (http is allowed only for literal loopback)")
    path = parts.path
    if not allow_path and path not in ("", "/"):
        raise BuilderConfigError(f"{name} must be an origin with no path")
    if allow_path:
        if "%" in path or "\\" in path or any(seg in (".", "..") for seg in path.split("/")):
            raise BuilderConfigError(f"{name} has an unsafe path")
        path = path.rstrip("/")
    else:
        path = ""
    default = 443 if parts.scheme == "https" else 80
    return Origin(parts.scheme, host, port if port is not None else default), path


@dataclass(frozen=True)
class BuilderConfig:
    owner_sub: str
    public_origin: Origin
    workspace_origin: Origin
    workspace_base_path: str
    workspace_token: str = field(repr=False)
    connect_timeout: float = 5.0
    read_timeout: float = 60.0
    write_timeout: float = 30.0
    pool_timeout: float = 5.0

    @property
    def workspace_base_url(self) -> str:
        return self.workspace_origin.serialized + self.workspace_base_path

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> BuilderConfig:
        missing = [
            name
            for name in ("BUILDER_OWNER_SUB", "BUILDER_PUBLIC_ORIGIN", "BUILDER_WORKSPACE_URL", "BUILDER_WORKSPACE_TOKEN")
            if not environ.get(name)
        ]
        if missing:
            raise BuilderConfigError("missing required environment: " + ", ".join(missing))
        owner = environ["BUILDER_OWNER_SUB"]
        if owner != owner.strip() or len(owner) > 512 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in owner):
            raise BuilderConfigError("BUILDER_OWNER_SUB must be an exact subject without surrounding whitespace")
        public, _ = _parse_origin_url("BUILDER_PUBLIC_ORIGIN", environ["BUILDER_PUBLIC_ORIGIN"], allow_path=False)
        workspace, base_path = _parse_origin_url("BUILDER_WORKSPACE_URL", environ["BUILDER_WORKSPACE_URL"], allow_path=True)
        token = environ["BUILDER_WORKSPACE_TOKEN"]
        if len(token) < MIN_TOKEN_LENGTH or len(token) > 4096 or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
            raise BuilderConfigError(
                f"BUILDER_WORKSPACE_TOKEN must be at least {MIN_TOKEN_LENGTH} token68 characters"
            )
        return cls(owner, public, workspace, base_path, token)


def workspace_ssl_context(environ: Mapping[str, str]) -> ssl.SSLContext:
    """Verifying TLS context; honors SSL_CERT_FILE/SSL_CERT_DIR explicitly.

    The client runs with ``trust_env=False`` so no proxy variable can redirect
    it, which also stops httpx reading these, so they are applied here.
    Verification is never disabled.
    """

    cafile = environ.get("SSL_CERT_FILE") or None
    capath = environ.get("SSL_CERT_DIR") or None
    if cafile and not os.path.isfile(cafile):
        raise BuilderConfigError("SSL_CERT_FILE does not name a readable file")
    context = ssl.create_default_context(cafile=cafile, capath=capath)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


async def hub_session_checker(request: Any) -> Any:
    """The Hub's own live-session decision (signature, expiry, ended sessions)."""

    from collab_hub_api.web.authz import get_web_session

    return await get_web_session(request)


class _Refusal(Exception):
    def __init__(self, status: int, error: str, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(error)
        self.status = status
        self.error = error
        self.headers = headers or {}


def _header(scope: Scope, name: bytes) -> str | None:
    """A single-valued request header; a repeated one is refused."""

    values = [v for k, v in scope.get("headers", ()) if k.lower() == name]
    if len(values) > 1:
        raise _Refusal(400, "bad-request")
    if not values:
        return None
    try:
        return values[0].decode("latin-1")
    except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 decodes all bytes
        raise _Refusal(400, "bad-request") from exc


def _host_matches(value: str | None, origin: Origin) -> bool:
    if not value:
        return False
    try:
        parts = urlsplit(f"{origin.scheme}://{value}")
        port = parts.port
    except ValueError:
        return False
    if parts.username is not None or parts.password is not None or parts.path or parts.query or parts.fragment:
        return False
    if not parts.hostname or parts.hostname.lower() != origin.host:
        return False
    default = 443 if origin.scheme == "https" else 80
    return (port if port is not None else default) == origin.port


def on_builder_path(path: str) -> bool:
    return path == PREFIX or path.startswith(PREFIX + "/")


class BuilderHubExtension:
    """Outer ASGI wrapper: Builder routes here, everything else to the Hub as-is."""

    def __init__(
        self,
        hub_app: ASGIApp,
        config: BuilderConfig,
        *,
        session_checker: SessionChecker = hub_session_checker,
        transport: httpx.AsyncBaseTransport | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.hub_app = hub_app
        self.config = config
        self.session_checker = session_checker
        self.transport = transport
        if transport is None and config.workspace_origin.scheme == "https" and ssl_context is None:
            ssl_context = workspace_ssl_context(os.environ)
        self.ssl_context = ssl_context

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind not in ("http", "websocket") or not on_builder_path(scope.get("path", "")):
            await self.hub_app(scope, receive, send)
            return
        if kind == "websocket":
            # Refuse before accepting: the server answers the upgrade with 403.
            message = await receive()
            if message.get("type") == "websocket.connect":
                await send({"type": "websocket.close", "code": 1008})
            return
        await self._handle_http(scope, receive, send)

    # -- request handling -------------------------------------------------

    async def _handle_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        page = path in PAGE_PATHS
        try:
            status, headers, body = await self._decide(scope, receive, page=page)
        except _Refusal as refusal:
            status, headers, body = self._error(refusal.status, refusal.error, page=page, extra=refusal.headers)
        except Exception:
            logger.exception("builder_request_failed")
            status, headers, body = self._error(503, "unavailable", page=page)
        await _send_response(send, status, headers, body)

    async def _decide(self, scope: Scope, receive: Receive, *, page: bool) -> tuple[int, dict[str, str], bytes]:
        cfg = self.config
        path = scope.get("path", "")
        method = scope.get("method", "")
        raw_path = scope.get("raw_path")
        if raw_path is not None and raw_path != path.encode("latin-1", "replace"):
            # Percent-encoded or otherwise re-spelled paths are not served: the
            # allowlist is matched on exactly the bytes the browser sent.
            raise _Refusal(404, "not-found")
        if scope.get("root_path"):
            raise _Refusal(404, "not-found")

        if not _host_matches(_header(scope, b"host"), cfg.public_origin):
            raise _Refusal(400, "bad-host")
        origin = _header(scope, b"origin")
        if origin is not None and origin != cfg.public_origin.serialized:
            raise _Refusal(403, "bad-origin")

        session = await self._live_session(scope)
        if session is None:
            if page and method == "GET":
                raise _Refusal(303, "signin", headers={"location": SIGNIN_REDIRECT})
            raise _Refusal(401, "unauthenticated")
        user = getattr(session, "user", None)
        if not isinstance(user, str) or not hmac.compare_digest(user.encode(), cfg.owner_sub.encode()):
            logger.warning("builder_owner_refused")
            raise _Refusal(403, "forbidden")

        if path == PREFIX:
            if method != "GET":
                raise _Refusal(405, "method-not-allowed", headers={"allow": "GET"})
            await _refuse_body(scope)
            return 303, {**SECURITY_HEADERS, "content-security-policy": API_CSP, "location": STUDIO_PATH}, b""

        route = ROUTES.get((method, path))
        if route is None:
            allowed = sorted(m for m, p in ROUTES if p == path)
            if allowed:
                raise _Refusal(405, "method-not-allowed", headers={"allow": ", ".join(allowed)})
            raise _Refusal(404, "not-found")
        upstream_path, forwards_query, kind = route

        query = scope.get("query_string", b"") or b""
        if len(query) > MAX_QUERY_BYTES:
            raise _Refusal(414, "query-too-long")
        if not forwards_query:
            query = b""
        elif not re.fullmatch(rb"[A-Za-z0-9._~%&=+-]*", query):
            raise _Refusal(400, "bad-query")

        upstream_headers = {
            "accept": "text/html" if kind == "page" else "application/json",
            "accept-encoding": "identity",
            "user-agent": "builder-hub-extension",
            "authorization": f"Bearer {cfg.workspace_token}",
        }
        body = b""
        if method == "POST":
            self._check_write(scope)
            upstream_headers["content-type"] = "application/json"
            upstream_headers[WORKBENCH_TOKEN_HEADER] = _header(scope, b"x-cog-workbench") or ""
            body = await _read_body(scope, receive)
            try:
                action = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                raise _Refusal(400, "bad-json") from None
            if isinstance(action, dict) and action.get('action') == 'build-resume' and isinstance(action.get('decision'), dict):
                # Human attribution is authenticated identity, never a form value.
                action['decision']['by'] = session.user
                body = json.dumps(action).encode()
        else:
            await _refuse_body(scope)

        return await self._proxy(method, upstream_path, query, upstream_headers, body, kind)

    async def _live_session(self, scope: Scope) -> Any:
        from starlette.requests import Request

        hub_scope = dict(scope)
        hub_scope["app"] = self.hub_app
        # A state dict of our own: the Hub caches its answer on request state,
        # and nothing else of this request reaches the Hub.
        hub_scope["state"] = {}
        try:
            return await self.session_checker(Request(hub_scope))
        except Exception as exc:
            logger.error("builder_session_undecidable", extra={"error_type": type(exc).__name__})
            raise _Refusal(503, "unavailable") from exc

    def _check_write(self, scope: Scope) -> None:
        if _header(scope, b"origin") != self.config.public_origin.serialized:
            raise _Refusal(403, "bad-origin")
        fetch_site = _header(scope, b"sec-fetch-site")
        if fetch_site is not None and fetch_site != "same-origin":
            raise _Refusal(403, "bad-origin")
        content_type = (_header(scope, b"content-type") or "").strip().lower()
        if content_type not in JSON_CONTENT_TYPES:
            raise _Refusal(415, "unsupported-media-type")
        token = _header(scope, b"x-cog-workbench")
        if token is None or not WORKBENCH_TOKEN_RE.fullmatch(token):
            raise _Refusal(403, "reload-required")

    async def _proxy(
        self, method: str, upstream_path: str, query: bytes, headers: dict[str, str], body: bytes, kind: str
    ) -> tuple[int, dict[str, str], bytes]:
        cfg = self.config
        url = httpx.URL(cfg.workspace_base_url + upstream_path)
        if query:
            url = url.copy_with(query=query)
        timeout = httpx.Timeout(
            connect=cfg.connect_timeout, read=cfg.read_timeout, write=cfg.write_timeout, pool=cfg.pool_timeout
        )
        client_kwargs: dict[str, Any] = {
            "trust_env": False,
            "follow_redirects": False,
            "timeout": timeout,
            "headers": {},
        }
        if self.transport is not None:
            client_kwargs["transport"] = self.transport
        elif self.ssl_context is not None:
            client_kwargs["verify"] = self.ssl_context
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                request = client.build_request(method, url, headers=headers, content=body if method == "POST" else None)
                # Only the headers this module chose: httpx adds Host and
                # Content-Length itself, nothing from the browser.
                for name in list(request.headers.keys()):
                    if name.lower() not in {*headers, "host", "content-length"}:
                        del request.headers[name]
                response = await client.send(request, stream=True)
                try:
                    status = response.status_code
                    content_type = response.headers.get("content-type", "")
                    encoding = response.headers.get("content-encoding", "identity").lower()
                    declared = response.headers.get("content-length")
                    if declared is not None and (not declared.isdigit() or int(declared) > MAX_RESPONSE_BODY):
                        raise _Refusal(502, "bad-gateway")
                    if encoding not in ("", "identity"):
                        # Refused before reading, so nothing is ever decompressed.
                        raise _Refusal(502, "bad-gateway")
                    payload = bytearray()
                    async for chunk in response.aiter_bytes():
                        payload += chunk
                        if len(payload) > MAX_RESPONSE_BODY:
                            raise _Refusal(502, "bad-gateway")
                finally:
                    await response.aclose()
        except _Refusal:
            raise
        except httpx.TimeoutException as exc:
            logger.warning("builder_workspace_timeout", extra={"error_type": type(exc).__name__})
            raise _Refusal(503, "unavailable") from exc
        except httpx.HTTPError as exc:
            logger.warning("builder_workspace_unreachable", extra={"error_type": type(exc).__name__})
            raise _Refusal(503, "unavailable") from exc

        if status < 200 or 300 <= status < 400 or status >= 500 or status in (401, 407):
            # Redirects are never followed or relayed; an upstream 401 means the
            # internal credential is wrong, which the browser must not read as
            # "sign in again".
            logger.warning("builder_workspace_bad_status", extra={"status": status})
            raise _Refusal(502, "bad-gateway")
        media = content_type.split(";", 1)[0].strip().lower()
        if kind == "page":
            if status != 200 or media != "text/html":
                raise _Refusal(502, "bad-gateway")
            try:
                html = bytes(payload).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _Refusal(502, "bad-gateway") from exc
            html = rewrite_studio_html(html)
            out = html.encode("utf-8")
            return (
                200,
                {**SECURITY_HEADERS, "content-security-policy": studio_csp(html), "content-type": "text/html; charset=utf-8"},
                out,
            )
        if media != "application/json":
            raise _Refusal(502, "bad-gateway")
        return (
            status,
            {**SECURITY_HEADERS, "content-security-policy": API_CSP, "content-type": "application/json"},
            bytes(payload),
        )

    def _error(
        self, status: int, error: str, *, page: bool, extra: Mapping[str, str] | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        headers = {**SECURITY_HEADERS, "content-security-policy": API_CSP, **(extra or {})}
        if status in (303,):
            return status, headers, b""
        headers["content-type"] = "application/json"
        if status in (400, 413, 414, 415):
            headers["connection"] = "close"
        return status, headers, json.dumps({"error": error}).encode()


def studio_csp(html: str) -> str:
    def hashes(tag):
        blocks = re.findall(r'<' + tag + r'>(.*?)</' + tag + r'>', html, flags=re.DOTALL)
        return ' '.join("'sha256-" + base64.b64encode(hashlib.sha256(block.encode()).digest()).decode() + "'" for block in blocks) or "'none'"
    return STUDIO_CSP.format(scripts=hashes('script'), styles=hashes('style'))


def rewrite_studio_html(html: str) -> str:
    """Point the Studio page at the ``/builder`` routes and add Hub navigation.

    Literal, bounded rewrites only: exact quoted root API path prefixes, the
    root link, and one banner. Payload JSON is never parsed or altered.
    """

    for quote in ("'", '"', "`"):
        html = html.replace(f"{quote}/api/suite/", f"{quote}{PREFIX}/api/suite/")
    html = html.replace('href="/"', f'href="{HOME_PATH}"')
    for anchor in ("<header", "<main"):
        index = html.find(anchor)
        if index != -1:
            return html[:index] + OWNER_BANNER + html[index:]
    index = html.find("</title>")
    if index != -1:
        index += len("</title>")
        return html[:index] + OWNER_BANNER + html[index:]
    return OWNER_BANNER + html


def install_navigation(home_module, owner_sub: str) -> None:
    """Add an owner-only Builder link through the pinned Hub's chrome data.

    No Hub HTML, scripts or authentication behavior are copied. This small
    integration seam is qualified against the exact Hub revision in sources.
    """
    original = home_module._chrome

    def chrome(surface, session, root_path, back_path):
        result = original(surface, session, root_path, back_path)
        if session is not None and session.user == owner_sub:
            result = replace(result, nav=result.nav +
                             '<a href="' + result.root + '/builder/studio">Builder Studio</a>')
        return result

    home_module._chrome = chrome


async def _refuse_body(scope: Scope) -> None:
    length = _header(scope, b"content-length")
    if _header(scope, b"transfer-encoding") is not None or (length is not None and length.strip() != "0"):
        raise _Refusal(400, "unexpected-body")


async def _read_body(scope: Scope, receive: Receive) -> bytes:
    length = _header(scope, b"content-length")
    if length is not None:
        if not length.isdigit():
            raise _Refusal(400, "bad-request")
        if int(length) > MAX_REQUEST_BODY:
            raise _Refusal(413, "too-large")
    body = bytearray()
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            raise _Refusal(400, "bad-request")
        body += message.get("body", b"")
        if len(body) > MAX_REQUEST_BODY:
            raise _Refusal(413, "too-large")
        if not message.get("more_body", False):
            return bytes(body)


async def _send_response(send: Send, status: int, headers: Mapping[str, str], body: bytes) -> None:
    raw = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items() if k != "content-length"]
    raw.append((b"content-length", str(len(body)).encode()))
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": body})


def main() -> None:  # pragma: no cover - exercised in deployment
    import uvicorn
    from collab_hub_api.config import Config
    from collab_hub_api.core import make_app
    from collab_hub_api.observability import configure_logging

    builder_config = BuilderConfig.from_env(os.environ)
    ssl_context = workspace_ssl_context(os.environ) if builder_config.workspace_origin.scheme == "https" else None
    # The Hub never needs the workspace credential; keep it out of the
    # environment anything else in this process might read or pass on.
    os.environ.pop("BUILDER_WORKSPACE_TOKEN", None)

    config = Config.parse()
    configure_logging(config.observability.logging)
    from collab_hub_api.web import home
    install_navigation(home, builder_config.owner_sub)
    hub = make_app(config)
    if getattr(hub.state, "web_surface", None) is None:
        raise SystemExit("Builder requires the Hub web surface (web.enabled) for session checks")
    app = BuilderHubExtension(hub, builder_config, ssl_context=ssl_context)
    uvicorn.run(
        app,
        host=config.server.hostname,
        port=config.server.port,
        proxy_headers=config.server.proxy_headers,
        forwarded_allow_ips=config.server.forwarded_allow_ips,
        log_config=None,
        use_colors=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
