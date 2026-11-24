"""Builder Hub extension: authentication, CSRF, route restrictions, fail-closed.

No Hub source is needed: the Hub app is a small Starlette stand-in, the live
session decision is an injected checker, and the workspace is an httpx mock
transport that records exactly what would have been sent.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from builder_hub import hub_extension as ext  # noqa: E402
from builder_hub.hub_extension import (  # noqa: E402
    MAX_REQUEST_BODY,
    MAX_RESPONSE_BODY,
    BuilderConfig,
    BuilderConfigError,
    BuilderHubExtension,
    rewrite_studio_html,
)

ORIGIN = "https://hub.example.test"
OWNER = "owner-subject-123"
TOKEN = "t" * 48
WB = "abcdef0123456789"
ENV = {
    "BUILDER_OWNER_SUB": OWNER,
    "BUILDER_PUBLIC_ORIGIN": ORIGIN,
    "BUILDER_WORKSPACE_URL": "http://127.0.0.1:8765",
    "BUILDER_WORKSPACE_TOKEN": TOKEN,
}
STUDIO_HTML = (
    "<!doctype html><html><title>Studio</title><style>a{}</style>"
    "<header><strong>Cog Workbench</strong><a href=\"/\">Inspect</a></header><main>"
    "<script>const token='__T__';fetch('/api/suite/action');fetch(\"/api/suite/catalog\");"
    "getBuild('/api/suite/build?id='+x);const other='/api/other';</script></main>"
)


@dataclass
class FakeSession:
    user: str


class Unavailable(Exception):
    pass


class Upstream:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.handler = self.default

    def default(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/studio":
            return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, text=STUDIO_HTML)
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "set-cookie": "leak=1", "x-internal": "secret"},
            content=b'{"ok": true, "path": "/api/suite/x"}',
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


def make_hub() -> Starlette:
    async def home(request):
        return PlainTextResponse("hub home " + request.headers.get("cookie", ""))

    async def ws(websocket):
        await websocket.accept()
        await websocket.send_text("hub ws")
        await websocket.close()

    hub = Starlette(
        routes=[
            Route("/web/home", home),
            Route("/builderx", home),
            Route("/v1/echo", home, methods=["GET", "POST"]),
            WebSocketRoute("/ws", ws),
        ]
    )
    hub.state.web_surface = object()
    return hub


@pytest.fixture
def setup():
    hub = make_hub()
    upstream = Upstream()
    sessions = {"good": FakeSession(OWNER), "other": FakeSession("someone-else"), "prefix": FakeSession(OWNER + "x")}
    seen_apps = []

    async def checker(request):
        seen_apps.append(request.app)
        value = request.cookies.get("collab_web")
        if value == "broken":
            raise Unavailable("ended-session store down")
        return sessions.get(value)

    app = BuilderHubExtension(
        hub, BuilderConfig.from_env(ENV), session_checker=checker, transport=httpx.MockTransport(upstream)
    )
    client = TestClient(app, base_url=ORIGIN, follow_redirects=False)
    return client, upstream, hub, seen_apps


def owner(client, cookie="good"):
    client.cookies.set("collab_web", cookie)
    return client


def write_headers(**extra):
    headers = {"Origin": ORIGIN, "Content-Type": "application/json", "X-Cog-Workbench": WB, "Sec-Fetch-Site": "same-origin"}
    headers.update(extra)
    return headers


# -- configuration ----------------------------------------------------------


@pytest.mark.parametrize("name", sorted(ENV))
def test_every_variable_is_mandatory(name):
    env = {k: v for k, v in ENV.items() if k != name}
    with pytest.raises(BuilderConfigError, match=name):
        BuilderConfig.from_env(env)
    with pytest.raises(BuilderConfigError):
        BuilderConfig.from_env({**ENV, name: ""})


@pytest.mark.parametrize(
    "url",
    [
        "http://workspace.internal:8080",
        "http://localhost:8080",
        "https://user:pw@workspace.internal",
        "https://user@workspace.internal",
        "https://workspace.internal/?x=1",
        "https://workspace.internal/#frag",
        "https://workspace.internal/a/../b",
        "https://workspace.internal/%2e%2e",
        "ftp://workspace.internal",
        "workspace.internal",
        " https://workspace.internal",
        "https://workspace.internal:99999",
    ],
)
def test_unsafe_workspace_urls_refused(url):
    with pytest.raises(BuilderConfigError):
        BuilderConfig.from_env({**ENV, "BUILDER_WORKSPACE_URL": url})


def test_safe_workspace_urls_accepted():
    cfg = BuilderConfig.from_env({**ENV, "BUILDER_WORKSPACE_URL": "https://ws.internal:8443/base/"})
    assert cfg.workspace_base_url == "https://ws.internal:8443/base"
    assert BuilderConfig.from_env({**ENV, "BUILDER_WORKSPACE_URL": "http://[::1]:9"}).workspace_base_url == "http://[::1]:9"


@pytest.mark.parametrize(
    "origin", ["http://hub.example.test", "https://hub.example.test/path", "https://u@hub.example.test", "https://h/?q"]
)
def test_unsafe_public_origin_refused(origin):
    with pytest.raises(BuilderConfigError):
        BuilderConfig.from_env({**ENV, "BUILDER_PUBLIC_ORIGIN": origin})


@pytest.mark.parametrize("token", ["short", "x" * 40 + " y", "x" * 40 + "\n", "é" * 40])
def test_weak_or_malformed_token_refused(token):
    with pytest.raises(BuilderConfigError):
        BuilderConfig.from_env({**ENV, "BUILDER_WORKSPACE_TOKEN": token})


@pytest.mark.parametrize("sub", [" " + OWNER, OWNER + "\n", "a\x00b"])
def test_owner_sub_must_be_exact(sub):
    with pytest.raises(BuilderConfigError):
        BuilderConfig.from_env({**ENV, "BUILDER_OWNER_SUB": sub})


def test_token_not_in_repr():
    assert TOKEN not in repr(BuilderConfig.from_env(ENV))


def test_ssl_cert_file_must_exist(tmp_path):
    with pytest.raises(BuilderConfigError):
        ext.workspace_ssl_context({"SSL_CERT_FILE": str(tmp_path / "missing.pem")})
    ctx = ext.workspace_ssl_context({})
    assert ctx.check_hostname and ctx.verify_mode.name == "CERT_REQUIRED"


# -- Hub passthrough --------------------------------------------------------


def test_non_builder_requests_reach_hub_unchanged(setup):
    client, upstream, hub, seen = setup
    client.cookies.set("collab_web", "anything")
    r = client.get("/web/home")
    assert r.status_code == 200 and r.text == "hub home collab_web=anything"
    assert client.get("/builderx").status_code == 200
    assert client.post("/v1/echo", content=b"x" * (MAX_REQUEST_BODY + 10)).status_code == 200
    with client.websocket_connect("/ws") as ws:
        assert ws.receive_text() == "hub ws"
    assert upstream.requests == [] and seen == []
    assert "content-security-policy" not in r.headers


def test_websocket_on_builder_refused(setup):
    client, upstream, *_ = setup
    owner(client)
    for path in ("/builder", "/builder/studio", "/builder/api/suite/job"):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(path):
                pass
    assert upstream.requests == []


# -- authentication ---------------------------------------------------------


def test_unauthenticated_page_redirects_to_signin(setup):
    client, upstream, *_ = setup
    for path in ("/builder", "/builder/studio"):
        r = client.get(path)
        assert r.status_code == 303
        assert r.headers["location"] == "/web/signin?next=%2Fbuilder%2Fstudio"
        assert r.headers["cache-control"].startswith("no-store")
    assert upstream.requests == []


@pytest.mark.parametrize("cookie", [None, "expired-or-revoked", ""])
def test_unauthenticated_api_is_401_json(setup, cookie):
    client, upstream, *_ = setup
    if cookie is not None:
        client.cookies.set("collab_web", cookie)
    r = client.get("/builder/api/suite/catalog")
    assert r.status_code == 401 and r.json() == {"error": "unauthenticated"}
    r = client.post("/builder/api/suite/action", headers=write_headers(), content=b"{}")
    assert r.status_code == 401
    assert upstream.requests == []


def test_failed_session_lookup_is_503(setup):
    client, upstream, *_ = setup
    owner(client, "broken")
    for path in ("/builder/studio", "/builder/api/suite/builds"):
        r = client.get(path)
        assert r.status_code == 503 and r.json() == {"error": "unavailable"}
    assert upstream.requests == []


@pytest.mark.parametrize("cookie", ["other", "prefix"])
def test_non_owner_is_403(setup, cookie):
    client, upstream, *_ = setup
    owner(client, cookie)
    assert client.get("/builder/studio").status_code == 403
    assert client.post("/builder/api/suite/action", headers=write_headers(), content=b"{}").status_code == 403
    assert upstream.requests == []


def test_session_checker_uses_hub_app_state(setup):
    client, upstream, hub, seen = setup
    owner(client)
    assert client.get("/builder/api/suite/catalog").status_code == 200
    assert seen and all(app is hub for app in seen)
    assert seen[0].state.web_surface is hub.state.web_surface


def test_default_checker_delegates_to_hub_get_web_session(monkeypatch):
    calls = []

    async def get_web_session(request):
        calls.append(request.app.state.web_surface)
        return FakeSession(OWNER)

    fake = type(sys)("collab_hub_api.web.authz")
    fake.get_web_session = get_web_session
    for name in ("collab_hub_api", "collab_hub_api.web"):
        monkeypatch.setitem(sys.modules, name, type(sys)(name))
    monkeypatch.setitem(sys.modules, "collab_hub_api.web.authz", fake)
    hub = make_hub()
    upstream = Upstream()
    app = BuilderHubExtension(hub, BuilderConfig.from_env(ENV), transport=httpx.MockTransport(upstream))
    r = TestClient(app, base_url=ORIGIN).get("/builder/api/suite/catalog")
    assert r.status_code == 200 and calls == [hub.state.web_surface]


def test_default_checker_exception_fails_closed(monkeypatch):
    async def get_web_session(request):
        raise RuntimeError("WebSessionUndecidable")

    fake = type(sys)("collab_hub_api.web.authz")
    fake.get_web_session = get_web_session
    for name in ("collab_hub_api", "collab_hub_api.web"):
        monkeypatch.setitem(sys.modules, name, type(sys)(name))
    monkeypatch.setitem(sys.modules, "collab_hub_api.web.authz", fake)
    upstream = Upstream()
    app = BuilderHubExtension(make_hub(), BuilderConfig.from_env(ENV), transport=httpx.MockTransport(upstream))
    assert TestClient(app, base_url=ORIGIN).get("/builder/studio").status_code == 503
    assert upstream.requests == []


# -- routes -----------------------------------------------------------------


def test_builder_root_redirects_to_studio(setup):
    client, upstream, *_ = setup
    owner(client)
    r = client.get("/builder")
    assert r.status_code == 303 and r.headers["location"] == "/builder/studio"
    assert upstream.requests == []


@pytest.mark.parametrize(
    "public,upstream_path",
    [
        ("/builder/api/suite/catalog", "/api/suite/catalog"),
        ("/builder/api/suite/builds", "/api/suite/builds"),
        ("/builder/api/suite/build?id=run-1", "/api/suite/build"),
        ("/builder/api/suite/job?id=abc123", "/api/suite/job"),
    ],
)
def test_allowlisted_gets_proxied_with_prefix_stripped(setup, public, upstream_path):
    client, upstream, *_ = setup
    owner(client)
    r = client.get(public)
    assert r.status_code == 200 and r.json()["ok"] is True
    sent = upstream.requests[-1]
    assert sent.method == "GET" and sent.url.path == upstream_path
    assert str(sent.url).startswith("http://127.0.0.1:8765/api/suite/")
    if "?" in public:
        assert sent.url.query == public.split("?", 1)[1].encode()


def test_query_dropped_where_not_needed_and_validated(setup):
    client, upstream, *_ = setup
    owner(client)
    client.get("/builder/api/suite/catalog?x=1")
    assert upstream.requests[-1].url.query == b""
    assert client.get("/builder/api/suite/job?id=" + "a" * 3000).status_code == 414


@pytest.mark.parametrize(
    "method,path,status",
    [
        ("GET", "/builder/", 404),
        ("GET", "/builder/studio/", 404),
        ("GET", "/builder/api/suite/action", 405),
        ("POST", "/builder/studio", 405),
        ("PUT", "/builder/api/suite/action", 405),
        ("DELETE", "/builder/api/suite/build", 405),
        ("HEAD", "/builder/studio", 405),
        ("OPTIONS", "/builder/api/suite/action", 405),
        ("GET", "/builder/api/suite/other", 404),
        ("GET", "/builder/api/suite", 404),
        ("GET", "/builder/web/home", 404),
        ("POST", "/builder", 405),
    ],
)
def test_route_and_method_bypasses_refused(setup, method, path, status):
    client, upstream, *_ = setup
    owner(client)
    r = client.request(method, path, headers=write_headers())
    assert r.status_code == status
    assert upstream.requests == []


def test_encoded_paths_refused(setup):
    client, upstream, *_ = setup
    owner(client)
    app = client.app

    async def call(raw_path: bytes, path: str, query: bytes = b""):
        sent = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http", "method": "GET", "path": path, "raw_path": raw_path, "root_path": "",
            "query_string": query, "headers": [(b"host", b"hub.example.test"), (b"cookie", b"collab_web=good")],
        }
        await app(scope, receive, send)
        return sent[0]["status"]

    import anyio

    assert anyio.run(call, b"/builder/%73tudio", "/builder/studio") == 404
    assert anyio.run(call, b"/builder/api%2Fsuite/catalog", "/builder/api/suite/catalog") == 404
    assert anyio.run(call, b"/builder/../web/home", "/builder/../web/home") == 404
    assert anyio.run(call, b"/builder/api/suite/../../studio", "/builder/api/suite/../../studio") == 404
    assert anyio.run(call, b"/builder/api/suite/job", "/builder/api/suite/job", b'id=<script>"') == 400
    assert anyio.run(call, b"/builder/studio", "/builder/studio") == 200
    assert len(upstream.requests) == 1


# -- Host / Origin / CSRF ---------------------------------------------------


@pytest.mark.parametrize("host", ["evil.example", "hub.example.test:8443", "hub.example.test.evil", "user@hub.example.test", ""])
def test_bad_host_refused(setup, host):
    client, upstream, *_ = setup
    owner(client)
    r = client.get("/builder/studio", headers={"Host": host})
    assert r.status_code == 400
    assert upstream.requests == []


def test_host_with_default_port_and_case_accepted(setup):
    client, upstream, *_ = setup
    owner(client)
    assert client.get("/builder/api/suite/catalog", headers={"Host": "HUB.example.test:443"}).status_code == 200


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://hub.example.test", ORIGIN + ":443", ORIGIN + "/"])
def test_bad_origin_refused_for_reads_and_writes(setup, origin):
    client, upstream, *_ = setup
    owner(client)
    assert client.get("/builder/api/suite/catalog", headers={"Origin": origin}).status_code == 403
    r = client.post("/builder/api/suite/action", headers=write_headers(Origin=origin), content=b"{}")
    assert r.status_code == 403
    assert upstream.requests == []


def test_write_requires_origin_and_same_origin_fetch(setup):
    client, upstream, *_ = setup
    owner(client)
    headers = write_headers()
    del headers["Origin"]
    assert client.post("/builder/api/suite/action", headers=headers, content=b"{}").status_code == 403
    r = client.post("/builder/api/suite/action", headers=write_headers(**{"Sec-Fetch-Site": "same-site"}), content=b"{}")
    assert r.status_code == 403
    assert upstream.requests == []


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""])
def test_write_requires_json_content_type(setup, ctype):
    client, upstream, *_ = setup
    owner(client)
    r = client.post("/builder/api/suite/action", headers=write_headers(**{"Content-Type": ctype}), content=b"{}")
    assert r.status_code == 415
    assert upstream.requests == []


@pytest.mark.parametrize("wb", [None, "", "bad token", "x" * 200, "a\"b"])
def test_write_requires_workbench_token(setup, wb):
    client, upstream, *_ = setup
    owner(client)
    headers = write_headers()
    if wb is None:
        del headers["X-Cog-Workbench"]
    else:
        headers["X-Cog-Workbench"] = wb
    assert client.post("/builder/api/suite/action", headers=headers, content=b"{}").status_code == 403
    assert upstream.requests == []


def test_repeated_security_header_refused(setup):
    client, upstream, *_ = setup
    owner(client)
    r = client.post(
        "/builder/api/suite/action",
        headers=[("Origin", ORIGIN), ("Origin", "https://evil.example"), ("Content-Type", "application/json"), ("X-Cog-Workbench", WB)],
        content=b"{}",
    )
    assert r.status_code == 400
    assert upstream.requests == []


# -- what is forwarded ------------------------------------------------------


FORGED = {
    "Authorization": "Bearer user-supplied",
    "Proxy-Authorization": "Basic abc",
    "X-Forwarded-For": "10.0.0.1",
    "X-Forwarded-Host": "evil.example",
    "X-Forwarded-Proto": "http",
    "Forwarded": "for=1.2.3.4",
    "X-Real-IP": "1.2.3.4",
    "X-Original-URL": "/admin",
    "X-Auth-Request-User": OWNER,
    "X-Remote-User": OWNER,
    "Cookie": "collab_web=good; other=secret-cookie",
    "X-CSRF-Token": "csrf-secret",
}


def test_post_forwards_only_fixed_headers_and_internal_token(setup):
    client, upstream, *_ = setup
    owner(client)
    body = b'{"action": "snapshot", "keep": "/api/suite/untouched"}'
    r = client.post(
        "/builder/api/suite/action", headers={**write_headers(), **FORGED, "Content-Type": "application/json; charset=utf-8"}, content=body
    )
    assert r.status_code == 200
    sent = upstream.requests[-1]
    assert sent.method == "POST" and sent.url.path == "/api/suite/action"
    assert sent.content == body
    names = {k.lower() for k in sent.headers}
    assert names <= {"host", "accept", "accept-encoding", "user-agent", "authorization", "content-type", "content-length", "x-cog-workbench"}
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert sent.headers["content-type"] == "application/json"
    assert sent.headers["x-cog-workbench"] == WB
    assert sent.headers["host"] == "127.0.0.1:8765"
    raw = repr(list(sent.headers.raw))
    for leaked in ("secret-cookie", "collab_web", "user-supplied", "evil.example", "csrf-secret", "10.0.0.1", OWNER):
        assert leaked not in raw


def test_get_forwards_no_browser_headers(setup):
    client, upstream, *_ = setup
    owner(client)
    client.get("/builder/api/suite/builds", headers={**FORGED, "X-Cog-Workbench": WB})
    sent = upstream.requests[-1]
    names = {k.lower() for k in sent.headers}
    assert names <= {"host", "accept", "accept-encoding", "user-agent", "authorization"}
    assert sent.content == b""


def test_response_headers_are_fixed_and_token_never_returned(setup):
    client, upstream, *_ = setup
    owner(client)
    r = client.get("/builder/api/suite/catalog")
    assert "set-cookie" not in r.headers and "x-internal" not in r.headers
    assert r.headers["content-type"] == "application/json"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"].startswith("no-store")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    # payload JSON is passed through byte for byte, never rewritten
    assert r.content == b'{"ok": true, "path": "/api/suite/x"}'
    for response in (r, client.get("/builder/studio"), client.get("/builder/nope")):
        assert TOKEN not in response.text and TOKEN not in repr(response.headers)


def test_upstream_error_does_not_echo_token(setup):
    client, upstream, *_ = setup
    owner(client)

    def boom(request):
        raise httpx.ConnectError(f"failed with {request.headers['authorization']}")

    upstream.handler = boom
    r = client.get("/builder/api/suite/catalog")
    assert r.status_code == 503 and TOKEN not in r.text


# -- Studio page -------------------------------------------------------------


def test_studio_page_rewritten_with_navigation_and_csp(setup):
    client, upstream, *_ = setup
    owner(client)
    r = client.get("/builder/studio", headers=FORGED)
    assert r.status_code == 200
    assert upstream.requests[-1].url.path == "/studio"
    html = r.text
    assert "fetch('/builder/api/suite/action')" in html
    assert 'fetch("/builder/api/suite/catalog")' in html
    assert "getBuild('/builder/api/suite/build?id='" in html
    assert "'/api/suite/" not in html and "'/api/other'" in html
    assert 'href="/web/home"' in html and "Owner preview" in html
    assert html.index("Owner preview") < html.index("<header")
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp and "unsafe-inline" not in csp
    assert "http" not in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-type"] == "text/html; charset=utf-8"


def test_rewrite_is_literal_and_falls_back():
    assert '<nav' in rewrite_studio_html("x")
    out = rewrite_studio_html("<title>t</title><p>'/api/suite/x' /api/suite/y</p>")
    assert out.startswith("<title>t</title><style>") and "'/builder/api/suite/x' /api/suite/y" in out


def test_gate_attribution_uses_authenticated_owner(setup):
    client, upstream, *_ = setup
    owner(client)
    response = client.post('/builder/api/suite/action', headers=write_headers(), json={
        'action': 'build-resume', 'id': 'example',
        'decision': {'by': 'forged-person', 'verdict': 'accept'},
    })
    assert response.status_code == 200
    assert json.loads(upstream.requests[-1].content)['decision']['by'] == OWNER


def test_studio_csp_hashes_only_the_served_code(setup):
    import base64
    import hashlib
    import re
    client, *_ = setup
    response = owner(client).get('/builder/studio')
    csp = response.headers['content-security-policy']
    for script in re.findall(r'<script>(.*?)</script>', response.text, re.DOTALL):
        expected = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        assert 'sha256-' + expected in csp
    assert 'unsafe-inline' not in csp and 'unsafe-eval' not in csp


def test_studio_page_requires_html(setup):
    client, upstream, *_ = setup
    owner(client)
    upstream.handler = lambda request: httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}")
    assert client.get("/builder/studio").status_code == 502
    upstream.handler = lambda request: httpx.Response(200, headers={"content-type": "text/html"}, content=b"\xff\xfe")
    assert client.get("/builder/studio").status_code == 502


# -- bodies and upstream failures -------------------------------------------


def test_request_body_bound(setup):
    client, upstream, *_ = setup
    owner(client)
    ok = client.post("/builder/api/suite/action", headers=write_headers(), content=b"{" + b" " * (MAX_REQUEST_BODY - 2) + b"}")
    assert ok.status_code == 200 and len(upstream.requests[-1].content) == MAX_REQUEST_BODY
    big = client.post("/builder/api/suite/action", headers=write_headers(), content=b"x" * (MAX_REQUEST_BODY + 1))
    assert big.status_code == 413

    def chunks():
        for _ in range(5):
            yield b"x" * (1024 * 1024)

    streamed = client.post("/builder/api/suite/action", headers=write_headers(), content=chunks())
    assert streamed.status_code == 413
    assert len(upstream.requests) == 1


def test_get_with_body_refused(setup):
    client, upstream, *_ = setup
    owner(client)
    assert client.request("GET", "/builder/api/suite/catalog", content=b"{}").status_code == 400
    assert upstream.requests == []


def test_bad_content_length_refused(setup):
    client, upstream, *_ = setup
    owner(client)
    r = client.post("/builder/api/suite/action", headers={**write_headers(), "Content-Length": "abc"}, content=b"{}")
    assert r.status_code in (400, 413)
    assert upstream.requests == []


def test_response_body_bound(setup):
    client, upstream, *_ = setup
    owner(client)
    upstream.handler = lambda request: httpx.Response(
        200, headers={"content-type": "application/json"}, content=b"x" * (MAX_RESPONSE_BODY + 1)
    )
    assert client.get("/builder/api/suite/catalog").status_code == 502

    def stream(request):
        async def gen():
            for _ in range(17):
                yield b"x" * (1024 * 1024)

        return httpx.Response(200, headers={"content-type": "application/json"}, content=gen())

    upstream.handler = stream
    assert client.get("/builder/api/suite/catalog").status_code == 502


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://evil.example/"}),
        httpx.Response(307, headers={"location": "/api/suite/catalog"}),
        httpx.Response(500, json={"error": "trace"}),
        httpx.Response(401, json={"error": "token"}),
        httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html>"),
        httpx.Response(200, headers={"content-type": "application/json", "content-encoding": "gzip"}, content=b"\x1f\x8b"),
    ],
)
def test_bad_upstream_responses_are_502(setup, response):
    client, upstream, *_ = setup
    owner(client)
    upstream.handler = lambda request: response
    r = client.get("/builder/api/suite/catalog")
    assert r.status_code == 502 and r.json() == {"error": "bad-gateway"}
    assert len(upstream.requests) == 1  # never followed


def test_upstream_client_errors_pass_through(setup):
    client, upstream, *_ = setup
    owner(client)
    upstream.handler = lambda request: httpx.Response(400, json={"error": "bad id"})
    r = client.get("/builder/api/suite/build?id=nope")
    assert r.status_code == 400 and r.json() == {"error": "bad id"}


@pytest.mark.parametrize("exc", [httpx.ConnectError("x"), httpx.ReadTimeout("x"), httpx.RemoteProtocolError("x")])
def test_unreachable_workspace_is_503(setup, exc):
    client, upstream, *_ = setup
    owner(client)

    def fail(request):
        raise exc

    upstream.handler = fail
    r = client.get("/builder/api/suite/catalog")
    assert r.status_code == 503 and json.loads(r.text) == {"error": "unavailable"}


def test_client_ignores_proxy_environment(setup, monkeypatch):
    client, upstream, *_ = setup
    owner(client)
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://evil.example:3128")
    created = []
    real = httpx.AsyncClient

    def spy(*args, **kwargs):
        created.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(ext.httpx, "AsyncClient", spy)
    assert client.get("/builder/api/suite/catalog").status_code == 200
    assert created[0]["trust_env"] is False and created[0]["follow_redirects"] is False
    timeout = created[0]["timeout"]
    assert timeout.connect and timeout.read and timeout.write and timeout.pool


def test_security_headers_on_errors_and_redirects(setup):
    client, *_ = setup
    for r in (client.get("/builder/studio"), client.get("/builder/api/suite/catalog")):
        assert r.headers["cache-control"].startswith("no-store")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer"
