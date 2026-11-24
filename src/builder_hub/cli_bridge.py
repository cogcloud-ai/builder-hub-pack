#!/usr/bin/env python3
"""Workspace-side CLI shim for the strictly bounded host-services bridge.

Invoked either explicitly as::

    python -m builder_hub.cli_bridge claude [args...]
    python -m builder_hub.cli_bridge docker [args...]

or via an executable ``argv[0]`` wrapper named ``claude`` or ``docker``.

Because upstream ``cog-claude`` scrubs ambient ``BUILDER_*`` and
``SSL_CERT_FILE`` environment variables inside ``clean_env()``, this shim loads
its client configuration from ``/etc/builder-host/client.json`` by default
(or ``BUILDER_HOST_CONFIG`` when explicitly set for tests/parent tooling).
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from typing import Any
import urllib.error
from urllib.parse import urlsplit
import urllib.request

from builder_hub.host_bridge import (
    BridgeError,
    CONTAINER_NAME_RE,
    DOCKER_INSPECT_FORMAT,
    FORBIDDEN_PATH_SEGMENTS,
    FORBIDDEN_SHELL_TOKENS,
    INPUT_INDEX_RE,
    MAX_CANDIDATE_FILE_COUNT,
    MAX_CLAUDE_STDIN_BYTES,
    MAX_CLAUDE_TIMEOUT,
    MAX_DOCKER_FILES_BYTES,
    MAX_DOCKER_TIMEOUT,
    MAX_INPUT_FILE_COUNT,
    MAX_PYTHON_ARG_LEN,
    MAX_PYTHON_ARGV_COUNT,
    MAX_SETTINGS_BYTES,
    READINESS_TIMEOUT,
    REQUESTED_IMAGE_RE,
    parse_claude_request,
    validate_filemap_paths,
    validate_relative_path,
    validate_token,
)

DEFAULT_CLIENT_CONFIG_PATH = "/etc/builder-host/client.json"
DEFAULT_CA_FILE = "/etc/builder-host/ca.crt"
DEFAULT_WORKSPACE_ROOT = "/opt/builder-suite"
MAX_RESPONSE_JSON_BYTES = 5 * 1024 * 1024

ALLOWED_CLIENT_CONFIG_KEYS = frozenset({"url", "token", "ca_file", "workspace_root"})

EXPECTED_DOCKER_RUN_FLAGS = frozenset({"--read-only"})
EXPECTED_DOCKER_RUN_VALUE_FLAGS: dict[str, str] = {
    "--pull": "never",
    "--network": "none",
    "--cap-drop": "ALL",
    "--security-opt": "no-new-privileges",
    "--user": "65534:65534",
    "--cpus": "1",
    "--memory": "256m",
    "--memory-swap": "256m",
    "--pids-limit": "64",
    "--tmpfs": "/tmp:rw,noexec,nosuid,size=64m",
    "--workdir": "/candidate",
    "--entrypoint": "python",
}
EXPECTED_DOCKER_RUN_ENVS = frozenset({"PYTHONDONTWRITEBYTECODE=1", "HOME=/tmp"})
DOCKER_PS_FILTER_RE = re.compile(r"^name=\^/(cog-verify-[0-9a-f]{32})\$$")


class CliBridgeError(ValueError):
    """Fail-closed error raised by the workspace CLI shim."""


@dataclass(frozen=True)
class ClientConfig:
    url: str
    token: str
    ca_file: Path | None
    workspace_root: Path


def _validate_bridge_url(raw_url: Any) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise CliBridgeError("Host bridge URL is required.")
    url = raw_url.strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CliBridgeError("Host bridge URL must not contain credentials, query, or fragment.")
    if parsed.path not in ("", "/"):
        raise CliBridgeError("Host bridge URL must not contain a base path.")
    if not parsed.hostname:
        raise CliBridgeError("Host bridge URL must include a hostname.")
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None:
        return url
    raise CliBridgeError("Host bridge URL must use https:// (http:// is allowed only for literal 127.0.0.1).")


def load_client_config(environ: Mapping[str, str] | None = None) -> ClientConfig:
    env = os.environ if environ is None else environ
    explicit_cfg_path = env.get("BUILDER_HOST_CONFIG")
    file_data: dict[str, Any] = {}

    if explicit_cfg_path:
        cfg_path = Path(explicit_cfg_path)
        if not cfg_path.is_file():
            raise CliBridgeError("BUILDER_HOST_CONFIG file does not exist.")
        file_data = _read_client_config_json(cfg_path)
    else:
        default_path = Path(DEFAULT_CLIENT_CONFIG_PATH)
        if default_path.is_file():
            file_data = _read_client_config_json(default_path)

    raw_url = env.get("BUILDER_HOST_URL") or file_data.get("url")
    raw_token = env.get("BUILDER_HOST_TOKEN") or file_data.get("token")
    raw_ca = env.get("SSL_CERT_FILE") or file_data.get("ca_file")
    raw_workspace_root = (
        env.get("BUILDER_WORKSPACE_ROOT") or file_data.get("workspace_root") or DEFAULT_WORKSPACE_ROOT
    )

    url = _validate_bridge_url(raw_url)
    try:
        token = validate_token(raw_token)
    except ValueError as exc:
        raise CliBridgeError(str(exc)) from None

    ca_file: Path | None = None
    if raw_ca is not None and raw_ca != "":
        if not isinstance(raw_ca, str):
            raise CliBridgeError("ca_file must be a path string.")
        ca_candidate = Path(raw_ca)
        if not ca_candidate.is_file():
            raise CliBridgeError("Configured CA certificate file does not exist.")
        ca_file = ca_candidate
    elif url.startswith("https://") and Path(DEFAULT_CA_FILE).is_file():
        ca_file = Path(DEFAULT_CA_FILE)

    if not isinstance(raw_workspace_root, str) or not Path(raw_workspace_root).is_absolute():
        raise CliBridgeError("workspace_root must be an absolute path.")

    return ClientConfig(
        url=url,
        token=token,
        ca_file=ca_file,
        workspace_root=Path(raw_workspace_root),
    )


def _read_client_config_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError:
        raise CliBridgeError("Unable to read host bridge client config.") from None
    if len(raw) > 64 * 1024:
        raise CliBridgeError("Host bridge client config is too large.")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CliBridgeError("Host bridge client config must be valid UTF-8 JSON.") from None
    if not isinstance(parsed, dict):
        raise CliBridgeError("Host bridge client config must be a JSON object.")
    if set(parsed.keys()) - ALLOWED_CLIENT_CONFIG_KEYS:
        raise CliBridgeError("Host bridge client config contains unsupported keys.")
    return parsed


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> Any:
        return None


def post_bridge(
    config: ClientConfig,
    endpoint: str,
    payload: Mapping[str, Any],
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Send an authenticated JSON POST request to the host bridge without redirects."""
    if endpoint not in ("/cli/claude", "/cli/docker"):
        raise CliBridgeError("Unsupported bridge endpoint.")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        config.url + endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {config.token}",
        },
        method="POST",
    )

    handlers: list[urllib.request.BaseHandler] = [_NoRedirectHandler()]
    if config.url.startswith("https://"):
        ssl_ctx = ssl.create_default_context(
            cafile=str(config.ca_file) if config.ca_file is not None else None
        )
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))

    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            raw = resp.read(MAX_RESPONSE_JSON_BYTES + 1)
    except urllib.error.HTTPError as exc:
        err_body = exc.read(8192).decode("utf-8", errors="replace")
        detail = ""
        try:
            err_json = json.loads(err_body)
            if isinstance(err_json, dict) and isinstance(err_json.get("error"), str):
                detail = f": {err_json['error']}"
        except ValueError:
            pass
        raise CliBridgeError(f"Host bridge rejected request (HTTP {exc.code}){detail}") from None
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        raise CliBridgeError(f"Host bridge request failed ({type(exc).__name__}).") from None

    if len(raw) > MAX_RESPONSE_JSON_BYTES:
        raise CliBridgeError("Host bridge response exceeded maximum size.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CliBridgeError("Host bridge returned malformed JSON.") from None
    if not isinstance(data, dict) or data.get("ok") is not True:
        raise CliBridgeError("Host bridge returned an invalid response envelope.")
    return data


def _allowed_roots(config: ClientConfig) -> tuple[Path, ...]:
    roots: list[Path] = []
    for raw_root in (config.workspace_root, Path("/tmp")):
        resolved = Path(os.path.realpath(str(raw_root)))
        if resolved != Path("/") and resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


def _is_strictly_inside(path: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        if path != root and path.is_relative_to(root):
            return True
    return False


def _ensure_allowed_path(raw_path: str, allowed_roots: tuple[Path, ...], *, expect_dir: bool) -> Path:
    if not raw_path or "\x00" in raw_path:
        raise CliBridgeError("Invalid mount or file path.")
    path = Path(raw_path)
    if not path.is_absolute():
        raise CliBridgeError("Mount path must be absolute.")
    if ".." in path.parts:
        raise CliBridgeError("Parent traversal segments are not allowed in mount paths.")
    try:
        lstat_res = os.lstat(path)
    except OSError:
        raise CliBridgeError("Referenced workspace path does not exist.") from None
    if stat.S_ISLNK(lstat_res.st_mode):
        raise CliBridgeError("Symlinks are not allowed as mount or settings paths.")
    try:
        real = path.resolve(strict=True)
    except OSError:
        raise CliBridgeError("Referenced workspace path could not be resolved.") from None
    if not _is_strictly_inside(real, allowed_roots):
        raise CliBridgeError("Path escapes allowed workspace roots.")
    # Also reject any intermediate symlink below a matching allowed root.
    for root in allowed_roots:
        if path.is_relative_to(root):
            cur = root
            for part in path.relative_to(root).parts:
                cur = cur / part
                if cur.is_symlink():
                    raise CliBridgeError("Intermediate symlinks are not allowed in mount paths.")
            break
    if expect_dir:
        if not stat.S_ISDIR(lstat_res.st_mode):
            raise CliBridgeError("Candidate mount path must be a regular directory.")
    else:
        if not stat.S_ISREG(lstat_res.st_mode):
            raise CliBridgeError("Input mount path must be a regular file.")
    return real


def _read_regular_file_bounded(path: Path, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        raise CliBridgeError("Unable to open regular file safely (possible symlink or permission error).") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CliBridgeError("Only regular files may be transferred to the host bridge.")
        if st.st_size > max_bytes:
            raise CliBridgeError("Mounted file contents exceed maximum allowed byte budget.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise CliBridgeError("Mounted file contents exceed maximum allowed byte budget.")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def collect_candidate_files(
    raw_dir: str,
    allowed_roots: tuple[Path, ...],
    *,
    max_total_bytes: int = MAX_DOCKER_FILES_BYTES,
) -> tuple[dict[str, str], int]:
    """Gather regular files under candidate directory without following symlinks."""
    root_dir = _ensure_allowed_path(raw_dir, allowed_roots, expect_dir=True)
    files: dict[str, str] = {}
    total_bytes = 0

    def _walk(cur_dir: Path, rel_prefix: str) -> None:
        nonlocal total_bytes
        try:
            entries = sorted(os.scandir(cur_dir), key=lambda e: e.name)
        except OSError:
            raise CliBridgeError("Unable to traverse candidate directory.") from None
        for entry in entries:
            name = entry.name
            if name.lower() in FORBIDDEN_PATH_SEGMENTS:
                raise CliBridgeError(f"Forbidden directory or entry in candidate: {name}")
            if entry.is_symlink():
                raise CliBridgeError("Symlinks are forbidden inside candidate directory.")
            rel_path = f"{rel_prefix}/{name}" if rel_prefix else name
            try:
                clean_rel = validate_relative_path(rel_path)
            except BridgeError as exc:
                raise CliBridgeError(exc.message) from None

            if entry.is_dir(follow_symlinks=False):
                _walk(Path(entry.path), clean_rel)
            elif entry.is_file(follow_symlinks=False):
                if len(files) >= MAX_CANDIDATE_FILE_COUNT:
                    raise CliBridgeError("Candidate directory exceeds file count limit.")
                remaining = max_total_bytes - total_bytes
                raw = _read_regular_file_bounded(Path(entry.path), remaining)
                total_bytes += len(raw)
                files[clean_rel] = base64.b64encode(raw).decode("ascii")
            else:
                raise CliBridgeError("Unsupported special file inside candidate directory.")

    _walk(root_dir, "")
    if not files:
        raise CliBridgeError("Candidate directory contains no regular files.")
    try:
        validate_filemap_paths(files.keys())
    except BridgeError as exc:
        raise CliBridgeError(exc.message) from None
    return files, total_bytes


def collect_input_file(
    raw_file: str,
    allowed_roots: tuple[Path, ...],
    *,
    remaining_bytes: int,
) -> tuple[str, int]:
    real_file = _ensure_allowed_path(raw_file, allowed_roots, expect_dir=False)
    raw = _read_regular_file_bounded(real_file, remaining_bytes)
    return base64.b64encode(raw).decode("ascii"), len(raw)


def _parse_bind_mount_spec(spec: str) -> tuple[str, str]:
    parts = spec.split(",")
    if len(parts) != 4:
        raise CliBridgeError("Unsupported --mount specification.")
    if parts[0] != "type=bind" or parts[3] != "readonly":
        raise CliBridgeError("Only readonly bind mounts are permitted.")
    if not parts[1].startswith("src=") or not parts[2].startswith("dst="):
        raise CliBridgeError("Malformed --mount src/dst specification.")
    src = parts[1][4:]
    dst = parts[2][4:]
    if not src or not dst:
        raise CliBridgeError("Empty --mount src or dst.")
    return src, dst


def build_docker_bridge_payload(args: list[str], config: ClientConfig) -> tuple[dict[str, Any], float]:
    """Parse ONLY the three exact docker invocations from cog-verify-candidate."""
    if not args:
        raise CliBridgeError("Missing docker subcommand.")

    # Form 1: docker image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' <image>
    if (
        len(args) == 5
        and args[0] == "image"
        and args[1] == "inspect"
        and args[2] == "--format"
        and args[3] == DOCKER_INSPECT_FORMAT
    ):
        image = args[4]
        if not REQUESTED_IMAGE_RE.fullmatch(image):
            raise CliBridgeError("Docker image inspect requires a pinned image digest.")
        return {"operation": "image_inspect", "requested_image": image}, READINESS_TIMEOUT + 10.0

    # Form 2: docker rm -f <cog-verify-uuid>
    if len(args) == 3 and args[0] == "rm" and args[1] == "-f":
        container = args[2]
        if not CONTAINER_NAME_RE.fullmatch(container):
            raise CliBridgeError("Docker rm only permits cog-verify generated container names.")
        return {"operation": "rm", "container": container}, READINESS_TIMEOUT + 10.0

    # Form 3 (qualification verification): docker ps -aq --filter name=^/cog-verify-<32hex>$
    if len(args) == 4 and args[0] == "ps" and args[1] == "-aq" and args[2] == "--filter":
        match = DOCKER_PS_FILTER_RE.fullmatch(args[3])
        if not match:
            raise CliBridgeError("Docker ps only permits exact cog-verify container name filter.")
        return {"operation": "ps", "container": match.group(1)}, READINESS_TIMEOUT + 10.0

    # Form 3: docker run <fixed policy args> <mounts> --entrypoint python <image> <python_argv...>
    if args[0] == "run":
        idx = 1
        seen_flags: set[str] = set()
        seen_values: dict[str, str] = {}
        seen_envs: set[str] = set()
        container: str | None = None
        candidate_src: str | None = None
        input_srcs: dict[str, str] = {}

        while idx < len(args):
            tok = args[idx]
            if not tok.startswith("-"):
                break
            if tok in EXPECTED_DOCKER_RUN_FLAGS:
                if tok in seen_flags:
                    raise CliBridgeError(f"Duplicate docker run flag: {tok}")
                seen_flags.add(tok)
                idx += 1
            elif tok == "--name":
                if container is not None or idx + 1 >= len(args):
                    raise CliBridgeError("Invalid or duplicate --name flag.")
                container = args[idx + 1]
                if not CONTAINER_NAME_RE.fullmatch(container):
                    raise CliBridgeError("Docker run container name must match cog-verify format.")
                idx += 2
            elif tok == "--env":
                if idx + 1 >= len(args):
                    raise CliBridgeError("Missing --env value.")
                env_val = args[idx + 1]
                if env_val not in EXPECTED_DOCKER_RUN_ENVS or env_val in seen_envs:
                    raise CliBridgeError("Unsupported or duplicate --env argument.")
                seen_envs.add(env_val)
                idx += 2
            elif tok == "--mount":
                if idx + 1 >= len(args):
                    raise CliBridgeError("Missing --mount value.")
                src, dst = _parse_bind_mount_spec(args[idx + 1])
                if dst == "/candidate":
                    if candidate_src is not None:
                        raise CliBridgeError("Duplicate /candidate mount.")
                    candidate_src = src
                elif dst.startswith("/inputs/"):
                    idx_key = dst[len("/inputs/") :]
                    if not INPUT_INDEX_RE.fullmatch(idx_key) or idx_key in input_srcs:
                        raise CliBridgeError("Invalid or duplicate /inputs mount target.")
                    if len(input_srcs) >= MAX_INPUT_FILE_COUNT:
                        raise CliBridgeError("Too many input mounts.")
                    input_srcs[idx_key] = src
                else:
                    raise CliBridgeError("Disallowed mount destination.")
                idx += 2
            elif tok in EXPECTED_DOCKER_RUN_VALUE_FLAGS:
                if tok in seen_values or idx + 1 >= len(args):
                    raise CliBridgeError(f"Invalid or duplicate docker run flag: {tok}")
                val = args[idx + 1]
                if val != EXPECTED_DOCKER_RUN_VALUE_FLAGS[tok]:
                    raise CliBridgeError(f"Docker run policy mismatch for {tok}.")
                seen_values[tok] = val
                idx += 2
            else:
                raise CliBridgeError(f"Disallowed docker run flag: {tok}")

        if seen_flags != EXPECTED_DOCKER_RUN_FLAGS:
            raise CliBridgeError("Missing required docker run isolation flags.")
        if seen_values != EXPECTED_DOCKER_RUN_VALUE_FLAGS:
            raise CliBridgeError("Missing required docker run policy arguments.")
        if seen_envs != EXPECTED_DOCKER_RUN_ENVS:
            raise CliBridgeError("Missing required docker run environment policy arguments.")
        if container is None or candidate_src is None:
            raise CliBridgeError("Docker run requires --name and readonly /candidate mount.")

        remaining = args[idx:]
        if len(remaining) < 2:
            raise CliBridgeError("Docker run requires pinned image and declared Python arguments.")
        image = remaining[0]
        if not REQUESTED_IMAGE_RE.fullmatch(image):
            raise CliBridgeError("Docker run requires a pinned image digest.")
        python_argv = remaining[1:]
        if len(python_argv) > MAX_PYTHON_ARGV_COUNT:
            raise CliBridgeError("Too many Python arguments for docker run.")
        for arg in python_argv:
            if len(arg) > MAX_PYTHON_ARG_LEN or "\x00" in arg or arg in FORBIDDEN_SHELL_TOKENS:
                raise CliBridgeError("Invalid Python argument for docker run.")

        # Native ExecutionSuite copies all candidate/input mounts beneath its
        # workspace state directory. Docker needs no ambient /tmp access.
        allowed_roots = (config.workspace_root.resolve(),)
        candidate_files, used_bytes = collect_candidate_files(
            candidate_src,
            allowed_roots,
            max_total_bytes=MAX_DOCKER_FILES_BYTES,
        )
        input_files: dict[str, str] = {}
        for idx_key in sorted(input_srcs.keys(), key=int):
            b64_data, size = collect_input_file(
                input_srcs[idx_key],
                allowed_roots,
                remaining_bytes=MAX_DOCKER_FILES_BYTES - used_bytes,
            )
            used_bytes += size
            input_files[idx_key] = b64_data

        payload = {
            "operation": "run",
            "container": container,
            "requested_image": image,
            "python_argv": python_argv,
            "candidate_files": candidate_files,
            "input_files": input_files,
        }
        return payload, MAX_DOCKER_TIMEOUT + 15.0

    raise CliBridgeError("Unsupported docker invocation; only isolated_execution forms are allowed.")


def build_claude_bridge_payload(
    args: list[str],
    config: ClientConfig,
    *,
    read_stdin: Any = None,
) -> tuple[dict[str, Any], float]:
    """Validate and translate upstream cog-claude CLI invocations for POST /cli/claude."""
    if not args:
        raise CliBridgeError("Missing claude arguments.")

    # Readiness invocations do not read stdin or settings.
    if args == ["--version"] or args == ["--help"] or args == ["auth", "status"]:
        payload = {"argv": list(args), "stdin": ""}
        try:
            parse_claude_request(payload)
        except BridgeError as exc:
            raise CliBridgeError(exc.message) from None
        return payload, READINESS_TIMEOUT + 10.0

    # Extract optional --settings <file> if passed by a compatible provider,
    # read bounded bytes safely within allowed roots, and never forward the workspace path.
    cleaned_argv: list[str] = []
    settings_b64: str | None = None
    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok == "--settings":
            if settings_b64 is not None or idx + 1 >= len(args):
                raise CliBridgeError("Invalid or duplicate --settings argument.")
            raw_settings_path = args[idx + 1]
            allowed_roots = _allowed_roots(config)
            real_settings = _ensure_allowed_path(raw_settings_path, allowed_roots, expect_dir=False)
            raw_bytes = _read_regular_file_bounded(real_settings, MAX_SETTINGS_BYTES)
            settings_b64 = base64.b64encode(raw_bytes).decode("ascii")
            idx += 2
        else:
            cleaned_argv.append(tok)
            idx += 1

    # Fail-fast validation before reading stdin or making a network call.
    probe_payload: dict[str, Any] = {"argv": cleaned_argv, "stdin": ""}
    if settings_b64 is not None:
        probe_payload["settings_b64"] = settings_b64
    try:
        parse_claude_request(probe_payload)
    except BridgeError as exc:
        raise CliBridgeError(exc.message) from None

    stdin_reader = read_stdin if read_stdin is not None else (lambda limit: sys.stdin.buffer.read(limit))
    raw_stdin = stdin_reader(MAX_CLAUDE_STDIN_BYTES + 1)
    if len(raw_stdin) > MAX_CLAUDE_STDIN_BYTES:
        raise CliBridgeError("Claude stdin prompt exceeds maximum allowed size.")
    try:
        stdin_text = raw_stdin.decode("utf-8")
    except UnicodeDecodeError:
        raise CliBridgeError("Claude stdin must be valid UTF-8.") from None

    payload: dict[str, Any] = {"argv": cleaned_argv, "stdin": stdin_text}
    if settings_b64 is not None:
        payload["settings_b64"] = settings_b64
    return payload, MAX_CLAUDE_TIMEOUT + 15.0


def _resolve_tool_and_args(argv: list[str], prog_name: str) -> tuple[str, list[str]]:
    base = Path(prog_name).name
    if base in ("claude", "docker"):
        return base, list(argv)
    if argv and argv[0] in ("claude", "docker"):
        return argv[0], list(argv[1:])
    raise CliBridgeError("Specify 'claude' or 'docker' as the tool name or argv[0].")


def main(
    argv: list[str] | None = None,
    *,
    prog: str | None = None,
    environ: Mapping[str, str] | None = None,
    read_stdin: Any = None,
    stdout_stream: Any = None,
    stderr_stream: Any = None,
) -> int:
    eff_argv = sys.argv[1:] if argv is None else list(argv)
    eff_prog = sys.argv[0] if prog is None else prog
    out = sys.stdout.buffer if stdout_stream is None else stdout_stream
    err = sys.stderr.buffer if stderr_stream is None else stderr_stream

    try:
        tool, tool_args = _resolve_tool_and_args(eff_argv, eff_prog)
        config = load_client_config(environ)
        if tool == "claude":
            payload, timeout = build_claude_bridge_payload(tool_args, config, read_stdin=read_stdin)
            endpoint = "/cli/claude"
        else:
            payload, timeout = build_docker_bridge_payload(tool_args, config)
            endpoint = "/cli/docker"
        response = post_bridge(config, endpoint, payload, timeout_seconds=timeout)
    except CliBridgeError as exc:
        err.write((f"builder-cli-bridge: {exc}\n").encode("utf-8"))
        err.flush()
        return 2

    stdout_text = response.get("stdout", "")
    stderr_text = response.get("stderr", "")
    exit_code = response.get("exit_code", 1)
    if not isinstance(stdout_text, str) or not isinstance(stderr_text, str) or type(exit_code) is not int:
        err.write(b"builder-cli-bridge: malformed host bridge response.\n")
        err.flush()
        return 2

    if stdout_text:
        out.write(stdout_text.encode("utf-8"))
        out.flush()
    if stderr_text:
        err.write(stderr_text.encode("utf-8"))
        err.flush()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
