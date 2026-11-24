"""Security boundary and contract tests for the host-services bridge.

All host CLI executions are mocked or use local Python child processes; no host
vendor credentials, live model calls, or live Docker daemon access are used.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import threading
import time
from typing import Any
import urllib.error
import urllib.request
import uuid

import pytest

from builder_hub import cli_bridge, host_bridge
from builder_hub.host_bridge import (
    BridgeError,
    HostBridgeConfig,
    HostBridgeService,
    SubprocessResult,
    create_server,
    parse_claude_request,
    parse_docker_request,
    run_bounded_subprocess,
    sanitize_claude_env,
    sanitize_docker_env,
)

TEST_TOKEN = "a" * 40
PINNED_IMAGE = "sha256:" + ("1" * 64)
OTHER_IMAGE = "sha256:" + ("9" * 64)
INSPECT_IDENTITY = f"{PINNED_IMAGE} linux amd64"
SAMPLE_CLAUDE_HELP = (
    "Usage: claude [options]\n"
    "  -p --safe-mode --setting-sources --strict-mcp-config --mcp-config\n"
    "  --tools --disallowedTools --permission-mode --no-session-persistence\n"
    "  --output-format --model --json-schema\n"
)


def _make_executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _generate_self_signed_tls(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3_ext\n"
        "prompt = no\n"
        "[dn]\n"
        "CN = 127.0.0.1\n"
        "[v3_ext]\n"
        "basicConstraints = CA:TRUE\n"
        "subjectAltName = IP:127.0.0.1\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-config",
            str(cfg),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    return cert, key


def _canonical_claude_print_argv(model: str = "claude-sonnet-4-5", schema: dict[str, Any] | None = None) -> list[str]:
    argv = [
        "-p",
        "--safe-mode",
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--tools",
        "",
        "--disallowedTools",
        "mcp__*",
        "--permission-mode",
        "dontAsk",
        "--no-session-persistence",
        "--output-format",
        "json",
        "--model",
        model,
    ]
    if schema is not None:
        argv += ["--json-schema", json.dumps(schema)]
    return argv


def _canonical_docker_run_argv(
    *,
    container: str,
    candidate_dir: Path,
    image: str = PINNED_IMAGE,
    inputs: list[tuple[int, Path]] | None = None,
    python_argv: list[str] | None = None,
) -> list[str]:
    mounts = ["--mount", f"type=bind,src={candidate_dir},dst=/candidate,readonly"]
    for idx, inp in (inputs or []):
        mounts += ["--mount", f"type=bind,src={inp},dst=/inputs/{idx},readonly"]
    return [
        "run",
        "--name",
        container,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--cpus",
        "1",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--pids-limit",
        "64",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--workdir",
        "/candidate",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "HOME=/tmp",
        *mounts,
        "--entrypoint",
        "python",
        image,
        *(python_argv or ["src/probe.py"]),
    ]


class _FakeRunner:
    """Deterministic mocked host CLI executor for Claude and Docker."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.active_containers: set[str] = set()
        self.claude_auth: dict[str, Any] = {"loggedIn": True, "authMethod": "claude.ai"}
        self.claude_help: str = SAMPLE_CLAUDE_HELP
        self.inspect_stdout: bytes = (INSPECT_IDENTITY + "\n").encode("utf-8")
        self.inspect_rc: int = 0
        self.run_stdout: bytes = b'{"ok":true}\n'
        self.run_rc: int = 0
        self.fail_rm: bool = False
        self.run_started: threading.Event = threading.Event()
        self.block_run: threading.Event | None = None
        self.observed_stage_snapshot: dict[str, Any] = {}

    def __call__(
        self,
        argv: list[str],
        *,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        stdin_bytes: bytes = b"",
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 2 * 1024 * 1024,
        cancel_event: threading.Event | None = None,
    ) -> SubprocessResult:
        self.calls.append(
            {
                "argv": list(argv),
                "cwd": str(cwd) if cwd is not None else None,
                "env": dict(env) if env is not None else {},
                "stdin": stdin_bytes,
                "timeout_seconds": timeout_seconds,
                "max_output_bytes": max_output_bytes,
            }
        )
        exe = Path(argv[0]).name
        if exe == "fake-claude":
            if argv[1:] == ["--version"]:
                return SubprocessResult(0, b"2.1.330 (Claude Code)\n", b"", "exited", 0.01)
            if argv[1:] == ["--help"]:
                return SubprocessResult(0, self.claude_help.encode("utf-8"), b"", "exited", 0.01)
            if argv[1:] == ["auth", "status"]:
                return SubprocessResult(0, json.dumps(self.claude_auth).encode("utf-8"), b"", "exited", 0.01)
            if "--settings" in argv:
                s_path = Path(argv[argv.index("--settings") + 1])
                self.observed_stage_snapshot["settings_mode"] = stat.S_IMODE(s_path.stat().st_mode)
                self.observed_stage_snapshot["settings_json"] = json.loads(s_path.read_text(encoding="utf-8"))
            if cwd is not None:
                self.observed_stage_snapshot["claude_cwd_mode"] = stat.S_IMODE(Path(cwd).stat().st_mode)
            model = argv[argv.index("--model") + 1]
            reply = {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": json.dumps({"echo_model": model, "stdin_len": len(stdin_bytes)}),
            }
            return SubprocessResult(0, json.dumps(reply).encode("utf-8"), b"", "exited", 0.02)

        if exe == "fake-docker":
            sub = argv[1]
            if sub == "image":
                return SubprocessResult(self.inspect_rc, self.inspect_stdout, b"", "exited", 0.01)
            if sub == "run":
                name = argv[argv.index("--name") + 1]
                self.active_containers.add(name)
                # Inspect staged permissions and contents while stage dir exists.
                mounts = [argv[i + 1] for i, tok in enumerate(argv) if tok == "--mount"]
                cand_src = Path(mounts[0].split(",")[1][4:])
                stage_dir = cand_src.parent
                snap: dict[str, Any] = {
                    "stage_dir": str(stage_dir),
                    "stage_mode": stat.S_IMODE(stage_dir.stat().st_mode),
                    "candidate_mode": stat.S_IMODE(cand_src.stat().st_mode),
                    "files": {},
                    "inputs": {},
                }
                for p in sorted(cand_src.rglob("*")):
                    rel = p.relative_to(cand_src).as_posix()
                    snap["files"][rel] = {
                        "is_dir": p.is_dir(),
                        "mode": stat.S_IMODE(p.stat().st_mode),
                        "bytes": None if p.is_dir() else p.read_bytes(),
                    }
                for m in mounts[1:]:
                    src = Path(m.split(",")[1][4:])
                    dst = m.split(",")[2][4:]
                    snap["inputs"][dst] = {
                        "mode": stat.S_IMODE(src.stat().st_mode),
                        "bytes": src.read_bytes(),
                    }
                self.observed_stage_snapshot = snap
                self.run_started.set()
                if self.block_run is not None:
                    while not self.block_run.is_set():
                        if cancel_event is not None and cancel_event.is_set():
                            return SubprocessResult(124, b"", b"canceled", "canceled", 0.05)
                        time.sleep(0.01)
                return SubprocessResult(self.run_rc, self.run_stdout, b"", "exited", 0.02)
            if sub == "rm":
                name = argv[3]
                if self.fail_rm:
                    return SubprocessResult(1, b"", b"cannot remove\n", "exited", 0.01)
                if name in self.active_containers:
                    self.active_containers.remove(name)
                    return SubprocessResult(0, (name + "\n").encode("utf-8"), b"", "exited", 0.01)
                return SubprocessResult(1, b"", b"No such container\n", "exited", 0.01)
            if sub == "ps":
                filt = argv[4]  # name=^/<host_container>$
                prefix = "name=^/"
                assert filt.startswith(prefix) and filt.endswith("$")
                name = filt[len(prefix) : -1]
                out = (name[:12] + "\n").encode("utf-8") if name in self.active_containers else b""
                return SubprocessResult(0, out, b"", "exited", 0.01)

        raise AssertionError(f"Unexpected executable invocation: {argv}")


@pytest.fixture()
def https_bridge(tmp_path: Path):
    cert, key = _generate_self_signed_tls(tmp_path)
    fake_claude = _make_executable(tmp_path / "fake-claude")
    fake_docker = _make_executable(tmp_path / "fake-docker")
    staging_root = tmp_path / "staging"
    staging_root.mkdir(mode=0o755)
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(mode=0o755)

    runner = _FakeRunner()
    config = HostBridgeConfig(
        host="127.0.0.1",
        port=0,
        token=TEST_TOKEN,
        tls_cert=cert,
        tls_key=key,
        claude_cli=fake_claude,
        verify_image=PINNED_IMAGE,
        docker_cli=fake_docker,
        staging_root=staging_root,
    )
    service = HostBridgeService(config, runner=runner)
    server = create_server(config, service=service, require_tls=True)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        client_cfg_path = tmp_path / "client.json"
        client_cfg_path.write_text(
            json.dumps(
                {
                    "url": f"https://127.0.0.1:{port}",
                    "token": TEST_TOKEN,
                    "ca_file": str(cert),
                    "workspace_root": str(workspace_root),
                }
            ),
            encoding="utf-8",
        )
        yield {
            "url": f"https://127.0.0.1:{port}",
            "cert": cert,
            "key": key,
            "token": TEST_TOKEN,
            "runner": runner,
            "service": service,
            "config": config,
            "staging_root": staging_root,
            "workspace_root": workspace_root,
            "client_cfg_path": client_cfg_path,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _https_request(
    url: str,
    *,
    ca_file: Path,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, Any]]:
    ctx = ssl.create_default_context(cafile=str(ca_file))
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# 1. Transport, TLS, Auth, and Logging Boundary Tests
# ---------------------------------------------------------------------------


def test_https_auth_and_routes(https_bridge):
    url = https_bridge["url"]
    cert = https_bridge["cert"]

    # Unauthenticated requests rejected before body processing.
    status, body = _https_request(f"{url}/healthz", ca_file=cert, method="GET")
    assert status == 401 and body["ok"] is False

    status, _ = _https_request(
        f"{url}/cli/claude",
        ca_file=cert,
        headers={"Authorization": "Bearer wrong-token", "Content-Type": "application/json"},
        body=b'{"argv":["--version"]}',
    )
    assert status == 401

    # Authenticated healthz succeeds.
    status, body = _https_request(
        f"{url}/healthz",
        ca_file=cert,
        method="GET",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert status == 200
    assert body == {
        "ok": True,
        "claude_enabled": True,
        "docker_enabled": True,
        "staging_root_configured": True,
    }

    # Wrong methods and unknown paths fail closed.
    status, _ = _https_request(
        f"{url}/cli/claude",
        ca_file=cert,
        method="GET",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert status == 405

    status, _ = _https_request(
        f"{url}/other",
        ca_file=cert,
        method="POST",
        headers={"Authorization": f"Bearer {TEST_TOKEN}", "Content-Type": "application/json"},
        body=b"{}",
    )
    assert status == 404

    # Non-JSON Content-Type rejected.
    status, _ = _https_request(
        f"{url}/cli/claude",
        ca_file=cert,
        headers={"Authorization": f"Bearer {TEST_TOKEN}", "Content-Type": "text/plain"},
        body=b"{}",
    )
    assert status == 415

    # NaN rejected by strict JSON parser.
    status, _ = _https_request(
        f"{url}/cli/claude",
        ca_file=cert,
        headers={"Authorization": f"Bearer {TEST_TOKEN}", "Content-Type": "application/json"},
        body=b'{"argv": ["--version"], "timeout_seconds": NaN}',
    )
    assert status == 400


def test_tls_verification_cannot_be_bypassed(https_bridge, tmp_path: Path):
    # Separate untrusted CA must fail TLS handshake.
    wrong_ca, _ = _generate_self_signed_tls(tmp_path / "other_ca" if (tmp_path / "other_ca").mkdir() is None else tmp_path)
    cfg = cli_bridge.ClientConfig(
        url=https_bridge["url"],
        token=TEST_TOKEN,
        ca_file=wrong_ca,
        workspace_root=https_bridge["workspace_root"],
    )
    with pytest.raises(cli_bridge.CliBridgeError, match="failed"):
        cli_bridge.post_bridge(cfg, "/cli/claude", {"argv": ["--version"], "stdin": ""}, timeout_seconds=5)


def test_url_scheme_and_token_validation(tmp_path: Path):
    # Plaintext HTTP allowed ONLY for literal 127.0.0.1:<port>.
    cfg = cli_bridge.load_client_config(
        {
            "BUILDER_HOST_URL": "http://127.0.0.1:9443",
            "BUILDER_HOST_TOKEN": TEST_TOKEN,
            "BUILDER_WORKSPACE_ROOT": str(tmp_path),
        }
    )
    assert cfg.url == "http://127.0.0.1:9443"

    for bad_url in (
        "http://localhost:9443",
        "http://172.30.0.20:9443",
        "http://172.30.0.1:9443",
        "http://[::1]:9443",
        "https://user:pass@172.30.0.20:9443",
        "https://172.30.0.20:9443/prefix",
        "https://172.30.0.20:9443?x=1",
    ):
        with pytest.raises(cli_bridge.CliBridgeError):
            cli_bridge.load_client_config(
                {"BUILDER_HOST_URL": bad_url, "BUILDER_HOST_TOKEN": TEST_TOKEN}
            )

    with pytest.raises(cli_bridge.CliBridgeError, match="at least 32"):
        cli_bridge.load_client_config(
            {"BUILDER_HOST_URL": "https://172.30.0.20:9443", "BUILDER_HOST_TOKEN": "short"}
        )


def test_client_config_survives_cog_claude_clean_env(https_bridge, monkeypatch: pytest.MonkeyPatch):
    # Simulate cog-claude clean_env(): BUILDER_* and SSL_CERT_FILE are completely scrubbed.
    monkeypatch.setattr(cli_bridge, "DEFAULT_CLIENT_CONFIG_PATH", str(https_bridge["client_cfg_path"]))
    scrubbed_env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "USER": "nobody"}
    out = io.BytesIO()
    err = io.BytesIO()
    rc = cli_bridge.main(
        ["--version"],
        prog="/usr/local/bin/claude",
        environ=scrubbed_env,
        stdout_stream=out,
        stderr_stream=err,
    )
    assert rc == 0, err.getvalue().decode()
    assert b"2.1.330" in out.getvalue()


def test_no_user_input_or_token_in_bridge_logs(https_bridge, caplog: pytest.LogCaptureFixture):
    secret_prompt = "TOP_SECRET_USER_PROMPT_99999"
    with caplog.at_level(logging.INFO, logger="builder_hub.host_bridge"):
        out = io.BytesIO()
        err = io.BytesIO()
        rc = cli_bridge.main(
            ["claude", *_canonical_claude_print_argv()],
            prog="python -m builder_hub.cli_bridge",
            environ={"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])},
            read_stdin=lambda _limit: secret_prompt.encode("utf-8"),
            stdout_stream=out,
            stderr_stream=err,
        )
    assert rc == 0
    joined_logs = "\n".join(rec.getMessage() for rec in caplog.records)
    assert secret_prompt not in joined_logs
    assert TEST_TOKEN not in joined_logs
    assert "bridge_request" in joined_logs


# ---------------------------------------------------------------------------
# 2. Claude Bridge Policy & Shim Tests
# ---------------------------------------------------------------------------


def test_claude_readiness_and_print_invocations(https_bridge, monkeypatch: pytest.MonkeyPatch):
    # Inject forbidden ambient API keys into host process env; verify bridge strips them.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-forbidden")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "bad-auth")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-forbidden")
    monkeypatch.setenv("BUILDER_HOST_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/home/bridge-user/.claude")

    env = {"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])}
    for sub_args, expected_substr in (
        (["--version"], b"2.1.330"),
        (["--help"], b"--safe-mode"),
        (["auth", "status"], b'"claude.ai"'),
    ):
        out, err = io.BytesIO(), io.BytesIO()
        rc = cli_bridge.main(["claude", *sub_args], environ=env, stdout_stream=out, stderr_stream=err)
        assert rc == 0, err.getvalue().decode()
        assert expected_substr in out.getvalue()

    # Exact cog-claude print JSON invocation with strict --json-schema.
    schema = {
        "type": "object",
        "properties": {"ready": {"type": "boolean"}},
        "required": ["ready"],
        "additionalProperties": False,
    }
    out, err = io.BytesIO(), io.BytesIO()
    rc = cli_bridge.main(
        ["claude", *_canonical_claude_print_argv(model="claude-sonnet-4-5", schema=schema)],
        environ=env,
        read_stdin=lambda _limit: b"Build a safe cog.",
        stdout_stream=out,
        stderr_stream=err,
    )
    assert rc == 0, err.getvalue().decode()
    parsed = json.loads(out.getvalue().decode("utf-8"))
    assert parsed["subtype"] == "success"
    inner = json.loads(parsed["result"])
    assert inner["echo_model"] == "claude-sonnet-4-5"
    assert inner["stdin_len"] == len(b"Build a safe cog.")

    last_call = https_bridge["runner"].calls[-1]
    assert "--model" in last_call["argv"]
    assert last_call["argv"][last_call["argv"].index("--model") + 1] == "claude-sonnet-4-5"
    assert "--fallback-model" not in last_call["argv"]
    # Verify host env sanitization.
    child_env = last_call["env"]
    assert "CLAUDE_CONFIG_DIR" in child_env
    for forbidden in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_USE_BEDROCK",
        "OPENROUTER_API_KEY",
        "BUILDER_HOST_TOKEN",
        "HTTP_PROXY",
    ):
        assert forbidden not in child_env
    # Verify owner-only empty temp cwd was used.
    assert https_bridge["runner"].observed_stage_snapshot["claude_cwd_mode"] == 0o700


def test_claude_settings_file_bytes_validated_and_rewritten_by_host(https_bridge):
    ws = https_bridge["workspace_root"]
    safe_settings = ws / "safe-settings.json"
    safe_settings.write_text(
        json.dumps(
            {
                "mcpServers": {},
                "hooks": {},
                "disableAllHooks": True,
                "enabledPlugins": {},
                "permissions": {"allow": [], "deny": ["Bash(*)"], "defaultMode": "dontAsk"},
            }
        ),
        encoding="utf-8",
    )
    out, err = io.BytesIO(), io.BytesIO()
    rc = cli_bridge.main(
        ["claude", *_canonical_claude_print_argv(), "--settings", str(safe_settings)],
        environ={"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])},
        read_stdin=lambda _limit: b"hello",
        stdout_stream=out,
        stderr_stream=err,
    )
    assert rc == 0, err.getvalue().decode()
    snap = https_bridge["runner"].observed_stage_snapshot
    assert snap["settings_mode"] == 0o600
    assert snap["settings_json"]["mcpServers"] == {}
    assert snap["settings_json"]["hooks"] == {}
    assert snap["settings_json"]["disableAllHooks"] is True
    assert snap["settings_json"]["permissions"]["allow"] == []
    assert snap["settings_json"]["permissions"]["deny"] == ["Bash(*)"]

    # Unsafe settings file (apiKeyHelper / permissions.allow / non-empty mcpServers) rejected!
    for bad_obj in (
        {"apiKeyHelper": "/bin/sh -c id"},
        {"mcpServers": {"evil": {"command": "sh"}}},
        {"hooks": {"PreToolUse": [{"command": "id"}]}},
        {"enabledPlugins": {"evil": True}},
        {"permissions": {"allow": ["Bash(*)"]}},
        {"permissions": {"defaultMode": "bypassPermissions"}},
        {"model": "other-model"},
    ):
        bad_file = ws / "bad-settings.json"
        bad_file.write_text(json.dumps(bad_obj), encoding="utf-8")
        out, err = io.BytesIO(), io.BytesIO()
        rc = cli_bridge.main(
            ["claude", *_canonical_claude_print_argv(), "--settings", str(bad_file)],
            environ={"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])},
            read_stdin=lambda _limit: b"hello",
            stdout_stream=out,
            stderr_stream=err,
        )
        assert rc == 2


@pytest.mark.parametrize(
    "bad_payload",
    [
        {"argv": ["--version"], "stdin": "unexpected"},
        {"argv": ["auth", "login"], "stdin": ""},
        {"argv": ["-p", "--dangerously-skip-permissions"], "stdin": "hi"},
        {"argv": [*_canonical_claude_print_argv(), "--fallback-model", "claude-haiku"], "stdin": "hi"},
        {"argv": [*_canonical_claude_print_argv(), "--allowedTools", "Bash"], "stdin": "hi"},
        {"argv": [*_canonical_claude_print_argv(), "--settings", "/etc/passwd"], "stdin": "hi"},
        {"argv": [*_canonical_claude_print_argv(), "--add-dir", "/etc"], "stdin": "hi"},
        {"argv": [*_canonical_claude_print_argv(), "extra-positional"], "stdin": "hi"},
        {
            "argv": [a if a != "dontAsk" else "bypassPermissions" for a in _canonical_claude_print_argv()],
            "stdin": "hi",
        },
        {
            "argv": [a if a != "" else "user" for a in _canonical_claude_print_argv()],
            "stdin": "hi",
        },
        {
            "argv": [
                *_canonical_claude_print_argv(),
                "--json-schema",
                json.dumps({"type": "object", "$ref": "https://evil.example/s.json"}),
            ],
            "stdin": "hi",
        },
        {"argv": _canonical_claude_print_argv(), "stdin": "hi", "timeout_seconds": 661},
        {"argv": _canonical_claude_print_argv(), "stdin": "hi", "extra": 1},
    ],
)
def test_claude_rejects_disallowed_invocations(bad_payload: dict[str, Any]):
    with pytest.raises(BridgeError):
        parse_claude_request(bad_payload)


# ---------------------------------------------------------------------------
# 3. Docker Bridge Policy, Staging, Concurrency, and Shim Tests
# ---------------------------------------------------------------------------


def test_docker_inspect_ignores_requested_image_and_checks_linux_identity(https_bridge):
    env = {"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])}
    out, err = io.BytesIO(), io.BytesIO()
    # The configured image is the only accepted immutable identity.
    rc = cli_bridge.main(
        ["image", "inspect", "--format", "{{.Id}} {{.Os}} {{.Architecture}}", PINNED_IMAGE],
        prog="/usr/local/bin/docker",
        environ=env,
        stdout_stream=out,
        stderr_stream=err,
    )
    assert rc == 0, err.getvalue().decode()
    assert out.getvalue().decode("utf-8").strip() == INSPECT_IDENTITY
    assert https_bridge["runner"].calls[-1]["argv"][-1] == PINNED_IMAGE
    out, err = io.BytesIO(), io.BytesIO()
    rc = cli_bridge.main(
        ['image', 'inspect', '--format', '{{.Id}} {{.Os}} {{.Architecture}}', OTHER_IMAGE],
        prog='/usr/local/bin/docker', environ=env, stdout_stream=out, stderr_stream=err)
    assert rc != 0

    # Non-linux inspect output must fail closed.
    https_bridge["runner"].inspect_stdout = f"{PINNED_IMAGE} darwin arm64\n".encode("utf-8")
    out, err = io.BytesIO(), io.BytesIO()
    rc = cli_bridge.main(
        ["docker", "image", "inspect", "--format", "{{.Id}} {{.Os}} {{.Architecture}}", PINNED_IMAGE],
        environ=env,
        stdout_stream=out,
        stderr_stream=err,
    )
    assert rc == 1


def test_idle_tcp_connection_does_not_block_tls_service(https_bridge):
    import socket
    from urllib.parse import urlsplit
    parsed = urlsplit(https_bridge['url'])
    with socket.create_connection((parsed.hostname, parsed.port), timeout=2):
        before = time.monotonic()
        status, _ = _https_request(https_bridge['url'] + '/healthz',
                                   ca_file=https_bridge['cert'], method='GET',
                                   headers={'Authorization': 'Bearer ' + TEST_TOKEN})
        assert status == 200
        assert time.monotonic() - before < 2


def test_docker_run_stages_under_staging_root_enforces_policy_and_cleans_up(https_bridge):
    ws = https_bridge["workspace_root"]
    cand = ws / "candidate-1"
    (cand / "src").mkdir(parents=True)
    (cand / "pixi.toml").write_text("[workspace]\nname='c'\n", encoding="utf-8")
    (cand / "src" / "probe.py").write_text("print('ok')\n", encoding="utf-8")

    # Input bundle with restrictive 0o600 mode (must be staged 0o644 for UID 65534).
    inp = ws / "bundle.json"
    inp.write_text('{"ready":true}', encoding="utf-8")
    inp.chmod(0o600)

    container = "cog-verify-" + uuid.uuid4().hex
    docker_args = _canonical_docker_run_argv(
        container=container,
        candidate_dir=cand,
        image=PINNED_IMAGE,
        inputs=[(0, inp)],
        python_argv=["src/probe.py", "--bundle", "/inputs/0"],
    )
    env = {"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])}
    out, err = io.BytesIO(), io.BytesIO()
    rc = cli_bridge.main(["docker", *docker_args], environ=env, stdout_stream=out, stderr_stream=err)
    assert rc == 0, err.getvalue().decode()
    assert out.getvalue() == b'{"ok":true}\n'

    # Check host docker run argv used PINNED_IMAGE, exact fixed flags, and host staging path.
    run_call = next(c for c in https_bridge["runner"].calls if c["argv"][1] == "run")
    argv = run_call["argv"]
    assert PINNED_IMAGE in argv
    assert OTHER_IMAGE not in argv
    assert str(cand) not in " ".join(argv)
    assert str(inp) not in " ".join(argv)
    for flag_pair in (
        ("--pull", "never"),
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--user", "65534:65534"),
        ("--cpus", "1"),
        ("--memory", "256m"),
        ("--memory-swap", "256m"),
        ("--pids-limit", "64"),
        ("--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"),
        ("--workdir", "/candidate"),
        ("--entrypoint", "python"),
    ):
        idx = argv.index(flag_pair[0])
        assert argv[idx + 1] == flag_pair[1]
    assert "--read-only" in argv

    # Check staging directory location, permissions, and cleanup.
    snap = https_bridge["runner"].observed_stage_snapshot
    stage_dir = Path(snap["stage_dir"])
    assert stage_dir.parent == https_bridge["staging_root"]
    assert snap["stage_mode"] == 0o700
    assert snap["candidate_mode"] == 0o755
    assert snap["files"]["src"]["mode"] == 0o755
    assert snap["files"]["src/probe.py"]["mode"] == 0o644
    assert snap["inputs"]["/inputs/0"]["mode"] == 0o644
    assert snap["inputs"]["/inputs/0"]["bytes"] == b'{"ready":true}'
    assert not stage_dir.exists(), "Staging directory must be deleted after run"

    # Container was removed in finally; repeated rm verifies real absence via ps and succeeds.
    out, err = io.BytesIO(), io.BytesIO()
    rc = cli_bridge.main(["docker", "rm", "-f", container], environ=env, stdout_stream=out, stderr_stream=err)
    assert rc == 0

    # Scoped ps query runs real host docker ps against the bridge-owned container name.
    out, err = io.BytesIO(), io.BytesIO()
    rc = cli_bridge.main(
        ["docker", "ps", "-aq", "--filter", f"name=^/{container}$"],
        environ=env,
        stdout_stream=out,
        stderr_stream=err,
    )
    assert rc == 0
    assert out.getvalue().strip() == b""
    ps_calls = [c for c in https_bridge["runner"].calls if c["argv"][1] == "ps"]
    assert ps_calls, "Scoped ps must invoke real host docker ps"


def test_concurrent_rm_cancels_running_container_and_ps_does_not_fake(https_bridge):
    ws = https_bridge["workspace_root"]
    cand = ws / "cand-slow"
    cand.mkdir()
    (cand / "sleep.py").write_text("import time; time.sleep(60)\n", encoding="utf-8")

    runner = https_bridge["runner"]
    runner.block_run = threading.Event()
    container = "cog-verify-" + uuid.uuid4().hex
    docker_args = _canonical_docker_run_argv(container=container, candidate_dir=cand, python_argv=["sleep.py"])
    env = {"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])}

    run_result: dict[str, int] = {}

    def _run_worker() -> None:
        out, err = io.BytesIO(), io.BytesIO()
        run_result["rc"] = cli_bridge.main(["docker", *docker_args], environ=env, stdout_stream=out, stderr_stream=err)

    t = threading.Thread(target=_run_worker, daemon=True)
    t.start()
    assert runner.run_started.wait(timeout=5.0)

    # While run is active, scoped ps must return the REAL non-empty container ID (never fake empty).
    ps_out, ps_err = io.BytesIO(), io.BytesIO()
    ps_rc = cli_bridge.main(
        ["docker", "ps", "-aq", "--filter", f"name=^/{container}$"],
        environ=env,
        stdout_stream=ps_out,
        stderr_stream=ps_err,
    )
    assert ps_rc == 0
    assert ps_out.getvalue().strip() != b""

    # Concurrent rm must NOT block behind run; it cancels run and removes container promptly.
    rm_start = time.monotonic()
    rm_out, rm_err = io.BytesIO(), io.BytesIO()
    rm_rc = cli_bridge.main(["docker", "rm", "-f", container], environ=env, stdout_stream=rm_out, stderr_stream=rm_err)
    assert rm_rc == 0
    assert time.monotonic() - rm_start < 3.0

    t.join(timeout=5.0)
    assert not t.is_alive()
    assert run_result["rc"] == 124

    # After removal, scoped ps returns real empty stdout.
    ps_out2, ps_err2 = io.BytesIO(), io.BytesIO()
    ps_rc2 = cli_bridge.main(
        ["docker", "ps", "-aq", "--filter", f"name=^/{container}$"],
        environ=env,
        stdout_stream=ps_out2,
        stderr_stream=ps_err2,
    )
    assert ps_rc2 == 0
    assert ps_out2.getvalue().strip() == b""

    # If docker rm fails AND container is still present in ps, repeated rm MUST fail (not fake success).
    runner.fail_rm = True
    host_container = https_bridge["service"]._containers[container].host_container
    runner.active_containers.add(host_container)
    rm_out2, rm_err2 = io.BytesIO(), io.BytesIO()
    rm_rc2 = cli_bridge.main(["docker", "rm", "-f", container], environ=env, stdout_stream=rm_out2, stderr_stream=rm_err2)
    assert rm_rc2 == 1


def test_unknown_container_rm_and_ps_rejected(https_bridge):
    env = {"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])}
    unknown = "cog-verify-" + ("a" * 32)
    for cmd in (
        ["docker", "rm", "-f", unknown],
        ["docker", "ps", "-aq", "--filter", f"name=^/{unknown}$"],
    ):
        out, err = io.BytesIO(), io.BytesIO()
        rc = cli_bridge.main(cmd, environ=env, stdout_stream=out, stderr_stream=err)
        assert rc == 2
    assert https_bridge["runner"].calls == []


def test_docker_shim_rejects_symlinks_git_pixi_host_escape_and_oversize(https_bridge, tmp_path: Path):
    ws = https_bridge["workspace_root"]
    env = {"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])}
    outside_secret = tmp_path / "outside-secret.txt"
    outside_secret.write_text("host-secret", encoding="utf-8")

    # 1. Arbitrary host path outside workspace_root and /tmp rejected (e.g. client.json or outside secret).
    cand_ok = ws / "cand-ok"
    cand_ok.mkdir()
    (cand_ok / "a.py").write_text("print(1)\n", encoding="utf-8")
    for bad_input in (https_bridge["client_cfg_path"], outside_secret):
        args = _canonical_docker_run_argv(
            container="cog-verify-" + uuid.uuid4().hex,
            candidate_dir=cand_ok,
            inputs=[(0, bad_input)],
        )
        out, err = io.BytesIO(), io.BytesIO()
        assert cli_bridge.main(["docker", *args], environ=env, stdout_stream=out, stderr_stream=err) == 2

    # 2. Symlink inside candidate directory rejected.
    cand_sym = ws / "cand-sym"
    cand_sym.mkdir()
    (cand_sym / "ok.py").write_text("print(1)\n", encoding="utf-8")
    (cand_sym / "leak.txt").symlink_to(outside_secret)
    args = _canonical_docker_run_argv(container="cog-verify-" + uuid.uuid4().hex, candidate_dir=cand_sym)
    out, err = io.BytesIO(), io.BytesIO()
    assert cli_bridge.main(["docker", *args], environ=env, stdout_stream=out, stderr_stream=err) == 2

    # 3. .git and .pixi directories inside candidate rejected.
    for forbidden_dir in (".git", ".pixi"):
        cand_bad = ws / f"cand-{forbidden_dir.strip('.')}"
        (cand_bad / forbidden_dir).mkdir(parents=True)
        (cand_bad / "a.py").write_text("print(1)\n", encoding="utf-8")
        (cand_bad / forbidden_dir / "config").write_text("x", encoding="utf-8")
        args = _canonical_docker_run_argv(container="cog-verify-" + uuid.uuid4().hex, candidate_dir=cand_bad)
        out, err = io.BytesIO(), io.BytesIO()
        assert cli_bridge.main(["docker", *args], environ=env, stdout_stream=out, stderr_stream=err) == 2

    # 4. > 8 MiB total rejected.
    cand_big = ws / "cand-big"
    cand_big.mkdir()
    (cand_big / "big.bin").write_bytes(b"x" * (8 * 1024 * 1024 + 1))
    args = _canonical_docker_run_argv(container="cog-verify-" + uuid.uuid4().hex, candidate_dir=cand_big)
    out, err = io.BytesIO(), io.BytesIO()
    assert cli_bridge.main(["docker", *args], environ=env, stdout_stream=out, stderr_stream=err) == 2

    # 5. Arbitrary docker commands/flags rejected.
    for bad_cmd in (
        ["docker", "ps"],
        ["docker", "ps", "-a"],
        ["docker", "ps", "-aq", "--filter", "name=other"],
        ["docker", "build", "."],
        ["docker", "exec", "foo", "sh"],
        ["docker", "rm", "-f", "not-a-verify-container"],
        [
            "docker",
            "run",
            "--privileged",
            "--name",
            "cog-verify-" + uuid.uuid4().hex,
            PINNED_IMAGE,
            "a.py",
        ],
    ):
        out, err = io.BytesIO(), io.BytesIO()
        assert cli_bridge.main(bad_cmd, environ=env, stdout_stream=out, stderr_stream=err) == 2

    assert https_bridge["runner"].calls == []


@pytest.mark.parametrize(
    "bad_payload",
    [
        {"operation": "exec", "container": "cog-verify-" + ("a" * 32)},
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": PINNED_IMAGE,
            "python_argv": ["a.py"],
            "candidate_files": {"a.py": base64.b64encode(b"x").decode()},
            "archive": "H4sIAAAAAAAA",
        },
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": PINNED_IMAGE,
            "python_argv": ["a.py"],
            "candidate_files": {"../escape.py": base64.b64encode(b"x").decode()},
        },
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": PINNED_IMAGE,
            "python_argv": ["a.py"],
            "candidate_files": {".git/config": base64.b64encode(b"x").decode()},
        },
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": PINNED_IMAGE,
            "python_argv": ["a.py"],
            "candidate_files": {".pixi/env": base64.b64encode(b"x").decode()},
        },
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": PINNED_IMAGE,
            "python_argv": ["a.py"],
            "candidate_files": {
                "a": base64.b64encode(b"x").decode(),
                "a/b.py": base64.b64encode(b"y").decode(),
            },
        },
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": "python:latest",
            "python_argv": ["a.py"],
            "candidate_files": {"a.py": base64.b64encode(b"x").decode()},
        },
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": PINNED_IMAGE,
            "python_argv": ["a.py", ";", "id"],
            "candidate_files": {"a.py": base64.b64encode(b"x").decode()},
        },
        {
            "operation": "run",
            "container": "cog-verify-" + ("a" * 32),
            "requested_image": PINNED_IMAGE,
            "python_argv": ["a.py"],
            "candidate_files": {"a.py": base64.b64encode(b"x").decode()},
            "host_path": "/etc/passwd",
        },
    ],
)
def test_host_docker_parser_rejects_unsafe_payloads(bad_payload: dict[str, Any]):
    with pytest.raises(BridgeError):
        parse_docker_request(bad_payload)


def test_host_config_rejects_unpinned_verify_image(tmp_path: Path):
    cert, key = _generate_self_signed_tls(tmp_path)
    docker_bin = _make_executable(tmp_path / "docker")
    with pytest.raises(ValueError, match="sha256"):
        HostBridgeConfig(
            host="127.0.0.1",
            port=9443,
            token=TEST_TOKEN,
            tls_cert=cert,
            tls_key=key,
            claude_cli=None,
            verify_image="python:3.12-slim",
            docker_cli=docker_bin,
            staging_root=None,
        ).validate()


# ---------------------------------------------------------------------------
# 4. Bounded Subprocess Runner (Real Process Group Kill & I/O Limits)
# ---------------------------------------------------------------------------


def test_bounded_subprocess_timeout_kills_process_group(tmp_path: Path):
    pid_file = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(30)\n"
    )
    res = run_bounded_subprocess(
        [sys.executable, "-c", script],
        timeout_seconds=0.4,
        max_output_bytes=4096,
    )
    assert res.execution_status == "timeout"
    assert res.exit_code == 124
    if pid_file.exists():
        gpid = int(pid_file.read_text().strip())
        time.sleep(0.1)
        with pytest.raises(ProcessLookupError):
            os.kill(gpid, 0)


def test_bounded_subprocess_enforces_output_limit_and_large_stdin():
    # Output limit enforcement.
    res = run_bounded_subprocess(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 500000); sys.stdout.flush()"],
        timeout_seconds=5.0,
        max_output_bytes=2048,
    )
    assert res.execution_status == "output-limit"
    assert res.exit_code == 124
    assert len(res.stdout) + len(res.stderr) == 2048

    # Large stdin (> 128 KiB) completes without pipe deadlock.
    big_stdin = b"a" * (200 * 1024)
    res2 = run_bounded_subprocess(
        [sys.executable, "-c", "import sys; data = sys.stdin.buffer.read(); print(len(data))"],
        stdin_bytes=big_stdin,
        timeout_seconds=5.0,
        max_output_bytes=4096,
    )
    assert res2.execution_status == "exited"
    assert res2.exit_code == 0
    assert res2.stdout.strip() == str(len(big_stdin)).encode("ascii")


def test_env_sanitizers_strip_secrets():
    dirty = {
        "PATH": "/usr/bin",
        "HOME": "/home/bridge-user",
        "CLAUDE_CONFIG_DIR": "/home/bridge-user/.claude",
        "ANTHROPIC_API_KEY": "sk-secret",
        "ANTHROPIC_BASE_URL": "https://bad",
        "OPENAI_API_KEY": "sk-openai",
        "BUILDER_HOST_TOKEN": TEST_TOKEN,
        "DOCKER_HOST": "unix:///var/run/docker.sock",
    }
    c_env = sanitize_claude_env(dirty)
    assert set(c_env.keys()) == {"PATH", "HOME", "CLAUDE_CONFIG_DIR"}
    d_env = sanitize_docker_env(dirty)
    assert set(d_env.keys()) == {"PATH", "HOME", "DOCKER_HOST"}


# ---------------------------------------------------------------------------
# 5. Qualification Mode (Refusal Not Fallback)
# ---------------------------------------------------------------------------


def test_qualification_passes_and_refuses_policy_gaps(https_bridge):
    service: HostBridgeService = https_bridge["service"]
    runner: _FakeRunner = https_bridge["runner"]

    # Happy path including docker confinement probe.
    runner.run_stdout = b"confined\n"
    report = service.qualify(require_claude=True, require_docker=True, probe_docker=True)
    assert report["ok"] is True
    names = {c["check"] for c in report["checks"]}
    assert {
        "tls",
        "staging_root",
        "claude_version",
        "claude_help_controls",
        "claude_subscription_auth",
        "docker_pinned_image",
        "docker_confinement_probe",
    } <= names

    # API-key auth instead of claude.ai subscription -> explicit refusal.
    runner.claude_auth = {"loggedIn": True, "authMethod": "api_key"}
    report_bad_auth = service.qualify(require_claude=True, require_docker=True)
    assert report_bad_auth["ok"] is False
    auth_check = next(c for c in report_bad_auth["checks"] if c["check"] == "claude_subscription_auth")
    assert auth_check["passed"] is False

    # Missing required --safe-mode flag -> explicit refusal.
    runner.claude_auth = {"loggedIn": True, "authMethod": "claude.ai"}
    runner.claude_help = "Usage: claude --version\n"
    report_old_cli = service.qualify(require_claude=True, require_docker=True)
    assert report_old_cli["ok"] is False
    help_check = next(c for c in report_old_cli["checks"] if c["check"] == "claude_help_controls")
    assert help_check["passed"] is False
    assert "--safe-mode" in help_check["missing_flags"]

    # Unavailable pinned image -> explicit refusal without host fallback.
    runner.claude_help = SAMPLE_CLAUDE_HELP
    runner.inspect_rc = 1
    report_no_img = service.qualify(require_claude=True, require_docker=True)
    assert report_no_img["ok"] is False
    img_check = next(c for c in report_no_img["checks"] if c["check"] == "docker_pinned_image")
    assert img_check["passed"] is False


def test_real_cli_wrapper_subprocess_argv0_and_module_mode(https_bridge, tmp_path: Path):
    pkg_src = str(Path(__file__).resolve().parents[1] / "src")
    bin_dir = tmp_path / "wrappers"
    bin_dir.mkdir()
    for tool in ("claude", "docker"):
        wrapper = bin_dir / tool
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import sys\n"
            f"sys.path.insert(0, {pkg_src!r})\n"
            "from builder_hub.cli_bridge import main\n"
            "raise SystemExit(main())\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

    env = {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"]),
        "PYTHONPATH": pkg_src,
    }
    # argv[0] wrapper mode for claude
    res_claude = subprocess.run(
        [str(bin_dir / "claude"), "--version"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert res_claude.returncode == 0, res_claude.stderr
    assert "2.1.330" in res_claude.stdout

    # argv[0] wrapper mode for docker
    res_docker = subprocess.run(
        [str(bin_dir / "docker"), "image", "inspect", "--format", "{{.Id}} {{.Os}} {{.Architecture}}", PINNED_IMAGE],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert res_docker.returncode == 0, res_docker.stderr
    assert res_docker.stdout.strip() == INSPECT_IDENTITY

    # python -m builder_hub.cli_bridge mode
    res_mod = subprocess.run(
        [sys.executable, "-m", "builder_hub.cli_bridge", "claude", "auth", "status"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert res_mod.returncode == 0, res_mod.stderr
    assert json.loads(res_mod.stdout)["authMethod"] == "claude.ai"


def test_http_redirect_refused_never_leaks_token(tmp_path: Path):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    leaked: list[str] = []

    class _RedirectHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/cli/claude":
                self.send_response(307)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/steal")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                leaked.append(self.headers.get("Authorization") or "")
                self.send_response(200)
                self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    try:
        cfg = cli_bridge.ClientConfig(
            url=f"http://127.0.0.1:{port}",
            token=TEST_TOKEN,
            ca_file=None,
            workspace_root=tmp_path,
        )
        with pytest.raises(cli_bridge.CliBridgeError, match="307"):
            cli_bridge.post_bridge(cfg, "/cli/claude", {"argv": ["--version"], "stdin": ""}, timeout_seconds=5)
        assert leaked == []
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=3)


def test_tmp_root_allowed_for_subdirs_but_not_root_itself_or_escape(https_bridge):
    env = {"BUILDER_HOST_CONFIG": str(https_bridge["client_cfg_path"])}

    # Mounting workspace_root itself or /tmp itself must be rejected.
    for root_dir in (https_bridge["workspace_root"], Path("/tmp")):
        args = _canonical_docker_run_argv(
            container="cog-verify-" + uuid.uuid4().hex,
            candidate_dir=root_dir,
        )
        out, err = io.BytesIO(), io.BytesIO()
        assert cli_bridge.main(["docker", *args], environ=env, stdout_stream=out, stderr_stream=err) == 2

    # Subdirectory inside /tmp is allowed.
    sub_tmp = Path("/tmp") / f"builder-bridge-test-{uuid.uuid4().hex}"
    sub_tmp.mkdir(mode=0o700)
    try:
        (sub_tmp / "probe.py").write_text("print('hi')\n", encoding="utf-8")
        args = _canonical_docker_run_argv(
            container="cog-verify-" + uuid.uuid4().hex,
            candidate_dir=sub_tmp,
            python_argv=["probe.py"],
        )
        out, err = io.BytesIO(), io.BytesIO()
        rc = cli_bridge.main(["docker", *args], environ=env, stdout_stream=out, stderr_stream=err)
        assert rc == 0, err.getvalue().decode()
    finally:
        import shutil
        shutil.rmtree(sub_tmp, ignore_errors=True)


def test_claude_output_limit_returns_nonzero_and_bounded_bytes(tmp_path: Path):
    cert, key = _generate_self_signed_tls(tmp_path)
    noisy_claude = tmp_path / "noisy-claude"
    noisy_claude.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.write('A' * 50000)\nsys.stdout.flush()\n",
        encoding="utf-8",
    )
    noisy_claude.chmod(0o755)
    cfg = HostBridgeConfig(
        host="127.0.0.1",
        port=0,
        token=TEST_TOKEN,
        tls_cert=cert,
        tls_key=key,
        claude_cli=noisy_claude,
        verify_image=None,
        docker_cli=None,
        staging_root=None,
        max_output_bytes=2048,
    )
    service = HostBridgeService(cfg)
    status, body, op = service.handle_claude({"argv": _canonical_claude_print_argv(), "stdin": "hello"})
    assert status == 200
    assert op == "print"
    assert body["execution_status"] == "output-limit"
    assert body["exit_code"] == 124
    assert len(body["stdout"].encode("utf-8")) + len(body["stderr"].encode("utf-8")) == 2048


def test_host_bridge_main_qualify_cli_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    cert, key = _generate_self_signed_tls(tmp_path)
    staging = tmp_path / "stage"
    staging.mkdir()

    # Fake executable claude that passes --version, --help, and auth status (claude.ai).
    claude_ok = tmp_path / "claude-ok"
    claude_ok.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']: print('2.1.330')\n"
        f"elif args == ['--help']: print({SAMPLE_CLAUDE_HELP!r})\n"
        "elif args == ['auth', 'status']: print(json.dumps({'loggedIn': True, 'authMethod': 'claude.ai'}))\n"
        "else: sys.exit(2)\n",
        encoding="utf-8",
    )
    claude_ok.chmod(0o755)

    docker_ok = tmp_path / "docker-ok"
    docker_ok.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"if sys.argv[1:3] == ['image', 'inspect']: print({INSPECT_IDENTITY!r})\n"
        "else: sys.exit(1)\n",
        encoding="utf-8",
    )
    docker_ok.chmod(0o755)

    monkeypatch.setenv("BUILDER_HOST_TOKEN", TEST_TOKEN)
    rc = host_bridge.main(
        [
            "qualify",
            "--tls-cert",
            str(cert),
            "--tls-key",
            str(key),
            "--claude-cli",
            str(claude_ok),
            "--verify-image",
            PINNED_IMAGE,
            "--docker-cli",
            str(docker_ok),
            "--staging-root",
            str(staging),
            "--require-claude",
            "--require-docker",
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True

    # Short token -> exit code 2 fail-closed.
    monkeypatch.setenv("BUILDER_HOST_TOKEN", "too-short")
    rc_bad = host_bridge.main(["qualify"])
    assert rc_bad == 2
