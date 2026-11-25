"""Strictly bounded host-services HTTPS bridge for Builder workspaces.

Runs as a trusted host-side service (or dedicated privileged bridge container on
the kind Docker network) that alone accesses:

1. The pinned native ``claude`` CLI and vendor-owned host subscription login
   files — without copying vendor credentials into Kubernetes or the workspace.
2. The host Docker daemon and a single pinned verification image digest
   (``sha256:<64hex>``) — without mounting the Docker socket into the workspace.

Security invariants:
- HTTPS with TLS 1.2+ is required in serve mode.
- Every endpoint requires ``Authorization: Bearer <token>`` verified in constant
  time against ``BUILDER_HOST_TOKEN`` (>= 32 chars).
- ``POST /cli/claude`` accepts only the exact upstream ``cog-claude``
  invocations (``--version``, ``--help``, ``auth status``, and the tool-free
  non-interactive ``-p`` JSON invocation). Arbitrary flags, permission
  escalation, silent model substitution, and ambient API-key/endpoint overrides
  are rejected or stripped. Optional ``--settings`` bytes are strictly
  validated and replaced with a host-written canonical safe settings file.
- ``POST /cli/docker`` accepts only three structured operations corresponding to
  the exact invocations emitted by public ``cog-verify-candidate``
  (``image_inspect``, ``run``, ``rm``). Incoming host paths, archives,
  symlinks, ``.git``/``.pixi`` entries, and client-requested images are never
  trusted. Files are staged as regular files under an owner-only directory
  below ``BUILDER_STAGING_ROOT`` and run with the exact read-only, network-none,
  unprivileged resource-capped Docker policy. Containers and staging directories
  are always removed.
- Logs never include prompts, argv payloads, tokens, file contents, or stdout.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
import uuid

logger = logging.getLogger("builder_hub.host_bridge")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9443
MIN_TOKEN_LENGTH = 32

MAX_CLAUDE_TIMEOUT = 660
DEFAULT_CLAUDE_TIMEOUT = 600
READINESS_TIMEOUT = 30
MAX_DOCKER_TIMEOUT = 600
DEFAULT_DOCKER_TIMEOUT = 240

MAX_CLI_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_CLAUDE_STDIN_BYTES = 2 * 1024 * 1024
MAX_CLAUDE_REQUEST_BYTES = 3 * 1024 * 1024
MAX_DOCKER_FILES_BYTES = 8 * 1024 * 1024
MAX_DOCKER_REQUEST_BYTES = 12 * 1024 * 1024
MAX_SETTINGS_BYTES = 64 * 1024
MAX_JSON_SCHEMA_BYTES = 256 * 1024
MAX_CANDIDATE_FILE_COUNT = 2000
MAX_INPUT_FILE_COUNT = 64
MAX_PYTHON_ARGV_COUNT = 128
MAX_PYTHON_ARG_LEN = 4096
MAX_REL_PATH_LEN = 256
MAX_CONTAINER_HISTORY = 1024
REQUEST_SOCKET_TIMEOUT = 30.0

# Matches cog-claude/binding/provider.json model_id pattern exactly.
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
# Host-configured pinned verification image MUST be an immutable sha256 image ID.
VERIFY_IMAGE_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
# Matches cog-verify-candidate/src/isolated_execution.py image syntax.
REQUESTED_IMAGE_RE = re.compile(r"^(sha256:[a-f0-9]{64}|[^\s,@]+@sha256:[a-f0-9]{64})$")
# Matches cog-verify-candidate/src/isolated_execution.py container name syntax.
CONTAINER_NAME_RE = re.compile(r"^cog-verify-[0-9a-f]{32}$")
# Actual Docker inspect output required: "<sha256:64hex> linux <arch>".
INSPECT_OUTPUT_RE = re.compile(r"^sha256:[a-f0-9]{64} linux [A-Za-z0-9_.-]+$")
SAFE_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._+-]{0,127}$")
INPUT_INDEX_RE = re.compile(r"^(0|[1-9][0-9]{0,2})$")

FORBIDDEN_PATH_SEGMENTS = frozenset({".", "..", ".git", ".pixi"})
FORBIDDEN_SHELL_TOKENS = frozenset({";", "&&", "|", "||", ">", "<"})

# Strict environment allowlists for host subprocesses: API key overrides,
# base URLs, gateway tokens, proxy overrides, and bridge secrets never enter.
CLAUDE_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SYSTEMROOT",
        "CLAUDE_CONFIG_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
    }
)

DOCKER_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "XDG_RUNTIME_DIR",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
    }
)

REQUIRED_CLAUDE_HELP_FLAGS = (
    "--safe-mode",
    "--tools",
    "--no-session-persistence",
    "--json-schema",
    "--setting-sources",
    "--strict-mcp-config",
    "--mcp-config",
    "--disallowedTools",
    "--permission-mode",
    "--output-format",
    "--model",
)

ALLOWED_SETTINGS_KEYS = frozenset(
    {
        "mcpServers",
        "enableAllProjectMcpServers",
        "enabledMcpjsonServers",
        "disabledMcpjsonServers",
        "hooks",
        "disableAllHooks",
        "enabledPlugins",
        "extraKnownMarketplaces",
        "permissions",
    }
)

ALLOWED_PERMISSION_KEYS = frozenset({"allow", "ask", "deny", "defaultMode"})

CLAUDE_REQUIRED_FLAGS = frozenset(
    {
        "-p",
        "--safe-mode",
        "--strict-mcp-config",
        "--no-session-persistence",
    }
)

CLAUDE_REQUIRED_VALUE_FLAGS = frozenset(
    {
        "--setting-sources",
        "--mcp-config",
        "--tools",
        "--disallowedTools",
        "--permission-mode",
        "--output-format",
        "--model",
    }
)

CLAUDE_OPTIONAL_VALUE_FLAGS = frozenset({"--json-schema"})

DOCKER_INSPECT_FORMAT = "{{.Id}} {{.Os}} {{.Architecture}}"

DOCKER_FIXED_RUN_POLICY_ARGS: tuple[str, ...] = (
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
)


class BridgeError(ValueError):
    """Fail-closed validation or policy error with static, safe error details."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _strict_json_loads(raw: bytes | str) -> Any:
    def _reject_constant(value: str) -> Any:
        raise ValueError(f"Unsupported JSON constant: {value}")

    if isinstance(raw, bytes):
        text = raw.decode("utf-8")
    else:
        text = raw
    return json.loads(text, parse_constant=_reject_constant)


def _decode_strict_base64(value: Any, *, field_name: str, max_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise BridgeError(400, "invalid_base64", f"{field_name} must be a base64 string.")
    max_encoded = ((max_bytes + 2) // 3) * 4 + 4
    if len(value) > max_encoded:
        raise BridgeError(413, "payload_too_large", f"{field_name} exceeds maximum size.")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise BridgeError(400, "invalid_base64", f"{field_name} is not valid base64.") from None
    if len(decoded) > max_bytes:
        raise BridgeError(413, "payload_too_large", f"{field_name} exceeds maximum size.")
    return decoded


def validate_token(token: str | None) -> str:
    if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
        raise ValueError(f"BUILDER_HOST_TOKEN must be at least {MIN_TOKEN_LENGTH} characters.")
    if "\r" in token or "\n" in token or "\x00" in token:
        raise ValueError("BUILDER_HOST_TOKEN must not contain control characters.")
    return token


def validate_executable_path(raw_path: str, *, label: str) -> Path:
    if not raw_path or "\x00" in raw_path or "\n" in raw_path or "\r" in raw_path:
        raise ValueError(f"{label} must be a valid absolute path.")
    path = Path(raw_path)
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path.")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ValueError(f"{label} does not exist.") from None
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"{label} must point to an executable regular file.")
    return path


def validate_staging_root(raw_path: str) -> Path:
    if not raw_path or "\x00" in raw_path or "," in raw_path:
        raise ValueError("BUILDER_STAGING_ROOT must be an absolute path without commas.")
    path = Path(raw_path)
    if not path.is_absolute() or path == Path("/"):
        raise ValueError("BUILDER_STAGING_ROOT must be a non-root absolute directory.")
    if path.is_symlink():
        raise ValueError("BUILDER_STAGING_ROOT must not be a symlink.")
    if not path.is_dir():
        raise ValueError("BUILDER_STAGING_ROOT must exist as a directory.")
    if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
        raise ValueError("BUILDER_STAGING_ROOT must be readable, writable, and searchable.")
    return path


def validate_relative_path(raw: Any) -> str:
    """Validate a candidate-relative regular-file POSIX path."""
    if not isinstance(raw, str) or not raw or len(raw) > MAX_REL_PATH_LEN:
        raise BridgeError(400, "invalid_path", "Candidate file path is invalid.")
    if "\x00" in raw or "\\" in raw or ":" in raw:
        raise BridgeError(400, "invalid_path", "Candidate file path contains forbidden characters.")
    if raw.startswith("/") or raw.endswith("/") or "//" in raw:
        raise BridgeError(400, "invalid_path", "Candidate file path must be a normalized relative path.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise BridgeError(400, "invalid_path", "Candidate file path contains control characters.")
    segments = raw.split("/")
    for segment in segments:
        if not segment or segment.lower() in FORBIDDEN_PATH_SEGMENTS:
            raise BridgeError(400, "forbidden_path", "Candidate path segment is forbidden.")
        if not SAFE_PATH_SEGMENT_RE.fullmatch(segment):
            raise BridgeError(400, "invalid_path", "Candidate path segment contains unsupported characters.")
    return raw


def validate_filemap_paths(paths: Iterable[str]) -> None:
    """Reject file/directory path collisions (e.g. both 'a' and 'a/b')."""
    path_set = set(paths)
    for rel in path_set:
        parts = rel.split("/")
        for depth in range(1, len(parts)):
            prefix = "/".join(parts[:depth])
            if prefix in path_set:
                raise BridgeError(400, "path_collision", "Candidate filemap has a file/directory collision.")


def validate_json_schema_arg(raw_schema: Any) -> str:
    if not isinstance(raw_schema, str):
        raise BridgeError(400, "invalid_schema", "--json-schema value must be a JSON string.")
    if len(raw_schema.encode("utf-8")) > MAX_JSON_SCHEMA_BYTES:
        raise BridgeError(413, "schema_too_large", "--json-schema exceeds maximum size.")
    try:
        parsed = _strict_json_loads(raw_schema)
    except (ValueError, UnicodeDecodeError):
        raise BridgeError(400, "invalid_schema", "--json-schema must be valid JSON.") from None
    if not isinstance(parsed, dict) or parsed.get("type") != "object":
        raise BridgeError(400, "invalid_schema", "--json-schema must describe a JSON object.")

    def _check_refs(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("$ref", "$dynamicRef"):
                    if not isinstance(value, str) or not value.startswith("#"):
                        raise BridgeError(400, "remote_schema_ref", "Remote schema references are not allowed.")
                _check_refs(value)
        elif isinstance(node, list):
            for item in node:
                _check_refs(item)

    _check_refs(parsed)
    return json.dumps(parsed, separators=(",", ":"))


def validate_claude_settings(raw_bytes: bytes) -> dict[str, Any]:
    """Validate optional --settings bytes and build a fixed safe settings dict."""
    if len(raw_bytes) > MAX_SETTINGS_BYTES:
        raise BridgeError(413, "settings_too_large", "Settings payload exceeds maximum size.")
    try:
        parsed = _strict_json_loads(raw_bytes)
    except (UnicodeDecodeError, ValueError):
        raise BridgeError(400, "invalid_settings", "Settings payload must be valid UTF-8 JSON.") from None
    if not isinstance(parsed, dict):
        raise BridgeError(400, "invalid_settings", "Settings payload must be a JSON object.")
    unexpected = set(parsed.keys()) - ALLOWED_SETTINGS_KEYS
    if unexpected:
        raise BridgeError(400, "forbidden_settings_key", "Settings payload contains unsupported keys.")

    if "mcpServers" in parsed and parsed["mcpServers"] != {}:
        raise BridgeError(400, "forbidden_settings_value", "Settings mcpServers must be empty.")
    if "enableAllProjectMcpServers" in parsed and parsed["enableAllProjectMcpServers"] is not False:
        raise BridgeError(400, "forbidden_settings_value", "Project MCP servers must remain disabled.")
    if "enabledMcpjsonServers" in parsed and parsed["enabledMcpjsonServers"] != []:
        raise BridgeError(400, "forbidden_settings_value", "MCP JSON servers must remain disabled.")
    if "disabledMcpjsonServers" in parsed:
        val = parsed["disabledMcpjsonServers"]
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise BridgeError(400, "invalid_settings", "disabledMcpjsonServers must be a string list.")
    if "hooks" in parsed and parsed["hooks"] != {}:
        raise BridgeError(400, "forbidden_settings_value", "Settings hooks must be empty.")
    if "disableAllHooks" in parsed and parsed["disableAllHooks"] is not True:
        raise BridgeError(400, "forbidden_settings_value", "Hooks must remain disabled.")
    if "enabledPlugins" in parsed and parsed["enabledPlugins"] != {}:
        raise BridgeError(400, "forbidden_settings_value", "Plugins must remain disabled.")
    if "extraKnownMarketplaces" in parsed and parsed["extraKnownMarketplaces"] != {}:
        raise BridgeError(400, "forbidden_settings_value", "Plugin marketplaces must remain empty.")

    deny_list: list[str] = []
    if "permissions" in parsed:
        perms = parsed["permissions"]
        if not isinstance(perms, dict):
            raise BridgeError(400, "invalid_settings", "Settings permissions must be an object.")
        if set(perms.keys()) - ALLOWED_PERMISSION_KEYS:
            raise BridgeError(400, "forbidden_settings_key", "Settings permissions contains unsupported keys.")
        if "allow" in perms and perms["allow"] != []:
            raise BridgeError(400, "forbidden_settings_value", "Settings permissions.allow must be empty.")
        if "ask" in perms and perms["ask"] != []:
            raise BridgeError(400, "forbidden_settings_value", "Settings permissions.ask must be empty.")
        if "defaultMode" in perms and perms["defaultMode"] != "dontAsk":
            raise BridgeError(400, "forbidden_settings_value", "Settings permissions.defaultMode must be dontAsk.")
        if "deny" in perms:
            raw_deny = perms["deny"]
            if (
                not isinstance(raw_deny, list)
                or len(raw_deny) > 128
                or not all(isinstance(x, str) and len(x) <= 256 for x in raw_deny)
            ):
                raise BridgeError(400, "invalid_settings", "Settings permissions.deny must be a bounded string list.")
            deny_list = list(raw_deny)

    # Always emit a fixed, host-controlled canonical settings object.
    return {
        "mcpServers": {},
        "enableAllProjectMcpServers": False,
        "enabledMcpjsonServers": [],
        "hooks": {},
        "disableAllHooks": True,
        "enabledPlugins": {},
        "extraKnownMarketplaces": {},
        "permissions": {
            "allow": [],
            "ask": [],
            "deny": deny_list,
            "defaultMode": "dontAsk",
        },
    }


@dataclass(frozen=True)
class ClaudeInvocation:
    operation: str  # "version" | "help" | "auth_status" | "print"
    model: str | None
    json_schema: str | None
    stdin: str
    settings: dict[str, Any] | None
    timeout_seconds: int


def parse_claude_request(
    payload: Any,
    *,
    default_timeout: int = DEFAULT_CLAUDE_TIMEOUT,
) -> ClaudeInvocation:
    """Strictly validate a POST /cli/claude request against upstream cog-claude."""
    if not isinstance(payload, dict):
        raise BridgeError(400, "invalid_body", "Request body must be a JSON object.")
    allowed_keys = {"argv", "stdin", "settings_b64", "timeout_seconds"}
    if set(payload.keys()) - allowed_keys:
        raise BridgeError(400, "unexpected_field", "Request contains unsupported fields.")

    argv = payload.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 32
        or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv)
    ):
        raise BridgeError(400, "invalid_claude_argv", "argv must be a non-empty list of strings.")

    stdin = payload.get("stdin", "")
    if not isinstance(stdin, str):
        raise BridgeError(400, "invalid_stdin", "stdin must be a string.")
    if len(stdin.encode("utf-8")) > MAX_CLAUDE_STDIN_BYTES:
        raise BridgeError(413, "stdin_too_large", "stdin exceeds maximum size.")

    settings_b64 = payload.get("settings_b64")
    raw_timeout = payload.get("timeout_seconds")

    # Readiness forms from cog-claude/src/turn_runtime.py:
    #   claude --version
    #   claude --help
    #   claude auth status
    if argv == ["--version"] or argv == ["--help"] or argv == ["auth", "status"]:
        if stdin:
            raise BridgeError(400, "unexpected_stdin", "Readiness commands do not accept stdin.")
        if settings_b64 is not None:
            raise BridgeError(400, "unexpected_settings", "Readiness commands do not accept settings.")
        if raw_timeout is not None:
            if type(raw_timeout) is not int or not (1 <= raw_timeout <= READINESS_TIMEOUT):
                raise BridgeError(400, "invalid_timeout", "Readiness timeout is out of range.")
            timeout = raw_timeout
        else:
            timeout = min(15, READINESS_TIMEOUT)
        op = "version" if argv == ["--version"] else ("help" if argv == ["--help"] else "auth_status")
        return ClaudeInvocation(
            operation=op,
            model=None,
            json_schema=None,
            stdin="",
            settings=None,
            timeout_seconds=timeout,
        )

    # Print JSON invocation from cog-claude/src/turn_runtime.py lines 381-386.
    if argv[0] != "-p":
        raise BridgeError(400, "disallowed_claude_argv", "Only exact cog-claude invocations are permitted.")

    seen_flags: set[str] = set()
    values: dict[str, str] = {}
    idx = 0
    while idx < len(argv):
        token = argv[idx]
        if token in CLAUDE_REQUIRED_FLAGS:
            if token in seen_flags:
                raise BridgeError(400, "duplicate_flag", "Duplicate Claude CLI flag.")
            seen_flags.add(token)
            idx += 1
        elif token in CLAUDE_REQUIRED_VALUE_FLAGS or token in CLAUDE_OPTIONAL_VALUE_FLAGS:
            if token in values:
                raise BridgeError(400, "duplicate_flag", "Duplicate Claude CLI flag.")
            if idx + 1 >= len(argv):
                raise BridgeError(400, "missing_flag_value", "Missing value for Claude CLI flag.")
            values[token] = argv[idx + 1]
            idx += 2
        else:
            raise BridgeError(400, "disallowed_claude_flag", "Unsupported or unsafe Claude CLI argument.")

    if seen_flags != CLAUDE_REQUIRED_FLAGS:
        raise BridgeError(400, "missing_required_flag", "Required cog-claude safety flags are missing.")
    if not CLAUDE_REQUIRED_VALUE_FLAGS.issubset(values.keys()):
        raise BridgeError(400, "missing_required_flag", "Required cog-claude control flags are missing.")

    if values["--setting-sources"] != "":
        raise BridgeError(400, "invalid_setting_sources", "--setting-sources must be empty.")
    try:
        mcp_cfg = _strict_json_loads(values["--mcp-config"])
    except ValueError:
        raise BridgeError(400, "invalid_mcp_config", "--mcp-config must be valid JSON.") from None
    if mcp_cfg != {"mcpServers": {}}:
        raise BridgeError(400, "invalid_mcp_config", "--mcp-config must declare empty mcpServers.")
    if values["--tools"] != "":
        raise BridgeError(400, "invalid_tools", "--tools must be empty.")
    if values["--disallowedTools"] != "mcp__*":
        raise BridgeError(400, "invalid_disallowed_tools", "--disallowedTools must be 'mcp__*'.")
    if values["--permission-mode"] != "dontAsk":
        raise BridgeError(400, "invalid_permission_mode", "--permission-mode must be 'dontAsk'.")
    if values["--output-format"] != "json":
        raise BridgeError(400, "invalid_output_format", "--output-format must be 'json'.")

    model = values["--model"]
    if not MODEL_ID_RE.fullmatch(model):
        raise BridgeError(400, "invalid_model", "--model does not match allowed model identifier pattern.")

    json_schema: str | None = None
    if "--json-schema" in values:
        json_schema = validate_json_schema_arg(values["--json-schema"])

    validated_settings: dict[str, Any] | None = None
    if settings_b64 is not None:
        raw_settings = _decode_strict_base64(
            settings_b64,
            field_name="settings_b64",
            max_bytes=MAX_SETTINGS_BYTES,
        )
        validated_settings = validate_claude_settings(raw_settings)

    if raw_timeout is not None:
        if type(raw_timeout) is not int or not (1 <= raw_timeout <= MAX_CLAUDE_TIMEOUT):
            raise BridgeError(400, "invalid_timeout", f"timeout_seconds must be 1..{MAX_CLAUDE_TIMEOUT}.")
        timeout = raw_timeout
    else:
        timeout = min(default_timeout, MAX_CLAUDE_TIMEOUT)

    return ClaudeInvocation(
        operation="print",
        model=model,
        json_schema=json_schema,
        stdin=stdin,
        settings=validated_settings,
        timeout_seconds=timeout,
    )


@dataclass(frozen=True)
class DockerInspectInvocation:
    requested_image: str


@dataclass(frozen=True)
class DockerRmInvocation:
    container: str


@dataclass(frozen=True)
class DockerPsInvocation:
    container: str


@dataclass(frozen=True)
class DockerRunInvocation:
    container: str
    requested_image: str
    python_argv: tuple[str, ...]
    candidate_files: dict[str, bytes]
    input_files: dict[str, bytes]
    timeout_seconds: int


DockerInvocation = DockerInspectInvocation | DockerRmInvocation | DockerPsInvocation | DockerRunInvocation


def parse_docker_request(
    payload: Any,
    *,
    default_timeout: int = DEFAULT_DOCKER_TIMEOUT,
) -> DockerInvocation:
    """Strictly validate a POST /cli/docker structured request."""
    if not isinstance(payload, dict):
        raise BridgeError(400, "invalid_body", "Request body must be a JSON object.")
    operation = payload.get("operation")
    if operation == "image_inspect":
        if set(payload.keys()) - {"operation", "requested_image"}:
            raise BridgeError(400, "unexpected_field", "image_inspect contains unsupported fields.")
        requested_image = payload.get("requested_image")
        if not isinstance(requested_image, str) or not REQUESTED_IMAGE_RE.fullmatch(requested_image):
            raise BridgeError(400, "invalid_image", "requested_image must be a pinned digest.")
        return DockerInspectInvocation(requested_image=requested_image)

    if operation == "rm":
        if set(payload.keys()) - {"operation", "container"}:
            raise BridgeError(400, "unexpected_field", "rm contains unsupported fields.")
        container = payload.get("container")
        if not isinstance(container, str) or not CONTAINER_NAME_RE.fullmatch(container):
            raise BridgeError(400, "invalid_container", "container must be a cog-verify generated name.")
        return DockerRmInvocation(container=container)

    if operation == "ps":
        if set(payload.keys()) - {"operation", "container"}:
            raise BridgeError(400, "unexpected_field", "ps contains unsupported fields.")
        container = payload.get("container")
        if not isinstance(container, str) or not CONTAINER_NAME_RE.fullmatch(container):
            raise BridgeError(400, "invalid_container", "container must be a cog-verify generated name.")
        return DockerPsInvocation(container=container)

    if operation == "run":
        allowed_keys = {
            "operation",
            "container",
            "requested_image",
            "python_argv",
            "candidate_files",
            "input_files",
            "timeout_seconds",
        }
        unexpected = set(payload.keys()) - allowed_keys
        if unexpected:
            raise BridgeError(400, "unexpected_field", "run contains unsupported fields (archives/host paths rejected).")

        container = payload.get("container")
        if not isinstance(container, str) or not CONTAINER_NAME_RE.fullmatch(container):
            raise BridgeError(400, "invalid_container", "container must be a cog-verify generated name.")

        requested_image = payload.get("requested_image")
        if not isinstance(requested_image, str) or not REQUESTED_IMAGE_RE.fullmatch(requested_image):
            raise BridgeError(400, "invalid_image", "requested_image must be a pinned digest.")

        python_argv = payload.get("python_argv")
        if (
            not isinstance(python_argv, list)
            or not python_argv
            or len(python_argv) > MAX_PYTHON_ARGV_COUNT
        ):
            raise BridgeError(400, "invalid_python_argv", "python_argv must be a non-empty bounded list.")
        validated_py_argv: list[str] = []
        for arg in python_argv:
            if not isinstance(arg, str) or len(arg) > MAX_PYTHON_ARG_LEN or "\x00" in arg:
                raise BridgeError(400, "invalid_python_argv", "Invalid entry in python_argv.")
            if arg in FORBIDDEN_SHELL_TOKENS:
                raise BridgeError(400, "invalid_python_argv", "Shell control tokens are not allowed in python_argv.")
            validated_py_argv.append(arg)

        raw_candidate = payload.get("candidate_files")
        if not isinstance(raw_candidate, dict) or not raw_candidate:
            raise BridgeError(400, "invalid_candidate_files", "candidate_files must be a non-empty filemap.")
        if len(raw_candidate) > MAX_CANDIDATE_FILE_COUNT:
            raise BridgeError(413, "too_many_files", "candidate_files exceeds file count limit.")

        raw_inputs = payload.get("input_files", {})
        if not isinstance(raw_inputs, dict):
            raise BridgeError(400, "invalid_input_files", "input_files must be a filemap.")
        if len(raw_inputs) > MAX_INPUT_FILE_COUNT:
            raise BridgeError(413, "too_many_files", "input_files exceeds file count limit.")

        total_bytes = 0
        candidate_files: dict[str, bytes] = {}
        for rel_path, b64_content in raw_candidate.items():
            clean_path = validate_relative_path(rel_path)
            if clean_path in candidate_files:
                raise BridgeError(400, "duplicate_path", "Duplicate path in candidate_files.")
            remaining = MAX_DOCKER_FILES_BYTES - total_bytes
            data = _decode_strict_base64(b64_content, field_name="candidate_files", max_bytes=remaining)
            total_bytes += len(data)
            candidate_files[clean_path] = data
        validate_filemap_paths(candidate_files.keys())

        input_files: dict[str, bytes] = {}
        for idx_key, b64_content in raw_inputs.items():
            if not isinstance(idx_key, str) or not INPUT_INDEX_RE.fullmatch(idx_key):
                raise BridgeError(400, "invalid_input_index", "input_files keys must be non-negative integer strings.")
            remaining = MAX_DOCKER_FILES_BYTES - total_bytes
            data = _decode_strict_base64(b64_content, field_name="input_files", max_bytes=remaining)
            total_bytes += len(data)
            input_files[idx_key] = data

        raw_timeout = payload.get("timeout_seconds")
        if raw_timeout is not None:
            if type(raw_timeout) is not int or not (1 <= raw_timeout <= MAX_DOCKER_TIMEOUT):
                raise BridgeError(400, "invalid_timeout", f"timeout_seconds must be 1..{MAX_DOCKER_TIMEOUT}.")
            timeout = raw_timeout
        else:
            timeout = min(default_timeout, MAX_DOCKER_TIMEOUT)

        return DockerRunInvocation(
            container=container,
            requested_image=requested_image,
            python_argv=tuple(validated_py_argv),
            candidate_files=candidate_files,
            input_files=input_files,
            timeout_seconds=timeout,
        )

    raise BridgeError(400, "disallowed_docker_operation", "Only image_inspect, run, rm, and scoped ps are supported.")


def sanitize_claude_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep only vendor-safe host environment variables; strip API keys and tokens."""
    source = os.environ if env is None else env
    return {k: v for k, v in source.items() if k in CLAUDE_ENV_ALLOWLIST}


def sanitize_docker_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep only minimal host environment variables for invoking the Docker CLI."""
    source = os.environ if env is None else env
    return {k: v for k, v in source.items() if k in DOCKER_ENV_ALLOWLIST}


def kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        if proc.poll() is None:
            proc.kill()


@dataclass(frozen=True)
class SubprocessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    execution_status: str  # "exited" | "timeout" | "output-limit" | "canceled"
    elapsed_seconds: float


SubprocessRunner = Callable[..., SubprocessResult]


def run_bounded_subprocess(
    argv: list[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    stdin_bytes: bytes = b"",
    timeout_seconds: float = 30.0,
    max_output_bytes: int = MAX_CLI_OUTPUT_BYTES,
    cancel_event: threading.Event | None = None,
) -> SubprocessResult:
    """Run a subprocess in its own process group with bounded I/O and hard timeout."""
    start = time.monotonic()
    stdin_file = None
    try:
        if stdin_bytes:
            stdin_file = tempfile.TemporaryFile()
            stdin_file.write(stdin_bytes)
            stdin_file.seek(0)
            stdin_arg: Any = stdin_file
        else:
            stdin_arg = subprocess.DEVNULL

        proc = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
            stdin=stdin_arg,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        if stdin_file is not None:
            stdin_file.close()
        raise BridgeError(502, "subprocess_unavailable", "Configured host executable could not be started.") from None

    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    output: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    status = "exited"

    try:
        while selector.get_map():
            if cancel_event is not None and cancel_event.is_set():
                status = "canceled"
                break
            elapsed = time.monotonic() - start
            if elapsed >= timeout_seconds:
                status = "timeout"
                break
            wait_for = min(0.05, max(0.0, timeout_seconds - elapsed))
            for key, _ in selector.select(wait_for):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                used = len(output["stdout"]) + len(output["stderr"])
                remaining = max_output_bytes - used
                if remaining > 0:
                    output[key.data].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    status = "output-limit"
                    break
            if status != "exited":
                break

        if status != "exited":
            kill_process_group(proc)

        try:
            wait_budget = max(0.05, timeout_seconds - (time.monotonic() - start)) if status == "exited" else 5.0
            code = proc.wait(timeout=wait_budget)
        except subprocess.TimeoutExpired:
            status = "timeout"
            kill_process_group(proc)
            code = proc.wait()

        return SubprocessResult(
            exit_code=code if status == "exited" else 124,
            stdout=bytes(output["stdout"]),
            stderr=bytes(output["stderr"]),
            execution_status=status,
            elapsed_seconds=round(time.monotonic() - start, 3),
        )
    finally:
        if proc.poll() is None:
            kill_process_group(proc)
            proc.wait()
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
        if stdin_file is not None:
            stdin_file.close()


def _create_owner_only_tempdir(prefix: str, staging_root: Path | None) -> Path:
    parent = str(staging_root) if staging_root is not None else None
    raw_dir = tempfile.mkdtemp(prefix=prefix, dir=parent)
    os.chmod(raw_dir, 0o700)
    if "," in raw_dir:
        shutil.rmtree(raw_dir, ignore_errors=True)
        raise BridgeError(500, "staging_error", "Staging path contains unsupported comma character.")
    return Path(raw_dir)


def _write_regular_file_exclusive(path: Path, data: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise BridgeError(500, "staging_error", "Staged target is not a regular file.")
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def stage_docker_workspace(
    *,
    staging_root: Path | None,
    candidate_files: Mapping[str, bytes],
    input_files: Mapping[str, bytes],
) -> tuple[Path, Path, dict[str, Path]]:
    """Materialize regular files only under a new owner-only directory."""
    stage_dir = _create_owner_only_tempdir("builder-host-stage-", staging_root)
    try:
        candidate_dir = stage_dir / "candidate"
        candidate_dir.mkdir(mode=0o755)
        os.chmod(candidate_dir, 0o755)

        for rel_path, content in candidate_files.items():
            clean = validate_relative_path(rel_path)
            parts = clean.split("/")
            cur = candidate_dir
            for part in parts[:-1]:
                cur = cur / part
                if cur.is_symlink():
                    raise BridgeError(500, "staging_error", "Unexpected symlink during staging.")
                if not cur.exists():
                    cur.mkdir(mode=0o755)
                    os.chmod(cur, 0o755)
                elif not cur.is_dir():
                    raise BridgeError(400, "path_collision", "Path collision during staging.")
            target = cur / parts[-1]
            _write_regular_file_exclusive(target, content, mode=0o644)

        input_paths: dict[str, Path] = {}
        if input_files:
            inputs_dir = stage_dir / "inputs"
            inputs_dir.mkdir(mode=0o755)
            os.chmod(inputs_dir, 0o755)
            for idx_key in sorted(input_files.keys(), key=int):
                target = inputs_dir / idx_key
                _write_regular_file_exclusive(target, input_files[idx_key], mode=0o644)
                input_paths[idx_key] = target

        return stage_dir, candidate_dir, input_paths
    except BaseException:
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise


@dataclass(frozen=True)
class HostBridgeConfig:
    host: str
    port: int
    token: str
    tls_cert: Path | None
    tls_key: Path | None
    claude_cli: Path | None
    verify_image: str | None
    docker_cli: Path | None
    staging_root: Path | None
    claude_timeout: int = DEFAULT_CLAUDE_TIMEOUT
    docker_timeout: int = DEFAULT_DOCKER_TIMEOUT
    max_output_bytes: int = MAX_CLI_OUTPUT_BYTES

    def validate(self, *, require_tls: bool = True, require_capability: bool = True) -> None:
        validate_token(self.token)
        min_port = 0 if self.host == "127.0.0.1" else 1
        if not (min_port <= self.port <= 65535):
            raise ValueError("BUILDER_HOST_PORT must be in 1..65535.")
        if not (1 <= self.claude_timeout <= MAX_CLAUDE_TIMEOUT):
            raise ValueError(f"BUILDER_HOST_CLAUDE_TIMEOUT must be in 1..{MAX_CLAUDE_TIMEOUT}.")
        if not (1 <= self.docker_timeout <= MAX_DOCKER_TIMEOUT):
            raise ValueError(f"BUILDER_HOST_DOCKER_TIMEOUT must be in 1..{MAX_DOCKER_TIMEOUT}.")
        if not (1024 <= self.max_output_bytes <= MAX_CLI_OUTPUT_BYTES):
            raise ValueError(f"BUILDER_HOST_MAX_OUTPUT_BYTES must be in 1024..{MAX_CLI_OUTPUT_BYTES}.")
        if require_tls:
            if self.tls_cert is None or self.tls_key is None:
                raise ValueError("BUILDER_HOST_TLS_CERT and BUILDER_HOST_TLS_KEY are required.")
            if not self.tls_cert.is_file() or not self.tls_key.is_file():
                raise ValueError("TLS certificate and key files must exist.")
        if self.claude_cli is not None:
            validate_executable_path(str(self.claude_cli), label="BUILDER_CLAUDE_CLI")
        if self.verify_image is not None:
            if not VERIFY_IMAGE_RE.fullmatch(self.verify_image):
                raise ValueError("BUILDER_VERIFY_IMAGE must match sha256:<64 lowercase hex>.")
            if self.docker_cli is None:
                raise ValueError("Docker CLI path is required when BUILDER_VERIFY_IMAGE is configured.")
            validate_executable_path(str(self.docker_cli), label="BUILDER_DOCKER_CLI")
        if self.staging_root is not None:
            validate_staging_root(str(self.staging_root))
        if require_capability and self.claude_cli is None and self.verify_image is None:
            raise ValueError("Configure BUILDER_CLAUDE_CLI and/or BUILDER_VERIFY_IMAGE.")

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        host: str | None = None,
        port: int | None = None,
        tls_cert: str | None = None,
        tls_key: str | None = None,
        claude_cli: str | None = None,
        verify_image: str | None = None,
        docker_cli: str | None = None,
        staging_root: str | None = None,
        require_tls: bool = True,
        require_capability: bool = True,
    ) -> HostBridgeConfig:
        env = os.environ if environ is None else environ
        eff_host = (host or env.get("BUILDER_HOST_BIND") or DEFAULT_HOST).strip()
        raw_port = str(port) if port is not None else env.get("BUILDER_HOST_PORT", str(DEFAULT_PORT))
        try:
            eff_port = int(raw_port)
        except ValueError:
            raise ValueError("BUILDER_HOST_PORT must be an integer.") from None

        token = validate_token(env.get("BUILDER_HOST_TOKEN"))

        eff_cert = tls_cert or env.get("BUILDER_HOST_TLS_CERT") or None
        eff_key = tls_key or env.get("BUILDER_HOST_TLS_KEY") or None
        eff_claude = claude_cli or env.get("BUILDER_CLAUDE_CLI") or None
        eff_image = verify_image or env.get("BUILDER_VERIFY_IMAGE") or None
        eff_staging = staging_root or env.get("BUILDER_STAGING_ROOT") or None

        eff_docker = docker_cli or env.get("BUILDER_DOCKER_CLI") or None
        if eff_image and not eff_docker:
            detected = shutil.which("docker")
            eff_docker = detected or "/usr/bin/docker"

        def _parse_int(name: str, default: int) -> int:
            raw = env.get(name)
            if raw is None or raw == "":
                return default
            try:
                return int(raw)
            except ValueError:
                raise ValueError(f"{name} must be an integer.") from None

        cfg = cls(
            host=eff_host,
            port=eff_port,
            token=token,
            tls_cert=Path(eff_cert) if eff_cert else None,
            tls_key=Path(eff_key) if eff_key else None,
            claude_cli=Path(eff_claude) if eff_claude else None,
            verify_image=eff_image,
            docker_cli=Path(eff_docker) if eff_docker else None,
            staging_root=Path(eff_staging) if eff_staging else None,
            claude_timeout=_parse_int("BUILDER_HOST_CLAUDE_TIMEOUT", DEFAULT_CLAUDE_TIMEOUT),
            docker_timeout=_parse_int("BUILDER_HOST_DOCKER_TIMEOUT", DEFAULT_DOCKER_TIMEOUT),
            max_output_bytes=_parse_int("BUILDER_HOST_MAX_OUTPUT_BYTES", MAX_CLI_OUTPUT_BYTES),
        )
        cfg.validate(require_tls=require_tls, require_capability=require_capability)
        return cfg


@dataclass
class _ContainerRecord:
    host_container: str
    state: str  # "running" | "removed" | "removal-failed"
    cancel_event: threading.Event


class HostBridgeService:
    """Core policy enforcement and host execution broker."""

    def __init__(
        self,
        config: HostBridgeConfig,
        *,
        runner: SubprocessRunner = run_bounded_subprocess,
    ) -> None:
        self.config = config
        self.runner = runner
        self._lock = threading.Lock()
        self._containers: OrderedDict[str, _ContainerRecord] = OrderedDict()

    def handle_healthz(self) -> tuple[int, dict[str, Any]]:
        return (
            200,
            {
                "ok": True,
                "claude_enabled": self.config.claude_cli is not None,
                "docker_enabled": self.config.verify_image is not None,
                "staging_root_configured": self.config.staging_root is not None,
            },
        )

    def handle_claude(self, payload: Any) -> tuple[int, dict[str, Any], str]:
        if self.config.claude_cli is None:
            raise BridgeError(503, "claude_disabled", "Claude host bridge is not configured.")
        invocation = parse_claude_request(payload, default_timeout=self.config.claude_timeout)

        # Always run in a fresh owner-only temporary directory so host workspace
        # CLAUDE.md / .claude / .mcp.json files can never be discovered.
        temp_parent = str(self.config.staging_root) if self.config.staging_root is not None else None
        with tempfile.TemporaryDirectory(prefix="builder-host-claude-", dir=temp_parent) as tmp_dir:
            os.chmod(tmp_dir, 0o700)
            claude_bin = str(self.config.claude_cli)
            if invocation.operation == "version":
                cmd = [claude_bin, "--version"]
            elif invocation.operation == "help":
                cmd = [claude_bin, "--help"]
            elif invocation.operation == "auth_status":
                cmd = [claude_bin, "auth", "status"]
            else:
                assert invocation.model is not None
                cmd = [
                    claude_bin,
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
                    invocation.model,
                ]
                if invocation.json_schema is not None:
                    cmd += ["--json-schema", invocation.json_schema]
                if invocation.settings is not None:
                    settings_path = Path(tmp_dir) / "settings.json"
                    _write_regular_file_exclusive(
                        settings_path,
                        json.dumps(invocation.settings, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                        mode=0o600,
                    )
                    cmd += ["--settings", str(settings_path)]

            result = self.runner(
                cmd,
                cwd=tmp_dir,
                env=sanitize_claude_env(),
                stdin_bytes=invocation.stdin.encode("utf-8") if invocation.stdin else b"",
                timeout_seconds=invocation.timeout_seconds,
                max_output_bytes=self.config.max_output_bytes,
            )

        body = {
            "ok": True,
            "exit_code": result.exit_code,
            "stdout": result.stdout.decode("utf-8", errors="replace"),
            "stderr": result.stderr.decode("utf-8", errors="replace"),
            "execution_status": result.execution_status,
            "elapsed_seconds": result.elapsed_seconds,
        }
        return 200, body, invocation.operation

    def _register_container(self, client_container: str) -> _ContainerRecord:
        with self._lock:
            if client_container in self._containers:
                raise BridgeError(409, "duplicate_container", "Container identifier was already used.")
            while len(self._containers) >= MAX_CONTAINER_HISTORY:
                evict_key = None
                for key, rec in self._containers.items():
                    if rec.state != "running":
                        evict_key = key
                        break
                if evict_key is None:
                    raise BridgeError(429, "too_many_active_containers", "Too many concurrent verification runs.")
                del self._containers[evict_key]
            record = _ContainerRecord(
                host_container="cog-verify-hb-" + uuid.uuid4().hex,
                state="running",
                cancel_event=threading.Event(),
            )
            self._containers[client_container] = record
            return record

    def _query_host_container_ps(self, host_container: str) -> SubprocessResult:
        assert self.config.docker_cli is not None
        return self.runner(
            [
                str(self.config.docker_cli),
                "ps",
                "-aq",
                "--filter",
                f"name=^/{host_container}$",
            ],
            cwd=None,
            env=sanitize_docker_env(),
            stdin_bytes=b"",
            timeout_seconds=min(15, READINESS_TIMEOUT),
            max_output_bytes=64 * 1024,
        )

    def _remove_host_container(self, host_container: str) -> bool:
        assert self.config.docker_cli is not None
        try:
            rm_res = self.runner(
                [str(self.config.docker_cli), "rm", "-f", host_container],
                cwd=None,
                env=sanitize_docker_env(),
                stdin_bytes=b"",
                timeout_seconds=min(15, READINESS_TIMEOUT),
                max_output_bytes=64 * 1024,
            )
        except BridgeError:
            return False
        if rm_res.execution_status == "exited" and rm_res.exit_code == 0:
            return True
        # If container was already removed (e.g. run finally raced with explicit rm),
        # succeed only when a real filtered docker ps query confirms it is absent.
        try:
            ps_res = self._query_host_container_ps(host_container)
        except BridgeError:
            return False
        return (
            ps_res.execution_status == "exited"
            and ps_res.exit_code == 0
            and ps_res.stdout.strip() == b""
        )

    def handle_docker(self, payload: Any) -> tuple[int, dict[str, Any], str]:
        if self.config.verify_image is None or self.config.docker_cli is None:
            raise BridgeError(503, "docker_disabled", "Docker verification host bridge is not configured.")
        invocation = parse_docker_request(payload, default_timeout=self.config.docker_timeout)
        if isinstance(invocation, (DockerInspectInvocation, DockerRunInvocation)):
            if invocation.requested_image.rsplit('@', 1)[-1] != self.config.verify_image:
                raise BridgeError(400, 'image_mismatch', 'The requested image differs from the qualified host image.')

        if isinstance(invocation, DockerInspectInvocation):
            # Never pass requested_image to Docker; always inspect the host's pinned digest.
            result = self.runner(
                [
                    str(self.config.docker_cli),
                    "image",
                    "inspect",
                    "--format",
                    DOCKER_INSPECT_FORMAT,
                    self.config.verify_image,
                ],
                cwd=None,
                env=sanitize_docker_env(),
                stdin_bytes=b"",
                timeout_seconds=min(15, READINESS_TIMEOUT),
                max_output_bytes=64 * 1024,
            )
            if result.execution_status != "exited" or result.exit_code != 0:
                return (
                    200,
                    {
                        "ok": True,
                        "exit_code": result.exit_code if result.exit_code != 0 else 1,
                        "stdout": "",
                        "stderr": "Pinned verification image inspection failed.\n",
                        "execution_status": result.execution_status,
                        "elapsed_seconds": result.elapsed_seconds,
                    },
                    "image_inspect",
                )
            identity = result.stdout.decode("utf-8", errors="replace").strip()
            if not INSPECT_OUTPUT_RE.fullmatch(identity):
                return (
                    200,
                    {
                        "ok": True,
                        "exit_code": 1,
                        "stdout": "",
                        "stderr": "Pinned verification image identity is not a Linux immutable sha256 image.\n",
                        "execution_status": "exited",
                        "elapsed_seconds": result.elapsed_seconds,
                    },
                    "image_inspect",
                )
            return (
                200,
                {
                    "ok": True,
                    "exit_code": 0,
                    "stdout": identity + "\n",
                    "stderr": "",
                    "execution_status": "exited",
                    "elapsed_seconds": result.elapsed_seconds,
                },
                "image_inspect",
            )

        if isinstance(invocation, DockerPsInvocation):
            with self._lock:
                record = self._containers.get(invocation.container)
            if record is None:
                raise BridgeError(404, "unknown_container", "Container was not created by this bridge.")
            result = self._query_host_container_ps(record.host_container)
            return (
                200,
                {
                    "ok": True,
                    "exit_code": result.exit_code,
                    "stdout": result.stdout.decode("utf-8", errors="replace"),
                    "stderr": result.stderr.decode("utf-8", errors="replace"),
                    "execution_status": result.execution_status,
                    "elapsed_seconds": result.elapsed_seconds,
                },
                "ps",
            )

        if isinstance(invocation, DockerRmInvocation):
            with self._lock:
                record = self._containers.get(invocation.container)
            if record is None:
                # The native supervisor can time out while the Python shim is
                # still starting. Register a cancellation tombstone so a late
                # request with this identity cannot start after cleanup.
                try:
                    record = self._register_container(invocation.container)
                except BridgeError as exc:
                    if exc.code != 'duplicate_container':
                        raise
                    with self._lock:
                        record = self._containers[invocation.container]
            # Signal any in-flight docker run immediately without blocking on it,
            # then invoke real docker rm -f / absence check on the host container.
            record.cancel_event.set()
            removed = self._remove_host_container(record.host_container)
            with self._lock:
                record.state = "removed" if removed else "removal-failed"
            return (
                200,
                {
                    "ok": True,
                    "exit_code": 0 if removed else 1,
                    "stdout": "",
                    "stderr": "" if removed else "Container removal failed.\n",
                    "execution_status": "exited",
                    "elapsed_seconds": 0.0,
                },
                "rm",
            )

        # DockerRunInvocation
        record = self._register_container(invocation.container)
        stage_dir: Path | None = None
        try:
            stage_dir, candidate_dir, input_paths = stage_docker_workspace(
                staging_root=self.config.staging_root,
                candidate_files=invocation.candidate_files,
                input_files=invocation.input_files,
            )
            mounts: list[str] = [
                "--mount",
                f"type=bind,src={candidate_dir},dst=/candidate,readonly",
            ]
            for idx_key in sorted(input_paths.keys(), key=int):
                mounts += [
                    "--mount",
                    f"type=bind,src={input_paths[idx_key]},dst=/inputs/{idx_key},readonly",
                ]

            # Never pass requested_image or client host paths; enforce fixed policy.
            docker_argv = [
                str(self.config.docker_cli),
                "run",
                "--name",
                record.host_container,
                *DOCKER_FIXED_RUN_POLICY_ARGS,
                '--label', 'cogcloud.builder-verifier=true',
                *mounts,
                "--entrypoint",
                "python",
                self.config.verify_image,
                *invocation.python_argv,
            ]
            result = self.runner(
                docker_argv,
                cwd=None,
                env=sanitize_docker_env(),
                stdin_bytes=b"",
                timeout_seconds=invocation.timeout_seconds,
                max_output_bytes=self.config.max_output_bytes,
                cancel_event=record.cancel_event,
            )
        finally:
            removed = self._remove_host_container(record.host_container)
            for _ in range(2):
                if removed:
                    break
                removed = self._remove_host_container(record.host_container)
            with self._lock:
                if removed:
                    record.state = "removed"
                elif record.state != "removed":
                    record.state = "removal-failed"
            if stage_dir is not None:
                shutil.rmtree(stage_dir, ignore_errors=True)

        return (
            200,
            {
                "ok": True,
                "exit_code": result.exit_code if removed else 1,
                "stdout": result.stdout.decode("utf-8", errors="replace"),
                "stderr": result.stderr.decode("utf-8", errors="replace") if removed else 'Verification container cleanup failed.',
                "execution_status": result.execution_status if removed else 'cleanup-failed',
                "elapsed_seconds": result.elapsed_seconds,
            },
            "run",
        )

    def cleanup_abandoned(self) -> None:
        """Recover only this bridge's labelled verification containers at startup."""
        if self.config.verify_image is None:
            return
        result = self.runner([str(self.config.docker_cli), 'ps', '-aq', '--filter',
                              'label=cogcloud.builder-verifier=true'], cwd=None,
                             env=sanitize_docker_env(), stdin_bytes=b'', timeout_seconds=15,
                             max_output_bytes=65536)
        if result.exit_code != 0:
            raise ValueError('Cannot inspect abandoned verifier containers.')
        for ident in result.stdout.decode().split():
            if not re.fullmatch(r'[a-f0-9]{12,64}', ident):
                raise ValueError('Unexpected verifier container identity.')
            if not self._remove_host_container(ident):
                raise ValueError('Cannot remove an abandoned verifier container.')
        if self.config.staging_root:
            for path in self.config.staging_root.glob('builder-host-stage-*'):
                if path.is_symlink() or not path.is_dir():
                    raise ValueError('Unexpected staging path during startup cleanup.')
                shutil.rmtree(path)

    def qualify(
        self,
        *,
        require_claude: bool = False,
        require_docker: bool = False,
        probe_docker: bool = False,
    ) -> dict[str, Any]:
        """Run non-destructive host bridge qualification checks; report refusal not fallback."""
        checks: list[dict[str, Any]] = []

        def _add(name: str, passed: bool, detail: str, **extra: Any) -> None:
            entry: dict[str, Any] = {"check": name, "passed": passed, "detail": detail}
            entry.update(extra)
            checks.append(entry)

        # 1. TLS configuration check
        if self.config.tls_cert and self.config.tls_key:
            try:
                build_server_ssl_context(self.config.tls_cert, self.config.tls_key)
                _add("tls", True, "Server TLS certificate and key loaded (TLS 1.2+).")
            except (OSError, ssl.SSLError, ValueError) as exc:
                _add("tls", False, f"TLS configuration invalid: {type(exc).__name__}.")
        else:
            _add("tls", False, "TLS certificate and key are not configured.")

        # 2. Staging root check (if configured)
        if self.config.staging_root is not None:
            try:
                validate_staging_root(str(self.config.staging_root))
                probe_dir = _create_owner_only_tempdir("builder-host-qualify-", self.config.staging_root)
                shutil.rmtree(probe_dir)
                _add("staging_root", True, "Dedicated staging root is writable and non-symlink.")
            except (OSError, ValueError) as exc:
                _add("staging_root", False, f"Staging root unusable: {type(exc).__name__}.")

        # 3. Claude CLI checks
        if self.config.claude_cli is not None:
            try:
                _, ver_body, _ = self.handle_claude({"argv": ["--version"], "stdin": ""})
                ver_ok = ver_body["exit_code"] == 0 and bool(ver_body["stdout"].strip())
                _add(
                    "claude_version",
                    ver_ok,
                    "Claude CLI version inspected." if ver_ok else "Claude CLI --version failed.",
                    version=ver_body["stdout"].strip()[:120] if ver_ok else None,
                )
            except BridgeError as exc:
                _add("claude_version", False, f"Refused: {exc.code}.")

            try:
                _, help_body, _ = self.handle_claude({"argv": ["--help"], "stdin": ""})
                help_text = help_body["stdout"]
                missing = [flag for flag in REQUIRED_CLAUDE_HELP_FLAGS if flag not in help_text]
                help_ok = help_body["exit_code"] == 0 and not missing
                _add(
                    "claude_help_controls",
                    help_ok,
                    "All required cog-claude safety flags present."
                    if help_ok
                    else "Claude CLI is missing required safety flags; refusal without fallback.",
                    missing_flags=missing,
                )
            except BridgeError as exc:
                _add("claude_help_controls", False, f"Refused: {exc.code}.")

            try:
                _, auth_body, _ = self.handle_claude({"argv": ["auth", "status"], "stdin": ""})
                auth_ok = False
                auth_method = None
                if auth_body["exit_code"] == 0:
                    try:
                        auth_json = _strict_json_loads(auth_body["stdout"])
                        if isinstance(auth_json, dict):
                            auth_method = auth_json.get("authMethod")
                            auth_ok = auth_json.get("loggedIn") is True and auth_method == "claude.ai"
                    except ValueError:
                        auth_ok = False
                _add(
                    "claude_subscription_auth",
                    auth_ok,
                    "Claude subscription login verified (claude.ai)."
                    if auth_ok
                    else "Claude subscription login unavailable or not claude.ai; no API-key fallback.",
                    auth_method=auth_method if isinstance(auth_method, str) else None,
                )
            except BridgeError as exc:
                _add("claude_subscription_auth", False, f"Refused: {exc.code}.")
        elif require_claude:
            _add("claude_cli", False, "BUILDER_CLAUDE_CLI is not configured.")

        # 4. Docker verification checks
        if self.config.verify_image is not None and self.config.docker_cli is not None:
            try:
                _, inspect_body, _ = self.handle_docker(
                    {"operation": "image_inspect", "requested_image": self.config.verify_image}
                )
                inspect_ok = inspect_body["exit_code"] == 0 and bool(
                    INSPECT_OUTPUT_RE.fullmatch(inspect_body["stdout"].strip())
                )
                _add(
                    "docker_pinned_image",
                    inspect_ok,
                    "Pinned Linux verification image inspected."
                    if inspect_ok
                    else "Pinned verification image unavailable; refusal without host fallback.",
                    image_identity=inspect_body["stdout"].strip() if inspect_ok else None,
                )
            except BridgeError as exc:
                _add("docker_pinned_image", False, f"Refused: {exc.code}.")

            if probe_docker:
                probe_script = (
                    "import os, socket\n"
                    "from pathlib import Path\n"
                    "assert os.getuid() == 65534\n"
                    "assert Path('/sys/fs/cgroup/memory.max').read_text().strip() == '268435456'\n"
                    "assert Path('/sys/fs/cgroup/pids.max').read_text().strip() == '64'\n"
                    "quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split(); assert int(quota) == int(period)\n"
                    "status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)\n"
                    "assert int(status['CapEff'].strip(), 16) == 0 and status['NoNewPrivs'].strip() == '1'\n"
                    "assert not Path('/var/run/docker.sock').exists()\n"
                    "assert not any(key.startswith(('BUILDER_', 'ANTHROPIC_', 'OPENROUTER_')) for key in os.environ)\n"
                    "try:\n"
                    "    Path('/candidate/mutated').write_text('no')\n"
                    "    raise AssertionError('candidate writable')\n"
                    "except OSError:\n"
                    "    pass\n"
                    "Path('/tmp/ok').write_text('ok')\n"
                    "for address, port in [('1.1.1.1', 443), ('172.30.0.20', 9443), ('172.30.0.21', 9443)]:\n"
                    "    with socket.socket() as s:\n"
                    "        s.settimeout(0.2)\n"
                    "        try: s.connect((address, port))\n"
                    "        except OSError: pass\n"
                    "        else: raise AssertionError('network reachable')\n"
                    "print('confined')\n"
                )
                try:
                    _, run_body, _ = self.handle_docker(
                        {
                            "operation": "run",
                            "container": "cog-verify-" + uuid.uuid4().hex,
                            "requested_image": self.config.verify_image,
                            "python_argv": ["probe.py"],
                            "candidate_files": {
                                "probe.py": base64.b64encode(probe_script.encode("utf-8")).decode("ascii"),
                            },
                            "input_files": {},
                            "timeout_seconds": 15,
                        }
                    )
                    probe_ok = run_body["exit_code"] == 0 and "confined" in run_body["stdout"]
                    _add(
                        "docker_confinement_probe",
                        probe_ok,
                        "Container confinement probe succeeded."
                        if probe_ok
                        else "Container confinement probe failed; refusal without fallback.",
                    )
                except BridgeError as exc:
                    _add("docker_confinement_probe", False, f"Refused: {exc.code}.")
        elif require_docker:
            _add("docker_verify_image", False, "BUILDER_VERIFY_IMAGE is not configured.")

        overall_ok = bool(checks) and all(item["passed"] for item in checks)
        return {"ok": overall_ok, "checks": checks}


def build_server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


class HostBridgeHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        service: HostBridgeService,
    ) -> None:
        self.service = service
        super().__init__(server_address, _HostBridgeRequestHandler)


class _HostBridgeRequestHandler(BaseHTTPRequestHandler):
    server_version = "builder-host-bridge"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_SOCKET_TIMEOUT)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Suppress default BaseHTTPRequestHandler logging so raw paths/queries
        # or client input are never written to logs.
        return

    def _route_name(self) -> str:
        if self.path == "/healthz":
            return "healthz"
        if self.path == "/cli/claude":
            return "claude"
        if self.path == "/cli/docker":
            return "docker"
        return "unknown"

    def _audit(self, *, method: str, route: str, op: str, status: int, detail: str = "") -> None:
        logger.info(
            "bridge_request method=%s route=%s op=%s status=%d detail=%s",
            method,
            route,
            op,
            status,
            detail,
        )

    def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def _check_auth(self) -> bool:
        expected = self.server.service.config.token  # type: ignore[attr-defined]
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return False
        presented = auth_header[7:]
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))

    def _read_json_body(self, *, max_bytes: int) -> Any:
        if self.headers.get("Transfer-Encoding"):
            raise BridgeError(411, "chunked_unsupported", "Chunked transfer encoding is not supported.")
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise BridgeError(415, "unsupported_media_type", "Content-Type must be application/json.")
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise BridgeError(411, "length_required", "Content-Length header is required.")
        try:
            length = int(raw_len)
        except ValueError:
            raise BridgeError(400, "invalid_content_length", "Invalid Content-Length header.") from None
        if length < 0 or length > max_bytes:
            raise BridgeError(413, "body_too_large", "Request body exceeds maximum allowed size.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise BridgeError(400, "incomplete_body", "Incomplete request body.")
        try:
            return _strict_json_loads(body)
        except (UnicodeDecodeError, ValueError):
            raise BridgeError(400, "invalid_json", "Request body must be valid UTF-8 JSON.") from None

    def do_GET(self) -> None:  # noqa: N802
        route = self._route_name()
        if route != "healthz":
            status = 405 if route in ("claude", "docker") else 404
            self._audit(method="GET", route=route, op="none", status=status, detail="route_or_method")
            self._send_json(status, {"ok": False, "error": "Not allowed."})
            return
        if not self._check_auth():
            self._audit(method="GET", route=route, op="healthz", status=401, detail="unauthorized")
            self._send_json(401, {"ok": False, "error": "Unauthorized."})
            return
        status, body = self.server.service.handle_healthz()  # type: ignore[attr-defined]
        self._audit(method="GET", route=route, op="healthz", status=status)
        self._send_json(status, body)

    def do_POST(self) -> None:  # noqa: N802
        route = self._route_name()
        if route not in ("claude", "docker"):
            status = 405 if route == "healthz" else 404
            self._audit(method="POST", route=route, op="none", status=status, detail="route_or_method")
            self._send_json(status, {"ok": False, "error": "Not allowed."})
            return
        # Authenticate before reading request body.
        if not self._check_auth():
            self._audit(method="POST", route=route, op="none", status=401, detail="unauthorized")
            self._send_json(401, {"ok": False, "error": "Unauthorized."})
            return

        max_body = MAX_CLAUDE_REQUEST_BYTES if route == "claude" else MAX_DOCKER_REQUEST_BYTES
        op = "unknown"
        try:
            payload = self._read_json_body(max_bytes=max_body)
            if route == "claude":
                status, body, op = self.server.service.handle_claude(payload)  # type: ignore[attr-defined]
            else:
                status, body, op = self.server.service.handle_docker(payload)  # type: ignore[attr-defined]
            self._audit(
                method="POST",
                route=route,
                op=op,
                status=status,
                detail=f"rc={body.get('exit_code')} state={body.get('execution_status')}",
            )
            self._send_json(status, body)
        except BridgeError as exc:
            self._audit(method="POST", route=route, op=op, status=exc.status_code, detail=exc.code)
            self._send_json(exc.status_code, {"ok": False, "code": exc.code, "error": exc.message})
        except Exception:
            self._audit(method="POST", route=route, op=op, status=500, detail="internal_error")
            self._send_json(500, {"ok": False, "code": "internal_error", "error": "Internal host bridge error."})

    def _reject_other_method(self) -> None:
        route = self._route_name()
        self._audit(method="OTHER", route=route, op="none", status=405, detail="method_not_allowed")
        self._send_json(405, {"ok": False, "error": "Method not allowed."})

    do_PUT = _reject_other_method  # noqa: N815
    do_DELETE = _reject_other_method  # noqa: N815
    do_PATCH = _reject_other_method  # noqa: N815
    do_HEAD = _reject_other_method  # noqa: N815
    do_OPTIONS = _reject_other_method  # noqa: N815


def create_server(
    config: HostBridgeConfig,
    *,
    service: HostBridgeService | None = None,
    require_tls: bool = True,
) -> HostBridgeHTTPServer:
    config.validate(require_tls=require_tls, require_capability=True)
    svc = service or HostBridgeService(config)
    server = HostBridgeHTTPServer((config.host, config.port), svc)
    if require_tls:
        assert config.tls_cert is not None and config.tls_key is not None
        ssl_ctx = build_server_ssl_context(config.tls_cert, config.tls_key)
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="builder-host-bridge",
        description="Strictly bounded host-services HTTPS bridge for Builder workspaces.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("serve", "qualify"):
        sp = sub.add_parser(name)
        sp.add_argument("--host", default=None, help="Bind address (default: BUILDER_HOST_BIND or 127.0.0.1)")
        sp.add_argument("--port", type=int, default=None, help="Bind port (default: BUILDER_HOST_PORT or 9443)")
        sp.add_argument("--tls-cert", default=None, help="Path to TLS certificate PEM")
        sp.add_argument("--tls-key", default=None, help="Path to TLS private key PEM")
        sp.add_argument("--claude-cli", default=None, help="Fixed host path to native claude executable")
        sp.add_argument("--verify-image", default=None, help="Pinned Docker verification image (sha256:64hex)")
        sp.add_argument("--docker-cli", default=None, help="Fixed host path to docker executable")
        sp.add_argument("--staging-root", default=None, help="Dedicated staging directory (BUILDER_STAGING_ROOT)")
        if name == "qualify":
            sp.add_argument("--require-claude", action="store_true", help="Fail if Claude CLI is not configured")
            sp.add_argument("--require-docker", action="store_true", help="Fail if verification image is not configured")
            sp.add_argument("--probe-docker", action="store_true", help="Run a short confinement probe container")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        config = HostBridgeConfig.from_env(
            host=args.host,
            port=args.port,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
            claude_cli=args.claude_cli,
            verify_image=args.verify_image,
            docker_cli=args.docker_cli,
            staging_root=args.staging_root,
            require_tls=(args.command == "serve"),
            require_capability=(args.command == "serve"),
        )
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2

    service = HostBridgeService(config)

    if args.command == "qualify":
        report = service.qualify(
            require_claude=args.require_claude,
            require_docker=args.require_docker,
            probe_docker=args.probe_docker,
        )
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1

    try:
        service.cleanup_abandoned()
    except (ValueError, BridgeError):
        print(json.dumps({'ok': False, 'error': 'Verifier startup cleanup failed.'}), file=sys.stderr)
        return 2
    server = create_server(config, service=service, require_tls=True)

    def _shutdown_handler(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    logger.info(
        "bridge_started host=%s port=%d claude_enabled=%s docker_enabled=%s staging_root=%s",
        config.host,
        config.port,
        config.claude_cli is not None,
        config.verify_image is not None,
        config.staging_root is not None,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
