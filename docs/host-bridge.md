# Host-services bridge

The host-services bridge (`builder_hub.host_bridge` and `builder_hub.cli_bridge`)
isolates two privileged host capabilities behind a narrow, fail-closed HTTPS
broker so the Kubernetes Builder workspace pod never receives vendor credentials
or the Docker socket:

1. **Native Claude subscription turns (`POST /cli/claude`)**: reuses the host's
   existing vendor-owned `claude` CLI and subscription login without copying
   credentials into Kubernetes or modifying upstream `cog-claude`.
2. **Pinned Docker candidate verification (`POST /cli/docker`)**: executes the
   exact container confinement policy from upstream
   `cog-verify-candidate/src/isolated_execution.py` without exposing the Docker
   socket or arbitrary `docker` commands to the workspace.

## Deployment topology

Two separate trusted containers run on the existing kind Docker network:

- `builder-claude-service` at `172.30.0.20:9443` receives the native Claude
  executable read-only and its vendor-owned `~/.claude` and `~/.claude.json`
  stores read-write, as required for native token refresh. This includes vendor
  session/configuration history; it remains confined to the private provider
  service. It receives no Docker socket, Docker group or verifier credential.
- `builder-verify-service` at `172.30.0.21:9443` receives the real Docker CLI and
  socket, and no vendor store or Claude credential. It gets a dedicated staging
  directory mounted at the **identical absolute path** on
  the host and inside the bridge container, configured via
  `BUILDER_STAGING_ROOT`, so host Docker can resolve bind-mount sources staged
  by the bridge.

The two services have distinct internal tokens and private secret directories.
The model subprocess cannot read the verifier's Docker socket or secrets.

Inside the Kubernetes workspace pod, thin executable wrappers at
`/usr/local/bin/claude` and `/usr/local/bin/docker` invoke:

```sh
exec /var/collab-hub-api/.venv/bin/python -m builder_hub.cli_bridge claude "$@"
```

and

```sh
exec /var/collab-hub-api/.venv/bin/python -m builder_hub.cli_bridge docker "$@"
```

`cli_bridge.py` also supports `argv[0]` dispatch when invoked directly via a
wrapper or symlink whose basename is `claude` or `docker`.

## Security boundary

### Transport, authentication, and logging

- **TLS 1.2+ required**: `serve` mode requires `BUILDER_HOST_TLS_CERT` and
  `BUILDER_HOST_TLS_KEY` (with SAN covering the bridge IP, e.g.
  `IP:172.30.0.20`). The CLI shim requires `https://` URLs; plaintext `http://`
  is refused everywhere except literal `http://127.0.0.1:<port>` for local unit
  tests. Certificate verification and hostname checking are never disabled.
- **Constant-time bearer auth**: every endpoint (`GET /healthz`,
  `POST /cli/claude`, `POST /cli/docker`) requires
  `Authorization: Bearer <token>` verified with `hmac.compare_digest` before
  reading request bodies. `BUILDER_HOST_TOKEN` must be at least 32 characters
  with no control characters. HTTP redirects are refused so the bearer token
  cannot be leaked.
- **No user input in logs**: default HTTP request logging is suppressed. Audit
  entries log only static method, route name, operation kind, HTTP status,
  exit code, and status/error code — never prompts, argv payloads, tokens, file
  contents, or stdout/stderr.

### `POST /cli/claude` policy

Only exact upstream `cog-claude/src/turn_runtime.py` invocations are accepted:

- `["--version"]` (no stdin, readiness timeout cap `<= 30s`)
- `["--help"]` (no stdin, readiness timeout cap `<= 30s`)
- `["auth", "status"]` (no stdin, readiness timeout cap `<= 30s`)
- Tool-free print JSON turn (`-p`) with every required safety control:
  `--safe-mode`, `--setting-sources ""`, `--strict-mcp-config`,
  `--mcp-config '{"mcpServers":{}}'`, `--tools ""`,
  `--disallowedTools "mcp__*"`, `--permission-mode dontAsk`,
  `--no-session-persistence`, `--output-format json`,
  `--model <MODEL_ID>` (validated against `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`),
  and optional `--json-schema <OBJECT_SCHEMA>` (local `$ref` only).

Additional controls:

- Arbitrary flags, permission escalations (`--dangerously-skip-permissions`,
  `--allowedTools`, etc.), positional prompts, and `--fallback-model` are
  rejected; the host never substitutes another model.
- If a compatible caller passes `--settings <temp_json_path>`, `cli_bridge`
  reads the regular file within allowed workspace roots (`<= 64 KiB`, no
  symlinks) and sends `settings_b64` without forwarding workspace paths. The
  host validates that only safe empty/disabling keys are present (`mcpServers`,
  `hooks`, `enabledPlugins`, `permissions` with empty `allow`/`ask` and
  `defaultMode: "dontAsk"`) and writes a canonical host-controlled `0600`
  settings file. Passing `--settings` directly in `/cli/claude` `argv` is
  rejected.
- Host execution uses an empty owner-only (`0700`) temporary working directory
  and a strict environment allowlist that preserves vendor-owned `HOME` /
  `CLAUDE_CONFIG_DIR` while stripping API keys, base URLs, cloud provider
  switches, proxy overrides, and `BUILDER_HOST_TOKEN`.
- Stdin and combined stdout+stderr are bounded (`<= 2 MiB`), execution timeout
  is capped at `<= 660s`, and timeouts or output overruns kill the entire
  subprocess process group (`SIGKILL`) and return exit code `124`.

### `POST /cli/docker` policy

`cli_bridge` never proxies arbitrary `docker` commands or the Docker API. It
parses only the exact invocations emitted by public
`cog-verify-candidate/src/isolated_execution.py` and its qualification test
(`cog-verify-candidate/tests/test_isolation.py`):

1. `docker image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' <image>`
   - Host requires the requested digest to match `BUILDER_VERIFY_IMAGE`, then
     inspects only that configured immutable image
     (`sha256:<64hex>`).
   - Host verifies output matches `^sha256:[a-f0-9]{64} linux [A-Za-z0-9_.-]+$`
     and fails closed otherwise.
2. `docker run` with the exact fixed confinement flags:
   `--name cog-verify-<32hex> --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --cpus 1 --memory 256m --memory-swap 256m --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=64m --workdir /candidate --env PYTHONDONTWRITEBYTECODE=1 --env HOME=/tmp`,
   readonly `/candidate` mount, optional readonly `/inputs/<N>` mounts,
   `--entrypoint python`, pinned image digest, and declared Python arguments.
   - Workspace shim confines file collection to subdirectories/files strictly
     inside `workspace_root` (default `/opt/builder-suite`). Native verification
     copies temporary inputs into workspace state before invoking Docker. It
     rejects symlinks, `.git`, `.pixi`, special files, parent traversal, and
     inputs exceeding `8 MiB` total.
   - Protocol uses an explicit relative regular-file map (`candidate_files`,
     `input_files`) and rejects archives or host paths.
   - Host creates a fresh `0700` directory under `BUILDER_STAGING_ROOT`,
     reconstructs only validated relative regular files (`O_CREAT | O_EXCL | O_NOFOLLOW`)
     with `0755` staging subdirectories and `0644` files so container UID
     `65534:65534` can read mounted files (even when workspace inputs were
     mode `0600`), runs `BUILDER_VERIFY_IMAGE` under a bridge-owned container
     name (`cog-verify-hb-<32hex>`), caps runtime (`<= 600s`) and combined
     output (`<= 2 MiB`), and always removes both container and staging
     directory in `finally`.
3. `docker rm -f cog-verify-<32hex>`
   - Creates a cancellation tombstone if the native supervisor timed out before
     the request reached the bridge. A late run with that identity is refused.
   - Signals the running `run` operation concurrently without serializing behind
     the run lock, kills/removes the bridge-owned host container, and verifies
     actual absence via a real filtered `docker ps` query before returning `0`
     on repeated removal.
4. `docker ps -aq --filter name=^/cog-verify-<32hex>$`
   - Allowed only for bridge-owned container names; runs a real host
     `docker ps -aq --filter name=^/<host_container>$` query and returns actual
     Docker output without faking empty results.

## Configuration

### Host bridge environment (`python -m builder_hub.host_bridge`)

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `BUILDER_HOST_BIND` | No | `127.0.0.1` | Bind IP (e.g. `172.30.0.20` or `0.0.0.0` in the dedicated bridge container) |
| `BUILDER_HOST_PORT` | No | `9443` | HTTPS port |
| `BUILDER_HOST_TOKEN` | Yes | — | Internal bearer token (`>= 32` chars) |
| `BUILDER_HOST_TLS_CERT` | Yes (`serve`) | — | Server TLS certificate PEM |
| `BUILDER_HOST_TLS_KEY` | Yes (`serve`) | — | Server TLS private key PEM |
| `BUILDER_CLAUDE_CLI` | Conditional | — | Fixed absolute path to native `claude` binary |
| `BUILDER_VERIFY_IMAGE` | Conditional | — | Pinned verification image ID (`sha256:<64hex>`) |
| `BUILDER_DOCKER_CLI` | No | `which docker` | Fixed absolute path to `docker` CLI |
| `BUILDER_STAGING_ROOT` | Recommended | system temp | Dedicated non-symlink directory mounted identically on host and bridge container |
| `BUILDER_HOST_CLAUDE_TIMEOUT` | No | `600` | Default Claude timeout (`1..660` seconds) |
| `BUILDER_HOST_DOCKER_TIMEOUT` | No | `240` | Default Docker run timeout (`1..600` seconds) |
| `BUILDER_HOST_MAX_OUTPUT_BYTES` | No | `2097152` | Combined stdout+stderr cap (`1024..2097152` bytes) |

### Workspace client config (`builder_hub.cli_bridge`)

Upstream `cog-claude/src/turn_runtime.py` scrubs `BUILDER_*` and
`SSL_CERT_FILE` in `clean_env()`. Therefore the shim reads a mounted read-only
Kubernetes Secret JSON file at `/etc/builder-host/client.json` (mode `0440`) by
default:

```json
{
  "url": "https://172.30.0.20:9443",
  "token": "<at-least-32-character-internal-token>",
  "docker_url": "https://172.30.0.21:9443",
  "docker_token": "<distinct-verifier-token>",
  "ca_file": "/etc/builder-host/ca.crt",
  "workspace_root": "/opt/builder-suite"
}
```

For tests or parent tooling, `BUILDER_HOST_CONFIG` overrides the JSON config
file path, and `BUILDER_HOST_URL`, `BUILDER_HOST_TOKEN`, `SSL_CERT_FILE`, and
`BUILDER_WORKSPACE_ROOT` are honored when present. Default `ca_file` falls back
to `/etc/builder-host/ca.crt` when present.

## Qualification and running

Run non-destructive qualification checks on the host bridge before serving
traffic (reports explicit refusal with exit code `1` on any missing safety
control, API-key-only Claude auth, or unavailable pinned Linux image — never
falls back):

```sh
python3 -m builder_hub.host_bridge qualify --require-claude --require-docker --probe-docker
```

Start the HTTPS host bridge:

```sh
python3 -m builder_hub.host_bridge serve
```

Run the unit and security-boundary tests (uses mocked host processes only; no
credentials, live model calls, or live Docker daemon required):

```sh
pytest tests/test_host_bridge.py
```
