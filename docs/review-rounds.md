# Model review evidence

Implemented by Codex GPT-6.1-Sol, Claude Opus 5.5 and Gemini 4 Neon, according to
the coordinating session and delegated worker evidence. Claude implemented the
Hub session/proxy extension. Gemini implemented the host services bridge and
CLI adapter and reviewed the initial architecture. Codex integrated deployment,
persistence, policy enforcement, qualification and review fixes.

## Round 1 — workspace and deployment

Reviewer: Claude Opus 5.5 (`claude-opus-5-5`).
Reviewed commit: `b0374c74f1c741e3a10a6ce8b17e6d392587daef`.
Date: 2026-11-24 UTC. Verdict: **CHANGES REQUESTED**.
Scope excluded the Claude-authored Hub proxy and incomplete Gemini bridge.
Validation: 124 unit tests passed on the archived commit and focused probes.
No live cluster, Docker build or model calls were performed by the reviewer.

Findings and implementation disposition:

1. TLS handshake could block the accept loop. Moved handshake to timed handler
   threads in both services and added idle-connection regression tests.
2. Missing qualification could select native trusted-local default. Injected
   an explicitly unavailable Docker image, enforce exact qualified image on the
   bridge, and refuse unqualified acceptance/resume. Added override tests.
3. Persistent execution files lacked image integrity checks. Added complete
   source/environment inventories, checks before PVC code execution, and an
   explicit trusted-image refresh that preserves runtime state.
4. Image context included uncommitted files. Build now refuses dirty trees,
   archives the exact commit, and records revision/base image labels.
5. Bridge implementation/wiring was incomplete. Gemini supplied the bridge and
   tests. Host defaults now match the dedicated Docker network address.
6. Hosted Suite overrides lacked tests. Added boundary tests for package
   destinations, trusted execution, policies, continuation and persistence.

Additional fixes include reserved package names, server-side model selection,
binding revision handling, resumable initialization, bounded in-memory jobs,
byte-wise credential comparisons and a file-based workspace service token.

These dispositions require subsequent review and live qualification. They do
not convert the reviewed commit into a PASS. Human merge decision remains pending.
