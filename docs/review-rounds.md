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

## Round 2 — cross-component review

Reviewed head: `4fdc9203a75af6e770d6dc272008145a2cc24d62`.
Reviewed parent/base: `b0374c74f1c741e3a10a6ce8b17e6d392587daef`.
PR base: `d0b43f11b9bb47e82daaade4d60eb6392e46d2bc`.
Date: 2026-11-24 UTC. Both verdicts: **CHANGES REQUESTED**.

Claude Opus 5.5 reviewed the Gemini bridge and Codex integration, excluding its
own Hub proxy. Gemini 4 Neon reviewed the Claude/Codex Hub and workspace boundary,
excluding its own bridge. Each ran 177 tests against archived source; neither
performed live deployment/model tests or claimed a human review.

Dispositions in the subsequent implementation:

* Split Claude and verifier into separate containers, internal tokens, TLS
  credentials and mounts. The Claude process has no Docker socket/group or
  verifier credential. Corrected the vendor-store documentation to describe
  read-write native refresh and the vendor history visible to its provider.
* Reject symlinked package/runtime/marker targets before filesystem operations,
  and clear partial source entries before resuming copies containing environment
  symlinks. Added interruption and escape regressions.
* Close connections on all proxy refusals that may leave request bodies unread.
* Move page tokens to metadata. The Hub now renders only its own immutable Studio
  assets, accepting only validated token/qualification metadata from the workspace.
  Arbitrary workspace scripts/styles are discarded and tested as hostile input.
* Add cancellation tombstones for timeouts before container creation, cleanup
  retries, labelled startup recovery and cleanup-failure reporting. Native live
  qualification exposed this pre-start race after mock tests had passed.
* Verify the persistent suite before provider admission; reserve the coordinator
  package name and explicitly preserve the bytecode-write prohibition.
* Fix the Linux temporary-directory assumption by limiting Docker file transfers
  to workspace state. Both GitHub CI test runs passed at
  `d80a9c332d8aca33c8811fb35ec97985c0d7b0d1`.

Remaining private-preview limitations: host/vendor infrastructure is trusted;
connection concurrency is bounded by container resources rather than a multi-user
admission scheduler; a native CLI turn can continue until its host timeout after
a client disappears. No multi-tenant or immutable-model attestation is claimed.
Subsequent exact-commit review and live qualification remain required before
calling these dispositions a PASS. Human merge decision remains pending.
