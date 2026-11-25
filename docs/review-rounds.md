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

## Round 3 — complementary component reviews

Head: 3aff95df4ca4388b46ec24ad2ba9c0dda1d2d401.
Compared base: 4fdc9203a75af6e770d6dc272008145a2cc24d62.
Publication: 2026-11-24 UTC; Claude's report is dated 2026-11-23 local.
The [published summary](https://github.com/cogcloud-ai/builder-hub-pack/pull/1#issuecomment-7123588028)
preserves the evidence and exclusions.

- Claude Opus 5.5 (claude-opus-5-5): PASS for the Gemini bridge and Codex
  integration. Excluded its own Hub proxy and the Studio render changes.
  Verified archived imports and ran 187 tests. No live Docker, Kubernetes or
  model calls by this reviewer.
- Gemini 4 Neon (gemini-4-neon): PASS for the Claude/Codex Hub, Studio,
  workspace and deployment boundary. Excluded its own host/CLI bridge and
  bridge tests. Read exact public GitHub source and pinned upstream; static
  review only, with no executed tests or live deployment/model calls.

A prior Gemini filesystem recheck was BLOCKED by its workspace hook and issued
no verdict. The successful public-source review respected that restriction.
These are complementary scoped reviews, not a whole-repository independent PASS
by one family or a human review.

## Round 4 — persistent task-cache restart fix

Reviewer: Claude Opus 5.5 (claude-opus-5-5), 2026-11-24.
Head: 48f968ed265cc24bd563071193fd05062a176f9f.
Base: 3aff95df4ca4388b46ec24ad2ba9c0dda1d2d401.
Implemented by Codex GPT-6.1-Sol, from the coordinating session evidence.
Verdict: PASS for this delta only; no blocking or major finding.

Static public-source review covered initialize.py, its tests and README, with
trust/entrypoint/admission interactions inspected. The reviewer did not execute
tests, build or deploy; the coordinator's 190-test result is separate. The fix
restores disposable Pixi task records from immutable source before the unchanged
complete inventory check. It preserves runtime evidence and refuses source or
environment tampering. Nits: missing nested-cache/file-target/no-image-cache
fixtures; task scheduling caches remain mutable during a running session.
Earlier component reviews were not re-executed by this reviewer.

## Documentation handoff

The subsequent developer handoff and sanitized historical qualification summary
are authored by Codex GPT-6.1-Sol. They change no runtime code. Earlier model
verdicts and deployment evidence remain tied to the exact SHAs above, not to a
later documentation head. No new independent review is claimed for the handoff.
Human merge decision remains pending.
