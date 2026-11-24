# Builder Hub pack

Private, persistent Cog Builder Studio workspaces integrated with Collab Hub.
Open `/builder/studio` on the Hub origin and sign in normally. The initial
deployment is a single-owner preview on the Gaming test cluster.

The public Cog suite owns Studio, provider admission, design, authoring, native
Op sequencing, contract/candidate Gates, verification and evidence. This repo
owns their hosted boundary and deployment. Exact public revisions are recorded
in `sources.json`; Builder and Hub behavior remain in their original repositories.

## Boundaries

The Hub extension checks the existing live browser session, its ended-session
store and an explicit owner subject on every Builder request. Gate attribution
comes from that session. It proxies only the fixed Studio surface to a separate
persistent workspace, without forwarding cookies or Hub secrets. Studio scripts
and styles are protected by hashes in its content security policy.

The workspace retains bindings, build cycles, candidates and native evidence.
Before executing its persistent Python, it checks every trusted source and
installed environment file against an inventory from the immutable image. An
explicit image refresh preserves runtime state; owner/source changes require
migration. Runtime environment installation and arbitrary Workbench filesystem
or process endpoints are unavailable.

A restricted HTTPS provider bridge uses the native Claude subscription login
in its vendor-owned store. A separate verifier bridge receives Docker authority;
the Claude subprocess has no Docker socket or verifier credentials.
The current provider selector is Claude `sonnet`; native provenance retains the
reported model and CLI version. An alias does not attest immutable weights.

Generated verification reuses the native Docker policy: fixed immutable image,
no network, read-only root/candidate/inputs, UID 65534, no Linux capabilities,
one CPU, 256 MiB RAM, 64 processes and bounded temporary storage. Candidate
containers receive no vendor credentials, Docker socket, Hub cookie, Hub database
access or Hub signing key. There is no trusted-local fallback. Before isolation
qualification is recorded, automatic continuation is refused server-side.

## Build and test

Use Python 3.11+ and Docker on Linux x86-64. Build committed source only.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/python -m pytest -q
python3 build.py --tag collab-builder/studio:preview
```

The build reproduces the foundation at its exact public `basePack` revision,
then uses `git archive HEAD` for this integration. Labels record the revision
and resolved base image. For an already built foundation, supply
`--base-image collab-builder/worker:step1`. Suite and Hub pins must agree.

## Private test deployment

Deploy the foundation using its public `pack/README.md` and set the dedicated
`KUBECONFIG`. Load this image into kind with its canonical digest alias.

```sh
python3 deploy/gaming.py --origin "$HUB_ORIGIN" --values "$HUB_VALUES" \
  --hub-source "$HUB_SOURCE" --username "$HUB_USERNAME" \
  --host-address 172.30.0.20 --image "$STUDIO_IMAGE_DIGEST"
```

This creates TLS certificates, private service channels, owner mapping and the
persistent workspace, then upgrades the Hub API. Its worker controller retains
the existing worker image. The script targets the foundation's `collab-builder`
namespace without changing public DNS or the host firewall.

Build the verifier image from the pinned suite's
`cog-verify-candidate/isolation/Dockerfile`, using an immutable public Python base.
Use its resulting local `sha256:` identity below.

```sh
python3 deploy/host.py --image "$STUDIO_IMAGE_DIGEST" \
  --verify-image "$VERIFY_IMAGE_ID" --directory "$HOST_RUNTIME_DIRECTORY"
docker exec builder-claude-service python -m builder_hub.host_bridge qualify \
  --require-claude
docker exec builder-verify-service python -m builder_hub.host_bridge qualify \
  --require-docker --probe-docker
kubectl -n collab-builder exec deployment/builder-workspace -- \
  python -m builder_hub.admit
```

The bridge uses only the private kind Docker network. Credential and certificate
material stays in the private host runtime directory and vendor store. See
[host bridge](docs/host-bridge.md) for its exact capability allowlist. The Docker
daemon remains trusted infrastructure.

Run the public verifier's real `test_isolation.py` through the workspace CLI
bridge before creating the `builder-execution` ConfigMap with `policy.json`.
The policy requires `qualified: true`, `mode: docker` and the exact `image`
identity. The service imposes timeout/output caps. Start a new build afterwards;
an existing build cannot silently change its execution policy on resume.

The operator-only `builder_hub.qualification` module runs inside the Hub API pod.
It uses short-lived synthetic signed test sessions to check owner/anonymous/
foreign-origin/revocation behavior and run the model-free fixture. `--live-build`
also performs a bounded synthetic build; `--retained-build ID` checks recovery
after restart. Sessions are revoked afterwards. Automated fixture acceptance
is not human review or release acceptance.

## Scope

This is a private single-owner preview with one workspace replica, rather than
a qualified multi-tenant service. The current kind CNI does not enforce
NetworkPolicy. TLS and service credentials protect internal APIs; Docker's
network isolation independently confines candidates. Arbitrary provider
selection, manual unisolated tests and publication remain unavailable.

See [architecture](docs/architecture.md) and the PR's model review evidence.
The human merge decision remains separate from deployment qualification.
