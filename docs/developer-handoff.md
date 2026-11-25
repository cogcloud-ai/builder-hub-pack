# Developer handoff and preview deployment reference

This is the public handoff for turning the working single-owner preview into a
repeatably installable Nebari software pack beside an existing collab-hub-pack.
It records the 2026-11-24 deployment and the previously manual steps. No access
to the original machines, private notes, installed bindings or chat is required
to develop the pack. A new live installation needs its own infrastructure,
authorized provider login and generated service secrets.

The recipe below assembles existing helpers; it is not a qualified one-command
installer. The exact original environment passed the recorded checks. A clean
end-to-end installation from these instructions remains acceptance work in
[issue #8](https://github.com/cogcloud-ai/builder-hub-pack/issues/8).

## Where to start

Until [PR #1](https://github.com/cogcloud-ai/builder-hub-pack/pull/1) merges, the
implementation is on feat/hosted-studio; main contains the initial scaffold.
Clone into a fresh directory rather than resetting an existing developer tree:

~~~bash
git clone --branch feat/hosted-studio https://github.com/cogcloud-ai/builder-hub-pack.git
cd builder-hub-pack
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
~~~

Use Python 3.11+; historical local tests used Python 3.14. The image build requires
Linux x86-64, Docker with BuildKit/buildx, Git and Python with tarfile's data
extraction filter. Unit tests do not need Gaming, Docker, a cluster or paid models.
Read [AGENTS.md](../AGENTS.md) and [architecture](architecture.md).

An editable install keeps development tests on this checkout. For an archived
exact-commit review, set PYTHONPATH to the archive's src and inspect the imported
builder_hub path; otherwise an editable environment can accidentally test the
live tree instead of the archived SHA.

## Public source and historical image identities

[sources.json](../sources.json) is authoritative for build dependencies.
The suite's repositories.json pins the component repositories.

| Component | Qualified source revision |
| --- | --- |
| Hosted integration, including restart fix | 48f968ed265cc24bd563071193fd05062a176f9f |
| Integration before cache-only restart fix; live authoring ran here | 3aff95df4ca4388b46ec24ad2ba9c0dda1d2d401 |
| Foundation pack in cog-op-builder | 3ac1e6a39685420c3dc96293b927c55f19c549b6 |
| Public suite coordinator | d6beeba96ffb0767e0f3574a676c94267ee30ba1 |
| Collab Hub | eab8189a5d476a8c9debbe23c8db173793d31746 |
| Workbench (from suite manifest) | 15d5ca38358f806f7b00910d748dad866e7a6d32 |
| Candidate verifier (from suite manifest) | db17869b0c7146585c5e8506781d55fdaf1fac8c |
| Claude provider (from suite manifest) | 2747bf92fb00a8af2fe920bfd998970f9c81c41e |

The [sanitized qualification record](evidence/preview-2026-11-24.json) contains
the local integration, foundation and verifier image identities. They were
built on the test host, not published to a registry. They are evidence, not
downloadable release artifacts or identities a rebuild must reproduce.

## Reference topology and resource ownership

| Part | Preview arrangement |
| --- | --- |
| Platform | Disposable kind cluster; Docker network kind, subnet 172.30.0.0/16 |
| Platform charts | Nebari operator 0.2.0, Envoy Gateway v1.9.1, cert-manager v1.19.1 |
| Hub | Helm release collab-hub in collab-builder; PostgreSQL/Keycloak in collab-builder-infra |
| Hub API | Integration image wraps the pinned Hub app; /builder/studio uses live Hub owner sessions |
| Workspace | Deployment builder-workspace, service port 8443, one replica, 12 GiB PVC |
| Provider | Host Docker container builder-claude-service at 172.30.0.20:9443 |
| Verifier | Separate host Docker container builder-verify-service at 172.30.0.21:9443 |
| Candidate execution | Pinned host Docker image, network none, UID 65534, read-only mounts/root, resource limits |

The foundation's public [pack guide](https://github.com/cogcloud-ai/cog-op-builder/blob/3ac1e6a39685420c3dc96293b927c55f19c549b6/pack/README.md)
creates the test platform, realm, Hub values and browser OIDC configuration.
The application adds its workspace and service channels. The run controller
continues to use the foundation worker image, not the Studio image.

The scripts currently assume those release/namespace/issuer names. They also
rewrite the supplied Hub values and upgrade its API image. Issue #4 must define
shared resource ownership for an existing Hub instead of treating that mutation
as the final Nebari integration contract. Kubernetes/kind versions are not yet a
published support matrix.

## Configuration and private material

Copy [preview.env.example](examples/preview.env.example) to a private operator
directory and edit it. Values are placeholders; do not source it against the
existing deployment. Use a dedicated KUBECONFIG.

| Input/state | Source and treatment |
| --- | --- |
| Public origin, owner username, paths, addresses | Operator configuration; example contains no real hostname/account |
| Owner subject | deploy/gaming.py resolves the enabled user through the test realm; never substitute a username for its subject |
| Hub values | Generated by foundation helpers; retain privately because generated configuration can contain secrets |
| Service tokens | Generated/reused in Secret builder-preview-channel; distinct workspace, provider and verifier keys |
| Client configuration | Secret builder-host-client; client.json contains service tokens and must remain private |
| Internal TLS | cert-manager Certificates builder-workspace-tls, builder-host-tls and builder-verify-tls; issuer builder-ca |
| Provider login | Native Claude CLI login in the operator's vendor-owned store, mounted only into the provider service |
| Persistent work | Workspace PVC; bindings, cycles, decisions, candidates and evidence are local runtime state |
| Private host files | Generated below HOST_RUNTIME_DIRECTORY/private; staging is separate and disposable |

Do not export Secret data, private keys, installed binding files, full Hub values,
vendor history or raw user/provider records to Git. The provider's vendor-store
mounts are read-write for refresh and include its existing history; the verifier
gets no vendor store. The provider gets no Docker socket or verifier credential.
See [host bridge](host-bridge.md) for protocol and environment details.

## Build and prepare a disposable preview

Use Bash for the following operator commands. Start from the integration checkout
and the edited example environment:

~~~bash
set -euo pipefail
source /path/to/private/preview.env
mkdir -p "$WORK_ROOT/upstream"
git clone https://github.com/cogcloud-ai/cog-op-builder.git "$WORK_ROOT/upstream/foundation"
git -C "$WORK_ROOT/upstream/foundation" checkout --detach 3ac1e6a39685420c3dc96293b927c55f19c549b6
git clone https://github.com/openteams-ai/collab-hub-pack.git "$HUB_SOURCE"
git -C "$HUB_SOURCE" checkout --detach eab8189a5d476a8c9debbe23c8db173793d31746
git clone https://github.com/cogcloud-ai/cog-verify-candidate.git "$WORK_ROOT/upstream/verifier"
git -C "$WORK_ROOT/upstream/verifier" checkout --detach db17869b0c7146585c5e8506781d55fdaf1fac8c
~~~

Provision the disposable cluster with a default StorageClass. The existing kind
Docker network must have room for the two configured static bridge addresses.
Check it with docker network inspect kind; the historical subnet was
172.30.0.0/16 with gateway 172.30.0.1. Do not change an occupied network to match
this recipe. General network/service discovery belongs to issue #4.

Follow the pinned foundation pack guide to install platform charts, run
pack/platform.py with your hostname/port and HUB_VALUES output, install Hub and
the smoke proof chart, then run pack/configure_web.py with HUB_USERNAME to enable
browser login. Supply a new account password through its password-stdin option,
not a checked-in file. Rerun configure_web.py after Helm changes when needed to
reconcile its internal OIDC hostname mapping.

Public HTTPS must resolve and be reachable by the operator and Hub API. The
preview used a user service to forward Envoy's 443 to the host's private
interface at 8443. Its portable equivalent is:

~~~bash
# Set FORWARD_ADDRESS to your chosen private interface address.
gateway_service=$(kubectl -n envoy-gateway-system get service \
  -l gateway.envoyproxy.io/owning-gateway-name=nebari-gateway \
  -o jsonpath='{.items[0].metadata.name}')
kubectl -n envoy-gateway-system port-forward \
  --address "127.0.0.1,$FORWARD_ADDRESS" "service/$gateway_service" 8443:443
~~~

Keep that foreground process or an operator-managed service running while using
the development endpoint. Configure client trust using the foundation guide's
public CA instructions. Exact-leaf browser trust needs renewal when that leaf
rotates; it is a development workaround, not the Nebari release TLS plan.

From the integration checkout, build committed source and the verifier:

~~~bash
revision=$(git rev-parse HEAD)
short_revision=$(git rev-parse --short=12 HEAD)
studio_repository="collab-builder/studio-$short_revision"
studio_tag="$studio_repository:preview"
python3 build.py --tag "$studio_tag"
docker build --build-arg "BASE_IMAGE=$VERIFY_BASE" \
  -f "$WORK_ROOT/upstream/verifier/isolation/Dockerfile" \
  -t collab-builder/verify:preview "$WORK_ROOT/upstream/verifier"
VERIFY_IMAGE_ID=$(docker image inspect collab-builder/verify:preview --format '{{.Id}}')
export VERIFY_IMAGE_ID
~~~

Without --base-image, build.py retrieves and builds the pinned public foundation.
Reusing --base-image is an optimization for an already verified foundation, not
a required local artifact. BUILD_NETWORK=host was needed on the original host
when Docker build DNS could not reach registries; that is optional host-specific
configuration, not permission to disable TLS verification.

## Import images and verify the resolved revision

The current deployment uses imagePullPolicy Never. Only Studio/foundation worker
images need importing into kind; the verifier image stays in host Docker.
Load the foundation worker as described in its pack guide if not already loaded.

~~~bash
# Wait for this entire pipeline to finish BEFORE creating any digest alias.
docker save "$studio_tag" | docker exec -i "$KIND_NODE" \
  ctr -n k8s.io images import --all-platforms -
canonical_tag="docker.io/$studio_tag"
studio_index=$(docker exec "$KIND_NODE" ctr -n k8s.io images ls \
  | awk -v ref="$canonical_tag" '$1 == ref {print $3}')
[[ "$studio_index" =~ ^sha256:[a-f0-9]{64}$ ]]
STUDIO_IMAGE="$studio_repository@$studio_index"
export STUDIO_IMAGE
docker exec "$KIND_NODE" ctr -n k8s.io images tag \
  "$canonical_tag" "docker.io/$STUDIO_IMAGE"
docker exec "$KIND_NODE" crictl inspecti "docker.io/$STUDIO_IMAGE" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); actual=d["info"]["imageSpec"]["config"]["Labels"]["org.opencontainers.image.revision"]; assert actual==sys.argv[1], (actual,sys.argv[1]); print("Resolved source revision:",actual)' "$revision"
~~~

This order matters: aliasing before import completed once associated the new
digest name with the old image. Updating the containerd alias did not immediately
clear the CRI lookup cache. A fresh repository name plus actual CRI configuration
inspection resolved it. A digest-looking pod image name alone is not evidence
that the node resolved the intended content. These local loading workarounds
should disappear from normal registry-based installation (issue #5).

## Deploy services and admit the provider

The test realm user and CA must exist before deploying. Native Claude must be
installed and signed in on the host under the intended operator account. The
reference CLI was 2.1.330, using the sonnet alias; its reported usage named
claude-sonnet-5-5, without immutable-model identity attestation.

~~~bash
python3 deploy/gaming.py --origin "$HUB_ORIGIN" --values "$HUB_VALUES" \
  --hub-source "$HUB_SOURCE" --username "$HUB_USERNAME" \
  --host-address "$PROVIDER_ADDRESS" --verify-host-address "$VERIFIER_ADDRESS" \
  --image "$STUDIO_IMAGE"
python3 deploy/host.py --image "$studio_tag" --verify-image "$VERIFY_IMAGE_ID" \
  --directory "$HOST_RUNTIME_DIRECTORY" \
  --address "$PROVIDER_ADDRESS" --verify-address "$VERIFIER_ADDRESS"
docker exec builder-claude-service python -m builder_hub.host_bridge qualify --require-claude
docker exec builder-verify-service python -m builder_hub.host_bridge qualify --require-docker --probe-docker
kubectl -n collab-builder exec deployment/builder-workspace -- python -m builder_hub.admit
~~~

Host Docker, its CLI/socket and native Claude executable/store are explicit
external prerequisites for this profile. deploy/host.py uses network kind and
/usr/bin/docker. It starts separate restartable containers and exports only
their own service credentials/certificates to private host files. It does not
install Claude or obtain someone else's login.

## Qualify execution before activating it

Run the public verifier's real isolation tests through the workspace shim:

~~~bash
kubectl -n collab-builder exec deployment/builder-workspace -- \
  env "COG_VERIFY_ISOLATION_IMAGE=$VERIFY_IMAGE_ID" \
  /opt/builder-suite/cog-workbench/.pixi/envs/default/bin/python \
  -m unittest discover -s /opt/builder-suite/cog-verify-candidate/tests \
  -p test_isolation.py -v
~~~

The reference passed six tests, including actual timeout/cancellation cleanup.
The host probe checks confinement, limits, no secrets/socket and failure to reach
the network or either bridge. If either qualification fails, stop here.
Only after the preceding checks pass, record that operator qualification:

~~~bash
python3 - "$VERIFY_IMAGE_ID" "$revision" > "$WORK_ROOT/policy.json" <<'PY'
import datetime, json, sys
print(json.dumps({"qualified": True, "mode": "docker", "image": sys.argv[1],
    "qualification": {"integration_revision": sys.argv[2],
        "native_isolation_tests": 6, "host_confinement_probe": "PASS",
        "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}}))
PY
kubectl -n collab-builder create configmap builder-execution \
  --from-file="policy.json=$WORK_ROOT/policy.json" --dry-run=client -o yaml \
  | kubectl apply -f -
kubectl -n collab-builder rollout restart deployment/builder-workspace
kubectl -n collab-builder rollout status deployment/builder-workspace --timeout=300s
kubectl -n collab-builder exec deployment/collab-hub-api -- python -m builder_hub.qualification
~~~

This ConfigMap is an operator assertion, not an automatically authenticated or
image-bound attestation. Automating/staleness-checking it is issue #6. The
service imposes a 60-second/1-MiB execution policy and refuses missing qualification
or any trusted-local fallback. Existing cycles cannot silently adopt a changed
execution policy; start a new cycle after qualification.

The HTTP qualifier checks anonymous page 303/API 401, wrong owner 403, owner page
200, foreign Origin 403, session revocation 401, and native fixture totals 21/31.
It creates short-lived synthetic sessions inside the Hub API and revokes them.
It does not test an actual browser/IdP sign-in; perform that separately.

## Functional build and restart evidence

The shipped qualifier's --live-build default brief generated a broad
absence-of-effects criterion for which it had no instrumented evidence. The
evaluator correctly stopped at the two-round budget despite passing tests.
Do not present that command as a reliably passing release check.

The successful synthetic brief is stored in the qualification record. It tests
four functional criteria (empty input, Unicode code points, whitespace/multiple
strings, malformed inputs). Enter it through Studio's saved build flow with a
new Cog name, an explicit test owner, two rounds and twelve model units. Review
the contract and candidate Gates. The original operator test explicitly marked
its decisions as automated fixture acceptance, not human release acceptance.
No evaluation or execution controls were bypassed.

Historical build 20261124T060419Z-2131b4aa completed in one round, reserving five
model units: 18 declared tests, eight isolated execution records and four passing
criteria. The following checks use YOUR new completed cycle ID, not that host's
private state:

~~~bash
# Set BUILD_ID to the completed synthetic cycle on your installation.
kubectl -n collab-builder exec deployment/collab-hub-api -- \
  python -m builder_hub.qualification --retained-build "$BUILD_ID"
for phase in before after; do
  if [ "$phase" = after ]; then
    kubectl -n collab-builder rollout restart deployment/builder-workspace
    kubectl -n collab-builder rollout status deployment/builder-workspace --timeout=300s
  fi
  kubectl -n collab-builder exec -i deployment/builder-workspace -- \
    python - "$BUILD_ID" > "$WORK_ROOT/retention-$phase.json" <<'PY'
import hashlib, json, pathlib, re, sys
ident = sys.argv[1]
assert re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}', ident)
root = pathlib.Path('/opt/builder-suite/op-cog-builder/cycles') / ident
assert root.is_dir() and not root.is_symlink()
files = {}
for path in sorted(root.rglob('*')):
    if path.is_symlink():
        raise ValueError('Unexpected symlink in synthetic fixture evidence.')
    if path.is_file():
        files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(files, sort_keys=True))
PY
done
python3 - "$WORK_ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
before = json.loads((root / 'retention-before.json').read_text())
after = json.loads((root / 'retention-after.json').read_text())
assert before and before == after, 'Synthetic cycle artifacts changed.'
print('Unchanged synthetic build files:', len(before))
PY
kubectl -n collab-builder exec deployment/collab-hub-api -- \
  python -m builder_hub.qualification --retained-build "$BUILD_ID"
kubectl -n collab-builder exec deployment/builder-workspace -- python -m builder_hub.admit
~~~

The original restart comparison hashed every regular file under the completed
cycle before/after restart; all 52 hashes were identical. Retain that comparison
in your private test evidence as well as the HTTP status result. Never publish
real user cycles or binding records.

## Known constraints and previously resolved failures

- Native model turns update Pixi task-cache records. The first post-build restart
  failed full inventory verification. initialize.py now restores only those
  disposable caches from the immutable image before the unchanged source and
  environment verification. Never disable the integrity check to recover.
- Full inventory checks take time on small CPUs; allow the existing 300-second
  rollout window and inspect init-container logs if it fails. Startup is not an
  instant health check.
- Marker owner/source-pin changes require an explicit migration. Trusted-image
  refresh preserves runtime state but is not a general pin migration or rollback.
- Native verifier temporary inputs must reside in workspace state for transfer.
  Expanding the shim to arbitrary /tmp or host paths is not the fix.
- Cleanup needs cancellation tombstones for a timeout before container creation,
  real absence checks and labelled startup recovery. Mock-only tests missed this.
- The kind CNI does not enforce NetworkPolicy. Internal TLS/tokens and Docker
  network-none confinement are separate controls. This is not multi-user isolation.
- Abandoned provider turns may run until their host timeout; concurrency is
  bounded by container resources. Vendor and Docker infrastructure are trusted.
- Admission rechecks the persistent inventory. If legitimate task-cache changes
  cause admission to refuse during a session, restart through the initializer;
  do not weaken verification or copy another checkout's binding.

## Evidence, ownership and next work

The committed [qualification summary](evidence/preview-2026-11-24.json) is a
sanitized historical operator record, not raw logs, a current health report or a
fresh-install qualification. Runtime/model review evidence is in
[review rounds](review-rounds.md) and the linked PR summary. No source after a
reviewed SHA inherits an exact-commit independent PASS automatically.

| Delivery | Issue |
| --- | --- |
| Coordinating Nebari-pack delivery | [#3](https://github.com/cogcloud-ai/builder-hub-pack/issues/3) |
| Installation contract and existing-Hub resource ownership — start here | [#4](https://github.com/cogcloud-ai/builder-hub-pack/issues/4) |
| Versioned OCI/chart and image publication | [#5](https://github.com/cogcloud-ai/builder-hub-pack/issues/5) |
| Setup, diagnostics and bound qualification | [#6](https://github.com/cogcloud-ai/builder-hub-pack/issues/6) |
| Upgrade, backup, restore and removal | [#7](https://github.com/cogcloud-ai/builder-hub-pack/issues/7) |
| Fresh installation/upgrade/restore CI and operator guide | [#8](https://github.com/cogcloud-ai/builder-hub-pack/issues/8) |

The existing Hub [pack conventions](https://github.com/openteams-ai/collab-hub-pack/blob/eab8189a5d476a8c9debbe23c8db173793d31746/README.md)
and its software-pack template link are the public starting point; issue #4
must verify the chosen supported versions. Do not fork the shared planner or
Studio for hosting. [Guided intake adoption #2](https://github.com/cogcloud-ai/builder-hub-pack/issues/2)
is independent of installation delivery.

Original machines retain deployment values, KUBECONFIG, private keys, native
provider login, images, PVC/database content and raw evidence. These are not
source prerequisites. Recreate them from public source and your own configuration;
do not depend on the original hostnames, file paths or artifacts.
