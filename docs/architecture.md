# Initial integration contract

The public suite coordinator is pinned to
`d6beeba96ffb0767e0f3574a676c94267ee30ba1` and Hub to
`eab8189a5d476a8c9debbe23c8db173793d31746`. The suite manifest defines all
component revisions, including Workbench `15d5ca38358f806f7b00910d748dad866e7a6d32`.
Never use unpublished local Workbench revisions as deployment prerequisites.

The proposed public entry point is `/builder/studio` on the existing Hub origin.
A small Hub process extension authenticates requests through Hub's existing
`get_web_session` function, including ended-session lookup, and checks an
explicit owner subject. It proxies only the Studio page and fixed Studio API
endpoints to a separate workspace service. It must not forward Hub cookies or
authorization headers. Writes require the exact configured public Origin.
The extension wraps the unmodified pinned Hub ASGI app and delegates every
non-Builder request unchanged. No Hub signing secret enters the workspace.

The workspace service reuses public Studio and Suite code. Persistent storage
holds workspace state and artifacts. An internal service credential protects
access even where the test cluster does not enforce NetworkPolicy. Internal
TLS is preferred and certificate validation must never be disabled.

First qualify browsing, saved progress and trusted model-free fixture operations.
Model provider admission is explicit. Generated package tests, environment
installation, generic arbitrary package operations and publication remain
disabled until their execution containment is proven. A safe preview must label
unavailable actions clearly and must refuse them server-side.
