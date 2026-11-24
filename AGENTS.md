# Builder Hub pack

Read README.md and docs/architecture.md before implementation. Keep source pins
public and exact. Reuse the public Cog suite and Collab Hub rather than vendoring
or forking their behavior. No runtime dependency on another developer workspace.
Never commit credentials, installed bindings, or private user inputs.

The initial preview is owner-only. Authenticate every Builder request using the
Hub's live session checks. Do not forward cookies, client secrets or session
signing keys into the execution workspace. Refuse generated-code execution until
its isolation has been qualified. Tests must cover authentication, CSRF, route
restrictions, persistence, and fail-closed behavior.

Record actual implementing and reviewing models in review evidence. A review
is evidence about an exact commit, not permission to merge or deploy elsewhere.
