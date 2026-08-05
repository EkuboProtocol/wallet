# wallet-mcp-server

## Git workflow

Work on `main` and push to it directly. Do not open a branch or a pull request for
ordinary changes, and do not wait to be asked to commit.

Commit early and often: each self-contained change — a fix, a doc edit, a small
refactor — is its own commit, pushed as soon as it builds and its tests pass. Prefer
several small pushes over one large one.

Reserve a branch for work that is genuinely large or risky enough that landing it
half-finished on `main` would break the build for someone else.
