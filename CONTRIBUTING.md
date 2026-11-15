# Contributing to Simple SIEM

## Propose a change first

Open an issue before you write code. State the behavior you want to change and
its acceptance scenarios as given/when/then steps:

```text
Given a signed-in user with the case:read permission
When the user filters cases by severity
Then only cases with that severity are listed
```

Wait for a maintainer to agree before starting large work. Small fixes, such
as a typo or a broken link, can go straight to a pull request.

## Work in containers

Nothing is installed on your host. Every tool runs in a container through
`make`:

```bash
make dev    # PostgreSQL, the API, and Vite with live reload
make test   # Go and frontend tests
make lint   # linters and checks
make build  # the web UI and bin/simple-siem
```

Apple `container` is the default. With Docker, prefix any target with
`CONTAINER=docker`, for example `CONTAINER=docker make test`, and use
`CONTAINER=docker make dev` to develop with Docker.

## Write the failing test first

Add a test that fails for the intended reason, then the smallest change that
makes it pass. A bug fix starts with a test that reproduces the bug. Tests ship
in the same pull request as the code they cover.

## Before you open a pull request

Run:

```bash
make lint test build
```

For UI changes, also run the browser tests:

```bash
make e2e
```

`make lint` runs the Go and frontend linters, the TypeScript type check, a
check of dependencies for known vulnerabilities, and a check of the workflow
files.

Add one line to [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]`
describing the change.

Checklist:

- [ ] The pull request is linked to an issue (`Closes #`).
- [ ] Tests were written first and fail without the change.
- [ ] `make lint test build` passes.
- [ ] `make e2e` passes for UI changes.
- [ ] `CHANGELOG.md` has a line under `Unreleased`.
- [ ] No secrets or personal data are included.

## Commit subjects

Follow the existing style:

```text
feat(web): add case filters
fix(api): reject expired sessions
test(detection): cover an empty window
docs: update the quick start
```

One logical change per commit.

## Reporting a vulnerability

Do not open a public issue. Follow [SECURITY.md](SECURITY.md) and use GitHub
private vulnerability reporting.
