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
`make`; [README.md](README.md#development) lists the commands.

Apple `container` is the default. With Docker, prefix any target with
`CONTAINER=docker`, for example `CONTAINER=docker make test`.

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
files, including their shell scripts.

Add one line to [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]`
describing the change.

Complete the checklist in
[.github/pull_request_template.md](.github/pull_request_template.md).

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
