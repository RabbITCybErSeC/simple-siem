# Simple SIEM

Simple SIEM is a SIEM layer that fetches slices of logs from stores you already
run (Elasticsearch first), normalizes them to Google SecOps UDM, runs
detections, and manages alerts and cases. It is not a log store.

**Status: pre-release.** Simple SIEM is not for production use yet. The first
release will be v0.1.0.

## What works today

- The `simple-siem` service: HTTP API, embedded web console, and PostgreSQL
  migrations.
- Sign-in with sessions and role-based access.
- An audit trail of security-relevant actions, readable by users with the
  `audit:read` permission.
- Fetching auth events from Elasticsearch and converting them to Google SecOps
  UDM.
- Brute-force-then-success detection over stored auth events.
- Cases in the web console: filter, inspect, and close.

## Requirements

- macOS with Apple [`container`](https://github.com/apple/container), or any
  machine with Docker
- `make` and `git`

Nothing else is installed on the host: Go, the linters, and PostgreSQL run in
containers.

## Quick start

```bash
git clone https://github.com/RabbITCybErSeC/simple-siem.git
cd simple-siem
make dev
```

`make dev` starts PostgreSQL, the API, and the Vite dev server. It runs in the
foreground, and the first run builds the toolchain image, so give it a few
minutes. Wait until the server answers:

```bash
curl http://127.0.0.1:5173/healthz
```

It prints `{"status":"ok"}`.

In a second terminal, create the first admin. The password is read from the
first line of a file, so type it once to a git-ignored path, create the admin,
then delete the file:

```bash
cd simple-siem
mkdir -p .make
read -rs password && printf '%s\n' "$password" > .make/admin-password && unset password
make run ARGS="admin create --email '<your-email>' --password-file .make/admin-password"
rm -f .make/admin-password
```

Replace `<your-email>` with your own email address. When prompted, type a
password of 12 to 128 characters and press Enter. The command prints `created
admin <id>`.

Open <http://127.0.0.1:5173> and sign in with that email address and password.

## Development

| Command | What it does |
| --- | --- |
| `make dev` | Start PostgreSQL, the API on port 8080, and Vite on port 5173, with live reload. |
| `make test` | Run the Go and frontend tests against PostgreSQL. |
| `make lint` | Run the Go and frontend linters, the TypeScript type check, dependency vulnerability checks, and checks of the workflow files, including their shell scripts. |
| `make build` | Build the web UI, then embed it in `bin/simple-siem`. |
| `make e2e` | Run the Playwright and axe browser tests against the built binary. |
| `make image` | Build the distroless runtime image `simple-siem:dev`. |
| `make db-shell` | Open `psql` on the development database. |
| `make down` | Stop the development containers and keep their data. |
| `make clean` | Remove the development containers, volumes, and build output. |
| `make es` | Start a single-node Elasticsearch for fetcher tests. |
| `make seed-auth-logs` | Write synthetic sshd and Windows logon events into Elasticsearch. |

With Docker instead of Apple `container`, prefix any target with
`CONTAINER=docker`, for example `CONTAINER=docker make test`.

## Command line

| Command | What it does |
| --- | --- |
| `simple-siem serve` | Run the HTTP API. |
| `simple-siem migrate` | Apply pending database migrations. |
| `simple-siem admin` | Create or recover admin accounts. |
| `simple-siem config` | Validate the file configuration. |
| `simple-siem run` | Run one pipeline once. |
| `simple-siem detect` | Run one detection window or fixture. |
| `simple-siem version` | Print the version. |

`simple-siem <command> -h` prints the flags of a command.

## Configuration

Configuration comes from environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `SIMPLE_SIEM_ENV` | `production` | `development` or `production` |
| `SIMPLE_SIEM_DATABASE_URL` | required | `postgres://user:password@host:5432/db` |
| `SIMPLE_SIEM_LISTEN` | `:8080` | Address and port the API listens on |
| `SIMPLE_SIEM_PUBLIC_URL` | `http://localhost:8080` in development | Required outside development, and must use `https` |
| `SIMPLE_SIEM_TRUSTED_PROXIES` | none | Comma-separated IPs or CIDR ranges of your reverse proxy |
| `SIMPLE_SIEM_SHUTDOWN_TIMEOUT` | `30s` | Time in-flight requests get on SIGTERM |
| `SIMPLE_SIEM_SESSION_IDLE_TIMEOUT` | `30m` | Idle time before a session expires; must not exceed the absolute lifetime |
| `SIMPLE_SIEM_SESSION_ABSOLUTE_LIFETIME` | `12h` | Maximum lifetime of a session |

Endpoints: `/` serves the embedded web UI, `/assets/*` serves its hashed
files with a one-year immutable cache, `/healthz` reports that the process is
alive, `/readyz` reports that the database is reachable (for load balancers),
and `/version` returns the build version.

`make build` compiles the web UI first and embeds it in `bin/simple-siem`.
`make image` builds the frontend in its own stage and produces a distroless,
non-root image for your machine's architecture; it runs with a read-only root
filesystem. Run it behind a reverse proxy that terminates TLS, and set
`SIMPLE_SIEM_PUBLIC_URL` and `SIMPLE_SIEM_TRUSTED_PROXIES` accordingly.

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md): how to propose a change and what a pull
  request must pass.
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately.
- [CHANGELOG.md](CHANGELOG.md): what changed in each release.
- [LICENSE](LICENSE): the license.

## License

MIT. See [LICENSE](LICENSE).
