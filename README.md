# Simple SIEM

A SIEM layer that fetches slices of logs from your existing stores
(Elasticsearch first), normalizes them to Google SecOps UDM, runs detections,
and manages alerts and cases. It is not a log store.

Status: early development. The service starts, migrates its PostgreSQL
database, reports health, writes an audit trail, and serves an embedded web UI
shell; detections and the first screens are still to come.

## Requirements

- macOS with Apple [`container`](https://github.com/apple/container), or any
  machine with Docker
- `make` and `git`

Nothing else is installed on the host: Go, the linters, and PostgreSQL run in
containers.

## Development

```bash
make dev        # PostgreSQL + API + Vite at http://127.0.0.1:5173
make test       # Go and frontend tests against a real PostgreSQL
make lint       # Go and frontend linters plus the TypeScript type check
make build      # build the web UI, then embed it in bin/simple-siem
make pnpm ARGS="add <package>"  # run pnpm in the web workspace
make shadcn-mcp # shadcn registry MCP server on stdio
make db-shell   # psql into the development database
make down       # stop containers, keep data
make clean      # remove containers, volumes, and build output
```

`make dev` runs the Vite development server on port 5173 and proxies `/api`,
`/healthz`, `/readyz`, and `/version` to the Go server on port 8080. Changes in
`web/src` reload in the browser without restarting either server.

With Docker instead of Apple `container`, prefix any target with
`CONTAINER=docker`, for example `CONTAINER=docker make test`.

Check it runs:

```bash
curl http://127.0.0.1:5173/healthz    # {"status":"ok"} through the Vite proxy
curl http://127.0.0.1:5173/version
```

## Running the binary

```text
simple-siem serve [--migrate=true|false]   run the HTTP API (migrates first by default)
simple-siem migrate                        apply pending database migrations
simple-siem version                        print the version
```

Configuration comes from environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `SIMPLE_SIEM_ENV` | `production` | `development` or `production` |
| `SIMPLE_SIEM_DATABASE_URL` | required | `postgres://user:password@host:5432/db` |
| `SIMPLE_SIEM_LISTEN` | `:8080` | |
| `SIMPLE_SIEM_PUBLIC_URL` | `http://localhost:8080` in development | Required and `https` in production |
| `SIMPLE_SIEM_TRUSTED_PROXIES` | none | Comma-separated IPs or CIDR ranges of your reverse proxy |
| `SIMPLE_SIEM_SHUTDOWN_TIMEOUT` | `30s` | Time in-flight requests get on SIGTERM |

Endpoints: `/` serves the embedded web UI, `/assets/*` serves its hashed
files with a one-year immutable cache, `/healthz` reports that the process is
alive, `/readyz` reports that the database is reachable (for load balancers),
and `/version` returns the build version.

`make build` compiles the web UI first and embeds it in `bin/simple-siem`.
`make image` builds the frontend in its own stage and produces a distroless,
non-root image for your machine's architecture; it runs with a read-only root
filesystem. Run it behind a reverse proxy that terminates TLS, and set
`SIMPLE_SIEM_PUBLIC_URL` and `SIMPLE_SIEM_TRUSTED_PROXIES` accordingly.

## License

MIT (license file to be added before the first release).
