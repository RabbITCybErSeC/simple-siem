# Simple SIEM

A SIEM layer that fetches slices of logs from your existing stores
(Elasticsearch first), normalizes them to Google SecOps UDM, runs detections,
and manages alerts and cases. It is not a log store.

Status: early development. The service starts, migrates its PostgreSQL
database, reports health, and writes an audit trail; detections and the UI
are not there yet.

## Requirements

- macOS with Apple [`container`](https://github.com/apple/container), or any
  machine with Docker
- `make` and `git`

Nothing else is installed on the host: Go, the linters, and PostgreSQL run in
containers.

## Development

```bash
make dev        # PostgreSQL + the API on http://127.0.0.1:8080, rebuilt on change
make test       # tests against a real PostgreSQL
make lint
make db-shell   # psql into the development database
make down       # stop containers, keep data
make clean      # remove containers, volumes, and build output
```

With Docker instead of Apple `container`, prefix any target with
`CONTAINER=docker`, for example `CONTAINER=docker make test`.

Check it runs:

```bash
curl http://127.0.0.1:8080/readyz     # {"status":"ready"}
curl http://127.0.0.1:8080/version
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

Endpoints: `/healthz` (process alive), `/readyz` (database reachable, for load
balancers), `/version`.

`make image` builds a distroless, non-root image for your machine's
architecture; it runs with a read-only root filesystem. Run it behind a reverse
proxy that terminates TLS, and set `SIMPLE_SIEM_PUBLIC_URL` and
`SIMPLE_SIEM_TRUSTED_PROXIES` accordingly.

## License

MIT (license file to be added before the first release).
