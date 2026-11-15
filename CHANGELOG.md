# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The `simple-siem` service: HTTP API, embedded web console, and PostgreSQL
  migrations.
- Sign-in with sessions and role-based access.
- An audit trail of security-relevant actions.
- Elasticsearch fetching of auth events and conversion to Google SecOps UDM.
- Brute-force-then-success detection over stored auth events.
- Cases in the web console: filter, inspect, and close.
- The MIT license.
- Contributor docs: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and this
  changelog.
