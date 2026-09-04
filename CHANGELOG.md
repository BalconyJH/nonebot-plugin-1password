# Changelog

All notable changes to this project are documented here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- towncrier release notes start -->

## [0.1.0] - 2026-09-04

Initial release.

### Added

- Metadata-only catalog search, resource information, and backend health commands for registered 1Password resources.
- Durable access requests, approvals, cancellation, status queries, approval quorums, self-approval restrictions, and idempotent voting.
- Immutable domain contracts and a typed extension API for trusted Action Providers with fixed targets, timeouts, and result codes.
- A standalone Remote Broker with TLS 1.3 mutual authentication, certificate-fingerprint identity, short-lived grants, idempotent jobs, rate limiting, and circuit breaking.
- SQLite WAL persistence, transactional audit evidence, notification Outbox delivery, execution recovery, and ordered Broker audit outlets.
- Strict public and private TOML catalogs, Action Policies, approval routes, and deployment configuration.
- Adapter-independent integration through Alconna, UniMessage, Uninfo, and Permission, with support for Python 3.10–3.13 and Uninfo 0.11.2 or later.
- User, API, security, operations, and development documentation, with strict documentation builds and downloadable pull-request previews.
- GitHub Actions quality and coverage gates, verified distribution artifacts, automatic version tagging, PyPI/TestPyPI Trusted Publishing, GitHub Releases, and GitHub Pages deployment.
- Dependabot configuration, repository protection templates, and Git/Jujutsu-compatible development tooling.

### Security

- Keep Secret resolution inside the Broker by default; never return Secret values or references to chat, RPC callers, logs, or audit records.
- Bind execution to approved policies and grants, preserve nonce replay protection throughout the accepted clock-skew window, and bound remote polling by its deadline.
- Enforce every command permission gate and contain sensitive failures at Waiter, transport, and persistence boundaries.
- Scan repository history and built distributions, and exclude credentials, databases, generated files, caches, and version-control metadata from release artifacts.
