# SecureWatch architecture

## Architectural decisions

1. **Modular monolith first.** The API has feature modules and shared infrastructure. It includes environment configuration, MongoDB connectivity, health routes, common errors, a read-only synthetic dashboard module, and an HMAC-authenticated Linux agent intake with fixed endpoint rules.
2. **Structured detection inputs.** The first endpoint rules run in the API against bounded SSH and sudo aggregates. They do not receive raw log text or execute event content, shell commands, or code from collected events.
3. **Separate identities.** Browser users, collector agents, and internal services will use distinct authentication and authorization paths. No public administrator signup is planned; the initial administrator will be created by a local bootstrap command in Phase 2.
4. **Versioned API.** REST endpoints live below `/api/v1`. Health liveness is process-only; readiness checks MongoDB with a ping.
5. **Least privilege.** The local Compose database creates an application user with `readWrite` on only the SecureWatch database. Production access will use a separately managed database user and network policy.
6. **Synthetic first.** The dashboard/admin preview remains labeled simulated. The separate Linux agent is read-only and sends an authenticated inventory snapshot; it does not accept commands or execute updates.

## Current request paths

```text
Browser dashboard ──GET /api/v1/dashboard/summary──▶ Express middleware ──demo mode──▶ synthetic payload
Browser health page ──GET /api/v1/health───────────▶ Express middleware ──readiness──▶ MongoDB ping
Linux agent ──HTTPS POST /api/v1/agents/report + HMAC──▶ Express middleware ──connected mode──▶ MongoDB latest snapshot
                                                                                         └─▶ fixed rules ──▶ daily-deduplicated alerts
```

In regular mode, the API connects to MongoDB and creates its agent report/replay/alert indexes before opening its local listener. In `DEMO_MODE=true`, it skips MongoDB and enables the dashboard/admin preview routes; the live agent intake is disabled. `/api/v1/health/live` does not depend on the database; readiness returns `503` if MongoDB is unavailable or intentionally skipped.

## Planned module boundaries

| Module | Responsibility |
| --- | --- |
| `auth` / `users` | Login, refresh sessions, profile, password changes, bootstrap, role checks |
| `events` | Validated normalized event intake, filters, pagination, detail views |
| `detection` | Fixed structured endpoint rules now; rule configuration and richer correlation later |
| `alerts` | Daily-deduplicated endpoint alerts now; assignment, review workflow, and notes later |
| `incidents` | Alert associations, investigation timeline, closure and resolution |
| `agents` | Per-agent HMAC authentication, replay protection, latest read-only host snapshot, security aggregates, and alert creation |
| `collectors` | Future enrollment, registration, source identity, heartbeat and health workflows |
| `reports` | Aggregations and safe CSV export |
| `audit` | Append-oriented records for administrative and workflow changes |
| `websocket` | Authenticated, role-aware event delivery with bounded payloads |

## Dependency and lockfile policy

JavaScript dependencies use semver ranges in workspace manifests. The generated root `package-lock.json` records the resolved graph; review dependency changes and commit the lockfile. CI and clean installs use `npm ci`. The read-only Linux agent uses Python's standard library; a separately packaged Python analysis engine can be added if richer correlation is needed. Container images receive patch updates while remaining on an explicitly selected major release.
