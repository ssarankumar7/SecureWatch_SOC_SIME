# Security notes and initial threat model

## Assets

- User credentials, refresh sessions, role assignments, and audit records (added in later phases).
- Security event aggregates, detection findings, alerts, incidents, and collector credentials.
- Database and signing secrets supplied through the environment.

## Trust boundaries

- Browser clients and collector agents are untrusted until independently authenticated.
- Event descriptions, metadata, timestamps, source labels, and collector payloads are untrusted data.
- Endpoint detections consume bounded structured aggregates only; they do not evaluate event content as code or commands.
- MongoDB is private to the host in the local setup. Production network controls and TLS are required before deployment.

## Foundation controls

- The API binds to `127.0.0.1` and MongoDB's published port is bound to host loopback.
- MongoDB authentication is enabled in Compose. The API uses an application account with database-specific `readWrite`, not the MongoDB root account.
- Environment values are validated and configuration errors identify keys without printing values.
- Startup logs avoid raw MongoDB driver errors and connection strings.
- Helmet, explicit CORS origins, a 64 KiB JSON body limit, and request rate limiting are enabled.
- Readiness returns coarse dependency state and never includes exception text.

## Dashboard preview

- `DEMO_MODE=true` serves a fixed synthetic dashboard payload and skips MongoDB startup. It is rejected when `NODE_ENV=production`.
- Preview host addresses, resource values, patch versions, and network findings are illustrative data. They do not come from a host, scan, or network capture.
- Patch recommendations are read-only. The UI can add an item to a browser-local review queue, but does not invoke `apt`, SSH, a collector, or any remote action.
- Keep demo mode bound to loopback. It is not an authenticated or production monitoring endpoint.

## AI alert triage preview

- The demo-only `/api/v1/copilot/analyze` route accepts a sample finding ID and resolves the finding from server-side synthetic data; it does not accept arbitrary prompts or alert text from the browser.
- The API holds `OPENAI_API_KEY` and sends only the selected synthetic finding to the OpenAI Responses API. The request sets `store: false`, constrains the response to a schema, limits calls to eight per minute per client IP, and never exposes provider errors or credentials to the browser.
- The model has no tools or host access. Its assessment is advisory and may be wrong; analysts must validate evidence and approve any containment outside this preview. The route is not mounted in connected mode because browser authentication, authorization, and live alert browsing are not yet implemented.
- Configure the key only in the API environment, never in a `VITE_*` variable or browser bundle. Treat any future real alert fields sent to a model as sensitive telemetry and review data handling and organizational policy before enabling that workflow.

## Administrator operations preview

- The demo-only `/api/v1/admin-preview` router is mounted only when `DEMO_MODE=true`. It serves synthetic workspace users, Linux accounts, and selected endpoint-file records, and keeps edits, requests, activity entries, and uploaded evidence in process memory.
- Directory role/status changes, host-account changes, package updates, and endpoint-file removal are illustrative workflows. Host account and endpoint-file requests enter a simulated approval queue. Approving a request sets a preview status only; it does not run a command, contact an endpoint, or alter the requested account, package, or file.
- Endpoint-file requests refer to one listed sample record by ID and show its exact path. This preview has no wildcard or bulk deletion. It does not remove files from a user’s computer or from the SecureWatch application host.
- Evidence uploads accept a small set of file extensions and check basic content signatures. The API retains bytes in memory (10 MiB per file, 100 MiB total); restart clears them. Removing evidence deletes only that app-managed in-memory preview record.
- The preview has no login, session identity, enforced admin authorization, durable audit log, retention policy, host agent, or real identity directory. API users on an exposed instance could alter the demo records. Bind it to loopback and never treat these controls as a security boundary.

## Read-only Linux agent

- `agents/linux/securewatch_agent.py` is a standard-library Python service for Linux. It runs as a dedicated non-login system account with a hardened systemd unit and no Linux capabilities. Its only network operation is an outbound HTTPS report POST; it has no command channel, updater, account manager, package installer, or file-removal action.
- Each enrolled host uses a distinct 32-byte secret, manually provisioned to the server's `AGENT_KEYS_JSON` mapping and a root-managed client config. The intake signs the exact request bytes with HMAC-SHA256, limits timestamp age, uses a unique nonce collection with a MongoDB TTL index, and validates a strict bounded schema before persisting the latest report per agent.
- The agent sends OS/kernel/uptime and resource metrics, aggregate network interface/socket counters, interactive account names and UIDs, cached APT update counts, and (when journal access permits) five-minute SSH authentication and sudo event counts. It omits peer IPs, packet payloads, credentials, password hashes, command history, home-directory files, sudo command text, and authentication log lines. Journal-derived counts can be unavailable when access is restricted.
- The connected API applies fixed host-level rules: 10 or more SSH failures in five minutes, the same failure burst with one or more SSH successes in that host window, and 20 or more sudo journal entries in five minutes. The second rule only means the counts co-occurred on a host; it cannot identify whether the same account or source was involved. These are analyst-review signals, not proof of compromise.
- Matched alerts are persisted in MongoDB and deduplicated by agent, rule, and UTC day. `sightings` counts matching reports and `peakCount` preserves the highest aggregate count for that daily alert. The alert model currently has a state field but no authenticated review API or UI workflow.
- The API binds to loopback. Remote clients require a TLS reverse proxy that preserves the request body and `X-SW-*` headers. Do not expose MongoDB or the API listener directly. Set API rate limits to match fleet size and agent interval.
- Latest reports and deduplicated endpoint alerts are stored in MongoDB; the current browser UI still shows synthetic demo alerts and does not query live reports or alerts. No browser login or RBAC exists, so do not add a public report-list endpoint before administrator authentication and authorization are implemented.
- The shared secret is a host credential. Protect the client config and server `.env`, provision one key per host, and rotate a key by changing both sides. The current project has no enrollment or automated secret rotation workflow.

## Known gaps before production use

The preview has no dashboard login, RBAC, refresh-token rotation, durable administrative audit model, event retention, WebSocket authorization, TLS proxy, backup/restore procedure, or production monitoring. The read-only agent intake and fixed detection rules are an initial authenticated ingestion boundary, not a complete production SIEM deployment. A host-control agent must add server-enforced user/admin authorization, constrained per-host actions, reversible quarantine and restore, approval separation, and tamper-resistant audit records before it can perform changes. Keep this project a local development foundation until the required controls are implemented and verified. Existing tests are health-route tests, not a security certification.
