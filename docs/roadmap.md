# Implementation roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Repository foundation, environment configuration, MongoDB connection, API health checks | Implemented in this workspace |
| 2 | Authentication, administrator bootstrap, RBAC | Planned |
| 3 | Event schemas, ingestion, listing, pagination | HMAC-authenticated Linux report intake validates bounded SSH/sudo event aggregates; general event search and pagination planned |
| 4 | Detection rules, alert generation, deduplication | Initial SSH failure/success and sudo-volume rules persist host-level daily-deduplicated alerts; configurable rules and analyst workflow planned |
| 5 | React dashboard, charts, event explorer, alert management | Dashboard preview implemented with synthetic endpoint and network detections; live report/alert views and alert management planned until browser authentication is implemented |
| 6 | Incident workflow, notes, assignments, audit logs | Planned |
| 7 | Python detection engine and authorized Ubuntu log collection | Read-only Linux agent reports aggregate host, account, patch, network, SSH, and sudo telemetry; authenticated intake and initial API-side endpoint rules implemented |
| 8 | Authenticated WebSocket delivery | Planned |
| 9 | Reports, CSV export, collector administration, retention | Planned |
| 10 | Security testing, production deployment, monitoring, documentation | Planned |

Each phase will update implementation status only after its code and requested verification are complete. The dashboard preview is simulated: no real endpoint is connected to the browser, no packet sensor is deployed, and no package manager changes are made.
