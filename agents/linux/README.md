# SecureWatch Linux agent

The first agent release is an **outbound-only, read-only monitor** for Linux systems you administer. It uses Python 3's standard library and a hardened systemd unit. It has no remote shell, downloader, self-update mechanism, or remediation actions.

## Data it reports

- Hostname, OS release, kernel, architecture, uptime, CPU, memory, and root filesystem usage.
- Local interactive account names and UIDs from `/etc/passwd`, plus active session counts by username when `who` is available; it does not read `/etc/shadow`, home-directory contents, SSH keys, or command history.
- Network interface byte counters and aggregate TCP/UDP socket counts. It does not report peer IP addresses or packet contents.
- Aggregate successful and failed SSH authentication counts over the last five minutes when `journalctl` is readable to the service account; otherwise these counts are `null`. Login log lines, usernames, and source IPs are not sent.
- Privacy-minimized five-minute security event aggregates for SSH failures, SSH successes, and sudo journal entries. The agent sends only an event type, count, and fixed window; it does not send raw logs, account names from log entries, source IPs, or sudo command text.
- Available and security update counts from the locally cached APT package metadata. The count is refreshed hourly. It does not update package indexes or install anything.

Reports are sent every 60 seconds by default (configurable from 30 to 3,600 seconds). The API stores the latest report per enrolled agent and evaluates initial rules: 10 or more SSH failures in five minutes, a failure burst with at least one SSH success in the same host window, and 20 or more sudo entries in five minutes. Matching alerts are deduplicated by agent, rule, and UTC day. Host-level co-occurrence cannot determine whether the same account or source was involved; findings require analyst review. The current web console is still a demo and does not display live reports or alerts; operator login and read authorization must be added before exposing them in the UI.

## Server requirements

1. Run the API in connected mode with MongoDB configured (`DEMO_MODE=false`). The API creates the report and replay-protection indexes at startup.
2. Keep the API listener on loopback and route `POST /api/v1/agents/report` through a TLS reverse proxy. Do not publish the raw API listener or MongoDB port to the internet. The proxy must preserve the request body and `X-SW-*` headers.
3. Create a unique agent ID and a unique 32-byte (64 hex character) key for each host. Add the ID-to-key mapping to the server's private `.env` file:

   ```dotenv
   AGENT_KEYS_JSON='{"customer-a-host-001":"REPLACE_WITH_64_HEX_CHARACTERS"}'
   ```

   Generate a key with `openssl rand -hex 32`. Keep `.env` owner-readable only and never commit it. Restart the API after changing agent keys. The API validates an HMAC-SHA256 signature, a two-minute timestamp window, and a unique nonce before storing a report.

The agent posts to `${server_url}/api/v1/agents/report`. Remote URLs must use HTTPS and a certificate trusted by the client's operating system. Plain HTTP is permitted only for loopback development.

## Client installation (Ubuntu/Debian with systemd)

1. Copy `agent.example.json` to a protected location on the client, then set a unique `agent_id`, the SecureWatch HTTPS origin, and the matching per-host secret:

   ```bash
   sudo install -d -o root -g root -m 0700 /root/securewatch-agent-config
   sudoedit /root/securewatch-agent-config/agent.json
   sudo chmod 600 /root/securewatch-agent-config/agent.json
   ```

   Use JSON, for example:

   ```json
   {
     "agent_id": "customer-a-host-001",
     "server_url": "https://securewatch.example.com",
     "shared_secret_hex": "THE_MATCHING_64_HEX_CHARACTER_KEY",
     "interval_seconds": 60
   }
   ```

2. Copy this repository's `agents/linux` directory to the client through your normal approved software distribution channel. Run the installer from that directory:

   ```bash
   sudo ./install.sh /root/securewatch-agent-config/agent.json
   ```

   The installer validates the config and creates a `securewatch-agent` system user with no login shell. The running service has no Linux capabilities and cannot write to the host filesystem.

3. Confirm the service and its latest status:

   ```bash
   sudo systemctl status securewatch-agent
   sudo journalctl -u securewatch-agent --since "10 minutes ago"
   ```

The agent automatically retries on its next reporting interval after a network or server outage. It logs report acceptance or a generic error, never the report body, key, or signed headers.

## Uninstall and key rotation

On the client, stop and remove the unit and files using your normal change process:

```bash
sudo systemctl disable --now securewatch-agent
sudo rm -f /etc/systemd/system/securewatch-agent.service
sudo rm -rf /opt/securewatch-agent /etc/securewatch-agent
sudo systemctl daemon-reload
sudo userdel securewatch-agent
```

For key rotation, provision a new per-host key in the API and the client configuration through your secret-management process, then restart the service. If a key is compromised, remove its agent ID from `AGENT_KEYS_JSON` immediately.

## Current boundaries

- No remote account lock/unlock, package installation, file deletion, or arbitrary command execution is implemented.
- No dashboard login, RBAC, live report/alert query screen, configurable rules, alert workflow, or general event history is implemented yet. Reports overwrite the latest snapshot for each agent; replay nonces expire after ten minutes. Alert records store rule, host, severity, counts, timestamps, a daily dedupe key, and a basic state; they do not contain raw log lines.
- SSH failure aggregates can be unavailable when the host's journal is not readable by the unprivileged service account. Do not add broad log-reading privileges without reviewing the host's access policy.
- The key mapping is manually provisioned. There is no public enrollment endpoint.
