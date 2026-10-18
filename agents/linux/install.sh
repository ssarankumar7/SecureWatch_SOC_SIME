#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer with sudo: sudo $0 /path/to/agent.json" >&2
  exit 1
fi

if [[ "$#" -ne 1 || ! -f "$1" ]]; then
  echo "Usage: sudo $0 /path/to/agent.json" >&2
  exit 2
fi

CONFIG_SOURCE="$(readlink -f -- "$1")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_MODE="$(stat -c '%a' "${CONFIG_SOURCE}")"
if (( (8#${CONFIG_MODE} & 8#077) != 0 )); then
  echo "Protect the configuration first: chmod 600 '${CONFIG_SOURCE}'" >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/securewatch_agent.py" --config "${CONFIG_SOURCE}" --check

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for this installer." >&2
  exit 1
fi

if ! getent passwd securewatch-agent >/dev/null; then
  useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin securewatch-agent
fi

if ! getent group securewatch-agent >/dev/null; then
  groupadd --system securewatch-agent
fi

install -d -o root -g root -m 0755 /opt/securewatch-agent
install -o root -g root -m 0755 "${SCRIPT_DIR}/securewatch_agent.py" /opt/securewatch-agent/securewatch_agent.py
install -d -o root -g securewatch-agent -m 0750 /etc/securewatch-agent
install -o root -g securewatch-agent -m 0640 "${CONFIG_SOURCE}" /etc/securewatch-agent/agent.json
install -o root -g root -m 0644 "${SCRIPT_DIR}/securewatch-agent.service" /etc/systemd/system/securewatch-agent.service

systemctl daemon-reload
systemctl enable --now securewatch-agent.service

echo "SecureWatch agent installed. Check status with: systemctl status securewatch-agent"
echo "Logs: journalctl -u securewatch-agent -f"
