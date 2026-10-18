#!/usr/bin/env python3
"""Read-only SecureWatch Linux endpoint monitor. Python 3 standard library only."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

VERSION = "0.2.0"
DEFAULT_CONFIG = "/etc/securewatch-agent/agent.json"
logger = logging.getLogger("securewatch-agent")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    except OSError:
        return platform.system(), platform.release()
    return values.get("PRETTY_NAME", values.get("NAME", "Linux")), values.get("VERSION_ID", "unknown")


def cpu_usage() -> float | None:
    def sample() -> tuple[int, int] | None:
        try:
            fields = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()[1:]
            values = [int(value) for value in fields]
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            return sum(values), idle
        except (OSError, ValueError, IndexError):
            return None

    before = sample()
    if before is None:
        return None
    time.sleep(0.2)
    after = sample()
    if after is None:
        return None
    total_delta = after[0] - before[0]
    idle_delta = after[1] - before[1]
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 1)


def memory_usage() -> dict[str, int] | None:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            key, value = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable"}:
                values[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    if "MemTotal" not in values or "MemAvailable" not in values:
        return None
    total = values["MemTotal"]
    available = min(total, values["MemAvailable"])
    return {"totalBytes": total, "availableBytes": available, "usedPercent": round((total - available) / total * 100, 1) if total else 0}


def disk_usage() -> dict[str, int] | None:
    try:
        usage = shutil.disk_usage("/")
        return {"mountpoint": "/", "totalBytes": usage.total, "freeBytes": usage.free, "usedPercent": round(usage.used / usage.total * 100, 1) if usage.total else 0}
    except OSError:
        return None


def network_interfaces() -> list[dict[str, int | str]]:
    result: list[dict[str, int | str]] = []
    root = Path("/sys/class/net")
    try:
        names = sorted(item.name for item in root.iterdir() if item.name != "lo")[:32]
    except OSError:
        return result
    for name in names:
        try:
            stats = root / name / "statistics"
            result.append({
                "name": name[:64],
                "rxBytes": int((stats / "rx_bytes").read_text(encoding="ascii").strip()),
                "txBytes": int((stats / "tx_bytes").read_text(encoding="ascii").strip()),
            })
        except (OSError, ValueError):
            continue
    return result


def connection_counts() -> dict[str, int]:
    counts = {"tcpEstablished": 0, "tcpListening": 0, "tcpTimeWait": 0, "udpSockets": 0}
    for filename in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = Path(filename).read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 4:
                continue
            state = fields[3]
            if state == "01":
                counts["tcpEstablished"] += 1
            elif state == "0A":
                counts["tcpListening"] += 1
            elif state == "06":
                counts["tcpTimeWait"] += 1
    for filename in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            counts["udpSockets"] += max(0, len(Path(filename).read_text(encoding="ascii").splitlines()) - 1)
        except OSError:
            continue
    return counts


def interactive_users() -> list[dict[str, int | str]]:
    users: list[dict[str, int | str]] = []
    try:
        for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines():
            fields = line.split(":")
            if len(fields) != 7:
                continue
            name, _password, uid, _gid, _gecos, _home, shell = fields
            try:
                uid_number = int(uid)
            except ValueError:
                continue
            if uid_number < 1000 or name in {"nobody", "nfsnobody"} or shell.endswith(("/nologin", "/false")) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", name):
                continue
            users.append({"username": name[:64], "uid": uid_number})
            if len(users) >= 200:
                break
    except OSError:
        pass
    return users


def package_updates() -> dict[str, int | str] | None:
    apt_get = shutil.which("apt-get")
    if apt_get:
        try:
            result = subprocess.run(
                [apt_get, "-s", "upgrade"],
                check=False,
                capture_output=True,
                text=True,
                timeout=25,
                env={**os.environ, "LC_ALL": "C"},
            )
            output = (result.stdout + "\n" + result.stderr)[:1_000_000]
            install_lines = [line for line in output.splitlines() if line.startswith("Inst ")]
            security = sum(1 for line in install_lines if "security" in line.casefold() or "-security" in line.casefold())
            if result.returncode == 0:
                return {"packageManager": "apt", "availableUpdates": len(install_lines), "securityUpdates": security, "checkedAt": utc_now()}
        except (OSError, subprocess.TimeoutExpired):
            return None
    return None


def user_activity() -> dict[str, Any]:
    sessions: dict[str, int] | None = None
    who = shutil.which("who")
    if who:
        try:
            result = subprocess.run([who, "-u"], check=False, capture_output=True, text=True, timeout=3, env={**os.environ, "LC_ALL": "C"})
            if result.returncode == 0:
                sessions = {}
                for line in result.stdout.splitlines()[:500]:
                    fields = line.split()
                    if fields and re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", fields[0]):
                        sessions[fields[0]] = sessions.get(fields[0], 0) + 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    journalctl = shutil.which("journalctl")
    ssh_logins: dict[str, int] | None = None
    if not journalctl:
        return {"activeSessions": sessions, "sshLoginsLast5m": None}
    try:
        result = subprocess.run(
            [journalctl, "--since=-5min", "--no-pager", "-o", "cat", "-u", "ssh", "-u", "sshd"],
            check=False,
            capture_output=True,
            text=True,
            timeout=4,
            env={**os.environ, "LC_ALL": "C"},
        )
        if result.returncode == 0:
            text = result.stdout[:1_000_000]
            failed_pattern = re.compile(r"failed password|invalid user|authentication failure", re.IGNORECASE)
            success_pattern = re.compile(r"accepted (?:password|publickey|keyboard-interactive)", re.IGNORECASE)
            lines = text.splitlines()
            ssh_logins = {
                "successful": sum(1 for line in lines if success_pattern.search(line)),
                "failed": sum(1 for line in lines if failed_pattern.search(line)),
            }
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {"activeSessions": sessions, "sshLoginsLast5m": ssh_logins}


def security_events(activity: dict[str, Any]) -> list[dict[str, Any]]:
    """Return bounded, privacy-minimized event aggregates for the last five minutes."""
    events: list[dict[str, Any]] = []
    ssh_logins = activity.get("sshLoginsLast5m")
    if isinstance(ssh_logins, dict):
        for event_type, field in (("ssh_auth_failure", "failed"), ("ssh_auth_success", "successful")):
            count = ssh_logins.get(field)
            if isinstance(count, int) and count > 0:
                events.append({"type": event_type, "count": min(count, 1_000_000), "windowSeconds": 300})

    journalctl = shutil.which("journalctl")
    if journalctl:
        try:
            result = subprocess.run(
                [journalctl, "--since=-5min", "--no-pager", "-o", "cat", "-n", "1000", "-t", "sudo"],
                check=False,
                capture_output=True,
                text=True,
                timeout=4,
                env={**os.environ, "LC_ALL": "C"},
            )
            if result.returncode == 0:
                count = min(len(result.stdout[:1_000_000].splitlines()), 1_000_000)
                if count:
                    events.append({"type": "sudo_activity", "count": count, "windowSeconds": 300})
        except (OSError, subprocess.TimeoutExpired):
            pass
    return events


def uptime_seconds() -> int | None:
    try:
        return max(0, int(float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])))
    except (OSError, ValueError, IndexError):
        return None


def collect_report(updates: dict[str, int | str] | None = None) -> dict[str, Any]:
    distribution, release = read_os_release()
    activity = user_activity()
    return {
        "schemaVersion": 1,
        "generatedAt": utc_now(),
        "host": {
            "hostname": platform.node()[:255] or "unknown",
            "distribution": distribution[:128],
            "release": release[:64],
            "kernel": platform.release()[:128],
            "architecture": platform.machine()[:64],
            "uptimeSeconds": uptime_seconds(),
        },
        "metrics": {
            "cpuPercent": cpu_usage(),
            "memory": memory_usage(),
            "rootDisk": disk_usage(),
        },
        "users": interactive_users(),
        "userActivity": activity,
        "securityEvents": security_events(activity),
        "packages": updates,
        "network": {
            "interfaces": network_interfaces(),
            "connectionCounts": connection_counts(),
        },
    }


def read_config(filename: str) -> dict[str, Any]:
    path = Path(filename)
    info = path.stat()
    if stat.S_IMODE(info.st_mode) & 0o027:
        raise ValueError("config_permissions_must_not_allow_other_users")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("config_must_be_an_object")
    agent_id = config.get("agent_id")
    secret = config.get("shared_secret_hex")
    server_url = config.get("server_url")
    interval = config.get("interval_seconds", 60)
    if not isinstance(agent_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", agent_id):
        raise ValueError("invalid_agent_id")
    if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", secret):
        raise ValueError("shared_secret_must_be_32_bytes_hex")
    if not isinstance(server_url, str):
        raise ValueError("server_url_required")
    parsed = urllib.parse.urlsplit(server_url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise ValueError("server_url_must_use_https_except_loopback_development")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("invalid_server_url")
    if not isinstance(interval, int) or isinstance(interval, bool) or not 30 <= interval <= 3600:
        raise ValueError("interval_seconds_must_be_between_30_and_3600")
    return {"agent_id": agent_id, "secret": bytes.fromhex(secret), "server_url": server_url.rstrip("/"), "interval_seconds": interval}


def report_url(server_url: str) -> str:
    parsed = urllib.parse.urlsplit(server_url)
    base_path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, f"{base_path}/api/v1/agents/report", "", ""))


def send_report(config: dict[str, Any], report: dict[str, Any]) -> int:
    body = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(24)
    body_digest = hashlib.sha256(body).hexdigest()
    signed = f"{config['agent_id']}\n{timestamp}\n{nonce}\n{body_digest}".encode("ascii")
    signature = hmac.new(config["secret"], signed, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        report_url(config["server_url"]),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"SecureWatch-Linux-Agent/{VERSION}",
            "X-SW-Agent-ID": config["agent_id"],
            "X-SW-Timestamp": timestamp,
            "X-SW-Nonce": nonce,
            "X-SW-Signature": signature,
        },
    )
    try:
        opener = urllib.request.build_opener(NoRedirectHandler())
        with opener.open(request, timeout=15) as response:
            response.read(4096)
            return response.status
    except urllib.error.HTTPError as error:
        error.read(4096)
        raise RuntimeError(f"controller_rejected_report_http_{error.code}") from None


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: urllib.request.Request, response: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


def run(config: dict[str, Any], once: bool) -> None:
    last_update_check: float | None = None
    cached_updates: dict[str, int | str] | None = None
    while True:
        now = time.monotonic()
        if last_update_check is None or now - last_update_check >= 3600:
            cached_updates = package_updates()
            last_update_check = now
        report = collect_report(cached_updates)
        try:
            status = send_report(config, report)
            logger.info("report accepted status=%d agent_id=%s", status, config["agent_id"])
        except Exception as error:  # Avoid logging request bodies, URLs, or credentials.
            logger.warning("report failed agent_id=%s reason=%s", config["agent_id"], type(error).__name__)
        if once:
            return
        time.sleep(config["interval_seconds"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only SecureWatch Linux endpoint monitor")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to the root-managed JSON configuration")
    parser.add_argument("--once", action="store_true", help="Collect and send one report, then exit")
    parser.add_argument("--check", action="store_true", help="Validate configuration without connecting to the controller")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if not sys.platform.startswith("linux"):
        logger.error("unsupported operating system; this agent requires Linux")
        return 2
    try:
        config = read_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        reason = str(error) if isinstance(error, ValueError) and str(error).startswith(("config_", "invalid_", "shared_", "server_", "interval_")) else type(error).__name__
        logger.error("invalid configuration reason=%s", reason)
        return 2
    if args.check:
        logger.info("configuration valid agent_id=%s", config["agent_id"])
        return 0
    run(config, args.once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
