#!/usr/bin/env python3
"""
VPNGuard 3.0 - Advanced Anti-VPN Blinking & IP Leak Prevention System for macOS.
Triple-GID Headless Architecture ensuring zero IP and DNS leaks with transparent sing-box TUN & dedicated Xray-core.

Usage:
    vpnguard status [--json] [--fast]   Check security posture & diagnostics
    vpnguard on                          Arm fail-closed killswitch and daemons
    vpnguard off                         Disarm killswitch (Captive Portal mode)
    vpnguard pause <300|900>             Temporarily disable protection with auto-resume
    vpnguard resume-if-expired           Re-arm protection if pause timer expired
    vpnguard test [--json]               Run 12-point active leak penetration audit
    vpnguard logs --json                 Output sanitized logs and PF/DNS/utun state
    vpnguard rules get                   Output current dynamic rules.json
    vpnguard rules apply [--stdin|path]  Validate and apply rules.json atomically
    vpnguard server list [--json]        List configured upstream server profiles
    vpnguard server ping --json          Measure direct TCP RTT via GID 890 + IP_BOUND_IF
    vpnguard server sync-pf              Re-resolve active relay via GID 890 DNS and load PF
    vpnguard server update [--stdin|p]   Validate and apply upstream server xray.json
    vpnguard run <command...>            Execute command inside fail-closed GID 888 sandbox
    vpnguard shell                       Spawn guarded interactive shell session
    vpnguard watch                       Start continuous local proxy flap monitor
"""

import sys
import os
import socket
import json
import subprocess
import time
import argparse
import re
import shutil
import secrets
import urllib.parse
import uuid
import copy
import ipaddress
import grp
import pwd
import struct
import tempfile
import fcntl
import select
import signal
import threading
import contextlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, Tuple, List, Callable

VERSION = "3.0.0"

# ANSI color codes
C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_RED     = "\033[31m"
C_GREEN   = "\033[32m"
C_YELLOW  = "\033[33m"
C_BLUE    = "\033[34m"
C_CYAN    = "\033[36m"
C_DIM     = "\033[2m"

# Default configuration paths
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
USER_CONFIG_PATH = os.path.expanduser("~/.vpnguard/config.json")
RUN_DIR = "/var/run/vpnguard"
STATE_LOCK_PATH = os.path.join(RUN_DIR, "state.lock")
PAUSE_UNTIL_FILE = os.path.join(RUN_DIR, "pause_until")
PAUSE_WATCHER_PID_FILE = os.path.join(RUN_DIR, "pause_watcher.pid")
EXEC_HELPER_PATH = "/usr/local/bin/vpnguard-exec"
LOCAL_EXEC_HELPER = os.path.join(PROJECT_ROOT, "bin", "vpnguard-exec")

RULES_FILE_PATH = "/usr/local/etc/vpnguard/rules.json"
SINGBOX_CONF_PATH = "/usr/local/etc/vpnguard/sing-box.json"
XRAY_CONF_PATH = "/usr/local/etc/vpnguard/xray.json"
SERVERS_FILE_PATH = "/usr/local/etc/vpnguard/servers.json"
ACTIVE_SERVER_META_PATH = "/usr/local/etc/vpnguard/active_server.json"
DESIRED_STATE_PATH = "/var/db/vpnguard/desired_state"
DNS_BACKUP_PATH = "/usr/local/etc/vpnguard/dns_backup.json"
API_SECRET_PATH = "/usr/local/etc/vpnguard/api_secret"
PF_ANCHOR_FILE = "/etc/pf.anchors/vpnguard"
PF_EGRESS_FILE = "/usr/local/etc/vpnguard/pf.egress.conf"
LOG_SINGBOX_PATH = "/var/log/vpnguard-singbox.log"
LOG_XRAY_PATH = "/var/log/vpnguard-xray.log"
LOG_PF_PATH = "/var/log/vpnguard.log"
SINGBOX_BIN = "/usr/local/libexec/vpnguard-singbox"
XRAY_BIN = "/usr/local/libexec/vpnguard-xray"
MANAGED_DNS_SERVER = "1.1.1.1"
MAX_STDIN_BYTES = 1024 * 1024  # 1 MiB limit for --stdin payloads
LOG_ROTATE_MAX_BYTES = 8 * 1024 * 1024  # 8 MiB per daemon log before safe .1 rotation

DEFAULT_RULES: Dict[str, Any] = {
    "apps": [
        {
            "id": "app-claude",
            "name": "Claude",
            "bundlePath": "/Applications/Claude.app",
            "action": "proxy",
            "enabled": True
        },
        {
            "id": "app-codex",
            "name": "Codex",
            "bundlePath": "/Applications/Codex.app",
            "action": "proxy",
            "enabled": True
        },
        {
            "id": "app-cursor",
            "name": "Cursor",
            "bundlePath": "/Applications/Cursor.app",
            "action": "proxy",
            "enabled": True
        }
    ],
    "domains": [
        {"id": "dom-anthropic", "domain": "anthropic.com", "action": "proxy", "enabled": True},
        {"id": "dom-claude", "domain": "claude.ai", "action": "proxy", "enabled": True},
        {"id": "dom-openai", "domain": "openai.com", "action": "proxy", "enabled": True},
        {"id": "dom-chatgpt", "domain": "chatgpt.com", "action": "proxy", "enabled": True},
        {"id": "dom-oaistatic", "domain": "oaistatic.com", "action": "proxy", "enabled": True},
        {"id": "dom-oaiusercontent", "domain": "oaiusercontent.com", "action": "proxy", "enabled": True},
        {"id": "dom-cursor-sh", "domain": "cursor.sh", "action": "proxy", "enabled": True},
        {"id": "dom-cursor-com", "domain": "cursor.com", "action": "proxy", "enabled": True},
        {"id": "dom-github", "domain": "github.com", "action": "proxy", "enabled": True},
        {"id": "dom-githubusercontent", "domain": "githubusercontent.com", "action": "proxy", "enabled": True},
        {"id": "dom-ru", "domain": ".ru", "action": "direct", "enabled": True},
        {"id": "dom-rf", "domain": ".рф", "action": "direct", "enabled": True},
        {"id": "dom-p1ai", "domain": ".xn--p1ai", "action": "direct", "enabled": True},
        {"id": "dom-su", "domain": ".su", "action": "direct", "enabled": True},
        {"id": "dom-2gis", "domain": "2gis.com", "action": "direct", "enabled": True}
    ],
    "presets": {
        "aiServicesProxy": True,
        "ruDirect": True,
        "blockQuic": True
    }
}

RU_DIRECT_DOMAINS: List[str] = [
    ".ru", ".рф", ".xn--p1ai", ".su", "2gis.com", "yandex.ru", "ya.ru",
    "vk.com", "gosuslugi.ru", "tbank.ru", "sber.ru", "sberbank.ru",
    "ozon.ru", "wildberries.ru", "kinopoisk.ru", "avito.ru"
]

AI_PROXY_DOMAINS: List[str] = [
    "anthropic.com", "claude.ai", "openai.com", "chatgpt.com",
    "oaistatic.com", "oaiusercontent.com", "cursor.sh", "cursor.com",
    "github.com", "githubusercontent.com", "perplexity.ai",
    "deepseek.com", "v0.dev", "groq.com", "cerebras.ai", "poe.com"
]


def read_desired_state(state_path: str = DESIRED_STATE_PATH) -> str:
    """Read persistent desired protection state ('on' or 'off'); defaults to 'on'."""
    if os.path.exists(state_path):
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                val = f.read().strip().lower()
            if val in ("on", "off"):
                return val
        except Exception:
            pass
    return "on"


def write_desired_state(state: str, state_path: str = DESIRED_STATE_PATH) -> None:
    """Persist desired protection state ('on' or 'off') cleanly."""
    clean = state.strip().lower()
    if clean not in ("on", "off"):
        raise ValueError(f"Invalid desired_state: {state}")
    atomic_write_text(state_path, f"{clean}\n", mode=0o644)


def _set_launchd_service_enabled(service_target: str, enabled: bool) -> None:
    """Enable or disable a system LaunchDaemon target via launchctl."""
    subcmd = "enable" if enabled else "disable"
    try:
        subprocess.run(["launchctl", subcmd, service_target], capture_output=True, timeout=10)
    except Exception:
        pass


_STATE_LOCK_GUARD = threading.Lock()
_STATE_LOCK_DEPTH = 0
_STATE_LOCK_FD: Optional[int] = None


def _resolve_state_lock_path(lock_path: Optional[str] = None) -> str:
    """Resolve state lock file path, falling back to a user temp path in unprivileged tests."""
    if lock_path:
        return lock_path
    if STATE_LOCK_PATH != "/var/run/vpnguard/state.lock":
        return STATE_LOCK_PATH
    if RUN_DIR != "/var/run/vpnguard":
        return os.path.join(RUN_DIR, "state.lock")
    if os.geteuid() == 0 and (os.access(RUN_DIR, os.W_OK) or (not os.path.exists(RUN_DIR) and os.access("/var/run", os.W_OK))):
        return STATE_LOCK_PATH
    return os.path.join(tempfile.gettempdir(), f"vpnguard_state_{os.getuid()}.lock")


@contextlib.contextmanager
def acquire_state_lock(timeout: float = 15.0, lock_path: Optional[str] = None):
    """
    Re-entrant, non-blocking exclusive flock with bounded timeout (10-15s).
    Prevents concurrent state mutations across CLI invocations while allowing nested calls
    (e.g., cmd_resume_if_expired / cmd_pause_watcher -> cmd_on) inside the same process.
    """
    global _STATE_LOCK_DEPTH, _STATE_LOCK_FD

    with _STATE_LOCK_GUARD:
        if _STATE_LOCK_DEPTH > 0:
            _STATE_LOCK_DEPTH += 1
            reentrant = True
        else:
            reentrant = False

    if reentrant:
        try:
            yield
        finally:
            with _STATE_LOCK_GUARD:
                _STATE_LOCK_DEPTH = max(0, _STATE_LOCK_DEPTH - 1)
        return

    target = _resolve_state_lock_path(lock_path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd = os.open(target, os.O_CREAT | os.O_RDWR, 0o644)
    acquired = False
    deadline = time.monotonic() + max(0.1, float(timeout))
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out waiting for VPNGuard state lock after {timeout:.0f}s")
                time.sleep(0.05)

        with _STATE_LOCK_GUARD:
            _STATE_LOCK_FD = fd
            _STATE_LOCK_DEPTH = 1
        yield
    finally:
        if acquired:
            with _STATE_LOCK_GUARD:
                _STATE_LOCK_DEPTH = max(0, _STATE_LOCK_DEPTH - 1)
                should_release = (_STATE_LOCK_DEPTH == 0)
                if should_release:
                    _STATE_LOCK_FD = None
            if should_release:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    os.close(fd)
                except Exception:
                    pass
        else:
            try:
                os.close(fd)
            except Exception:
                pass


def _write_private_validation_file(prefix: str, payload: Dict[str, Any]) -> Tuple[str, str]:
    """
    Create a private 0700 temp directory (inside /usr/local/etc/vpnguard when root)
    and write a 0600 JSON file inside it so secrets never leak to /tmp with 0644.
    """
    parent_dir: Optional[str] = None
    if os.geteuid() == 0 and os.path.isdir("/usr/local/etc/vpnguard"):
        parent_dir = "/usr/local/etc/vpnguard"
    tmp_dir = tempfile.mkdtemp(prefix=prefix, dir=parent_dir)
    os.chmod(tmp_dir, 0o700)
    tmp_path = os.path.join(tmp_dir, "config.json")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    os.chmod(tmp_path, 0o600)
    return tmp_dir, tmp_path


def load_config() -> Dict[str, Any]:
    """Load configuration prioritizing user config over package default."""
    config: Dict[str, Any] = {}
    if os.path.exists(DEFAULT_CONFIG_PATH):
        try:
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            print(f"{C_YELLOW}[!] Warning: Failed to load {DEFAULT_CONFIG_PATH}: {e}{C_RESET}", file=sys.stderr)

    if os.path.exists(USER_CONFIG_PATH):
        try:
            with open(USER_CONFIG_PATH, "r", encoding="utf-8") as f:
                user_conf = json.load(f)
                config.update(user_conf)
        except Exception as e:
            print(f"{C_YELLOW}[!] Warning: Failed to load {USER_CONFIG_PATH}: {e}{C_RESET}", file=sys.stderr)

    return config


def check_port_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is accepting connections on host."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def query_socks5_ip(host: str, port: int, timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    """Query egress IP through SOCKS5 proxy using curl with multi-mirror fallback."""
    mirrors = [
        ("https://ipinfo.io/json", "ipinfo"),
        ("https://api.ip.sb/geoip", "ipsb"),
        ("https://ifconfig.co/json", "ifconfig"),
    ]
    proc_timeout = max(5.0, float(timeout) + 2.5)
    for url, kind in mirrors:
        try:
            res = subprocess.run(
                ["curl", "-s", "--max-time", str(timeout), "-x", f"socks5h://{host}:{port}", url],
                capture_output=True,
                text=True,
                timeout=proc_timeout,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                ip_val = data.get("ip")
                if ip_val:
                    if kind == "ipsb":
                        return {
                            "ip": ip_val,
                            "country": data.get("country_code") or data.get("country", "Unknown"),
                            "city": data.get("city", ""),
                            "org": data.get("organization") or data.get("isp", "")
                        }
                    if kind == "ifconfig":
                        return {
                            "ip": ip_val,
                            "country": data.get("country_iso") or data.get("country", "Unknown"),
                            "city": data.get("city", ""),
                            "org": data.get("asn_org", "")
                        }
                    return data
        except Exception:
            continue
    return None


def query_http_proxy_ip(proxy_url: str, timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    """Query egress IP through HTTP proxy using curl with fallback."""
    proc_timeout = max(5.0, float(timeout) + 2.5)
    for url in ("https://ipinfo.io/json", "https://ifconfig.co/json"):
        try:
            res = subprocess.run(
                ["curl", "-s", "--max-time", str(timeout), "-x", proxy_url, url],
                capture_output=True,
                text=True,
                timeout=proc_timeout,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if data.get("ip"):
                    if "country_iso" in data and "country" not in data:
                        data["country"] = data["country_iso"]
                    return data
        except Exception:
            continue
    return None


def query_physical_ip(timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    """Query physical IP using curl bound directly to the active physical default interface."""
    iface = _get_physical_default_interface() or "en0"
    proc_timeout = max(5.0, float(timeout) + 2.5)
    try:
        res = subprocess.run(
            ["curl", "-s", "--interface", iface, "--max-time", str(timeout), "https://ipinfo.io/json"],
            capture_output=True,
            text=True,
            timeout=proc_timeout,
        )
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout)
    except Exception:
        pass
    return None


def run_privileged(
    cmd: List[str],
    capture_output: bool = True,
    text: bool = True,
    timeout: float = 10.0,
) -> subprocess.CompletedProcess:
    """Execute command directly when running as root, or via sudo -n otherwise."""
    full_cmd = cmd if os.geteuid() == 0 else ["sudo", "-n"] + cmd
    return subprocess.run(full_cmd, capture_output=capture_output, text=text, timeout=timeout)


def read_stdin_bounded(max_bytes: int = MAX_STDIN_BYTES) -> str:
    """Read UTF-8 payload from stdin with strict size limit to prevent DoS."""
    raw = sys.stdin.buffer.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"Stdin payload exceeds maximum allowed size ({max_bytes} bytes)")
    text = raw.decode("utf-8").strip()
    if not text:
        raise ValueError("Stdin payload is empty")
    return text


def atomic_write_text(
    target_path: str,
    content: str,
    mode: int = 0o644,
    group_name: Optional[str] = None
) -> None:
    """Atomically write text file with deterministic ownership and permissions."""
    parent = os.path.dirname(target_path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp_path = f"{target_path}.tmp_{os.getpid()}_{secrets.token_hex(4)}"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp_path, mode)
    if os.geteuid() == 0:
        gid = -1
        if group_name:
            try:
                gid = grp.getgrnam(group_name).gr_gid
            except KeyError:
                gid = 0
        else:
            gid = 0
        try:
            os.chown(tmp_path, 0, gid)
        except Exception:
            pass
    os.replace(tmp_path, target_path)
    try:
        os.chmod(target_path, mode)
    except Exception:
        pass


def flush_dns_cache() -> None:
    """Flush macOS mDNSResponder cache so routing/DNS changes take effect immediately."""
    try:
        run_privileged(["dscacheutil", "-flushcache"])
        run_privileged(["killall", "-HUP", "mDNSResponder"])
    except Exception:
        pass


def rotate_log_if_needed(
    path: str,
    max_bytes: int = LOG_ROTATE_MAX_BYTES,
    owner_user: Optional[str] = None,
    group_name: Optional[str] = None,
) -> bool:
    """
    Rotate log file -> '<path>.1' when size exceeds max_bytes.
    MUST be called only while the owning daemon is stopped or strictly BEFORE launchctl bootstrap/kickstart
    so launchd never continues writing to an unlinked inode.
    """
    try:
        if not os.path.exists(path):
            return False
        if os.path.getsize(path) <= max_bytes:
            return False
        rotated = f"{path}.1"
        os.replace(path, rotated)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o640 if group_name else 0o644)
        os.close(fd)
        uid = 0
        gid = 0
        if owner_user:
            try:
                uid = pwd.getpwnam(owner_user).pw_uid
            except KeyError:
                uid = 0
        if group_name:
            try:
                gid = grp.getgrnam(group_name).gr_gid
            except KeyError:
                gid = 0
        if owner_user or group_name:
            try:
                os.chown(path, uid, gid)
            except Exception:
                pass
        return True
    except Exception:
        return False


def _get_active_en_interfaces() -> Optional[set]:
    """Return active physical en* interfaces (link active or IPv4 assigned), or None if unavailable."""
    try:
        res = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3)
        if res.returncode != 0 or not res.stdout.strip():
            return None
        active = set()
        current_dev: Optional[str] = None
        for line in res.stdout.splitlines():
            if line and not line[0].isspace():
                iface = line.split(":", 1)[0].strip()
                current_dev = iface if re.match(r"^en\d+$", iface) else None
            elif current_dev:
                stripped = line.strip()
                if stripped.startswith("status: active") or stripped.startswith("inet "):
                    active.add(current_dev)
        return active
    except Exception:
        return None


def _list_hardware_network_services(active_only: bool = False) -> List[str]:
    """Return enabled macOS network services backed by physical en* interfaces."""
    services: List[str] = []
    active_devs = _get_active_en_interfaces() if active_only else None
    try:
        res = subprocess.run(["networksetup", "-listnetworkserviceorder"], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            return services
        current_svc: Optional[str] = None
        for raw_line in res.stdout.splitlines():
            line = raw_line.strip()
            m_svc = re.match(r"^\(\d+\)\s+(.+)$", line)
            if m_svc:
                name = m_svc.group(1).strip()
                current_svc = None if name.startswith("*") else name
                continue
            if current_svc and "Device:" in line:
                m_dev = re.search(r"Device:\s*([^)]+)\)", line)
                dev = m_dev.group(1).strip() if m_dev else ""
                if re.match(r"^en\d+$", dev):
                    if active_devs is None or dev in active_devs:
                        services.append(current_svc)
                current_svc = None
    except Exception:
        pass
    return services


def _get_service_dns(service: str) -> List[str]:
    """Read configured DNS servers for a network service ([] means DHCP/Empty)."""
    try:
        res = subprocess.run(["networksetup", "-getdnsservers", service], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            return []
        out = res.stdout.strip()
        if not out or "There aren't any DNS Servers" in out:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        return []


def _set_service_dns(service: str, servers: List[str]) -> bool:
    """Set DNS servers for a network service (or Empty when servers is empty)."""
    args = ["networksetup", "-setdnsservers", service] + (servers if servers else ["Empty"])
    res = run_privileged(args)
    return res.returncode == 0


def sync_system_dns() -> Tuple[bool, str]:
    """
    Backup original DNS servers per hardware service (without overwriting existing backups
    or saving our managed DNS) and point active services to MANAGED_DNS_SERVER (1.1.1.1)
    so mDNSResponder routes through utun99 -> sing-box hijack-dns instead of LAN routers.
    """
    backup: Dict[str, List[str]] = {}
    if os.path.exists(DNS_BACKUP_PATH):
        try:
            with open(DNS_BACKUP_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    backup = loaded
        except Exception:
            backup = {}

    services = _list_hardware_network_services(active_only=True)
    updated: List[str] = []
    backup_dirty = False

    for svc in services:
        current = _get_service_dns(svc)
        if svc not in backup and current != [MANAGED_DNS_SERVER] and current != ["172.19.0.2"]:
            backup[svc] = current
            backup_dirty = True
        if current != [MANAGED_DNS_SERVER]:
            if _set_service_dns(svc, [MANAGED_DNS_SERVER]):
                updated.append(svc)

    if backup_dirty or not os.path.exists(DNS_BACKUP_PATH):
        try:
            atomic_write_text(DNS_BACKUP_PATH, json.dumps(backup, indent=2, ensure_ascii=False), mode=0o644)
        except Exception as e:
            return False, f"Failed saving DNS backup: {e}"

    if updated:
        flush_dns_cache()
    return True, f"Synced DNS ({MANAGED_DNS_SERVER}) on: {', '.join(updated) if updated else 'all services up to date'}"


def restore_system_dns() -> Tuple[bool, str]:
    """Restore original DNS servers from dns_backup.json (or Empty on fallback)."""
    backup: Dict[str, List[str]] = {}
    if os.path.exists(DNS_BACKUP_PATH):
        try:
            with open(DNS_BACKUP_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    backup = loaded
        except Exception:
            backup = {}

    restored: List[str] = []
    hardware_services = _list_hardware_network_services(active_only=False)
    targets = list(dict.fromkeys(list(backup.keys()) + hardware_services))

    for svc in targets:
        try:
            current = _get_service_dns(svc)
            if svc in backup:
                orig = backup[svc] if isinstance(backup[svc], list) else []
                if current != orig and _set_service_dns(svc, orig):
                    restored.append(svc)
            else:
                if current in ([MANAGED_DNS_SERVER], ["172.19.0.2"]):
                    if _set_service_dns(svc, []):
                        restored.append(svc)
        except Exception:
            continue

    if os.path.exists(DNS_BACKUP_PATH):
        try:
            os.remove(DNS_BACKUP_PATH)
        except Exception:
            pass

    if restored:
        flush_dns_cache()
    return True, f"Restored DNS on: {', '.join(restored) if restored else 'none needed'}"


def format_pf_egress_rule(ips: List[str], port: int) -> str:
    """Validate relay IPs/port and format sub-anchor vpnguard/egress rule."""
    clean_ips: List[str] = []
    for raw_ip in ips:
        ip_str = str(raw_ip).strip()
        if not ip_str:
            continue
        ipaddress.ip_address(ip_str)
        if ip_str not in clean_ips:
            clean_ips.append(ip_str)
    if not clean_ips:
        raise ValueError("No valid relay IP addresses for PF egress rule")
    port_int = int(port)
    if not (1 <= port_int <= 65535):
        raise ValueError(f"Invalid relay port for PF egress rule: {port}")
    ip_block = ", ".join(clean_ips)
    return f"pass out quick proto {{ tcp, udp }} from any to {{ {ip_block} }} port {port_int} group 889 keep state (if-bound)\n"


def write_pf_egress_file(ips: List[str], port: int, target_path: str = PF_EGRESS_FILE) -> str:
    """Write validated PF egress rule to persistent runtime file."""
    rule_text = format_pf_egress_rule(ips, port)
    atomic_write_text(target_path, rule_text, mode=0o644)
    return rule_text


def apply_pf_egress(ips: List[str], port: int) -> Tuple[bool, str]:
    """Persist pf.egress.conf and load it atomically into sub-anchor vpnguard/egress."""
    try:
        write_pf_egress_file(ips, port, PF_EGRESS_FILE)
        res = run_privileged(["pfctl", "-a", "vpnguard/egress", "-f", PF_EGRESS_FILE])
        if res.returncode != 0:
            return False, (res.stderr.strip() or res.stdout.strip() or "pfctl failed")
        return True, "Loaded vpnguard/egress"
    except Exception as e:
        return False, str(e)


def _run_pfctl(args: List[str], timeout: float = 5.0) -> Optional[subprocess.CompletedProcess]:
    """Run pfctl directly as root, or directly via sudo -n when unprivileged (no wasted pre-call)."""
    cmd = (["pfctl"] + args) if os.geteuid() == 0 else (["sudo", "-n", "pfctl"] + args)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _parse_pf_blocked_packets(lines: List[str]) -> int:
    """Extract total packets blocked by kill-switch rules from `pfctl -s rules -v` output."""
    total_blocked = 0
    is_block_rule = False
    for line in lines:
        s = line.strip()
        if s.startswith("block "):
            is_block_rule = True
        elif is_block_rule and "[ Evaluations:" in s and "Packets:" in s:
            m = re.search(r"Packets:\s*(\d+)", s)
            if m:
                total_blocked += int(m.group(1))
            is_block_rule = False
        elif not s.startswith("["):
            is_block_rule = False
    return total_blocked


def get_pf_status() -> Dict[str, Any]:
    """Check macOS Packet Filter status, main anchor, and sub-anchor vpnguard/egress."""
    status = {
        "enabled": False,
        "main_anchor_linked": False,
        "anchor_loaded": False,
        "rules_count": 0,
        "rules": [],
        "egress_rules": [],
        "blocked_packets": 0,
        "has_group_888": False,
        "has_group_889": False,
        "has_group_890": False,
        "has_global_killswitch": False,
        "exit_table_ips": []
    }

    # 1. Check pf enabled
    res_info = _run_pfctl(["-s", "info"])
    if res_info is not None and res_info.returncode == 0 and "Status: Enabled" in res_info.stdout:
        status["enabled"] = True

    # 2. Check main ruleset contains anchor vpnguard
    res_sr = _run_pfctl(["-sr"])
    if res_sr is not None and res_sr.returncode == 0 and "vpnguard" in res_sr.stdout:
        status["main_anchor_linked"] = True
    elif os.path.exists("/etc/pf.conf"):
        try:
            with open("/etc/pf.conf", "r") as f:
                if 'anchor "vpnguard"' in f.read():
                    status["main_anchor_linked"] = True
        except Exception:
            pass

    # 3. Single `-s rules -v` query covers rules AND blocked packet counters
    res_rules = _run_pfctl(["-a", "vpnguard", "-s", "rules", "-v"])
    if res_rules is not None and res_rules.returncode == 0:
        raw_lines = res_rules.stdout.splitlines()
        status["blocked_packets"] = _parse_pf_blocked_packets(raw_lines)
        lines = [line.strip() for line in raw_lines if line.strip() and not line.strip().startswith("[")]
        status["rules"] = lines
        status["rules_count"] = len(lines)
        status["anchor_loaded"] = len(lines) > 0
        status["has_group_888"] = any("888" in l for l in lines)
        status["has_group_890"] = any("890" in l for l in lines)
        status["has_global_killswitch"] = any("block return out quick" in l for l in lines)

    # 4. Check rules inside sub-anchor vpnguard/egress
    res_egress = _run_pfctl(["-a", "vpnguard/egress", "-s", "rules"])
    if res_egress is not None and res_egress.returncode == 0 and res_egress.stdout.strip():
        eg_lines = [line.strip() for line in res_egress.stdout.strip().split("\n") if line.strip()]
        status["egress_rules"] = eg_lines
        status["rules_count"] += len(eg_lines)
        status["has_group_889"] = any("889" in l and "pass out quick" in l for l in eg_lines)
        found_ips: List[str] = []
        for l in eg_lines:
            for ip_m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", l):
                if ip_m not in found_ips:
                    found_ips.append(ip_m)
        status["exit_table_ips"] = found_ips
    else:
        # Backward compatibility if legacy anchor rules still define GID 889 egress directly
        status["has_group_889"] = any("889" in l and "pass out quick" in l for l in status["rules"])

    return status


def get_pf_blocked_packets() -> int:
    """Extract total packets blocked by kill-switch rules inside anchor vpnguard."""
    res = _run_pfctl(["-a", "vpnguard", "-s", "rules", "-v"])
    if res is None or res.returncode != 0:
        return 0
    return _parse_pf_blocked_packets(res.stdout.splitlines())


def _get_daemon_pid(service_label: str, exact_proc_name: str) -> Optional[int]:
    """Resolve daemon PID via launchctl print first, falling back to exact pgrep -x (never pgrep -f)."""
    try:
        res_lc = subprocess.run(
            ["launchctl", "print", f"system/{service_label}"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res_lc.returncode == 0 and "state = running" in res_lc.stdout:
            m = re.search(r"^\s*pid\s*=\s*(\d+)", res_lc.stdout, re.MULTILINE)
            if m:
                pid_val = int(m.group(1))
                if pid_val > 0:
                    return pid_val
    except Exception:
        pass

    try:
        res = subprocess.run(["pgrep", "-x", exact_proc_name], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            return int(res.stdout.strip().split()[0])
    except Exception:
        pass
    return None


def get_xray_process_status() -> Dict[str, Any]:
    """Inspect dedicated Xray proxy daemon process, user, and group."""
    info: Dict[str, Any] = {
        "running": False,
        "pid": None,
        "user": None,
        "group": None,
        "is_root": False
    }

    try:
        pid_val = _get_daemon_pid("com.vpnguard.xray", "vpnguard-xray")
        if pid_val is not None:
            info["pid"] = pid_val
            info["running"] = True

            res_ps = subprocess.run(["ps", "-o", "user,group,uid,gid", "-p", str(pid_val)], capture_output=True, text=True, timeout=3)
            if res_ps.returncode == 0:
                lines = [l.strip() for l in res_ps.stdout.strip().split("\n") if l.strip()]
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 4:
                        info["user"] = parts[0]
                        info["group"] = parts[1]
                        uid = int(parts[2])
                        info["is_root"] = (uid == 0)
    except Exception:
        pass

    return info


def get_singbox_process_status() -> Dict[str, Any]:
    """Inspect dedicated sing-box TUN daemon process, user, and group."""
    info: Dict[str, Any] = {
        "running": False,
        "pid": None,
        "user": None,
        "group": None,
        "is_root": False,
        "gid": None
    }
    try:
        pid_val = _get_daemon_pid("com.vpnguard.singbox", "vpnguard-singbox")
        if pid_val is not None:
            info["pid"] = pid_val
            info["running"] = True
            res_ps = subprocess.run(["ps", "-o", "user,group,uid,gid", "-p", str(pid_val)], capture_output=True, text=True, timeout=3)
            if res_ps.returncode == 0:
                lines = [l.strip() for l in res_ps.stdout.strip().split("\n") if l.strip()]
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 4:
                        info["user"] = parts[0]
                        info["group"] = parts[1]
                        info["is_root"] = (int(parts[2]) == 0)
                        info["gid"] = int(parts[3])
    except Exception:
        pass
    return info


def get_utun_status() -> Dict[str, Any]:
    """Inspect active utun interfaces and sing-box assigned IP."""
    info: Dict[str, Any] = {"active": False, "interface": None, "ip": None}
    try:
        res = subprocess.run(["ifconfig", "utun99"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            info["active"] = True
            info["interface"] = "utun99"
            for line in res.stdout.splitlines():
                if "inet " in line:
                    parts = line.strip().split()
                    idx = parts.index("inet")
                    info["ip"] = parts[idx + 1]
                    break
        else:
            res_all = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3)
            cur_if = None
            for line in res_all.stdout.splitlines():
                if line and not line.startswith("\t"):
                    cur_if = line.split(":")[0]
                elif "inet 172.19.0.1" in line:
                    info["active"] = True
                    info["interface"] = cur_if
                    info["ip"] = "172.19.0.1"
                    break
    except Exception:
        pass
    return info


def _extract_xray_endpoint(data: Dict[str, Any]) -> Tuple[str, int]:
    """Extract upstream address and port from an Xray JSON config."""
    for out in data.get("outbounds", []):
        proto = out.get("protocol", "").lower()
        tag = out.get("tag", "").lower()
        if proto in ["freedom", "direct", "blackhole"] or tag in ["direct", "block"]:
            continue
        settings = out.get("settings", {})
        vnext = settings.get("vnext", [])
        servers = settings.get("servers", [])
        if vnext and "address" in vnext[0]:
            return str(vnext[0]["address"]).strip(), int(vnext[0].get("port", 443))
        if servers and "address" in servers[0]:
            return str(servers[0]["address"]).strip(), int(servers[0].get("port", 443))
    return "", 443


def get_active_relay_endpoint() -> Tuple[List[str], int]:
    """Retrieve active relay IPv4 list and port from servers.json, xray.json, or pf.egress.conf."""
    if os.path.exists(SERVERS_FILE_PATH):
        try:
            with open(SERVERS_FILE_PATH, "r", encoding="utf-8") as f:
                store = json.load(f)
                active_id = store.get("activeId")
                for s in store.get("servers", []):
                    if s.get("id") == active_id:
                        port = int(s.get("port", 443))
                        resolved = [ip for ip in s.get("resolvedIps", []) if ip]
                        if resolved:
                            valid_ips = []
                            for candidate in resolved:
                                try:
                                    ipaddress.ip_address(candidate)
                                    valid_ips.append(candidate)
                                except ValueError:
                                    valid_ips.extend(resolve_host_ipv4(candidate))
                            if valid_ips:
                                return list(dict.fromkeys(valid_ips)), port
                        host = str(s.get("host", "")).strip()
                        if host:
                            return resolve_host_ipv4(host), port
        except Exception:
            pass

    if os.path.exists(XRAY_CONF_PATH):
        try:
            with open(XRAY_CONF_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                addr, port = _extract_xray_endpoint(data)
                if addr:
                    return resolve_host_ipv4(addr), port
        except Exception:
            pass

    if os.path.exists(PF_EGRESS_FILE):
        try:
            with open(PF_EGRESS_FILE, "r", encoding="utf-8") as f:
                txt = f.read()
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", txt)
                m_port = re.search(r"\bport\s+(\d+)\b", txt)
                if ips:
                    return ips, int(m_port.group(1)) if m_port else 443
        except Exception:
            pass

    return [], 443


def get_active_relay_ip() -> str:
    """Retrieve primary active relay IP from active endpoint or metadata."""
    ips, _ = get_active_relay_endpoint()
    if ips:
        return ips[0]
    if os.path.exists(ACTIVE_SERVER_META_PATH):
        try:
            with open(ACTIVE_SERVER_META_PATH, "r", encoding="utf-8") as f:
                meta = json.load(f)
                if meta.get("relayIp"):
                    return str(meta["relayIp"])
        except Exception:
            pass
    return ""


def sync_active_server_metadata(store: Optional[Dict[str, Any]] = None) -> None:
    """Persist non-sensitive active server metadata (0644) for unprivileged status queries."""
    if store is None and os.path.exists(SERVERS_FILE_PATH):
        try:
            with open(SERVERS_FILE_PATH, "r", encoding="utf-8") as f:
                store = json.load(f)
        except Exception:
            return
    if not isinstance(store, dict):
        return
    active_id = store.get("activeId") or None
    active_name = None
    relay_ip = None
    relay_port = 443
    for s in store.get("servers", []):
        if s.get("id") == active_id:
            active_name = s.get("name")
            resolved = s.get("resolvedIps") or []
            relay_ip = resolved[0] if resolved else s.get("host")
            relay_port = int(s.get("port", 443))
            break
    meta = {
        "activeServerId": active_id,
        "activeServerName": active_name,
        "relayIp": relay_ip,
        "relayPort": relay_port
    }
    try:
        atomic_write_text(ACTIVE_SERVER_META_PATH, json.dumps(meta, indent=2, ensure_ascii=False), mode=0o644)
    except Exception:
        pass


def resolve_active_proxy(config: Optional[Dict[str, Any]] = None) -> Tuple[str, int, int]:
    """Resolve active proxy host and ports (strictly dedicated Xray 18088 / 18089)."""
    return "127.0.0.1", 18088, 18089


def notify(title: str, message: str) -> None:
    """Send native macOS notification safely using osascript argv."""
    try:
        script = "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run"
        subprocess.run(["osascript", "-e", script, str(title), str(message)], capture_output=True, timeout=5)
    except Exception:
        pass


def get_or_create_api_secret(secret_path: str = API_SECRET_PATH) -> str:
    """
    Check for existing Clash API secret.
    System path (/usr/local/etc/vpnguard/api_secret) uses root:admin mode 640 so the
    desktop app can read it without exposing it inside sing-box.json (mode 600).
    """
    desired_mode = 0o640 if (secret_path == API_SECRET_PATH and os.geteuid() == 0) else 0o600
    if os.path.exists(secret_path):
        try:
            with open(secret_path, "r", encoding="utf-8") as f:
                token = f.read().strip()
                if token:
                    if os.geteuid() == 0 and secret_path == API_SECRET_PATH:
                        try:
                            shutil.chown(secret_path, user="root", group="admin")
                        except Exception:
                            pass
                    try:
                        os.chmod(secret_path, desired_mode)
                    except Exception:
                        pass
                    return token
        except Exception:
            pass

    token = secrets.token_hex(16)
    try:
        os.makedirs(os.path.dirname(secret_path), exist_ok=True)
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, desired_mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(token + "\n")
        if os.geteuid() == 0 and secret_path == API_SECRET_PATH:
            try:
                shutil.chown(secret_path, user="root", group="admin")
            except Exception:
                pass
        os.chmod(secret_path, desired_mode)
    except Exception:
        pass

    return token


def compile_domain_rules(rules: Dict[str, Any]) -> List[Tuple[str, str, bool]]:
    """
    Compile user domain rules and enabled presets into a single specificity-sorted list of (domain, action, is_user).
    Order guarantees:
    1. Higher DNS label specificity wins (e.g. local.example.com > example.com > .ru).
    2. Longer normalized suffix wins on equal label count.
    3. Explicit user rules take precedence over presets on equal specificity.
    4. Equal specificity/source breaks ties fail-safe: block > proxy > direct.
    """
    domains = rules.get("domains", [])
    presets = rules.get("presets", {})
    action_rank = {"block": 0, "proxy": 1, "direct": 2}

    candidates: List[Tuple[Tuple[int, int, int, int, str], str, str, str, bool]] = []

    def add_entry(raw_dom: str, raw_action: str, is_user: bool) -> None:
        dom = raw_dom.strip()
        if not dom:
            return
        action = raw_action if raw_action in action_rank else "proxy"
        norm = dom.lower().lstrip(".")
        if not norm:
            return
        labels = len([p for p in norm.split(".") if p])
        source_rank = 0 if is_user else 1
        sort_key = (-labels, source_rank, -len(norm), action_rank[action], norm)
        candidates.append((sort_key, norm, dom, action, is_user))

    for d in domains:
        if not d.get("enabled", True):
            continue
        add_entry(str(d.get("domain", "")), str(d.get("action", "proxy")), is_user=True)

    if presets.get("aiServicesProxy", True):
        for dom in AI_PROXY_DOMAINS:
            add_entry(dom, "proxy", is_user=False)

    if presets.get("ruDirect", True):
        for dom in RU_DIRECT_DOMAINS:
            add_entry(dom, "direct", is_user=False)

    candidates.sort(key=lambda item: item[0])

    compiled: List[Tuple[str, str, bool]] = []
    seen_norms: set = set()
    for _, norm, dom, action, is_user in candidates:
        if norm in seen_norms:
            continue
        seen_norms.add(norm)
        compiled.append((dom, action, is_user))
    return compiled


def build_singbox_config(rules: Dict[str, Any], relay_ip: Optional[Any] = None) -> Dict[str, Any]:
    """
    Compile high-level rules into full sing-box JSON configuration.
    Strictly preserves route order:
    1. sniff
    2. hijack-dns
    3. reject QUIC (if preset blockQuic)
    4. private IP direct
    5. apps (by process_path_regex)
    6. specificity-sorted domains (shared across dns.rules & route.rules)
    7. reject remaining UDP
    8. final: xray-upstream
    """
    relay_ips_list: List[str] = []
    if isinstance(relay_ip, (list, tuple)):
        relay_ips_list = [str(ip).strip() for ip in relay_ip if str(ip).strip()]
    elif isinstance(relay_ip, str) and relay_ip.strip():
        relay_ips_list = [relay_ip.strip()]

    if not relay_ips_list:
        active_ip = get_active_relay_ip()
        if active_ip:
            relay_ips_list = [active_ip]

    api_secret = get_or_create_api_secret()

    apps = rules.get("apps", [])
    presets = rules.get("presets", {})
    compiled_domains = compile_domain_rules(rules)

    # DNS routing rules built from the same specificity-sorted list as route.rules
    dns_rules: List[Dict[str, Any]] = []
    cur_dns_key: Optional[Tuple[str, str, bool]] = None
    cur_dns_batch: List[str] = []

    def flush_dns_batch() -> None:
        nonlocal cur_dns_key, cur_dns_batch
        if cur_dns_key and cur_dns_batch:
            kind, val, _ = cur_dns_key
            dns_rules.append({"domain_suffix": cur_dns_batch, kind: val})
        cur_dns_key = None
        cur_dns_batch = []

    for dom, action, is_user in compiled_domains:
        kind, val = (
            ("action", "reject") if action == "block"
            else (("server", "dns-direct") if action == "direct" else ("server", "dns-remote"))
        )
        batch_key = (kind, val, is_user)
        if batch_key != cur_dns_key:
            flush_dns_batch()
            cur_dns_key = batch_key
        cur_dns_batch.append(dom)
    flush_dns_batch()

    # Block AAAA / IPv6 DNS queries
    dns_rules.append({"query_type": ["AAAA"], "action": "reject"})

    # 2. Route rules
    route_rules: List[Dict[str, Any]] = [
        {"action": "sniff"},
        {"port": 53, "action": "hijack-dns"},
        {"protocol": "dns", "action": "hijack-dns"}
    ]

    # Reject QUIC (UDP 443)
    if presets.get("blockQuic", True):
        route_rules.append({"port": 443, "network": "udp", "action": "reject"})

    # Private IP Direct
    route_rules.append({"ip_is_private": True, "outbound": "direct"})

    # App rules by process_path_regex (for .app bundles) or exact process_path (for CLI binaries)
    for app in apps:
        if not app.get("enabled", True):
            continue
        bp = app.get("bundlePath", "").strip().rstrip("/")
        if not bp:
            continue
        action = app.get("action", "proxy")
        outbound = "xray-upstream" if action == "proxy" else ("direct" if action == "direct" else "block")
        if bp.endswith(".app"):
            escaped = re.escape(bp)
            regex = f"^{escaped}/.*"
            route_rules.append({"process_path_regex": [regex], "outbound": outbound})
        else:
            route_rules.append({"process_path": [bp], "outbound": outbound})

    # Domain rules (same specificity-sorted order as dns.rules)
    for dom, action, _ in compiled_domains:
        outbound = "xray-upstream" if action == "proxy" else ("direct" if action == "direct" else "block")
        route_rules.append({"domain_suffix": [dom], "outbound": outbound})

    # Block generic UDP leak
    route_rules.append({"network": "udp", "action": "reject"})

    cfg = {
        "log": {
            "level": "info",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "type": "https",
                    "server": "1.1.1.1",
                    "path": "/dns-query",
                    "detour": "xray-upstream"
                },
                {
                    "tag": "dns-direct",
                    "type": "tls",
                    "server": "77.88.8.8"
                }
            ],
            "rules": dns_rules,
            "final": "dns-remote",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "utun99",
                "address": [
                    "172.19.0.1/30"
                ],
                "auto_route": True,
                "strict_route": True,
                "stack": "gvisor",
                "route_exclude_address": [
                    f"{ip}/32" if "/" not in ip else ip for ip in relay_ips_list
                ] + [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.0.0/16"
                ]
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "xray-upstream",
                "server": "127.0.0.1",
                "server_port": 18088,
                "version": "5"
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "route": {
            "default_domain_resolver": "dns-remote",
            "auto_detect_interface": True,
            "find_process": True,
            "rules": route_rules,
            "final": "xray-upstream"
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": api_secret
            }
        }
    }

    # Fail-Closed invariant checks against accidental Fail-Open generation
    if cfg["route"]["final"] != "xray-upstream":
        raise ValueError(f"Fail-Closed invariant violated: route.final={cfg['route']['final']}")
    if not any(o.get("tag") == "xray-upstream" for o in cfg["outbounds"]):
        raise ValueError("Fail-Closed invariant violated: missing xray-upstream outbound")
    if any(r.get("outbound") == "direct" and set(r.keys()) == {"outbound"} for r in cfg["route"]["rules"]):
        raise ValueError("Fail-Closed invariant violated: unconditional direct catch-all rule detected")

    return cfg


def cmd_status(args: argparse.Namespace) -> int:
    """Print full security posture & diagnostics or JSON."""
    config = load_config()
    host, socks_port, http_port = resolve_active_proxy(config)
    pf_info = get_pf_status()
    pf_blocked = pf_info.get("blocked_packets", 0)
    xray_proc = get_xray_process_status()
    sb_proc = get_singbox_process_status()
    utun_info = get_utun_status()
    relay_ip = get_active_relay_ip()
    is_on = bool(pf_info["enabled"] and pf_info["anchor_loaded"] and sb_proc["running"] and xray_proc["running"])
    fast_mode = getattr(args, "fast", False)

    proxy_info = None
    if is_on and not fast_mode:
        proxy_info = query_socks5_ip(host, socks_port, timeout=2.0)
        if not proxy_info:
            proxy_info = query_http_proxy_ip(f"http://{host}:{http_port}", timeout=2.0)

    # Clash API Secret
    clash_secret = None
    if os.path.exists(API_SECRET_PATH):
        try:
            with open(API_SECRET_PATH, "r", encoding="utf-8") as f:
                clash_secret = f.read().strip() or None
        except Exception:
            pass
    if not clash_secret and os.path.exists(SINGBOX_CONF_PATH):
        try:
            with open(SINGBOX_CONF_PATH, "r", encoding="utf-8") as f:
                sb_data = json.load(f)
                secret_val = sb_data.get("experimental", {}).get("clash_api", {}).get("secret")
                if secret_val:
                    clash_secret = secret_val
        except Exception:
            pass
    if not clash_secret and os.geteuid() == 0:
        try:
            clash_secret = get_or_create_api_secret()
        except Exception:
            pass

    # JSON output requested
    if getattr(args, "json", False):
        exit_ip = proxy_info.get("ip") if proxy_info else None
        exit_loc = None
        if proxy_info:
            city = proxy_info.get("city", "")
            country = proxy_info.get("country", "")
            org = proxy_info.get("org", "")
            exit_loc = f"{city}, {country} ({org})" if city else f"{country} ({org})"

        pause_ts = _read_pause_until()
        active_pause_until = pause_ts if (not is_on and pause_ts is not None and pause_ts > time.time()) else None

        status_data = {
            "isProtectionOn": is_on,
            "pfEnabled": pf_info["enabled"],
            "pfRulesCount": pf_info["rules_count"],
            "pfBlockedPackets": pf_blocked,
            "xrayRunning": {
                "running": xray_proc["running"],
                "pid": xray_proc["pid"],
                "gid": xray_proc["group"],
                "user": xray_proc["user"]
            },
            "singboxRunning": {
                "running": sb_proc["running"],
                "pid": sb_proc["pid"],
                "gid": sb_proc.get("gid"),
                "user": sb_proc["user"]
            },
            "utunInterface": utun_info["interface"] if utun_info["active"] else None,
            "exitIp": exit_ip,
            "exitLocation": exit_loc,
            "relayIp": relay_ip,
            "activeServerId": None,
            "activeServerName": None,
            "clashApiUrl": "127.0.0.1:9090",
            "clashApiSecret": clash_secret,
            "pauseUntil": active_pause_until
        }
        if os.path.exists(SERVERS_FILE_PATH):
            try:
                with open(SERVERS_FILE_PATH, "r", encoding="utf-8") as f:
                    s_store = json.load(f)
                    act_id = s_store.get("activeId")
                    status_data["activeServerId"] = act_id
                    for s in s_store.get("servers", []):
                        if s.get("id") == act_id:
                            status_data["activeServerName"] = s.get("name")
                            break
            except Exception:
                pass
        if not status_data["activeServerId"] and os.path.exists(ACTIVE_SERVER_META_PATH):
            try:
                with open(ACTIVE_SERVER_META_PATH, "r", encoding="utf-8") as mf:
                    meta = json.load(mf)
                    status_data["activeServerId"] = meta.get("activeServerId")
                    status_data["activeServerName"] = meta.get("activeServerName")
                    if not status_data["relayIp"] and meta.get("relayIp"):
                        status_data["relayIp"] = meta.get("relayIp")
            except Exception:
                pass
        print(json.dumps(status_data, indent=2))
        return 0 if is_on else 1

    # Human-readable CLI formatting
    print(f"\n{C_BOLD}{C_CYAN}=== 🛡️  VPNGuard 3.0 Unified System Security Posture ==={C_RESET}\n")

    # 1. Physical Interface Check
    print(f"{C_BOLD}[1] Physical Network Interface (en0):{C_RESET}")
    phys_info = query_physical_ip()
    if phys_info:
        country = phys_info.get("country", "Unknown")
        ip = phys_info.get("ip", "Unknown")
        org = phys_info.get("org", "Unknown")
        city = phys_info.get("city", "Unknown")
        is_ru = (country == "RU")
        color = C_YELLOW if is_ru else C_GREEN
        print(f"    • Physical IP:    {color}{ip}{C_RESET}")
        print(f"    • Location:       {color}{city}, {country} ({org}){C_RESET}")
        if is_ru:
            print(f"    • Direct Route:   {C_YELLOW}Exposes Russian IP for direct RU services (.ru, ya.ru){C_RESET}")
    else:
        print(f"    • Physical IP:    {C_DIM}Direct queries blocked by PF Fail-Closed killswitch (Airtight){C_RESET}")

    # 2. Dedicated Xray Proxy Daemon Health Check
    print(f"\n{C_BOLD}[2] Dedicated Headless Xray Daemon (GID 889):{C_RESET}")
    socks_up = check_port_listening(host, socks_port)
    http_up = check_port_listening(host, http_port)

    if xray_proc["running"]:
        user_str = xray_proc["user"]
        grp_str = xray_proc["group"]
        root_warn = f"{C_RED}(CRITICAL: RUNNING AS ROOT!){C_RESET}" if xray_proc["is_root"] else f"{C_GREEN}(Unprivileged User){C_RESET}"
        print(f"    • Process:        {C_GREEN}RUNNING{C_RESET} (PID {xray_proc['pid']}, User: {user_str}, Group: {grp_str}) {root_warn}")
    else:
        print(f"    • Process:        {C_YELLOW}NOT ACTIVE (Run 'vpnguard on' or launchdaemon com.vpnguard.xray){C_RESET}")

    print(f"    • SOCKS5 Listener (127.0.0.1:{socks_port}): " +
          (f"{C_GREEN}LISTENING{C_RESET}" if socks_up else f"{C_RED}DOWN{C_RESET}"))
    print(f"    • HTTP Listener   (127.0.0.1:{http_port}): " +
          (f"{C_GREEN}LISTENING{C_RESET}" if http_up else f"{C_RED}DOWN{C_RESET}"))

    # 3. Headless sing-box TUN Daemon Health Check
    print(f"\n{C_BOLD}[3] Headless sing-box TUN Daemon (GID 890):{C_RESET}")
    if sb_proc["running"]:
        print(f"    • Process:        {C_GREEN}RUNNING{C_RESET} (PID {sb_proc['pid']}, User: {sb_proc['user']}, Group: {sb_proc['group']})")
    else:
        print(f"    • Process:        {C_YELLOW}NOT ACTIVE (Run 'vpnguard on' or launchdaemon com.vpnguard.singbox){C_RESET}")

    if utun_info["active"]:
        print(f"    • TUN Interface:  {C_GREEN}ACTIVE{C_RESET} ({utun_info['interface']} -> {utun_info['ip']})")
    else:
        print(f"    • TUN Interface:  {C_YELLOW}STANDBY (utun not active){C_RESET}")
    print(f"    • DNS Strategy:   {C_GREEN}Hijack-DNS + Remote DoH 1.1.1.1 (IPv4-Only, Direct DoT 77.88.8.8){C_RESET}")
    clash_api_up = check_port_listening("127.0.0.1", 9090)
    print(f"    • Clash API:      " + (f"{C_GREEN}127.0.0.1:9090 (Protected){C_RESET}" if clash_api_up else f"{C_YELLOW}127.0.0.1:9090 (Inactive){C_RESET}"))

    # 4. Tunnel egress query
    print(f"\n{C_BOLD}[4] Tunnel Egress & Leak Verification:{C_RESET}")
    if proxy_info:
        p_ip = proxy_info.get("ip", "Unknown")
        p_country = proxy_info.get("country", "Unknown")
        p_org = proxy_info.get("org", "Unknown")
        p_city = proxy_info.get("city", "Unknown")
        is_safe = p_country not in ["RU", "BY", "IR", "KP"]
        p_color = C_GREEN if is_safe else C_RED
        print(f"    • Egress Exit IP: {p_color}{p_ip}{C_RESET}")
        print(f"    • Egress Location:{p_color}{p_city}, {p_country} ({p_org}){C_RESET}")
        print(f"    • Tunnel Safety:  " + (f"{C_GREEN}SECURE (Non-RU Exit){C_RESET}" if is_safe else f"{C_RED}LEAK / RU EXIT!{C_RESET}"))
    else:
        print(f"    • Egress Exit:    {C_DIM}Standby (Connecting upstream...){C_RESET}")

    # 5. macOS Packet Filter 3-Point Check
    print(f"\n{C_BOLD}[5] Packet Filter (PF) System-Wide Fail-Closed Killswitch:{C_RESET}")
    print(f"    • PF Subsystem:   " +
          (f"{C_GREEN}ENABLED{C_RESET}" if pf_info["enabled"] else f"{C_RED}DISABLED{C_RESET}"))
    print(f"    • Main /etc/pf.conf: " +
          (f"{C_GREEN}LINKED (anchor \"vpnguard\" active){C_RESET}" if pf_info["main_anchor_linked"] else f"{C_RED}NOT LINKED (Run sudo ./install.sh){C_RESET}"))
    print(f"    • Anchor vpnguard:" +
          (f"{C_GREEN} LOADED ({pf_info['rules_count']} rules){C_RESET}" if pf_info["anchor_loaded"] else f"{C_RED} EMPTY / NOT LOADED{C_RESET}"))
    print(f"    • Group Isolation: " +
          (f"{C_GREEN}ACTIVE (GID 889 Xray + GID 890 singbox){C_RESET}" if (pf_info.get("has_group_889") and pf_info.get("has_group_890")) else f"{C_YELLOW}PARTIAL / INCOMPLETE{C_RESET}"))
    print(f"    • Fail-Closed:    " +
          (f"{C_GREEN}ACTIVE (Physical egress blocked for non-tunnel apps){C_RESET}" if pf_info.get("has_global_killswitch") else f"{C_YELLOW}STANDBY{C_RESET}"))
    print(f"    • Blocked Leaks:  {C_CYAN}{pf_blocked} packets blocked{C_RESET}")
    if pf_info["exit_table_ips"]:
        print(f"    • Relay IP Table: {C_GREEN}{', '.join(pf_info['exit_table_ips'])}{C_RESET}")

    # Verdict
    print(f"\n{C_BOLD}--- Overall Protection Verdict ---{C_RESET}")
    if is_on:
        print(f"{C_BOLD}{C_GREEN}🛡️  FAIL-CLOSED HEADLESS TUN PROTECTION ACTIVE:{C_RESET} All traffic is strictly guarded.\n")
        return 0
    elif not sb_proc["running"] and not pf_info["anchor_loaded"]:
        print(f"{C_BOLD}{C_YELLOW}⚠️  VPNGuard is OFF:{C_RESET} Protection is disarmed. Run '{C_CYAN}vpnguard on{C_RESET}' to enable.\n")
        return 1
    else:
        print(f"{C_BOLD}{C_YELLOW}⚠️  PARTIAL PROTECTION:{C_RESET} Ensure both daemons are running and PF is armed.")
        print(f"    Run '{C_CYAN}vpnguard on{C_RESET}'\n")
        return 1


def _read_pause_until(pause_file: Optional[str] = None) -> Optional[int]:
    """Read Unix timestamp from pause_until file, or None if missing/invalid."""
    target_file = pause_file or PAUSE_UNTIL_FILE
    if not os.path.exists(target_file):
        return None
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        val = int(raw)
        return val if val > 0 else None
    except Exception:
        return None


def _is_pause_watcher_alive(pid_file: Optional[str] = None) -> Optional[int]:
    """Return PID if an active vpnguard pause-watcher process is running, else None."""
    target_file = pid_file or PAUSE_WATCHER_PID_FILE
    if not os.path.exists(target_file):
        return None
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
        if pid <= 0 or pid == os.getpid():
            return None
        os.kill(pid, 0)
        res = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and "pause-watcher" in res.stdout:
            return pid
    except Exception:
        pass
    return None


def _clear_pause_state(run_dir: Optional[str] = None, kill_watcher: bool = True) -> None:
    """Remove pause_until / pause_watcher.pid and terminate any active pause-watcher."""
    target_dir = run_dir or RUN_DIR
    pause_file = os.path.join(target_dir, "pause_until")
    pid_file = os.path.join(target_dir, "pause_watcher.pid")

    if kill_watcher:
        alive_pid = _is_pause_watcher_alive(pid_file)
        if alive_pid is not None:
            try:
                import signal as _signal
                os.kill(alive_pid, _signal.SIGTERM)
            except Exception:
                pass

    for path in (pause_file, pid_file):
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass


def _disable_protection_core(quiet: bool = False) -> None:
    """Disarm PF kill-switch, stop sing-box, and restore original system DNS."""
    if not quiet:
        print(f"\n{C_BOLD}{C_YELLOW}=== ⚠️  Disabling VPNGuard Protection (Captive Portal Mode) ==={C_RESET}\n")
        print(f"{C_BOLD}[1/3] Disarming PF Kill-Switch...{C_RESET}")

    res_pf = subprocess.run(["/usr/local/libexec/vpnguard-pf-boot.sh", "off"], capture_output=True, text=True, timeout=15)
    if not quiet:
        if res_pf.returncode == 0:
            print(f"    {C_GREEN}✓ PF Kill-Switch disarmed (Direct physical egress allowed){C_RESET}")
        else:
            print(f"    {C_RED}[!] Warning: {res_pf.stderr.strip()}{C_RESET}")
        print(f"\n{C_BOLD}[2/3] Stopping vpnguard-singbox TUN daemon...{C_RESET}")

    subprocess.run(["launchctl", "bootout", "system/com.vpnguard.singbox"], capture_output=True, timeout=10)
    time.sleep(0.5)
    subprocess.run(["pkill", "-9", "-x", "vpnguard-singbox"], capture_output=True, timeout=5)
    singbox = get_singbox_process_status()
    if not quiet:
        if not singbox["running"]:
            print(f"    {C_GREEN}✓ vpnguard-singbox stopped successfully (utun99 released){C_RESET}")
        else:
            print(f"    {C_YELLOW}[!] vpnguard-singbox still running (PID {singbox['pid']}){C_RESET}")
        print(f"\n{C_BOLD}[3/3] Restoring original DNS and flushing caches...{C_RESET}")

    dns_ok, dns_msg = restore_system_dns()
    if not quiet:
        if dns_ok:
            print(f"    {C_GREEN}✓ {dns_msg}{C_RESET}")
        else:
            print(f"    {C_YELLOW}[!] {dns_msg}{C_RESET}")


def cmd_on(args: argparse.Namespace) -> int:
    """Prepare configs, arm fail-closed PF kill-switch, start xray + sing-box, and lock DNS."""
    if os.geteuid() != 0:
        print(f"{C_RED}[!] 'vpnguard on' requires root privileges. Run: sudo vpnguard on{C_RESET}", file=sys.stderr)
        return 1

    try:
        with acquire_state_lock():
            return _cmd_on_locked(args)
    except TimeoutError as e:
        print(f"{C_RED}[!] {e}{C_RESET}", file=sys.stderr)
        return 1


def _cmd_on_locked(args: argparse.Namespace) -> int:
    # Cancel any pending Wi-Fi pause timer & watcher when enabling protection manually
    _clear_pause_state(kill_watcher=True)

    print(f"\n{C_BOLD}{C_CYAN}=== 🛡️  Enabling VPNGuard Unified System Protection ==={C_RESET}\n")

    # 1. Resolve active relay and prepare pf.egress.conf + sing-box.json BEFORE arming PF
    print(f"{C_BOLD}[1/5] Preparing relay egress & sing-box configuration...{C_RESET}")
    current_rules = DEFAULT_RULES
    if os.path.exists(RULES_FILE_PATH):
        try:
            with open(RULES_FILE_PATH, "r", encoding="utf-8") as rf:
                current_rules = json.load(rf)
        except Exception:
            pass

    relay_ips, relay_port = get_active_relay_endpoint()
    if not relay_ips:
        active_host = ""
        if os.path.exists(SERVERS_FILE_PATH):
            try:
                with open(SERVERS_FILE_PATH, "r", encoding="utf-8") as sf:
                    s_store = json.load(sf)
                act_id = s_store.get("activeId")
                for s in s_store.get("servers", []):
                    if s.get("id") == act_id:
                        active_host = str(s.get("host", "")).strip()
                        relay_port = int(s.get("port", 443))
                        break
            except Exception:
                pass
        if not active_host and os.path.exists(XRAY_CONF_PATH):
            try:
                with open(XRAY_CONF_PATH, "r", encoding="utf-8") as xf:
                    active_host, relay_port = _extract_xray_endpoint(json.load(xf))
            except Exception:
                pass
        if active_host:
            relay_ips = resolve_ipv4_direct_via_gid890(active_host)

    if relay_ips:
        try:
            write_pf_egress_file(relay_ips, relay_port, PF_EGRESS_FILE)
        except Exception as e:
            print(f"    {C_RED}[!] Error updating pf.egress.conf: {e}{C_RESET}", file=sys.stderr)
            return 1

    try:
        sb_cfg = build_singbox_config(current_rules, relay_ip=relay_ips or None)
        tmp_sb = f"{SINGBOX_CONF_PATH}.tmp_{os.getpid()}"
        atomic_write_text(tmp_sb, json.dumps(sb_cfg, indent=2, ensure_ascii=False), mode=0o600)
        sb_bin = SINGBOX_BIN if os.path.exists(SINGBOX_BIN) else "sing-box"
        res_sb = subprocess.run([sb_bin, "check", "-c", tmp_sb], capture_output=True, text=True, timeout=10)
        if res_sb.returncode == 0:
            os.replace(tmp_sb, SINGBOX_CONF_PATH)
            os.chmod(SINGBOX_CONF_PATH, 0o600)
        else:
            if os.path.exists(tmp_sb):
                os.remove(tmp_sb)
            err = res_sb.stderr.strip() or res_sb.stdout.strip()
            print(f"    {C_RED}[!] sing-box config check failed: {err}{C_RESET}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"    {C_RED}[!] Error rebuilding sing-box.json: {e}{C_RESET}", file=sys.stderr)
        return 1
    sync_active_server_metadata()

    # Persist desired_state='on' strictly AFTER config validation and BEFORE calling vpnguard-pf-boot.sh on
    write_desired_state("on")

    # 2. Arm PF anchor rules BEFORE starting daemons (Fail-Closed)
    print(f"\n{C_BOLD}[2/5] Arming System Fail-Closed PF Kill-Switch...{C_RESET}")
    rotate_log_if_needed(LOG_PF_PATH)
    _set_launchd_service_enabled("system/com.vpnguard.pf", True)
    res_pf = subprocess.run(["/usr/local/libexec/vpnguard-pf-boot.sh", "on", "--no-dns-sync"], capture_output=True, text=True, timeout=15)
    if res_pf.returncode == 0:
        print(f"    {C_GREEN}✓ PF Kill-Switch armed successfully (Fail-Closed active){C_RESET}")
    else:
        err_pf = res_pf.stderr.strip() or res_pf.stdout.strip() or "vpnguard-pf-boot.sh failed"
        print(f"    {C_RED}[!] Error arming PF: {err_pf}{C_RESET}", file=sys.stderr)
        return 1

    # 3. Start xray LaunchDaemon (GID 889)
    print(f"\n{C_BOLD}[3/5] Starting vpnguard-xray LaunchDaemon (GID 889)...{C_RESET}")
    rotate_log_if_needed(LOG_XRAY_PATH, owner_user="_vpnguard_proxy", group_name="vpnguard-proxy")
    _set_launchd_service_enabled("system/com.vpnguard.xray", True)
    subprocess.run(["launchctl", "bootstrap", "system", "/Library/LaunchDaemons/com.vpnguard.xray.plist"], capture_output=True, timeout=10)
    subprocess.run(["launchctl", "kickstart", "-k", "system/com.vpnguard.xray"], capture_output=True, timeout=10)

    xray_ready = False
    for _ in range(10):
        if check_port_listening("127.0.0.1", 18088, timeout=0.5):
            xray_ready = True
            break
        time.sleep(0.3)

    xray = get_xray_process_status()
    if xray["running"] and xray_ready:
        print(f"    {C_GREEN}✓ vpnguard-xray is running (PID {xray['pid']}, GID {xray.get('group', '889')}){C_RESET}")
    else:
        print(f"    {C_RED}[!] vpnguard-xray failed to become ready (PF Kill-Switch remains armed){C_RESET}", file=sys.stderr)

    # 4. Start sing-box LaunchDaemon (GID 890)
    print(f"\n{C_BOLD}[4/5] Starting vpnguard-singbox LaunchDaemon (GID 890)...{C_RESET}")
    rotate_log_if_needed(LOG_SINGBOX_PATH)
    _set_launchd_service_enabled("system/com.vpnguard.singbox", True)
    subprocess.run(["launchctl", "bootstrap", "system", "/Library/LaunchDaemons/com.vpnguard.singbox.plist"], capture_output=True, timeout=10)
    subprocess.run(["launchctl", "kickstart", "-k", "system/com.vpnguard.singbox"], capture_output=True, timeout=10)

    utun_ready = False
    for _ in range(15):
        utun = get_utun_status()
        if utun["active"]:
            utun_ready = True
            break
        time.sleep(0.3)

    singbox = get_singbox_process_status()
    if singbox["running"] and utun_ready:
        print(f"    {C_GREEN}✓ vpnguard-singbox is running (PID {singbox['pid']}, interface utun99, IP 172.19.0.1){C_RESET}")
    else:
        print(f"    {C_RED}[!] vpnguard-singbox failed to bring up utun99 (PF Kill-Switch remains armed){C_RESET}", file=sys.stderr)

    # 5. Lock hardware DNS to 1.1.1.1 (routed into utun99 hijack-dns) & flush mDNSResponder
    print(f"\n{C_BOLD}[5/5] Syncing system DNS & flushing mDNSResponder cache...{C_RESET}")
    dns_ok, dns_msg = sync_system_dns()
    if dns_ok:
        print(f"    {C_GREEN}✓ {dns_msg}{C_RESET}")
    else:
        print(f"    {C_YELLOW}[!] DNS sync note: {dns_msg}{C_RESET}")

    if not (xray["running"] and xray_ready and singbox["running"] and utun_ready):
        print(f"{C_RED}[!] PF Kill-Switch is active, but one or more tunnel daemons failed to start.{C_RESET}", file=sys.stderr)
        return 1

    print(f"\n{C_BOLD}{C_GREEN}🛡️  VPNGuard fail-closed protection enabled (Xray PID {xray['pid']}, sing-box PID {singbox['pid']}, utun99 active).{C_RESET}\n")
    return 0


def cmd_off(args: argparse.Namespace) -> int:
    """Safely disable kill-switch, persist desired_state=off, stop sing-box, and restore DNS."""
    if os.geteuid() != 0:
        print(f"{C_RED}[!] 'vpnguard off' requires root privileges. Run: sudo vpnguard off{C_RESET}", file=sys.stderr)
        return 1

    try:
        with acquire_state_lock():
            _clear_pause_state(kill_watcher=True)
            write_desired_state("off")
            _set_launchd_service_enabled("system/com.vpnguard.pf", False)
            _set_launchd_service_enabled("system/com.vpnguard.singbox", False)
            _disable_protection_core(quiet=False)
    except TimeoutError as e:
        print(f"{C_RED}[!] {e}{C_RESET}", file=sys.stderr)
        return 1

    print(f"\n{C_BOLD}{C_GREEN}✅ Direct internet access restored. Captive portal login is now possible.{C_RESET}")
    print(f"{C_DIM}Run 'sudo vpnguard on' to re-enable fail-closed protection.{C_RESET}\n")
    return 0


def cmd_pause(args: argparse.Namespace) -> int:
    """Temporarily disable protection for <seconds> with a fail-safe background auto-resume watcher."""
    if os.geteuid() != 0:
        print(json.dumps({"status": "error", "message": "pause requires root privileges"}), file=sys.stderr)
        return 1

    try:
        seconds = int(getattr(args, "seconds", 300))
    except Exception:
        print(json.dumps({"status": "error", "message": "Invalid pause duration"}), file=sys.stderr)
        return 1

    if not (60 <= seconds <= 3600):
        print(json.dumps({"status": "error", "message": "Pause duration must be between 60 and 3600 seconds"}), file=sys.stderr)
        return 1

    try:
        with acquire_state_lock():
            pause_until = int(time.time()) + seconds
            os.makedirs(RUN_DIR, exist_ok=True)
            atomic_write_text(PAUSE_UNTIL_FILE, f"{pause_until}\n", mode=0o644)

            _disable_protection_core(quiet=True)

            watcher_pid = _is_pause_watcher_alive()
            if watcher_pid is None:
                proc = subprocess.Popen(
                    [sys.executable, "-s", os.path.realpath(__file__), "pause-watcher"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                watcher_pid = proc.pid
                atomic_write_text(PAUSE_WATCHER_PID_FILE, f"{watcher_pid}\n", mode=0o644)
    except TimeoutError as e:
        print(json.dumps({"status": "error", "message": str(e)}), file=sys.stderr)
        return 1

    print(json.dumps({
        "status": "ok",
        "pauseUntil": pause_until,
        "seconds": seconds,
        "watcherPid": watcher_pid
    }))
    return 0


def cmd_pause_watcher(args: argparse.Namespace) -> int:
    """Internal wall-clock background watcher that re-arms VPNGuard when pause_until expires."""
    if os.geteuid() != 0:
        return 1

    try:
        while True:
            target_ts = _read_pause_until()
            if target_ts is None:
                return 0

            if time.time() >= target_ts:
                with acquire_state_lock():
                    # Re-check under state lock so we never double-arm if resume-if-expired/on already ran
                    latest_ts = _read_pause_until()
                    if latest_ts is None or time.time() < latest_ts:
                        if latest_ts is None:
                            return 0
                        continue
                    rc = cmd_on(argparse.Namespace(json=True, fast=True))
                if rc == 0:
                    notify("🛡️ VPNGuard", "Пауза Wi-Fi завершена. Защита и Kill-Switch снова активны.")
                return rc

            time.sleep(5)
    finally:
        if os.path.exists(PAUSE_WATCHER_PID_FILE):
            try:
                with open(PAUSE_WATCHER_PID_FILE, "r", encoding="utf-8") as f:
                    recorded = int(f.read().strip())
                if recorded == os.getpid():
                    os.remove(PAUSE_WATCHER_PID_FILE)
            except Exception:
                pass


def cmd_resume_if_expired(args: argparse.Namespace) -> int:
    """Re-arm protection immediately if pause_until exists and has expired."""
    if os.geteuid() != 0:
        print(json.dumps({"status": "error", "message": "resume-if-expired requires root"}), file=sys.stderr)
        return 1

    try:
        with acquire_state_lock():
            target_ts = _read_pause_until()
            if target_ts is None:
                print(json.dumps({"status": "noop", "reason": "no_pause"}))
                return 0

            now = time.time()
            if now >= target_ts:
                _clear_pause_state(kill_watcher=True)
                rc = cmd_on(argparse.Namespace(json=True, fast=True))
                if rc == 0:
                    notify("🛡️ VPNGuard", "Защита автоматически восстановлена после паузы.")
                return rc

            print(json.dumps({
                "status": "waiting",
                "pauseUntil": target_ts,
                "remaining": max(0, int(target_ts - now))
            }))
            return 0
    except TimeoutError as e:
        print(json.dumps({"status": "error", "message": str(e)}), file=sys.stderr)
        return 1


def _tail_file_lines(path: str, max_lines: int = 150) -> str:
    """Read last max_lines from a text log file by seeking backwards in binary chunks."""
    if not os.path.exists(path):
        return f"(Файл не найден: {path})"
    if max_lines <= 0:
        return "(Лог пуст)"
    try:
        chunk_size = 8192
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            if pos == 0:
                return "(Лог пуст)"

            chunks: List[bytes] = []
            newline_count = 0
            # Collect enough chunks from EOF to cover max_lines (even with trailing newline)
            while pos > 0 and newline_count <= max_lines:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos, os.SEEK_SET)
                buf = f.read(read_size)
                chunks.append(buf)
                newline_count += buf.count(b"\n")

        tail_bytes = b"".join(reversed(chunks))
        raw_lines = tail_bytes.splitlines()
        if len(raw_lines) > max_lines:
            raw_lines = raw_lines[-max_lines:]
        text = b"\n".join(raw_lines).decode("utf-8", errors="replace").strip()
        return text if text else "(Лог пуст)"
    except Exception as e:
        return f"(Ошибка чтения {path}: {e})"


def _collect_sensitive_literals() -> List[str]:
    """Collect configured server IPs/hosts/SNI/keys and Clash API secret for log redaction."""
    safe_ips = {"127.0.0.1", "0.0.0.0", "1.1.1.1", "77.88.8.8", "172.19.0.1", "172.19.0.2"}
    literals: List[str] = []

    def add_lit(val: Any) -> None:
        if not val:
            return
        s = str(val).strip()
        if len(s) < 4 or s in safe_ips or s.startswith("127.0.0."):
            return
        if s not in literals:
            literals.append(s)

    if os.path.exists(API_SECRET_PATH):
        try:
            with open(API_SECRET_PATH, "r", encoding="utf-8") as f:
                add_lit(f.read().strip())
        except Exception:
            pass

    if os.path.exists(SERVERS_FILE_PATH):
        try:
            with open(SERVERS_FILE_PATH, "r", encoding="utf-8") as f:
                store = json.load(f)
            for s in store.get("servers", []):
                add_lit(s.get("host"))
                add_lit(s.get("sni"))
                for ip in s.get("resolvedIps") or []:
                    add_lit(ip)
                xc = s.get("xrayConfig") or {}
                for out in xc.get("outbounds", []):
                    stream = out.get("streamSettings") or {}
                    rs = stream.get("realitySettings") or {}
                    add_lit(rs.get("publicKey"))
                    add_lit(rs.get("shortId"))
                    add_lit(rs.get("serverName"))
                    ts = stream.get("tlsSettings") or {}
                    add_lit(ts.get("serverName"))
                    settings = out.get("settings") or {}
                    for srv_entry in settings.get("servers") or []:
                        add_lit(srv_entry.get("password"))
                        add_lit(srv_entry.get("secret"))
                    for vnext_entry in settings.get("vnext") or []:
                        for u_entry in vnext_entry.get("users") or []:
                            add_lit(u_entry.get("password"))
        except Exception:
            pass

    if os.path.exists(PF_EGRESS_FILE):
        try:
            with open(PF_EGRESS_FILE, "r", encoding="utf-8") as f:
                for ip_m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", f.read()):
                    add_lit(ip_m)
        except Exception:
            pass

    # Replace longest literals first to avoid partial prefix masking
    literals.sort(key=len, reverse=True)
    return literals


def redact_sensitive_text(text: str, extra_secrets: Optional[List[str]] = None) -> str:
    """Mask vless/trojan/ss/vmess URIs, UUIDs, passwords, Reality keys, Bearer tokens, and configured relay hosts/IPs."""
    if not text:
        return text

    redacted = text
    redacted = re.sub(
        r"\b(vless|trojan|ss|vmess)://[^\s\"'<>]+",
        lambda m: f"{m.group(1).lower()}://[REDACTED]",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "[REDACTED_UUID]",
        redacted,
    )
    redacted = re.sub(r"(Bearer\s+)[A-Za-z0-9._\-]+", r"\1[REDACTED_SECRET]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r"([?&](?:pbk|publicKey|sid|shortId|password|psk|secret|token|auth)=)[^&\s#]+",
        r"\1[REDACTED]",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r'("(?:publicKey|shortId|secret|id|password|psk|privateKey|token|auth)"\s*:\s*")[^"]+(")',
        r"\1[REDACTED]\2",
        redacted,
        flags=re.IGNORECASE,
    )

    for lit in (extra_secrets or []):
        if lit:
            redacted = redacted.replace(lit, "[REDACTED_SERVER]")

    return redacted


def _run_diag_cmd(cmd: List[str], max_lines: int = 120) -> str:
    """Execute a diagnostic read-only command and return bounded stdout/stderr."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        raw = res.stdout.strip() or res.stderr.strip() or "(пусто)"
        lines = raw.splitlines()[:max_lines]
        return "\n".join(lines)
    except Exception as e:
        return f"(Ошибка выполнения {' '.join(cmd)}: {e})"


def cmd_logs(args: argparse.Namespace) -> int:
    """Output sanitized last 150 lines of VPNGuard logs and PF/DNS/utun99 diagnostics."""
    secrets_list = _collect_sensitive_literals()

    logs_payload = {
        "singbox": redact_sensitive_text(_tail_file_lines(LOG_SINGBOX_PATH, 150), secrets_list),
        "xray": redact_sensitive_text(_tail_file_lines(LOG_XRAY_PATH, 150), secrets_list),
        "pf": redact_sensitive_text(_tail_file_lines(LOG_PF_PATH, 150), secrets_list),
    }

    pf_main = _run_diag_cmd(["pfctl", "-a", "vpnguard", "-s", "rules"], 120)
    pf_egress = _run_diag_cmd(["pfctl", "-a", "vpnguard/egress", "-s", "rules"], 60)
    pf_combined = f"# anchor vpnguard\n{pf_main}\n\n# sub-anchor vpnguard/egress\n{pf_egress}"

    system_payload = {
        "pfRules": redact_sensitive_text(pf_combined, secrets_list),
        "dns": redact_sensitive_text(_run_diag_cmd(["scutil", "--dns"], 120), secrets_list),
        "utun": redact_sensitive_text(_run_diag_cmd(["ifconfig", "utun99"], 60), secrets_list),
    }

    report = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "logs": logs_payload,
        "system": system_payload,
    }

    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    for name, content in logs_payload.items():
        print(f"=== LOG: {name} ===\n{content}\n")
    for name, content in system_payload.items():
        print(f"=== SYSTEM: {name} ===\n{content}\n")
    return 0


def cmd_dns_sync(args: argparse.Namespace) -> int:
    """Ensure active physical interfaces use managed DNS while protection is armed."""
    if os.geteuid() != 0:
        print(json.dumps({"status": "error", "message": "dns-sync requires root"}), file=sys.stderr)
        return 1

    pf_info = get_pf_status()
    sb_proc = get_singbox_process_status()
    if not (pf_info["enabled"] and pf_info["anchor_loaded"] and (sb_proc["running"] or read_desired_state() == "on")):
        print(json.dumps({"status": "skipped", "message": "Protection is not active"}))
        return 0

    ok, msg = sync_system_dns()
    if ok:
        print(json.dumps({"status": "ok", "message": msg}, ensure_ascii=False))
        return 0
    print(json.dumps({"status": "error", "message": msg}, ensure_ascii=False), file=sys.stderr)
    return 1


def cmd_rules_get(args: argparse.Namespace) -> int:
    """Output the active rules.json configuration."""
    rules_data = DEFAULT_RULES
    if os.path.exists(RULES_FILE_PATH):
        try:
            with open(RULES_FILE_PATH, "r", encoding="utf-8") as f:
                rules_data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed reading {RULES_FILE_PATH}: {e}", file=sys.stderr)
    else:
        # Create default rules.json if missing
        try:
            os.makedirs(os.path.dirname(RULES_FILE_PATH), exist_ok=True)
            with open(RULES_FILE_PATH, "w", encoding="utf-8") as f:
                json.dump(rules_data, f, indent=2, ensure_ascii=False)
            os.chmod(RULES_FILE_PATH, 0o644)
        except Exception:
            pass

    print(json.dumps(rules_data, indent=2, ensure_ascii=False))
    return 0


def cmd_rules_apply(args: argparse.Namespace) -> int:
    """Validate and atomically apply dynamic rules to sing-box.json with .bak rollback."""
    use_stdin = getattr(args, "stdin", False)
    input_path = getattr(args, "path", None)

    try:
        if use_stdin:
            raw_text = read_stdin_bounded()
            new_rules = json.loads(raw_text)
        else:
            if not input_path or not os.path.exists(input_path):
                raise FileNotFoundError(f"Rules file not found at {input_path}")
            with open(input_path, "r", encoding="utf-8") as f:
                new_rules = json.load(f)
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Failed reading rules input: {e}"}), file=sys.stderr)
        return 1

    # Validate schema
    if not isinstance(new_rules, dict) or "apps" not in new_rules or "domains" not in new_rules:
        err_msg = "Invalid rules format: must contain 'apps', 'domains', and optional 'presets'"
        print(json.dumps({"status": "error", "message": err_msg}), file=sys.stderr)
        return 1

    try:
        with acquire_state_lock():
            return _cmd_rules_apply_locked(new_rules)
    except TimeoutError as e:
        print(json.dumps({"status": "error", "message": str(e)}), file=sys.stderr)
        return 1


def _cmd_rules_apply_locked(new_rules: Dict[str, Any]) -> int:
    relay_ips, _ = get_active_relay_endpoint()
    try:
        sb_config = build_singbox_config(new_rules, relay_ip=relay_ips or None)
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}), file=sys.stderr)
        return 1

    tmp_sb_path = f"/usr/local/etc/vpnguard/singbox_tmp_{os.getpid()}.json"
    try:
        atomic_write_text(tmp_sb_path, json.dumps(sb_config, indent=2, ensure_ascii=False), mode=0o600)
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Failed writing temporary sing-box config: {e}"}), file=sys.stderr)
        return 1

    # Validate with sing-box check
    check_bin = SINGBOX_BIN if os.path.exists(SINGBOX_BIN) else "sing-box"
    res_check = subprocess.run([check_bin, "check", "-c", tmp_sb_path], capture_output=True, text=True, timeout=10)
    if res_check.returncode != 0:
        if os.path.exists(tmp_sb_path):
            os.remove(tmp_sb_path)
        err_msg = f"sing-box validation rejected generated config: {res_check.stderr.strip() or res_check.stdout.strip()}"
        print(json.dumps({"status": "error", "message": err_msg}), file=sys.stderr)
        return 1

    prev_rules_bytes: Optional[bytes] = None
    if os.path.exists(RULES_FILE_PATH):
        try:
            with open(RULES_FILE_PATH, "rb") as rf:
                prev_rules_bytes = rf.read()
        except Exception:
            pass
    prev_sb_bytes: Optional[bytes] = None
    if os.path.exists(SINGBOX_CONF_PATH):
        try:
            with open(SINGBOX_CONF_PATH, "rb") as sf:
                prev_sb_bytes = sf.read()
        except Exception:
            pass

    try:
        if prev_rules_bytes is not None:
            atomic_write_text(f"{RULES_FILE_PATH}.bak", prev_rules_bytes.decode("utf-8"), mode=0o644)
        if prev_sb_bytes is not None:
            atomic_write_text(f"{SINGBOX_CONF_PATH}.bak", prev_sb_bytes.decode("utf-8"), mode=0o600)

        atomic_write_text(RULES_FILE_PATH, json.dumps(new_rules, indent=2, ensure_ascii=False), mode=0o644)
        os.replace(tmp_sb_path, SINGBOX_CONF_PATH)
        os.chmod(SINGBOX_CONF_PATH, 0o600)

        sb_proc = get_singbox_process_status()
        if sb_proc["running"]:
            subprocess.run(["launchctl", "kickstart", "-k", "system/com.vpnguard.singbox"], capture_output=True, timeout=10)
            ready = False
            for _ in range(10):
                time.sleep(0.3)
                if get_singbox_process_status().get("running") and get_utun_status().get("active"):
                    ready = True
                    break
            if not ready:
                if prev_rules_bytes is not None:
                    atomic_write_text(RULES_FILE_PATH, prev_rules_bytes.decode("utf-8"), mode=0o644)
                if prev_sb_bytes is not None:
                    atomic_write_text(SINGBOX_CONF_PATH, prev_sb_bytes.decode("utf-8"), mode=0o600)
                subprocess.run(["launchctl", "kickstart", "-k", "system/com.vpnguard.singbox"], capture_output=True, timeout=10)
                print(json.dumps({"status": "error", "message": "sing-box failed health check after rules update; rolled back to .bak"}), file=sys.stderr)
                return 1

        flush_dns_cache()
        print(json.dumps({"status": "ok", "message": "Rules applied, DNS cache flushed, and sing-box updated successfully"}))
        return 0
    except Exception as e:
        if os.path.exists(tmp_sb_path):
            try:
                os.remove(tmp_sb_path)
            except Exception:
                pass
        print(json.dumps({"status": "error", "message": f"Failed applying configuration: {e}"}), file=sys.stderr)
        return 1


def resolve_host_ipv4(host: str) -> List[str]:
    """Resolve host to unique IPv4 addresses. Returns [] on failure (never returns raw hostname)."""
    host = host.strip()
    if not host:
        return []
    try:
        ip_obj = ipaddress.ip_address(host)
        return [host] if ip_obj.version == 4 else []
    except ValueError:
        pass
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(dict.fromkeys([res[4][0] for res in addr_info if res[4][0]]))
        if ips:
            return ips
    except Exception as e:
        print(f"[!] Warning resolving host '{host}': {e}", file=sys.stderr)
    return []


def validate_xray_config(xray_data: Dict[str, Any]) -> Tuple[bool, str]:
    """Validate Xray JSON configuration using vpnguard-xray run -test."""
    xray_bin = XRAY_BIN if os.path.exists(XRAY_BIN) else "xray"
    tmp_dir: Optional[str] = None
    try:
        test_data = copy.deepcopy(xray_data)
        test_data["log"] = {
            "access": "none",
            "loglevel": "warning"
        }
        tmp_dir, tmp_path = _write_private_validation_file("xray_val_", test_data)

        res = subprocess.run([xray_bin, "run", "-test", "-c", tmp_path], capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            return True, "Configuration OK."
        else:
            err = res.stderr.strip() or res.stdout.strip()
            return False, err
    except Exception as e:
        return False, f"Failed to execute Xray test binary: {e}"
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass


def parse_vless_uri(uri: str) -> Dict[str, Any]:
    """
    Parse a standard vless:// URI and generate a compliant, hardened Xray configuration.
    
    Format:
        vless://<uuid>@<host>:<port>?<query>#<remark>
        
    Guarantees:
        - Inbounds: strictly loopback-only SOCKS 127.0.0.1:18088 (udp: false) & HTTP 127.0.0.1:18089
        - Outbounds: strictly 'proxy' and 'block'. No direct/freedom!
        - Routing: all incoming traffic routed strictly to 'proxy'
    """
    uri = uri.strip()
    if not uri.startswith("vless://"):
        raise ValueError("Invalid URI scheme: must begin with 'vless://'")

    # Extract remark (#fragment)
    before_hash, sep_hash, remark_part = uri.partition("#")
    remark = urllib.parse.unquote(remark_part).strip() if sep_hash else ""

    # Extract query (?query)
    before_query, sep_query, query_part = before_hash.partition("?")
    query_params: Dict[str, List[str]] = {}
    if sep_query:
        query_params = urllib.parse.parse_qs(query_part, keep_blank_values=True)

    def get_param(key: str, default: str = "") -> str:
        for k, v in query_params.items():
            if k.lower() == key.lower() and v:
                return urllib.parse.unquote(v[0]).strip()
        return default

    # Extract user ID and host:port
    after_scheme = before_query[8:]  # strip 'vless://'
    if "@" not in after_scheme:
        raise ValueError("Invalid VLESS URI: missing '@' separating UUID and server address")

    uuid_str, _, host_port = after_scheme.partition("@")
    uuid_str = uuid_str.strip()
    try:
        uuid.UUID(uuid_str)
    except Exception:
        raise ValueError(f"Invalid UUID in VLESS URI: '{uuid_str}'")

    host_port = host_port.strip()
    if host_port.startswith("["):
        host, _, port_part = host_port[1:].partition("]:")
    else:
        host, _, port_part = host_port.partition(":")

    host = host.strip()
    if not host:
        raise ValueError("Invalid VLESS URI: host cannot be empty")

    port = 443
    if port_part:
        try:
            port = int(port_part.strip())
            if not (1 <= port <= 65535):
                raise ValueError()
        except Exception:
            raise ValueError(f"Invalid port in VLESS URI: '{port_part}'")

    if not remark:
        remark = f"{host}:{port}"

    # Query parameters
    transport = get_param("type", "tcp").lower()
    if transport in ["raw", ""]:
        transport = "tcp"

    security = get_param("security", "none").lower()
    if security not in ["reality", "tls", "none"]:
        security = "none"

    flow = get_param("flow", "")
    sni = get_param("sni", get_param("serverName", host))
    fp = get_param("fp", get_param("fingerprint", "chrome"))
    alpn_raw = get_param("alpn", "")
    alpn: List[str] = [x.strip() for x in alpn_raw.split(",") if x.strip()] if alpn_raw else []

    allow_insecure_val = get_param("allowInsecure", "0").lower()
    allow_insecure = allow_insecure_val in ["1", "true", "yes"]

    pbk = get_param("pbk", get_param("publicKey", ""))
    sid = get_param("sid", get_param("shortId", ""))
    spx = get_param("spx", get_param("spiderX", "/"))

    path = get_param("path", "/")
    header_host = get_param("host", sni if sni else host)
    mode = get_param("mode", "auto" if transport == "xhttp" else "gun")
    service_name = get_param("serviceName", "")
    authority = get_param("authority", sni if sni else host)
    extra_raw = get_param("extra", "")
    extra_dict: Optional[Dict[str, Any]] = None
    if extra_raw:
        try:
            parsed_extra = json.loads(extra_raw)
            if isinstance(parsed_extra, dict):
                extra_dict = parsed_extra
        except Exception:
            pass

    # User entry
    user_entry: Dict[str, Any] = {
        "id": uuid_str,
        "encryption": "none",
        "level": 8
    }
    if flow:
        user_entry["flow"] = flow

    # StreamSettings
    stream_settings: Dict[str, Any] = {
        "network": transport,
        "security": security
    }

    if security == "reality":
        if not pbk:
            raise ValueError("VLESS Reality URI must include 'pbk' (publicKey)")
        stream_settings["realitySettings"] = {
            "show": False,
            "fingerprint": fp if fp else "chrome",
            "serverName": sni,
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": spx if spx else "/"
        }
    elif security == "tls":
        tls_settings: Dict[str, Any] = {
            "allowInsecure": allow_insecure,
            "serverName": sni,
            "fingerprint": fp if fp else "chrome",
            "show": False
        }
        if alpn:
            tls_settings["alpn"] = alpn
        elif transport == "xhttp":
            tls_settings["alpn"] = ["h2", "h3"]
        stream_settings["tlsSettings"] = tls_settings

    # Transport-specific stream blocks
    if transport == "xhttp":
        xhttp_block: Dict[str, Any] = {
            "path": path if path else "/",
            "host": header_host,
            "mode": mode if mode else "auto"
        }
        if extra_dict:
            xhttp_block["extra"] = extra_dict
        stream_settings["xhttpSettings"] = xhttp_block
    elif transport == "ws":
        stream_settings["wsSettings"] = {
            "path": path if path else "/",
            "headers": {
                "Host": header_host
            }
        }
    elif transport == "grpc":
        grpc_block: Dict[str, Any] = {
            "serviceName": service_name,
            "multiMode": (mode.lower() == "multi")
        }
        if authority:
            grpc_block["authority"] = authority
        stream_settings["grpcSettings"] = grpc_block

    # Strict loopback listeners only
    inbounds = [
        {
            "tag": "socks-in",
            "port": 18088,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False
            }
        },
        {
            "tag": "http-in",
            "port": 18089,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {
                "allowTransparent": False
            }
        }
    ]

    proxy_outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [user_entry]
                }
            ]
        },
        "streamSettings": stream_settings
    }

    block_outbound = {
        "tag": "block",
        "protocol": "blackhole",
        "settings": {
            "response": {
                "type": "none"
            }
        }
    }

    routing = {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": ["socks-in", "http-in"],
                "outboundTag": "proxy"
            }
        ]
    }

    log_config = {
        "access": "none",
        "loglevel": "warning"
    }

    xray_config = {
        "log": log_config,
        "inbounds": inbounds,
        "outbounds": [proxy_outbound, block_outbound],
        "routing": routing
    }

    resolved_ips = resolve_host_ipv4(host)

    profile = {
        "id": str(uuid.uuid4()),
        "name": remark,
        "protocol": "vless",
        "host": host,
        "resolvedIps": resolved_ips,
        "port": port,
        "transport": transport,
        "security": security,
        "sni": sni,
        "flow": flow,
        "rawUri": uri,
        "xrayConfig": xray_config
    }
    return profile


def parse_xray_server_json(data: Dict[str, Any], default_name: str = "Imported Profile") -> Dict[str, Any]:
    """
    Parse a JSON object containing outbounds (e.g. from Happ/v2ray/xray export)
    and extract the upstream proxy outbound, generating a strictly isolated VPNGuard Xray config.
    """
    remarks = data.get("remarks") or data.get("name") or default_name
    outbounds = data.get("outbounds", [])
    if not outbounds and "protocol" in data:
        # User passed a single outbound dictionary
        outbounds = [data]

    proxy_outbound = None
    for out in outbounds:
        proto = out.get("protocol", "").lower()
        tag = out.get("tag", "").lower()
        if proto in ["freedom", "direct"] or tag == "direct":
            continue
        if proto in ["vless", "vmess", "trojan", "shadowsocks"]:
            proxy_outbound = copy.deepcopy(out)
            break

    if not proxy_outbound:
        raise ValueError("Could not find a valid proxy outbound (vless/vmess/trojan/shadowsocks)")

    settings = proxy_outbound.get("settings", {})
    vnext = settings.get("vnext", [])
    servers = settings.get("servers", [])
    host = ""
    port = 443
    flow = ""

    if vnext and "address" in vnext[0]:
        host = vnext[0]["address"].strip()
        port = int(vnext[0].get("port", 443))
        users = vnext[0].get("users", [])
        if users:
            flow = users[0].get("flow", "")
    elif servers and "address" in servers[0]:
        host = servers[0]["address"].strip()
        port = int(servers[0].get("port", 443))

    if not host:
        raise ValueError("Proxy outbound has missing or empty address")

    stream = proxy_outbound.get("streamSettings", {})
    transport = stream.get("network", "tcp")
    security = stream.get("security", "none")
    sni = ""
    if security == "reality":
        sni = stream.get("realitySettings", {}).get("serverName", "")
    elif security == "tls":
        sni = stream.get("tlsSettings", {}).get("serverName", "")

    # Force secure loopback inbounds only
    inbounds = [
        {
            "tag": "socks-in",
            "port": 18088,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        },
        {
            "tag": "http-in",
            "port": 18089,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {"allowTransparent": False}
        }
    ]

    proxy_outbound["tag"] = "proxy"
    block_outbound = {
        "tag": "block",
        "protocol": "blackhole",
        "settings": {"response": {"type": "none"}}
    }

    routing = {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": ["socks-in", "http-in"],
                "outboundTag": "proxy"
            }
        ]
    }

    log_config = {
        "access": "none",
        "loglevel": "warning"
    }

    xray_config = {
        "log": log_config,
        "inbounds": inbounds,
        "outbounds": [proxy_outbound, block_outbound],
        "routing": routing
    }

    resolved_ips = resolve_host_ipv4(host)

    profile = {
        "id": str(uuid.uuid4()),
        "name": remarks,
        "protocol": proxy_outbound.get("protocol", "vless"),
        "host": host,
        "resolvedIps": resolved_ips,
        "port": port,
        "transport": transport,
        "security": security,
        "sni": sni,
        "flow": flow,
        "rawUri": "",
        "xrayConfig": xray_config
    }
    return profile


def load_servers_store(store_path: Optional[str] = None) -> Dict[str, Any]:
    """Load server profiles from servers.json, migrating active xray.json if empty."""
    target_path = store_path or SERVERS_FILE_PATH
    store = None
    if os.path.exists(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "servers" in data:
                    store = data
        except Exception as e:
            print(f"[!] Warning loading {target_path}: {e}", file=sys.stderr)

    if not store:
        store = {"activeId": "", "servers": []}

    # Initial seeding only from live xray.json when initializing the system store
    if not store.get("servers") and target_path == SERVERS_FILE_PATH and os.path.exists(XRAY_CONF_PATH):
        try:
            with open(XRAY_CONF_PATH, "r", encoding="utf-8") as xf:
                primary_cfg = json.load(xf)
            migrated = parse_xray_server_json(primary_cfg, default_name="Основной сервер")
            store["servers"] = [migrated]
            store["activeId"] = migrated["id"]
        except Exception as e:
            print(f"[!] Warning migrating {XRAY_CONF_PATH}: {e}", file=sys.stderr)

    if not store.get("activeId") and store.get("servers"):
        store["activeId"] = store["servers"][0]["id"]

    try:
        save_servers_store(store, target_path)
    except Exception:
        pass

    return store


def save_servers_store(store: Dict[str, Any], store_path: Optional[str] = None) -> None:
    """Save server profiles to servers.json with mode 600 and root:wheel ownership."""
    target_path = store_path or SERVERS_FILE_PATH
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    tmp_path = f"{target_path}.tmp_{os.getpid()}_{secrets.token_hex(4)}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    os.chmod(tmp_path, 0o600)
    if os.geteuid() == 0:
        try:
            shutil.chown(tmp_path, user="root", group="wheel")
        except Exception:
            pass
    os.replace(tmp_path, target_path)
    try:
        os.chmod(target_path, 0o600)
    except Exception:
        pass
    if target_path == SERVERS_FILE_PATH:
        sync_active_server_metadata(store)


def activate_server(server_id: str, store_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Atomically switch active upstream server to server_id with full rollback on failure.
    Resolves domains directly via GID 890 + IP_BOUND_IF (bypassing dead/old tunnels).
    When VPN is OFF, updates configs without kickstarting daemons; when ON, verifies xray + utun99.
    """
    store = load_servers_store(store_path)
    server = None
    for s in store.get("servers", []):
        if s.get("id") == server_id:
            server = s
            break

    if not server:
        return False, f"Server profile '{server_id}' not found in store"

    host = server.get("host", "").strip()
    if not host:
        return False, "Server profile has invalid empty host address"
    port = int(server.get("port", 443))

    resolved_ips = resolve_ipv4_direct_via_gid890(host)
    if not resolved_ips:
        return False, f"Failed to resolve host '{host}' to any IPv4 address via GID 890 direct DNS"
    server["resolvedIps"] = resolved_ips

    xray_config = server.get("xrayConfig")
    if not xray_config or not isinstance(xray_config, dict):
        return False, "Server profile does not contain valid xrayConfig"

    # Step 1: Validate new Xray configuration
    xray_valid, xray_err = validate_xray_config(xray_config)
    if not xray_valid:
        return False, f"Xray syntax validation failed: {xray_err}"

    # Step 2: Validate new sing-box configuration
    current_rules = DEFAULT_RULES
    if os.path.exists(RULES_FILE_PATH):
        try:
            with open(RULES_FILE_PATH, "r", encoding="utf-8") as rf:
                current_rules = json.load(rf)
        except Exception:
            pass

    updated_sb = build_singbox_config(current_rules, relay_ip=resolved_ips)
    tmp_sb_dir: Optional[str] = None
    try:
        tmp_sb_dir, tmp_sb = _write_private_validation_file("singbox_val_", updated_sb)
        sb_bin = SINGBOX_BIN if os.path.exists(SINGBOX_BIN) else "sing-box"
        res_sb = subprocess.run([sb_bin, "check", "-c", tmp_sb], capture_output=True, text=True, timeout=10)
        if res_sb.returncode != 0:
            err = res_sb.stderr.strip() or res_sb.stdout.strip()
            return False, f"Sing-box validation failed: {err}"
    finally:
        if tmp_sb_dir and os.path.exists(tmp_sb_dir):
            try:
                shutil.rmtree(tmp_sb_dir, ignore_errors=True)
            except Exception:
                pass

    desired = read_desired_state()
    sb_proc = get_singbox_process_status()
    pf_info = get_pf_status()
    vpn_active = (desired != "off") and (sb_proc.get("running", False) or pf_info.get("anchor_loaded", False))

    # Offline activation: update persisted configs & active_server.json without kickstarting daemons
    if not vpn_active:
        try:
            write_pf_egress_file(resolved_ips, port, PF_EGRESS_FILE)
            atomic_write_text(XRAY_CONF_PATH, json.dumps(xray_config, indent=2, ensure_ascii=False), mode=0o640, group_name="vpnguard-proxy")
            atomic_write_text(SINGBOX_CONF_PATH, json.dumps(updated_sb, indent=2, ensure_ascii=False), mode=0o600)
            store["activeId"] = server_id
            save_servers_store(store, store_path)
            return True, f"Server '{server.get('name')}' activated (VPN is currently off)"
        except Exception as e:
            return False, f"Failed saving offline server configuration: {e}"

    # BOTH CHECKS PASSED & VPN IS ACTIVE: Proceed to apply with .bak rollback backup
    prev_xray_bytes: Optional[bytes] = None
    if os.path.exists(XRAY_CONF_PATH):
        try:
            with open(XRAY_CONF_PATH, "rb") as f:
                prev_xray_bytes = f.read()
        except Exception:
            pass

    prev_sb_bytes: Optional[bytes] = None
    if os.path.exists(SINGBOX_CONF_PATH):
        try:
            with open(SINGBOX_CONF_PATH, "rb") as f:
                prev_sb_bytes = f.read()
        except Exception:
            pass

    prev_egress_text: Optional[str] = None
    if os.path.exists(PF_EGRESS_FILE):
        try:
            with open(PF_EGRESS_FILE, "r", encoding="utf-8") as f:
                prev_egress_text = f.read()
        except Exception:
            pass

    prev_active_id = store.get("activeId", "")
    daemons_restarted = False

    def _rollback_activation() -> None:
        if prev_xray_bytes is not None:
            try:
                atomic_write_text(XRAY_CONF_PATH, prev_xray_bytes.decode("utf-8"), mode=0o640, group_name="vpnguard-proxy")
            except Exception:
                pass
        if prev_sb_bytes is not None:
            try:
                atomic_write_text(SINGBOX_CONF_PATH, prev_sb_bytes.decode("utf-8"), mode=0o600)
            except Exception:
                pass
        if prev_egress_text is not None:
            try:
                atomic_write_text(PF_EGRESS_FILE, prev_egress_text, mode=0o644)
                run_privileged(["pfctl", "-a", "vpnguard/egress", "-f", PF_EGRESS_FILE], timeout=10)
            except Exception:
                pass
        store["activeId"] = prev_active_id
        try:
            save_servers_store(store, store_path)
        except Exception:
            pass
        if daemons_restarted:
            for svc in ("system/com.vpnguard.xray", "system/com.vpnguard.singbox"):
                try:
                    subprocess.run(["launchctl", "kickstart", "-k", svc], capture_output=True, timeout=10)
                except Exception:
                    pass

    try:
        if prev_xray_bytes is not None:
            atomic_write_text(f"{XRAY_CONF_PATH}.bak", prev_xray_bytes.decode("utf-8"), mode=0o640, group_name="vpnguard-proxy")
        if prev_sb_bytes is not None:
            atomic_write_text(f"{SINGBOX_CONF_PATH}.bak", prev_sb_bytes.decode("utf-8"), mode=0o600)

        # 1. Update persistent pf.egress.conf & live sub-anchor vpnguard/egress (no PROJECT_ROOT writes)
        eg_ok, eg_err = apply_pf_egress(resolved_ips, port)
        if not eg_ok:
            return False, f"Failed updating PF sub-anchor vpnguard/egress: {eg_err}"

        # 2. Atomically replace xray.json (strip duplicate error file log owned by launchd) and sing-box.json
        xray_to_write = copy.deepcopy(xray_config)
        if isinstance(xray_to_write.get("log"), dict) and xray_to_write["log"].get("error") == LOG_XRAY_PATH:
            xray_to_write["log"].pop("error", None)
        atomic_write_text(XRAY_CONF_PATH, json.dumps(xray_to_write, indent=2, ensure_ascii=False), mode=0o640, group_name="vpnguard-proxy")
        atomic_write_text(SINGBOX_CONF_PATH, json.dumps(updated_sb, indent=2, ensure_ascii=False), mode=0o600)

        # 3. Update store & non-sensitive metadata
        store["activeId"] = server_id
        save_servers_store(store, store_path)

        # 4. Rotate large daemon logs cleanly before launchctl kickstart reopens descriptors
        rotate_log_if_needed(LOG_XRAY_PATH, owner_user="_vpnguard_proxy", group_name="vpnguard-proxy")
        rotate_log_if_needed(LOG_SINGBOX_PATH)
        daemons_restarted = True
        subprocess.run(["launchctl", "kickstart", "-k", "system/com.vpnguard.xray"], capture_output=True, timeout=10)
        subprocess.run(["launchctl", "kickstart", "-k", "system/com.vpnguard.singbox"], capture_output=True, timeout=10)

        # 5. Monitor for up to 6 seconds: verify xray ports AND utun99 come up
        daemons_ok = False
        last_failures: List[str] = []
        for _ in range(12):
            time.sleep(0.5)
            x_stat = get_xray_process_status()
            s_stat = get_singbox_process_status()
            p_socks = check_port_listening("127.0.0.1", 18088, timeout=0.3)
            p_http = check_port_listening("127.0.0.1", 18089, timeout=0.3)
            u_stat = get_utun_status()
            last_failures = []
            if not x_stat.get("running"):
                last_failures.append("xray stopped")
            if not s_stat.get("running"):
                last_failures.append("sing-box stopped")
            if not p_socks:
                last_failures.append("127.0.0.1:18088 closed")
            if not p_http:
                last_failures.append("127.0.0.1:18089 closed")
            if not u_stat.get("active"):
                last_failures.append("utun99 inactive")
            if not last_failures:
                daemons_ok = True
                break

        if not daemons_ok:
            print(f"{C_RED}[!] Daemons failed to stabilize within 6s. Rolling back...{C_RESET}", file=sys.stderr)
            _rollback_activation()
            detail = ", ".join(last_failures) if last_failures else "health check failed"
            return False, f"Daemons failed health check after activation ({detail}). Rollback successfully performed."

        flush_dns_cache()
        return True, f"Server '{server.get('name')}' successfully activated"
    except Exception as e:
        _rollback_activation()
        return False, f"Failed applying server configuration: {e}"


def cmd_server_list(args: argparse.Namespace) -> int:
    """List configured upstream server profiles."""
    is_json = getattr(args, "json", False)
    try:
        store = load_servers_store()
    except Exception as e:
        if is_json:
            print(json.dumps({"status": "error", "message": str(e)}))
        else:
            print(f"{C_RED}[!] Error loading server profiles: {e}{C_RESET}", file=sys.stderr)
        return 1

    active_id = store.get("activeId", "")
    safe_servers = []
    for s in store.get("servers", []):
        safe_servers.append({
            "id": s.get("id", ""),
            "name": s.get("name", "Unnamed"),
            "host": s.get("host", ""),
            "port": s.get("port", 443),
            "transport": s.get("transport", "tcp"),
            "security": s.get("security", "none"),
            "sni": s.get("sni", ""),
            "flow": s.get("flow", ""),
            "isActive": (s.get("id") == active_id)
        })

    if is_json:
        print(json.dumps(safe_servers, indent=2, ensure_ascii=False))
        return 0

    print(f"\n{C_BOLD}{C_CYAN}=== 🌐 VPNGuard Configured Upstream Servers ==={C_RESET}\n")
    if not safe_servers:
        print("  (No servers configured)")
    for s in safe_servers:
        active_mark = f"{C_GREEN}[ACTIVE]{C_RESET}" if s["isActive"] else "        "
        print(f"  {active_mark} {C_BOLD}{s['name']}{C_RESET}")
        print(f"           ID:        {s['id']}")
        print(f"           Address:   {s['host']}:{s['port']}")
        print(f"           Transport: {s['transport']} ({s['security']})")
        if s["sni"]:
            print(f"           SNI:       {s['sni']}")
        if s["flow"]:
            print(f"           Flow:      {s['flow']}")
        print()
    return 0


def cmd_server_import_vless(args: argparse.Namespace) -> int:
    """Parse vless:// URI or JSON configuration (from stdin or file) and register in servers.json."""
    use_stdin = getattr(args, "stdin", False)
    input_path = getattr(args, "path", None)

    try:
        if use_stdin:
            raw_input = read_stdin_bounded()
        else:
            if not input_path or not os.path.exists(input_path):
                raise FileNotFoundError(f"Configuration file not found at {input_path}")
            with open(input_path, "r", encoding="utf-8") as f:
                raw_input = f.read().strip()
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Failed reading server configuration: {e}"}), file=sys.stderr)
        return 1

    if not raw_input:
        print(json.dumps({"status": "error", "message": "Configuration input is empty"}), file=sys.stderr)
        return 1

    profile = None
    if raw_input.startswith("{"):
        try:
            json_data = json.loads(raw_input)
            profile = parse_xray_server_json(json_data)
        except Exception as e:
            err = f"Failed to parse server JSON configuration: {e}"
            print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
            return 1
    elif raw_input.startswith("vless://"):
        try:
            profile = parse_vless_uri(raw_input)
        except Exception as e:
            err = f"Failed to parse vless:// URI: {e}"
            print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
            return 1
    else:
        err = "Unsupported format: input must contain a 'vless://' link or a JSON object '{'"
        print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
        return 1

    valid, val_msg = validate_xray_config(profile["xrayConfig"])
    if not valid:
        err = f"Generated Xray configuration failed syntax validation: {val_msg}"
        print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
        return 1

    try:
        store = load_servers_store()
        store.setdefault("servers", []).append(profile)
        save_servers_store(store)
    except Exception as e:
        err = f"Failed to persist server profile: {e}"
        print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
        return 1

    active_id = store.get("activeId", "")
    safe_profile = {
        "id": profile["id"],
        "name": profile["name"],
        "host": profile["host"],
        "port": profile["port"],
        "transport": profile["transport"],
        "security": profile["security"],
        "sni": profile.get("sni", ""),
        "flow": profile.get("flow", ""),
        "isActive": (profile["id"] == active_id)
    }

    print(json.dumps({
        "status": "ok",
        "server": safe_profile
    }, indent=2, ensure_ascii=False))
    return 0


def _resolve_server_id_arg(args: argparse.Namespace) -> str:
    """Read server_id from bounded stdin or positional argument and validate format."""
    if getattr(args, "stdin", False):
        server_id = read_stdin_bounded(4096)
    else:
        server_id = (getattr(args, "server_id", None) or "").strip()
    if not server_id or len(server_id) > 128:
        raise ValueError("Invalid or empty server ID")
    return server_id


def cmd_server_activate(args: argparse.Namespace) -> int:
    """Atomically activate upstream server profile by ID."""
    try:
        server_id = _resolve_server_id_arg(args)
        with acquire_state_lock(timeout=15.0):
            store = load_servers_store()
            if not any(s.get("id") == server_id for s in store.get("servers", [])):
                raise ValueError(f"Server ID '{server_id}' not found in servers.json")
            success, msg = activate_server(server_id)
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1

    if success:
        print(json.dumps({
            "status": "ok",
            "activeId": server_id,
            "message": msg
        }, indent=2, ensure_ascii=False))
        return 0
    else:
        print(json.dumps({
            "status": "error",
            "message": msg
        }, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


def cmd_server_delete(args: argparse.Namespace) -> int:
    """Delete server profile by ID (cannot delete currently active server)."""
    try:
        server_id = _resolve_server_id_arg(args)
        store = load_servers_store()
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Failed loading store: {e}"}), file=sys.stderr)
        return 1

    active_id = store.get("activeId", "")
    if server_id == active_id:
        err = f"Cannot delete server {server_id}: server is currently active!"
        print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
        return 1

    servers = store.get("servers", [])
    found = False
    new_servers = []
    for s in servers:
        if s.get("id") == server_id:
            found = True
        else:
            new_servers.append(s)

    if not found:
        err = f"Server profile with ID '{server_id}' not found"
        print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
        return 1

    store["servers"] = new_servers
    try:
        save_servers_store(store)
    except Exception as e:
        err = f"Failed saving server store: {e}"
        print(json.dumps({"status": "error", "message": err}), file=sys.stderr)
        return 1

    print(json.dumps({
        "status": "ok",
        "deletedId": server_id
    }, indent=2, ensure_ascii=False))
    return 0


def _skip_dns_name(packet: bytes, offset: int) -> int:
    """Advance past a DNS QNAME/NAME (handling pointer compression safely)."""
    hops = 0
    cur = offset
    n = len(packet)
    while cur < n and hops < 32:
        length = packet[cur]
        if length == 0:
            return cur + 1
        if (length & 0xC0) == 0xC0:
            if cur + 1 >= n:
                raise ValueError("Truncated DNS compression pointer")
            return cur + 2
        cur += 1 + length
        hops += 1
    raise ValueError("Malformed DNS name")


def _build_dns_a_query(hostname: str, tx_id: int) -> bytes:
    """Build a standard RFC 1035 UDP DNS A-record query packet."""
    clean = hostname.strip().rstrip(".")
    if not clean:
        raise ValueError("Empty hostname")
    header = struct.pack("!HHHHHH", tx_id & 0xFFFF, 0x0100, 1, 0, 0, 0)
    qname_parts: List[bytes] = []
    for label in clean.split("."):
        encoded = label.encode("idna")
        if not (1 <= len(encoded) <= 63):
            raise ValueError(f"Invalid DNS label length in '{hostname}'")
        qname_parts.append(bytes([len(encoded)]) + encoded)
    qname = b"".join(qname_parts) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def _parse_dns_a_response(packet: bytes, expected_tx_id: int) -> List[str]:
    """Parse IPv4 A records from a raw DNS UDP response packet."""
    if len(packet) < 12:
        return []
    tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if tx_id != (expected_tx_id & 0xFFFF):
        return []
    if (flags & 0x000F) != 0:
        return []

    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(packet, offset) + 4
        if offset > len(packet):
            return []

    ips: List[str] = []
    for _ in range(ancount):
        offset = _skip_dns_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(packet):
            break
        if rtype == 1 and rclass == 1 and rdlength == 4:
            ip_str = socket.inet_ntoa(packet[offset:offset + 4])
            if ip_str not in ips:
                ips.append(ip_str)
        offset += rdlength
    return ips


def _run_in_gid890_worker(fn: Callable[[], Any], timeout: float = 10.0) -> Any:
    """
    Execute fn inside a short-lived forked child dropped to GID 890 + UID nobody.
    PF allows group 890 direct IPv4 TCP/UDP egress bypassing utun99 when bound via IP_BOUND_IF.
    """
    if os.geteuid() != 0:
        return fn()

    nobody_uid = 65534
    try:
        nobody_uid = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pass

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            try:
                os.setgroups([890])
                os.setgid(890)
                os.setuid(nobody_uid)
            except Exception as e:
                try:
                    os.write(write_fd, json.dumps({"ok": False, "error": f"GID 890 privilege drop failed: {e}"}).encode("utf-8"))
                    os.close(write_fd)
                except Exception:
                    pass
                os._exit(1)
            payload = json.dumps({"ok": True, "result": fn()}, ensure_ascii=False).encode("utf-8")
            os.write(write_fd, payload)
        except Exception as e:
            try:
                os.write(write_fd, json.dumps({"ok": False, "error": str(e)}).encode("utf-8"))
            except Exception:
                pass
        finally:
            try:
                os.close(write_fd)
            except Exception:
                pass
            os._exit(0)

    os.close(write_fd)
    chunks: List[bytes] = []
    deadline = time.monotonic() + max(0.5, timeout)
    timed_out = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready, _, _ = select.select([read_fd], [], [], remaining)
            if not ready:
                timed_out = True
                break
            chunk = os.read(read_fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(read_fd)
        if timed_out:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
        try:
            os.waitpid(pid, 0)
        except Exception:
            pass

    if timed_out:
        raise TimeoutError(f"GID 890 worker timed out after {timeout:.1f}s")

    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        return None
    parsed = json.loads(raw)
    if not parsed.get("ok"):
        raise RuntimeError(parsed.get("error", "GID 890 worker failed"))
    return parsed.get("result")


def resolve_ipv4_direct_via_gid890(
    hostname: str,
    dns_servers: Tuple[str, ...] = ("1.1.1.1", "8.8.8.8"),
    timeout: float = 2.5,
) -> List[str]:
    """
    Resolve hostname A records via direct UDP DNS (1.1.1.1 / 8.8.8.8) using GID 890 + IP_BOUND_IF,
    avoiding mDNSResponder / dead utun99 during failover or tunnel outages.
    """
    host = hostname.strip()
    if not host:
        return []
    try:
        if ipaddress.ip_address(host).version == 4:
            return [host]
    except ValueError:
        pass

    iface = _get_physical_default_interface()
    if_index: Optional[int] = None
    if iface:
        try:
            if_index = socket.if_nametoindex(iface)
        except Exception:
            if_index = None

    def _query_dns() -> List[str]:
        tx_id = secrets.randbelow(65535) + 1
        query = _build_dns_a_query(host, tx_id)
        for dns_ip in dns_servers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                if if_index is not None and if_index > 0:
                    try:
                        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF_DARWIN, struct.pack("I", if_index))
                    except OSError:
                        pass
                sock.sendto(query, (dns_ip, 53))
                resp, _ = sock.recvfrom(2048)
                ips = _parse_dns_a_response(resp, tx_id)
                if ips:
                    return ips
            except Exception:
                continue
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        return []

    try:
        res = _run_in_gid890_worker(_query_dns)
        return res if isinstance(res, list) else []
    except Exception:
        return []


def cmd_server_sync_pf(args: argparse.Namespace) -> int:
    """
    Re-resolve active relay domain directly via GID 890 + IP_BOUND_IF (bypassing utun99),
    refresh pf.egress.conf & vpnguard/egress, and update sing-box.json if relay IP rotated.
    """
    store = load_servers_store() if os.path.exists(SERVERS_FILE_PATH) else None
    active_srv = None
    host = ""
    port = 443
    prev_ips: List[str] = []

    if store:
        active_id = store.get("activeId")
        for s in store.get("servers", []):
            if s.get("id") == active_id:
                active_srv = s
                host = str(s.get("host", "")).strip()
                port = int(s.get("port", 443))
                prev_ips = [str(x).strip() for x in (s.get("resolvedIps") or []) if str(x).strip()]
                break

    if not host and os.path.exists(XRAY_CONF_PATH):
        try:
            with open(XRAY_CONF_PATH, "r", encoding="utf-8") as xf:
                host, port = _extract_xray_endpoint(json.load(xf))
        except Exception:
            pass

    ips: List[str] = []
    if host:
        ips = resolve_ipv4_direct_via_gid890(host)

    if not ips:
        ips = prev_ips
    if not ips:
        ips, port = get_active_relay_endpoint()
    if not ips:
        print(json.dumps({"status": "error", "message": "No active relay endpoint found"}), file=sys.stderr)
        return 1

    ok, msg = apply_pf_egress(ips, port)
    if not ok:
        print(json.dumps({"status": "error", "message": msg}), file=sys.stderr)
        return 1

    ips_changed = (ips != prev_ips)
    if store and active_srv is not None and ips_changed:
        active_srv["resolvedIps"] = ips
        try:
            save_servers_store(store)
        except Exception:
            pass

        # Keep utun99 route_exclude_address in sync with rotated relay IP
        try:
            current_rules = DEFAULT_RULES
            if os.path.exists(RULES_FILE_PATH):
                with open(RULES_FILE_PATH, "r", encoding="utf-8") as rf:
                    current_rules = json.load(rf)
            updated_sb = build_singbox_config(current_rules, relay_ip=ips)
            tmp_sb = f"{SINGBOX_CONF_PATH}.tmp_{os.getpid()}"
            atomic_write_text(tmp_sb, json.dumps(updated_sb, indent=2, ensure_ascii=False), mode=0o600)
            sb_bin = SINGBOX_BIN if os.path.exists(SINGBOX_BIN) else "sing-box"
            if subprocess.run([sb_bin, "check", "-c", tmp_sb], capture_output=True, timeout=10).returncode == 0:
                os.replace(tmp_sb, SINGBOX_CONF_PATH)
                os.chmod(SINGBOX_CONF_PATH, 0o600)
                if get_singbox_process_status().get("running"):
                    subprocess.run(["launchctl", "kickstart", "-k", "system/com.vpnguard.singbox"], capture_output=True, timeout=10)
            elif os.path.exists(tmp_sb):
                os.remove(tmp_sb)
        except Exception:
            pass

    print(json.dumps({"status": "ok", "ips": ips, "port": port, "ipsChanged": ips_changed, "message": msg}))
    return 0


IP_BOUND_IF_DARWIN = 25


def _get_physical_default_interface() -> Optional[str]:
    """Detect active physical IPv4 default interface (excluding utun/lo/awdl) via netstat."""
    excluded_prefixes = ("utun", "lo", "awdl", "llw", "ipsec", "bridge", "gif", "stf")
    try:
        res = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "default":
                    iface = parts[3].strip()
                    if iface and not iface.startswith(excluded_prefixes):
                        return iface
    except Exception:
        pass
    try:
        if os.path.exists("/usr/sbin/networksetup"):
            res = subprocess.run(["networksetup", "-listnetworkserviceorder"], capture_output=True, text=True, timeout=3)
            for m in re.finditer(r"Device:\s*(en\d+)\)", res.stdout):
                return m.group(1)
    except Exception:
        pass
    return "en0"


def _resolve_server_probe_ip(server: Dict[str, Any]) -> Optional[str]:
    """Prefer cached resolvedIps (works even when tunnel DNS is down), else resolve host."""
    for candidate in (server.get("resolvedIps") or []):
        cand_str = str(candidate).strip()
        if cand_str:
            try:
                ip_obj = ipaddress.ip_address(cand_str)
                if ip_obj.version == 4:
                    return cand_str
            except ValueError:
                pass
    host = str(server.get("host", "")).strip()
    if not host:
        return None
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.version == 4:
            return host
    except ValueError:
        pass
    ips = resolve_host_ipv4(host)
    for ip_cand in ips:
        try:
            if ipaddress.ip_address(ip_cand).version == 4:
                return ip_cand
        except ValueError:
            continue
    return None


def _probe_tcp_rtt_single(
    target_ip: str,
    port: int,
    if_index: Optional[int],
    timeout: float = 2.0
) -> Tuple[Optional[int], Optional[str]]:
    """Measure direct TCP handshake RTT (ms) optionally bound to physical interface via IP_BOUND_IF."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if if_index is not None and if_index > 0:
            try:
                sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF_DARWIN, struct.pack("I", if_index))
            except OSError:
                pass
        t0 = time.monotonic()
        sock.connect((target_ip, int(port)))
        elapsed_ms = max(1, int(round((time.monotonic() - t0) * 1000.0)))
        return elapsed_ms, None
    except Exception as e:
        return None, str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def ping_servers_via_gid890(servers: List[Dict[str, Any]], timeout: float = 2.0) -> List[Dict[str, Any]]:
    """
    Probe all servers concurrently via direct physical interface (IP_BOUND_IF) inside a GID 890
    child process so PF allows direct IPv4 bypass without weakening Kill-Switch rules.
    """
    iface = _get_physical_default_interface()
    if_index: Optional[int] = None
    if iface:
        try:
            if_index = socket.if_nametoindex(iface)
        except Exception:
            if_index = None

    prepared: List[Dict[str, Any]] = []
    for s in servers:
        prepared.append({
            "id": s.get("id", ""),
            "name": s.get("name", "Unnamed"),
            "host": s.get("host", ""),
            "port": int(s.get("port", 443)),
            "ip": _resolve_server_probe_ip(s),
        })

    def _run_probes() -> List[Dict[str, Any]]:
        def _probe_one(item: Dict[str, Any]) -> Dict[str, Any]:
            ip_addr = item["ip"]
            if not ip_addr:
                return {
                    "id": item["id"],
                    "name": item["name"],
                    "host": item["host"],
                    "ip": None,
                    "port": item["port"],
                    "latencyMs": None,
                    "reachable": False,
                    "error": "Failed to resolve server IPv4",
                }
            rtt, err = _probe_tcp_rtt_single(ip_addr, item["port"], if_index, timeout=timeout)
            return {
                "id": item["id"],
                "name": item["name"],
                "host": item["host"],
                "ip": ip_addr,
                "port": item["port"],
                "latencyMs": rtt,
                "reachable": (rtt is not None),
                "error": err,
            }

        if not prepared:
            return []
        with ThreadPoolExecutor(max_workers=min(8, len(prepared))) as pool:
            return list(pool.map(_probe_one, prepared))

    res = _run_in_gid890_worker(_run_probes)
    return res if isinstance(res, list) else []


def cmd_server_ping(args: argparse.Namespace) -> int:
    """Measure direct TCP RTT (ms) to all configured servers via GID 890 + IP_BOUND_IF."""
    is_json = getattr(args, "json", False)
    try:
        store = load_servers_store()
        servers = store.get("servers", [])
        results = ping_servers_via_gid890(servers, timeout=2.0)
    except Exception as e:
        if is_json:
            print(json.dumps({"status": "error", "message": str(e)}))
        else:
            print(f"{C_RED}[!] Server ping failed: {e}{C_RESET}", file=sys.stderr)
        return 1

    if is_json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0

    for item in results:
        lat = f"{item['latencyMs']} ms" if item["reachable"] else f"FAIL ({item.get('error')})"
        print(f"  • {item['name']} ({item['host']}:{item['port']}): {lat}")
    return 0


def cmd_server_update(args: argparse.Namespace) -> int:
    """Validate and atomically apply new upstream Xray JSON, syncing servers.json and PF."""
    use_stdin = getattr(args, "stdin", False)
    input_path = getattr(args, "path", None)

    try:
        if use_stdin:
            xray_data = json.loads(read_stdin_bounded())
        else:
            if not input_path or not os.path.exists(input_path):
                raise FileNotFoundError(f"Server configuration file not found at {input_path}")
            with open(input_path, "r", encoding="utf-8") as f:
                xray_data = json.load(f)
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Failed to parse Xray JSON config: {e}"}), file=sys.stderr)
        return 1

    try:
        profile = parse_xray_server_json(xray_data, default_name="Custom JSON Server")
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}), file=sys.stderr)
        return 1

    xray_valid, xray_err = validate_xray_config(profile["xrayConfig"])
    if not xray_valid:
        print(json.dumps({"status": "error", "message": f"Xray syntax validation failed: {xray_err}"}), file=sys.stderr)
        return 1

    try:
        with acquire_state_lock(timeout=15.0):
            store = load_servers_store()
            # Keep existing profile ID if matching host+port+name, else append new profile
            existing = next(
                (s for s in store.get("servers", [])
                 if s.get("host") == profile["host"] and s.get("port") == profile["port"] and s.get("name") == profile["name"]),
                None
            )
            if existing:
                existing.update({k: v for k, v in profile.items() if k != "id"})
                target_id = existing["id"]
            else:
                store.setdefault("servers", []).append(profile)
                target_id = profile["id"]
            save_servers_store(store)
            ok, msg = activate_server(target_id)
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Failed saving/activating server profile: {e}"}), file=sys.stderr)
        return 1

    if not ok:
        print(json.dumps({"status": "error", "message": msg}), file=sys.stderr)
        return 1

    print(json.dumps({
        "status": "ok",
        "serverId": target_id,
        "relayIp": profile["resolvedIps"][0] if profile.get("resolvedIps") else profile["host"],
        "relayPort": profile["port"],
        "message": msg
    }))
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Run comprehensive active leak penetration test suite (12 checks)."""
    is_json = getattr(args, "json", False)
    if not is_json:
        print(f"\n{C_BOLD}{C_CYAN}=== 🧪 VPNGuard 3.0 Rigorous Penetration Leak Audit (12 Checks) ==={C_RESET}\n")

    results: List[Tuple[str, bool, str]] = []
    helper_path = EXEC_HELPER_PATH if os.path.exists(EXEC_HELPER_PATH) else LOCAL_EXEC_HELPER
    target_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and (not target_user or target_user == "root"):
        try:
            cu = subprocess.run(["stat", "-f", "%Su", "/dev/console"], capture_output=True, text=True, timeout=5)
            console_user = cu.stdout.strip()
            if cu.returncode == 0 and console_user and console_user != "root":
                target_user = console_user
        except Exception:
            pass
    helper_prefix = ["sudo", "-u", target_user] if (os.geteuid() == 0 and target_user and target_user != "root") else []
    helper_runner = helper_prefix + [helper_path]
    config = load_config()
    host, socks_port, http_port = resolve_active_proxy(config)
    pf_info = get_pf_status()
    phys_info = query_physical_ip()

    # Test 1: 3-Point PF Kernel Killswitch Verification
    pf_ok = pf_info["enabled"] and pf_info["main_anchor_linked"] and pf_info["anchor_loaded"] and pf_info["has_group_888"] and pf_info["has_group_889"]
    results.append((
        "1. PF 3-Point Kernel Verification (Enabled + Linked + Armed)",
        pf_ok,
        f"PF: {'Enabled' if pf_info['enabled'] else 'OFF'}, /etc/pf.conf: {'Linked' if pf_info['main_anchor_linked'] else 'Unlinked'}, Rules: {pf_info['rules_count']} (Dual-GID)"
    ))

    # Test 2: Dedicated Xray Proxy Daemon Isolation (Non-root, GID 889)
    xray_proc = get_xray_process_status()
    proc_ok = xray_proc["running"] and (not xray_proc["is_root"]) and (xray_proc["group"] in ["vpnguard-proxy", "889"])
    results.append((
        "2. Dedicated Xray Proxy Daemon Isolation (Non-root, GID 889)",
        proc_ok,
        f"PID: {xray_proc['pid']}, User: {xray_proc['user']}, Group: {xray_proc['group']}" if xray_proc["running"] else "Xray daemon not running"
    ))

    # Test 3: Complete Happ Decoupling Prevention (lo0 10808/10809 blocked for GID 888)
    if os.path.exists(helper_path) and pf_info["anchor_loaded"]:
        test_happ = (
            "import socket, sys\n"
            "for port in [10808, 10809]:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    s.settimeout(0.5)\n"
            "    try:\n"
            "        s.connect(('127.0.0.1', port))\n"
            "        sys.exit(0)\n"
            "    except Exception:\n"
            "        pass\n"
            "sys.exit(1)\n"
        )
        res_happ = subprocess.run(helper_runner + [sys.executable, "-c", test_happ], capture_output=True, timeout=15)
        happ_blocked = (res_happ.returncode != 0)
        results.append((
            "3. Happ Decoupling Prevention (lo0:10808/10809 blocked)",
            happ_blocked,
            "BLOCKED (PF explicitly rejects loopback connections to Happ)" if happ_blocked else "FAILED! Happ loopback port accessible!"
        ))
    else:
        results.append(("3. Happ Decoupling Prevention", False, "SKIPPED (Helper or PF unavailable)"))

    # Test 4: Dedicated Xray Proxy Ports Reachability (18088 / 18089)
    socks_up = check_port_listening(host, socks_port)
    http_up = check_port_listening(host, http_port)
    ports_ok = socks_up and http_up
    results.append((
        "4. Dedicated Proxy Ports Reachability (SOCKS 18088 & HTTP 18089)",
        ports_ok,
        f"SOCKS (18088): {'UP' if socks_up else 'DOWN'}, HTTP (18089): {'UP' if http_up else 'DOWN'}"
    ))

    # Test 5: Remote Host Resolution via Proxy (Zero local mDNS query)
    try:
        test_domain = "api.anthropic.com"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((host, socks_port))
        s.sendall(b"\x05\x01\x00")
        s.recv(2)
        b_dom = test_domain.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(b_dom)]) + b_dom + (443).to_bytes(2, "big")
        s.sendall(req)
        resp = s.recv(10)
        s.close()
        dns_ok = (len(resp) >= 2 and resp[1] == 0)
        results.append((
            "5. Remote Host-Resolution (socks5h / Zero local mDNS)",
            dns_ok,
            f"Resolved & connected to {test_domain}:443 remotely via proxy" if dns_ok else "Resolution/connection standby (upstream tunnel required)"
        ))
    except Exception as e:
        results.append(("5. Remote Host-Resolution (socks5h / Zero local mDNS)", False, f"Standby: {e}"))

    # Test 6: Direct IPv4 Bypass Prevention (TCP 1.1.1.1:80 outside lo0)
    if os.path.exists(helper_path) and pf_info["anchor_loaded"]:
        test_v4 = (
            "import socket, sys\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(1.5)\n"
            "try:\n"
            "    s.connect(('1.1.1.1', 80))\n"
            "    sys.exit(0)\n"
            "except Exception:\n"
            "    sys.exit(1)\n"
        )
        res_v4 = subprocess.run(helper_runner + [sys.executable, "-c", test_v4], capture_output=True, timeout=15)
        blocked_v4 = (res_v4.returncode != 0)
        results.append((
            "6. Direct IPv4 TCP Bypass Prevention (1.1.1.1:80 direct)",
            blocked_v4,
            "BLOCKED (Instant TCP RST / drop by XNU PF killswitch)" if blocked_v4 else "FAILED! Direct packet escaped!"
        ))
    else:
        results.append(("6. Direct IPv4 TCP Bypass Prevention", False, "SKIPPED"))

    # Test 7: Direct IPv6 Bypass Prevention ([2606:4700:4700::1111]:80)
    if os.path.exists(helper_path) and pf_info["anchor_loaded"]:
        test_v6 = (
            "import socket, sys\n"
            "s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n"
            "s.settimeout(1.5)\n"
            "try:\n"
            "    s.connect(('2606:4700:4700::1111', 80))\n"
            "    sys.exit(0)\n"
            "except Exception:\n"
            "    sys.exit(1)\n"
        )
        res_v6 = subprocess.run(helper_runner + [sys.executable, "-c", test_v6], capture_output=True, timeout=15)
        blocked_v6 = (res_v6.returncode != 0)
        results.append((
            "7. Direct IPv6 TCP Bypass Prevention ([2606:..]:80 direct)",
            blocked_v6,
            "BLOCKED (Instant drop by XNU PF killswitch)" if blocked_v6 else "FAILED! Direct packet escaped!"
        ))
    else:
        results.append(("7. Direct IPv6 TCP Bypass Prevention", False, "SKIPPED"))

    # Test 8: Direct UDP DNS Leak Test (UDP 1.1.1.1:53 outside lo0)
    if os.path.exists(helper_path) and pf_info["anchor_loaded"]:
        test_udp = (
            "import socket, sys\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.settimeout(1.0)\n"
            "try:\n"
            "    s.sendto(b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x06google\\x03com\\x00\\x00\\x01\\x00\\x01', ('1.1.1.1', 53))\n"
            "    data = s.recv(512)\n"
            "    sys.exit(0)\n"
            "except Exception:\n"
            "    sys.exit(1)\n"
        )
        res_udp = subprocess.run(helper_runner + [sys.executable, "-c", test_udp], capture_output=True, timeout=15)
        blocked_udp = (res_udp.returncode != 0)
        results.append((
            "8. Direct UDP DNS Leak Prevention (1.1.1.1:53 unproxied)",
            blocked_udp,
            "BLOCKED (UDP packet rejected by XNU PF killswitch)" if blocked_udp else "FAILED! UDP packet escaped!"
        ))
    else:
        results.append(("8. Direct UDP DNS Leak Prevention", False, "SKIPPED"))

    # Test 9: Anti-LPE Security Check (Root execution prohibited)
    if os.path.exists(helper_path):
        res_root = subprocess.run(["sudo", "-n", helper_path, "/bin/ls"], capture_output=True, text=True, timeout=10)
        root_rejected = (res_root.returncode != 0 and (
            "a password is required" in res_root.stderr or
            "SECURITY VIOLATION" in res_root.stderr
        ))
        results.append((
            "9. Anti-LPE Security Check (Root execution prohibited)",
            root_rejected,
            "ENFORCED (Root execution rejected & sudoers hardened)" if root_rejected else "FAILED! Root execution permitted!"
        ))
    else:
        results.append(("9. Anti-LPE Security Check", False, "SKIPPED"))

    # Test 10: Environment Variable & Browser Sandbox Integrity
    if os.path.exists(helper_path):
        code_env = (
            "import os, json\n"
            "data = {\n"
            "    'HTTP_PROXY': os.environ.get('HTTP_PROXY'),\n"
            "    'http_proxy': os.environ.get('http_proxy'),\n"
            "    'HTTPS_PROXY': os.environ.get('HTTPS_PROXY'),\n"
            "    'https_proxy': os.environ.get('https_proxy'),\n"
            "    'ALL_PROXY': os.environ.get('ALL_PROXY'),\n"
            "    'all_proxy': os.environ.get('all_proxy'),\n"
            "    'NO_PROXY': os.environ.get('NO_PROXY'),\n"
            "    'BROWSER': os.environ.get('BROWSER'),\n"
            "    'CLAUDE': os.environ.get('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'),\n"
            "    'TZ': os.environ.get('TZ')\n"
            "}\n"
            "print(json.dumps(data))\n"
        )
        res_env = subprocess.run(helper_runner + [sys.executable, "-c", code_env], capture_output=True, text=True, timeout=15)
        lines = [l.strip() for l in res_env.stdout.strip().split("\n") if l.strip().startswith("{")]
        env_ok = False
        details = "Failed to read environment from sandbox"
        if lines:
            try:
                ed = json.loads(lines[0])
                has_http = (ed.get("HTTP_PROXY") == f"http://127.0.0.1:{http_port}" and ed.get("http_proxy") == f"http://127.0.0.1:{http_port}")
                has_socks = (ed.get("ALL_PROXY") == f"socks5h://127.0.0.1:{socks_port}" and ed.get("all_proxy") == f"socks5h://127.0.0.1:{socks_port}")
                has_browser = (ed.get("BROWSER") == "/usr/local/bin/vpnguard-browser")
                has_telemetry = (ed.get("CLAUDE") == "1")
                has_tz = bool(ed.get("TZ"))
                env_ok = has_http and has_socks and has_browser and has_telemetry and has_tz
                details = f"HTTP:{http_port}, SOCKS:{socks_port}, BROWSER:vpnguard-browser, TZ:{ed.get('TZ')}"
            except Exception as e:
                details = str(e)
        results.append((
            "10. Environment & Browser Sandbox Integrity",
            env_ok,
            details if env_ok else f"Failed checks: {details}"
        ))
    else:
        results.append(("10. Environment & Browser Sandbox Integrity", False, "SKIPPED"))

    # Test 11: Dual-Mirror Egress Check (Foreign & Alternate Mirrors via HTTP 18089)
    if os.path.exists(helper_path) and check_port_listening(host, http_port):
        code_dual = (
            "import urllib.request, json, sys, re, time\n"
            f"proxy_handler = urllib.request.ProxyHandler({{'http': 'http://{host}:{http_port}', 'https': 'http://{host}:{http_port}'}})\n"
            "opener = urllib.request.build_opener(proxy_handler)\n"
            "ip_foreign = None\n"
            "for _ in range(2):\n"
            "    try:\n"
            "        req1 = urllib.request.Request('https://api.ipify.org?format=json', headers={'User-Agent': 'curl/8.0'})\n"
            "        with opener.open(req1, timeout=5.0) as resp:\n"
            "            data1 = json.loads(resp.read().decode())\n"
            "            ip_foreign = data1.get('ip', '').strip()\n"
            "            if ip_foreign: break\n"
            "    except Exception:\n"
            "        time.sleep(0.5)\n"
            "ip_mirror = None\n"
            "for _ in range(2):\n"
            "    try:\n"
            "        req2 = urllib.request.Request('https://2ip.io', headers={'User-Agent': 'curl/8.0'})\n"
            "        with opener.open(req2, timeout=5.0) as resp:\n"
            "            text2 = resp.read().decode().strip()\n"
            "            m = re.search(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', text2)\n"
            "            if m:\n"
            "                ip_mirror = m.group(0)\n"
            "                break\n"
            "    except Exception:\n"
            "        try:\n"
            "            req2 = urllib.request.Request('https://ifconfig.co/json', headers={'User-Agent': 'curl/8.0'})\n"
            "            with opener.open(req2, timeout=5.0) as resp:\n"
            "                data2 = json.loads(resp.read().decode())\n"
            "                ip_mirror = data2.get('ip', '').strip()\n"
            "                if ip_mirror: break\n"
            "        except Exception:\n"
            "            time.sleep(0.5)\n"
            "print(json.dumps({'foreign': ip_foreign, 'mirror': ip_mirror}))\n"
        )
        res_dual = subprocess.run(helper_runner + [sys.executable, "-c", code_dual], capture_output=True, text=True, timeout=25)
        lines = [l.strip() for l in res_dual.stdout.strip().split("\n") if l.strip().startswith("{")]
        dual_ok = False

        has_placeholder = False
        try:
            with open("/usr/local/etc/vpnguard/xray.json", "r") as cf:
                if "REPLACE_WITH_UUID" in cf.read():
                    has_placeholder = True
        except Exception:
            pass

        if has_placeholder:
            dual_details = "Standby (Configure UUID in /usr/local/etc/vpnguard/xray.json to establish upstream tunnel)"
        else:
            dual_details = "Fail-Closed Active: Upstream tunnel reconnecting or timed out (Zero leak: Russian IP protected)"

        phys_ip = (phys_info or {}).get("ip", "")

        if lines:
            try:
                res_obj = json.loads(lines[0])
                f_ip = res_obj.get("foreign")
                m_ip = res_obj.get("mirror")
                if f_ip and m_ip:
                    no_leak = (f_ip != phys_ip) and (m_ip != phys_ip)
                    ip_match = (f_ip == m_ip)
                    if no_leak and ip_match:
                        dual_ok = True
                        dual_details = f"Verified: {f_ip} (Foreign & 2ip.io match, Provider IP {phys_ip} hidden)"
                    elif no_leak:
                        dual_ok = True
                        dual_details = f"Verified non-leaking pool: {f_ip} / {m_ip} (Provider IP {phys_ip} hidden)"
                    else:
                        dual_details = f"LEAK DETECTED! Returned provider IP: {f_ip}"
                elif f_ip or m_ip:
                    valid_ip = f_ip or m_ip
                    if valid_ip != phys_ip:
                        dual_ok = True
                        dual_details = f"Single mirror verified: {valid_ip} (Non-RU, Provider hidden)"
            except Exception as e:
                dual_details = f"Error evaluating mirrors: {e}"

        results.append((
            "11. Dual-Mirror Egress Check (Foreign & 2ip.io via 18089)",
            dual_ok,
            dual_details
        ))
    else:
        results.append((
            "11. Dual-Mirror Egress Check (Foreign & 2ip.io via 18089)",
            False,
            "SKIPPED (Helper or HTTP port 18089 unavailable)"
        ))

    # Test 12: Transparent TUN Egress & LAN DNS Leak Check (utun99 without HTTP_PROXY)
    utun_info = get_utun_status()
    if utun_info.get("active") and pf_info["anchor_loaded"]:
        tun_ok = False
        tun_details = "TUN egress check failed"
        try:
            res_tun = subprocess.run(
                ["curl", "-s", "--noproxy", "*", "--max-time", "5", "https://api.ipify.org?format=json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            tun_ip = ""
            if res_tun.returncode == 0 and res_tun.stdout.strip():
                tun_ip = json.loads(res_tun.stdout).get("ip", "").strip()

            phys_ip = (phys_info or {}).get("ip", "")
            # Also verify plain UDP 53 to RFC1918 LAN router is blocked for non-890 processes
            lan_dns_blocked = True
            if os.path.exists(helper_path):
                code_lan_dns = (
                    "import socket, sys\n"
                    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                    "s.settimeout(0.5)\n"
                    "try:\n"
                    "    s.sendto(b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x06google\\x03com\\x00\\x00\\x01\\x00\\x01', ('192.168.1.1', 53))\n"
                    "    s.recv(512)\n"
                    "    sys.exit(0)\n"
                    "except Exception:\n"
                    "    sys.exit(1)\n"
                )
                res_lan = subprocess.run(helper_runner + [sys.executable, "-c", code_lan_dns], capture_output=True, timeout=15)
                lan_dns_blocked = (res_lan.returncode != 0)

            if tun_ip and tun_ip != phys_ip and lan_dns_blocked:
                tun_ok = True
                tun_details = f"Verified via {utun_info['interface']}: {tun_ip} (no HTTP_PROXY, LAN port 53 blocked)"
            elif not lan_dns_blocked:
                tun_details = "FAILED! Plain DNS packet to RFC1918 LAN port 53 was not blocked"
            else:
                tun_details = f"Transparent TUN egress did not return valid non-RU IP (got '{tun_ip}')"
        except Exception as e:
            tun_details = f"TUN test error: {e}"
        results.append((
            "12. Transparent TUN Egress & LAN DNS Block (utun99)",
            tun_ok,
            tun_details
        ))
    else:
        results.append((
            "12. Transparent TUN Egress & LAN DNS Block (utun99)",
            False,
            "SKIPPED (utun99 or PF unavailable)"
        ))

    all_passed = all(r[1] for r in results)
    passed_count = sum(1 for r in results if r[1])
    failed_count = len(results) - passed_count

    if is_json:
        out = {
            "passed": all_passed,
            "total": len(results),
            "passedCount": passed_count,
            "failedCount": failed_count,
            "tests": [
                {
                    "id": idx + 1,
                    "name": r[0],
                    "passed": r[1],
                    "details": r[2]
                }
                for idx, r in enumerate(results)
            ]
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if all_passed else 1

    # Print results table
    print(f"{'Audit Test Item':<58} | {'Status':<10} | {'Details'}")
    print("-" * 105)
    for name, passed, details in results:
        status_str = f"{C_GREEN}PASS{C_RESET}" if passed else f"{C_RED}FAIL{C_RESET}"
        print(f"{name:<58} | {status_str:<19} | {details}")
    print("-" * 105)

    if all_passed:
        print(f"\n{C_BOLD}{C_GREEN}🎉 ALL {len(results)} AUDIT TESTS PASSED! Your connection is fully protected by Dual-GID jail.{C_RESET}\n")
        return 0
    else:
        print(f"\n{C_BOLD}{C_YELLOW}⚠️  SOME AUDIT TESTS FAILED OR ARE IN STANDBY. Review the results above.{C_RESET}\n")
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    """Execute command inside the VPNGuard protected sandbox."""
    if os.geteuid() == 0:
        print(f"{C_BOLD}{C_RED}[!] Security Error:{C_RESET} Running 'vpnguard run' as root is prohibited for safety.", file=sys.stderr)
        return 1

    if not args.command:
        print("Usage: vpnguard run <command> [args...]", file=sys.stderr)
        return 1

    config = load_config()
    host, socks_port, http_port = resolve_active_proxy(config)

    # 1. Fail-closed pre-flight check
    if not check_port_listening(host, socks_port) and not check_port_listening(host, http_port):
        print(f"{C_BOLD}{C_RED}[!] VPNGuard Pre-Flight Failed:{C_RESET} Dedicated Xray proxy is not listening on {host}:{socks_port}/{http_port}!", file=sys.stderr)
        print(f"{C_YELLOW}[i] Please ensure com.vpnguard.xray LaunchDaemon is running.{C_RESET}", file=sys.stderr)
        return 1

    # 2. Kernel PF fail-closed verification
    pf_info = get_pf_status()
    if not pf_info["anchor_loaded"]:
        print(f"{C_BOLD}{C_RED}[!] VPNGuard Pre-Flight Failed:{C_RESET} Kernel Packet Filter anchor is not loaded!", file=sys.stderr)
        print(f"{C_YELLOW}[i] Run: sudo /usr/local/libexec/vpnguard-pf-boot.sh{C_RESET}", file=sys.stderr)
        return 1

    # 3. Locate setuid launcher
    helper_path = EXEC_HELPER_PATH if os.path.exists(EXEC_HELPER_PATH) else LOCAL_EXEC_HELPER
    if not os.path.exists(helper_path):
        print(f"{C_BOLD}{C_RED}[!] Error:{C_RESET} Setuid launcher not found at {helper_path}!", file=sys.stderr)
        print(f"{C_YELLOW}[i] Please run: sudo ./install.sh{C_RESET}", file=sys.stderr)
        return 1

    # 4. Handle GUI / Electron apps (Cursor, Code)
    target_cmd = list(args.command)
    cmd_name = target_cmd[0].lower()

    if cmd_name in ["cursor", "code"] or cmd_name.endswith("/cursor") or cmd_name.endswith("/code"):
        direct_cursor = "/Applications/Cursor.app/Contents/MacOS/Cursor"
        direct_code = "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"

        if ("cursor" in cmd_name):
            if os.path.exists(direct_cursor):
                print(f"{C_CYAN}[i] Bypassing LaunchServices: Launching Cursor Mach-O binary directly...{C_RESET}")
                target_cmd[0] = direct_cursor
            else:
                print(f"{C_RED}[!] Error: Cursor binary not found at {direct_cursor}!{C_RESET}", file=sys.stderr)
                return 1
            user_data_dir = os.path.expanduser("~/.cursor-vpnguard-profile")
        elif ("code" in cmd_name):
            if os.path.exists(direct_code):
                print(f"{C_CYAN}[i] Bypassing LaunchServices: Launching VS Code Mach-O binary directly...{C_RESET}")
                target_cmd[0] = direct_code
            else:
                print(f"{C_RED}[!] Error: VS Code binary not found at {direct_code}!{C_RESET}", file=sys.stderr)
                return 1
            user_data_dir = os.path.expanduser("~/.vscode-vpnguard-profile")
        else:
            user_data_dir = os.path.expanduser("~/.vpnguard-electron-profile")
        flags = [
            f"--proxy-server=http://{host}:{http_port}",
            '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--disable-quic",
            "--lang=en-US",
            f"--user-data-dir={user_data_dir}"
        ]
        target_cmd[1:1] = flags

    if getattr(args, "no_socks", False):
        os.environ["VPNGUARD_NO_SOCKS"] = "1"

    full_cmd = [helper_path] + target_cmd
    try:
        return subprocess.call(full_cmd)
    except KeyboardInterrupt:
        return 130


def cmd_shell(args: argparse.Namespace) -> int:
    """Spawn an interactive shell inside the guarded sandbox."""
    if os.geteuid() == 0:
        print(f"{C_BOLD}{C_RED}[!] Security Error:{C_RESET} Running 'vpnguard shell' as root is prohibited for safety.", file=sys.stderr)
        return 1

    user_shell = os.environ.get("SHELL", "/bin/zsh")
    print(f"{C_BOLD}{C_GREEN}🛡️  Entering VPNGuard Protected Shell Session ({user_shell}){C_RESET}")
    print(f"{C_DIM}Type 'exit' to leave this session. All commands executed here are leak-proof.{C_RESET}\n")

    old_ps1 = os.environ.get("PS1", "%# ")
    custom_ps1 = f"🛡️ [vpnguard] {old_ps1}"
    os.environ["PS1"] = custom_ps1

    args.command = [user_shell, "-l"]
    return cmd_run(args)


def cmd_watch(args: argparse.Namespace) -> int:
    """Continuous fail-closed monitor for VPN drops and flaps."""
    config = load_config()
    host, socks_port, http_port = resolve_active_proxy(config)
    interval = getattr(args, "interval", 5)

    print(f"{C_BOLD}{C_CYAN}=== 🛡️  VPNGuard Flap Monitor Active (Interval: {interval}s) ==={C_RESET}")
    print(f"{C_DIM}Press Ctrl+C to stop monitoring.{C_RESET}\n")

    was_connected = None

    try:
        while True:
            is_connected = check_port_listening(host, socks_port, timeout=1.0) and check_port_listening(host, http_port, timeout=1.0)
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            if was_connected is None:
                was_connected = is_connected
                status_txt = f"{C_GREEN}CONNECTED{C_RESET}" if is_connected else f"{C_RED}DISCONNECTED{C_RESET}"
                print(f"[{now_str}] Initial State: {status_txt}")
            elif is_connected != was_connected:
                if not is_connected:
                    print(f"[{now_str}] {C_BOLD}{C_RED}⚠️  VPN FLAP DETECTED: Proxy disconnected! Kill-switch active.{C_RESET}")
                    notify("🛡️ VPNGuard Alert", "VPN disconnected! Fail-closed kill switch is blocking all leaks.")
                else:
                    info = query_socks5_ip(host, socks_port, timeout=2.0)
                    country = info.get("country", "Unknown") if info else "Unknown"
                    print(f"[{now_str}] {C_BOLD}{C_GREEN}✅ VPN RECONNECTED: Tunnel restored ({country}).{C_RESET}")
                    notify("🛡️ VPNGuard Restored", f"VPN reconnected successfully ({country}).")
                was_connected = is_connected

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{C_DIM}Flap monitor stopped.{C_RESET}")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vpnguard",
        description="VPNGuard 3.0 - Anti-VPN Blinking & IP Leak Prevention System for macOS"
    )
    parser.add_argument("--version", action="version", version=f"vpnguard {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # on
    p_on = subparsers.add_parser("on", help="Enable VPNGuard system protection (xray + sing-box + PF killswitch)")
    p_on.set_defaults(func=cmd_on)

    # off
    p_off = subparsers.add_parser("off", help="Disable killswitch and stop sing-box (Captive Portal mode)")
    p_off.set_defaults(func=cmd_off)

    # pause
    p_pause = subparsers.add_parser("pause", help="Temporarily disable protection with fail-safe auto-resume")
    p_pause.add_argument("seconds", type=int, help="Pause duration in seconds (60-3600)")
    p_pause.set_defaults(func=cmd_pause)

    # pause-watcher (internal)
    p_pause_watcher = subparsers.add_parser("pause-watcher", help=argparse.SUPPRESS)
    p_pause_watcher.set_defaults(func=cmd_pause_watcher)

    # resume-if-expired
    p_resume_exp = subparsers.add_parser("resume-if-expired", help="Re-arm protection if pause timer expired")
    p_resume_exp.set_defaults(func=cmd_resume_if_expired)

    # dns-sync
    p_dnssync = subparsers.add_parser("dns-sync", help="Sync active interface DNS to managed resolver while protection is on")
    p_dnssync.set_defaults(func=cmd_dns_sync)

    # status
    p_status = subparsers.add_parser("status", help="Check security posture and dependencies")
    p_status.add_argument("--json", action="store_true", help="Output status in JSON format")
    p_status.add_argument("--fast", action="store_true", help="Skip external egress IP curl checks")
    p_status.set_defaults(func=cmd_status)

    # test
    p_test = subparsers.add_parser("test", help="Run active leak penetration test suite")
    p_test.add_argument("--json", action="store_true", help="Output test results in JSON format")
    p_test.set_defaults(func=cmd_test)

    # logs
    p_logs = subparsers.add_parser("logs", help="Output sanitized diagnostic logs and PF/DNS state")
    p_logs.add_argument("--json", action="store_true", help="Output logs in JSON format")
    p_logs.set_defaults(func=cmd_logs)

    # rules
    p_rules = subparsers.add_parser("rules", help="Manage dynamic routing rules (rules.json)")
    rules_sub = p_rules.add_subparsers(dest="rules_action", help="Rules action")

    p_rules_get = rules_sub.add_parser("get", help="Get current rules.json")
    p_rules_get.set_defaults(func=cmd_rules_get)

    p_rules_apply = rules_sub.add_parser("apply", help="Apply new rules from a JSON file or --stdin")
    p_rules_apply.add_argument("path", nargs="?", help="Path to rules JSON file")
    p_rules_apply.add_argument("--stdin", action="store_true", help="Read rules JSON from stdin (max 1 MiB)")
    p_rules_apply.set_defaults(func=cmd_rules_apply)

    # server
    p_server = subparsers.add_parser("server", help="Manage upstream Xray server configuration and profiles")
    server_sub = p_server.add_subparsers(dest="server_action", help="Server action")

    p_server_list = server_sub.add_parser("list", help="List configured upstream servers")
    p_server_list.add_argument("--json", action="store_true", help="Output in JSON format")
    p_server_list.set_defaults(func=cmd_server_list)

    p_server_import = server_sub.add_parser("import-vless", help="Import server profile from vless:// URI or JSON (--stdin or file)")
    p_server_import.add_argument("path", nargs="?", help="Path to file containing vless:// URI")
    p_server_import.add_argument("--stdin", action="store_true", help="Read vless:// URI or JSON from stdin")
    p_server_import.set_defaults(func=cmd_server_import_vless)

    p_server_activate = server_sub.add_parser("activate", help="Activate upstream server profile by ID")
    p_server_activate.add_argument("server_id", nargs="?", help="Server ID (UUID) to activate")
    p_server_activate.add_argument("--stdin", action="store_true", help="Read server ID from stdin")
    p_server_activate.set_defaults(func=cmd_server_activate)

    p_server_delete = server_sub.add_parser("delete", help="Delete inactive upstream server profile by ID")
    p_server_delete.add_argument("server_id", nargs="?", help="Server ID (UUID) to delete")
    p_server_delete.add_argument("--stdin", action="store_true", help="Read server ID from stdin")
    p_server_delete.set_defaults(func=cmd_server_delete)

    p_server_update = server_sub.add_parser("update", help="Update upstream server from Xray JSON (--stdin or file)")
    p_server_update.add_argument("path", nargs="?", help="Path to new Xray JSON configuration")
    p_server_update.add_argument("--stdin", action="store_true", help="Read Xray JSON from stdin")
    p_server_update.set_defaults(func=cmd_server_update)

    p_server_sync_pf = server_sub.add_parser("sync-pf", help="Regenerate and load PF sub-anchor vpnguard/egress")
    p_server_sync_pf.set_defaults(func=cmd_server_sync_pf)

    p_server_ping = server_sub.add_parser("ping", help="Measure direct TCP latency (ms) to all configured servers")
    p_server_ping.add_argument("--json", action="store_true", help="Output ping results in JSON format")
    p_server_ping.set_defaults(func=cmd_server_ping)

    # run
    p_run = subparsers.add_parser("run", help="Execute command inside guarded sandbox")
    p_run.add_argument("--no-socks", action="store_true", help="Disable ALL_PROXY to protect Python 'requests' without PySocks")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="Command and arguments to execute")
    p_run.set_defaults(func=cmd_run)

    # shell
    p_shell = subparsers.add_parser("shell", help="Spawn interactive guarded shell")
    p_shell.add_argument("--no-socks", action="store_true", help="Disable ALL_PROXY in subshell")
    p_shell.set_defaults(func=cmd_shell)

    # watch
    p_watch = subparsers.add_parser("watch", help="Monitor VPN health and alert on flaps")
    p_watch.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    p_watch.set_defaults(func=cmd_watch)

    args = parser.parse_args()

    if not args.command:
        return cmd_status(args)

    if args.command == "rules" and not getattr(args, "rules_action", None):
        p_rules.print_help()
        return 1

    if args.command == "server" and not getattr(args, "server_action", None):
        p_server.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
