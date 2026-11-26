#!/bin/bash
# ==============================================================================
# install.sh - Complete Unified Installer for VPNGuard 3.0 on macOS
# Architecture:
#   Headless sing-box (TUN + DoT/DoH) + Dedicated vpnguard-xray (VLESS xhttp/Reality)
#   + System-wide Fail-Closed Packet Filter (PF) Kill-Switch
# ==============================================================================
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

C_RESET="\033[0m"
C_BOLD="\033[1m"
C_RED="\033[31m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_CYAN="\033[36m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Leave any TCC-protected CWD (e.g. ~/Desktop) and avoid world-writable /tmp so privileged tools never fail or load untrusted modules
cd /
BACKEND_ONLY=0
for arg in "$@"; do
    case "${arg}" in
        --backend-only) BACKEND_ONLY=1 ;;
    esac
done

CONSOLE_USER="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    TARGET_USER="${SUDO_USER}"
elif [[ -n "${CONSOLE_USER}" && "${CONSOLE_USER}" != "root" && "${CONSOLE_USER}" != "loginwindow" ]]; then
    TARGET_USER="${CONSOLE_USER}"
else
    TARGET_USER="$(id -un)"
fi
TARGET_HOME=$(dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "/Users/${TARGET_USER}")

echo -e "\n${C_BOLD}${C_CYAN}=== 🛡️  Installing VPNGuard 3.0 Unified System-Wide Protection ===${C_RESET}\n"

# 1. Require root
if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}[!] Error: This installer must be run as root.${C_RESET}"
    echo -e "${C_YELLOW}[i] Please run: sudo ./install.sh${C_RESET}\n"
    exit 1
fi

echo -e "${C_BOLD}[1/9] Target user identified:${C_RESET} ${TARGET_USER} (Home: ${TARGET_HOME})"

# 2. Setup DirectoryService groups & users (888, 889, 890)
echo -e "${C_BOLD}[2/9] Configuring DirectoryService groups & users (888, 889, 890)...${C_RESET}"
# Group 888: vpnguard (isolated sandbox group; processes enter ONLY via vpnguard-exec)
if ! dscl . -read /Groups/vpnguard &>/dev/null; then
    dscl . -create /Groups/vpnguard
    dscl . -create /Groups/vpnguard PrimaryGroupID 888
    dscl . -create /Groups/vpnguard RealName "VPNGuard Sandbox Client Group"
    echo -e "    ${C_GREEN}✓ Created group vpnguard (GID 888)${C_RESET}"
else
    echo -e "    ${C_GREEN}✓ Group vpnguard (GID 888) already exists${C_RESET}"
fi
# Ensure TARGET_USER is NOT in group 888 so normal apps/Chrome cannot access GID 888 browser profile directly
dseditgroup -o edit -d "${TARGET_USER}" -t user vpnguard 2>/dev/null || true
dscl . -delete /Groups/vpnguard GroupMembership 2>/dev/null || true

# Group 889: vpnguard-proxy (dedicated for headless Xray proxy daemon)
if ! dscl . -read /Groups/vpnguard-proxy &>/dev/null; then
    dscl . -create /Groups/vpnguard-proxy
    dscl . -create /Groups/vpnguard-proxy PrimaryGroupID 889
    dscl . -create /Groups/vpnguard-proxy RealName "VPNGuard Dedicated Proxy Daemon Group"
    echo -e "    ${C_GREEN}✓ Created group vpnguard-proxy (GID 889)${C_RESET}"
else
    echo -e "    ${C_GREEN}✓ Group vpnguard-proxy (GID 889) already exists${C_RESET}"
fi

# System user: _vpnguard_proxy (unprivileged daemon account)
if ! dscl . -read /Users/_vpnguard_proxy &>/dev/null; then
    dscl . -create /Users/_vpnguard_proxy
    dscl . -create /Users/_vpnguard_proxy UserShell /usr/bin/false
    dscl . -create /Users/_vpnguard_proxy RealName "VPNGuard Dedicated Proxy Daemon"
    dscl . -create /Users/_vpnguard_proxy UniqueID 489
    dscl . -create /Users/_vpnguard_proxy PrimaryGroupID 889
    dscl . -create /Users/_vpnguard_proxy NFSHomeDirectory /var/empty
    echo -e "    ${C_GREEN}✓ Created system user _vpnguard_proxy (UID 489, GID 889)${C_RESET}"
else
    echo -e "    ${C_GREEN}✓ System user _vpnguard_proxy already exists${C_RESET}"
fi

# Group 890: vpnguard-tun (dedicated for headless sing-box TUN daemon)
if ! dscl . -read /Groups/vpnguard-tun &>/dev/null; then
    dscl . -create /Groups/vpnguard-tun
    dscl . -create /Groups/vpnguard-tun PrimaryGroupID 890
    dscl . -create /Groups/vpnguard-tun RealName "VPNGuard Dedicated TUN Daemon Group"
    echo -e "    ${C_GREEN}✓ Created group vpnguard-tun (GID 890)${C_RESET}"
else
    echo -e "    ${C_GREEN}✓ Group vpnguard-tun (GID 890) already exists${C_RESET}"
fi

# 3. Dedicated Xray daemon binary and isolated browser profile directory
echo -e "${C_BOLD}[3/9] Verifying dedicated Xray daemon binary and isolated directories...${C_RESET}"
mkdir -p /usr/local/libexec /usr/local/etc/vpnguard /var/db/vpnguard/browser-profile
chown root:wheel /usr/local/etc/vpnguard /var/db/vpnguard
chmod 755 /usr/local/etc/vpnguard /var/db/vpnguard
chown root:vpnguard /var/db/vpnguard/browser-profile
chmod 770 /var/db/vpnguard/browser-profile

if [[ -f "/usr/local/libexec/vpnguard-xray" ]] && file -b "/usr/local/libexec/vpnguard-xray" | grep -q "Mach-O"; then
    echo -e "    ${C_GREEN}✓ Preserved existing Mach-O binary at /usr/local/libexec/vpnguard-xray${C_RESET}"
else
    XRAY_BIN=""
    for cand in "${SCRIPT_DIR}/bin/vpnguard-xray" /opt/homebrew/bin/xray /usr/local/bin/xray /opt/homebrew/opt/xray/bin/xray /usr/local/opt/xray/bin/xray; do
        if [[ -f "${cand}" ]] && file -b "${cand}" | grep -q "Mach-O"; then
            XRAY_BIN="${cand}"
            break
        fi
    done
    if [[ -z "${XRAY_BIN}" ]] && command -v xray &>/dev/null; then
        CMD_XRAY="$(command -v xray)"
        if file -b "${CMD_XRAY}" | grep -q "Mach-O"; then
            XRAY_BIN="${CMD_XRAY}"
        fi
    fi
    if [[ -z "${XRAY_BIN}" && "${TARGET_USER}" != "root" ]]; then
        echo -e "    ${C_YELLOW}[i] Attempting to install xray via Homebrew...${C_RESET}"
        if su - "${TARGET_USER}" -c "command -v brew &>/dev/null && brew install xray"; then
            for cand in /opt/homebrew/bin/xray /usr/local/bin/xray; do
                if [[ -f "${cand}" ]] && file -b "${cand}" | grep -q "Mach-O"; then
                    XRAY_BIN="${cand}"
                    break
                fi
            done
        fi
    fi
    if [[ -n "${XRAY_BIN}" ]]; then
        cp -f "${XRAY_BIN}" /usr/local/libexec/vpnguard-xray
        chown root:wheel /usr/local/libexec/vpnguard-xray
        chmod 755 /usr/local/libexec/vpnguard-xray
        xattr -c /usr/local/libexec/vpnguard-xray 2>/dev/null || true
        codesign --force -s - /usr/local/libexec/vpnguard-xray 2>/dev/null || true
        echo -e "    ${C_GREEN}✓ Installed /usr/local/libexec/vpnguard-xray (root:wheel 755)${C_RESET}"
    else
        echo -e "    ${C_RED}[!] Error: Could not locate Mach-O binary for xray!${C_RESET}"
        exit 1
    fi
fi

# IMPORTANT: Do NOT overwrite /usr/local/etc/vpnguard/xray.json if it exists!
if [[ ! -f "/usr/local/etc/vpnguard/xray.json" ]]; then
    if [[ -f "${SCRIPT_DIR}/src/xray/xray.json.example" ]]; then
        cp "${SCRIPT_DIR}/src/xray/xray.json.example" /usr/local/etc/vpnguard/xray.json
        chown root:vpnguard-proxy /usr/local/etc/vpnguard/xray.json
        chmod 640 /usr/local/etc/vpnguard/xray.json
        echo -e "    ${C_YELLOW}[i] Created template /usr/local/etc/vpnguard/xray.json (Please set your UUID!)${C_RESET}"
    fi
else
    chown root:vpnguard-proxy /usr/local/etc/vpnguard/xray.json
    chmod 640 /usr/local/etc/vpnguard/xray.json
    echo -e "    ${C_GREEN}✓ Preserved existing user configuration /usr/local/etc/vpnguard/xray.json${C_RESET}"
fi

# Deploy default servers.json if missing, and enforce 600 (root:wheel) permissions
if [[ ! -f "/usr/local/etc/vpnguard/servers.json" ]]; then
    if [[ -f "${SCRIPT_DIR}/src/servers.json" ]]; then
        cp "${SCRIPT_DIR}/src/servers.json" /usr/local/etc/vpnguard/servers.json
        chown root:wheel /usr/local/etc/vpnguard/servers.json
        chmod 600 /usr/local/etc/vpnguard/servers.json
        echo -e "    ${C_GREEN}✓ Initialized server profiles (/usr/local/etc/vpnguard/servers.json, mode 600)${C_RESET}"
    elif [[ -f "${SCRIPT_DIR}/src/servers.example.json" ]]; then
        cp "${SCRIPT_DIR}/src/servers.example.json" /usr/local/etc/vpnguard/servers.json
        chown root:wheel /usr/local/etc/vpnguard/servers.json
        chmod 600 /usr/local/etc/vpnguard/servers.json
        echo -e "    ${C_YELLOW}[i] Created template /usr/local/etc/vpnguard/servers.json (mode 600, please set your UUID!)${C_RESET}"
    fi
else
    chown root:wheel /usr/local/etc/vpnguard/servers.json 2>/dev/null || true
    chmod 600 /usr/local/etc/vpnguard/servers.json 2>/dev/null || true
    echo -e "    ${C_GREEN}✓ Preserved existing /usr/local/etc/vpnguard/servers.json (mode 600)${C_RESET}"
fi

# 4. Locate and install true Mach-O sing-box binary
echo -e "${C_BOLD}[4/9] Configuring dedicated sing-box TUN daemon binary...${C_RESET}"
SINGBOX_BIN=""

for cand in /usr/local/bin/sing-box /opt/homebrew/bin/sing-box /opt/homebrew/opt/sing-box/bin/sing-box /usr/local/opt/sing-box/bin/sing-box; do
    if [[ -f "${cand}" ]] && file -b "${cand}" | grep -q "Mach-O"; then
        SINGBOX_BIN="${cand}"
        break
    fi
done

if [[ -z "${SINGBOX_BIN}" ]] && command -v sing-box &>/dev/null; then
    CMD_SB="$(command -v sing-box)"
    if file -b "${CMD_SB}" | grep -q "Mach-O"; then
        SINGBOX_BIN="${CMD_SB}"
    fi
fi

if [[ -z "${SINGBOX_BIN}" ]]; then
    echo -e "    ${C_YELLOW}[i] Attempting to install sing-box via Homebrew...${C_RESET}"
    if su - "${TARGET_USER}" -c "command -v brew &>/dev/null && brew install sing-box"; then
        SINGBOX_BIN="/opt/homebrew/bin/sing-box"
        [[ -f "/usr/local/bin/sing-box" ]] && SINGBOX_BIN="/usr/local/bin/sing-box"
    fi
fi

if [[ -n "${SINGBOX_BIN}" && -f "${SINGBOX_BIN}" ]] && file -b "${SINGBOX_BIN}" | grep -q "Mach-O"; then
    cp -f "${SINGBOX_BIN}" /usr/local/libexec/vpnguard-singbox
    chown root:wheel /usr/local/libexec/vpnguard-singbox
    chmod 755 /usr/local/libexec/vpnguard-singbox
    xattr -c /usr/local/libexec/vpnguard-singbox 2>/dev/null || true
    codesign --force -s - /usr/local/libexec/vpnguard-singbox 2>/dev/null || true
    echo -e "    ${C_GREEN}✓ Installed Mach-O /usr/local/libexec/vpnguard-singbox (root:wheel 755)${C_RESET}"
else
    echo -e "${C_RED}[!] Error: Could not locate genuine Mach-O sing-box binary!${C_RESET}"
    exit 1
fi

# 5. Deploy and validate sing-box configuration (built from active rules.json)
echo -e "${C_BOLD}[5/9] Deploying sing-box configuration (/usr/local/etc/vpnguard/sing-box.json)...${C_RESET}"
API_SECRET_FILE="/usr/local/etc/vpnguard/api_secret"
if [[ ! -f "${API_SECRET_FILE}" ]]; then
    python3 -I -c 'import secrets; print(secrets.token_hex(16))' > "${API_SECRET_FILE}"
fi
chown root:admin "${API_SECRET_FILE}"
chmod 640 "${API_SECRET_FILE}"

if [[ ! -f "/usr/local/etc/vpnguard/rules.json" ]] && [[ -f "${SCRIPT_DIR}/src/rules.json" ]]; then
    cp "${SCRIPT_DIR}/src/rules.json" /usr/local/etc/vpnguard/rules.json
    chown root:wheel /usr/local/etc/vpnguard/rules.json
    chmod 644 /usr/local/etc/vpnguard/rules.json
fi

python3 -I -c "
import json, sys, os
sys.path.insert(0, '${SCRIPT_DIR}/src')
import vpnguard
rules = vpnguard.DEFAULT_RULES
if os.path.exists('/usr/local/etc/vpnguard/rules.json'):
    with open('/usr/local/etc/vpnguard/rules.json', 'r', encoding='utf-8') as rf:
        rules = json.load(rf)
ips, port = vpnguard.get_active_relay_endpoint()
cfg = vpnguard.build_singbox_config(rules, relay_ip=ips or None)
with open('/usr/local/etc/vpnguard/sing-box.json', 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
if ips:
    vpnguard.write_pf_egress_file(ips, port)
vpnguard.sync_active_server_metadata()
"
chown root:wheel /usr/local/etc/vpnguard/sing-box.json
chmod 600 /usr/local/etc/vpnguard/sing-box.json

# Validate syntax
if /usr/local/libexec/vpnguard-singbox check -c /usr/local/etc/vpnguard/sing-box.json; then
    echo -e "    ${C_GREEN}✓ sing-box.json syntax check passed successfully (mode 600)${C_RESET}"
else
    echo -e "${C_RED}[!] Error: sing-box configuration syntax check failed!${C_RESET}"
    exit 1
fi

# 6. Install LaunchDaemons
echo -e "${C_BOLD}[6/9] Installing system LaunchDaemons...${C_RESET}"
touch /var/log/vpnguard-singbox.log /var/log/vpnguard-xray.log /var/log/vpnguard.log
chown root:wheel /var/log/vpnguard*.log
chmod 640 /var/log/vpnguard*.log
chown _vpnguard_proxy:vpnguard-proxy /var/log/vpnguard-xray.log
chmod 660 /var/log/vpnguard-xray.log

cp "${SCRIPT_DIR}/src/xray/com.vpnguard.xray.plist" /Library/LaunchDaemons/com.vpnguard.xray.plist
chown root:wheel /Library/LaunchDaemons/com.vpnguard.xray.plist
chmod 644 /Library/LaunchDaemons/com.vpnguard.xray.plist

cp "${SCRIPT_DIR}/src/singbox/com.vpnguard.singbox.plist" /Library/LaunchDaemons/com.vpnguard.singbox.plist
chown root:wheel /Library/LaunchDaemons/com.vpnguard.singbox.plist
chmod 644 /Library/LaunchDaemons/com.vpnguard.singbox.plist

cp "${SCRIPT_DIR}/src/pf/com.vpnguard.pf.plist" /Library/LaunchDaemons/com.vpnguard.pf.plist
chown root:wheel /Library/LaunchDaemons/com.vpnguard.pf.plist
chmod 644 /Library/LaunchDaemons/com.vpnguard.pf.plist

if [[ -f "${SCRIPT_DIR}/src/netwatch/com.vpnguard.netwatch.plist" ]]; then
    cp "${SCRIPT_DIR}/src/netwatch/com.vpnguard.netwatch.plist" /Library/LaunchDaemons/com.vpnguard.netwatch.plist
    chown root:wheel /Library/LaunchDaemons/com.vpnguard.netwatch.plist
    chmod 644 /Library/LaunchDaemons/com.vpnguard.netwatch.plist
fi

NETWATCH_SRC=""
for nw_cand in \
    "${SCRIPT_DIR}/libexec/vpnguard-netwatch" \
    "${SCRIPT_DIR}/app/VPNGuardApp/.build/release/vpnguard-netwatch" \
    "/Applications/VPNGuard.app/Contents/Resources/backend/libexec/vpnguard-netwatch"; do
    if [[ -x "${nw_cand}" ]]; then
        NETWATCH_SRC="${nw_cand}"
        break
    fi
done
if [[ -z "${NETWATCH_SRC}" && -f "${SCRIPT_DIR}/app/VPNGuardApp/Package.swift" ]] && command -v swift &>/dev/null; then
    swift build --package-path "${SCRIPT_DIR}/app/VPNGuardApp" -c release --arch arm64 --product vpnguard-netwatch >/dev/null 2>&1 || true
    if [[ -x "${SCRIPT_DIR}/app/VPNGuardApp/.build/release/vpnguard-netwatch" ]]; then
        NETWATCH_SRC="${SCRIPT_DIR}/app/VPNGuardApp/.build/release/vpnguard-netwatch"
    fi
fi
if [[ -n "${NETWATCH_SRC}" ]]; then
    cp -f "${NETWATCH_SRC}" /usr/local/libexec/vpnguard-netwatch
    chown root:wheel /usr/local/libexec/vpnguard-netwatch
    chmod 755 /usr/local/libexec/vpnguard-netwatch
    xattr -c /usr/local/libexec/vpnguard-netwatch 2>/dev/null || true
    codesign --force -s - /usr/local/libexec/vpnguard-netwatch 2>/dev/null || true
    echo -e "    ${C_GREEN}✓ Installed /usr/local/libexec/vpnguard-netwatch (root:wheel 755)${C_RESET}"
fi
echo -e "    ${C_GREEN}✓ Installed all LaunchDaemons to /Library/LaunchDaemons/${C_RESET}"

# 7. Install PF anchor rules and boot script
echo -e "${C_BOLD}[7/9] Installing Fail-Closed Packet Filter (PF) anchor rules...${C_RESET}"
mkdir -p /etc/pf.anchors
cp "${SCRIPT_DIR}/src/pf/vpnguard.pf.conf" /etc/pf.anchors/vpnguard
chown root:wheel /etc/pf.anchors/vpnguard
chmod 644 /etc/pf.anchors/vpnguard

cp "${SCRIPT_DIR}/src/pf/vpnguard-captive.pf.conf" /etc/pf.anchors/vpnguard-captive
chown root:wheel /etc/pf.anchors/vpnguard-captive
chmod 644 /etc/pf.anchors/vpnguard-captive

cp "${SCRIPT_DIR}/src/pf/vpnguard-pf-boot.sh" /usr/local/libexec/vpnguard-pf-boot.sh
chown root:wheel /usr/local/libexec/vpnguard-pf-boot.sh
chmod 755 /usr/local/libexec/vpnguard-pf-boot.sh

if pfctl -vnf /etc/pf.anchors/vpnguard &>/dev/null && pfctl -vnf /etc/pf.anchors/vpnguard-captive &>/dev/null; then
    echo -e "    ${C_GREEN}✓ /etc/pf.anchors/vpnguard & vpnguard-captive syntax verified cleanly${C_RESET}"
else
    echo -e "${C_RED}[!] Error: PF anchor syntax check failed!${C_RESET}"
    exit 1
fi

PF_CONF="/etc/pf.conf"
if [[ ! -f "${PF_CONF}.vpnguard.bak" ]]; then
    cp "${PF_CONF}" "${PF_CONF}.vpnguard.bak"
fi

awk '
tolower($0) ~ /vpnguard/ { next }
/^anchor "com\.apple\/\*"/ && !inserted {
    print "# VPNGuard anti-leak anchor"
    print "anchor \"vpnguard\""
    print "load anchor \"vpnguard\" from \"/etc/pf.anchors/vpnguard\""
    print ""
    inserted = 1
}
{ print }
' "${PF_CONF}" > "${PF_CONF}.tmp"
mv "${PF_CONF}.tmp" "${PF_CONF}"
chmod 644 "${PF_CONF}"

if pfctl -n -f "${PF_CONF}" &>/dev/null; then
    pfctl -f "${PF_CONF}" 2>/dev/null || true
    echo -e "    ${C_GREEN}✓ Linked anchor into ${PF_CONF}${C_RESET}"
else
    echo -e "    ${C_RED}[!] Error: ${PF_CONF} syntax check failed after anchor insertion!${C_RESET}"
    exit 1
fi

# 8. Install CLI, Helper, and Sudoers rules
echo -e "${C_BOLD}[8/9] Installing CLI and configuring hardened sudoers (zero wildcards)...${C_RESET}"
mkdir -p /usr/local/bin /usr/local/share/vpnguard
rm -rf /usr/local/share/vpnguard/src
cp -R "${SCRIPT_DIR}/src" /usr/local/share/vpnguard/src
chown -R root:wheel /usr/local/share/vpnguard
chmod -R 755 /usr/local/share/vpnguard

if [[ "${BACKEND_ONLY}" -eq 1 && -f "${SCRIPT_DIR}/libexec/vpnguard-exec" ]] && file -b "${SCRIPT_DIR}/libexec/vpnguard-exec" | grep -q "Mach-O"; then
    cp -f "${SCRIPT_DIR}/libexec/vpnguard-exec" /usr/local/bin/vpnguard-exec
elif xcode-select -p &>/dev/null && command -v clang &>/dev/null && [[ -f "${SCRIPT_DIR}/src/vpnguard_exec.c" ]]; then
    clang -Wall -Wextra -Werror -O2 -o /usr/local/bin/vpnguard-exec "${SCRIPT_DIR}/src/vpnguard_exec.c"
elif [[ -f "${SCRIPT_DIR}/libexec/vpnguard-exec" ]] && file -b "${SCRIPT_DIR}/libexec/vpnguard-exec" | grep -q "Mach-O"; then
    cp -f "${SCRIPT_DIR}/libexec/vpnguard-exec" /usr/local/bin/vpnguard-exec
elif [[ -f "${SCRIPT_DIR}/bin/vpnguard-exec" ]] && file -b "${SCRIPT_DIR}/bin/vpnguard-exec" | grep -q "Mach-O"; then
    cp -f "${SCRIPT_DIR}/bin/vpnguard-exec" /usr/local/bin/vpnguard-exec
else
    echo -e "    ${C_RED}[!] Error: Neither clang (Xcode CLT) nor prebuilt Mach-O vpnguard-exec found!${C_RESET}"
    exit 1
fi
chown root:admin /usr/local/bin/vpnguard-exec
chmod 4750 /usr/local/bin/vpnguard-exec

cp "${SCRIPT_DIR}/bin/vpnguard" /usr/local/bin/vpnguard
chown root:wheel /usr/local/bin/vpnguard
chmod 755 /usr/local/bin/vpnguard

cp "${SCRIPT_DIR}/src/browser/vpnguard-browser" /usr/local/bin/vpnguard-browser
chown root:wheel /usr/local/bin/vpnguard-browser
chmod 755 /usr/local/bin/vpnguard-browser

mkdir -p /etc/sudoers.d
SUDOERS_FILE="/etc/sudoers.d/vpnguard"
cat << 'EOF' > "${SUDOERS_FILE}"
# VPNGuard administrative maintenance rules (strict exact-match, zero wildcards)
Defaults:%admin env_reset
%admin ALL=(ALL) NOPASSWD: /sbin/pfctl -s info, /sbin/pfctl -sr, /sbin/pfctl -a vpnguard -s rules, /sbin/pfctl -a vpnguard -s rules -v, /sbin/pfctl -a vpnguard/egress -s rules
%admin ALL=(ALL) NOPASSWD: /usr/local/bin/vpnguard on, \
    /usr/local/bin/vpnguard off, \
    /usr/local/bin/vpnguard pause 300, \
    /usr/local/bin/vpnguard pause 900, \
    /usr/local/bin/vpnguard resume-if-expired, \
    /usr/local/bin/vpnguard dns-sync, \
    /usr/local/bin/vpnguard status, \
    /usr/local/bin/vpnguard status --json, \
    /usr/local/bin/vpnguard status --json --fast, \
    /usr/local/bin/vpnguard rules get, \
    /usr/local/bin/vpnguard rules apply --stdin, \
    /usr/local/bin/vpnguard server list, \
    /usr/local/bin/vpnguard server list --json, \
    /usr/local/bin/vpnguard server ping --json, \
    /usr/local/bin/vpnguard server sync-pf, \
    /usr/local/bin/vpnguard server import-vless --stdin, \
    /usr/local/bin/vpnguard server activate --stdin, \
    /usr/local/bin/vpnguard server delete --stdin, \
    /usr/local/bin/vpnguard server update --stdin, \
    /usr/local/bin/vpnguard test, \
    /usr/local/bin/vpnguard test --json, \
    /usr/local/bin/vpnguard logs --json
EOF
chmod 440 "${SUDOERS_FILE}"
if visudo -c -f "${SUDOERS_FILE}" &>/dev/null; then
    echo -e "    ${C_GREEN}✓ Installed /etc/sudoers.d/vpnguard (strict, no wildcards)${C_RESET}"
else
    echo -e "    ${C_RED}[!] Warning: visudo check failed, removing sudoers file${C_RESET}"
    rm -f "${SUDOERS_FILE}"
    exit 1
fi

# 9. Respect template state and persistent desired_state before arming PF / starting daemons
DESIRED_STATE_FILE="/var/db/vpnguard/desired_state"
HAS_TEMPLATE_UUID=0
if [[ -f "/usr/local/etc/vpnguard/xray.json" ]] && grep -q "REPLACE_WITH_UUID" /usr/local/etc/vpnguard/xray.json 2>/dev/null; then
    HAS_TEMPLATE_UUID=1
fi

EXISTING_DESIRED_STATE=""
if [[ -f "${DESIRED_STATE_FILE}" ]]; then
    EXISTING_DESIRED_STATE=$(tr -d '[:space:]' < "${DESIRED_STATE_FILE}" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
fi

if [[ "${HAS_TEMPLATE_UUID}" -eq 1 ]]; then
    echo -e "${C_BOLD}[9/9] Template xray.json detected (REPLACE_WITH_UUID); leaving Kill-Switch disarmed...${C_RESET}"
    printf 'off\n' > "${DESIRED_STATE_FILE}"
    chown root:wheel "${DESIRED_STATE_FILE}"
    chmod 644 "${DESIRED_STATE_FILE}"
    launchctl disable system/com.vpnguard.pf 2>/dev/null || true
    launchctl disable system/com.vpnguard.singbox 2>/dev/null || true
    launchctl bootout system/com.vpnguard.pf 2>/dev/null || true
    launchctl bootout system/com.vpnguard.singbox 2>/dev/null || true
    launchctl bootout system/com.vpnguard.xray 2>/dev/null || true
    /usr/local/libexec/vpnguard-pf-boot.sh off >/dev/null 2>&1 || true
    echo -e "    ${C_YELLOW}[i] Configure a valid server in VPNGuard.app or xray.json, then enable protection.${C_RESET}"
elif [[ "${EXISTING_DESIRED_STATE}" == "off" ]]; then
    echo -e "${C_BOLD}[9/9] Respecting desired_state=off; leaving Kill-Switch disarmed...${C_RESET}"
    launchctl disable system/com.vpnguard.pf 2>/dev/null || true
    launchctl disable system/com.vpnguard.singbox 2>/dev/null || true
    launchctl bootout system/com.vpnguard.pf 2>/dev/null || true
    launchctl bootout system/com.vpnguard.singbox 2>/dev/null || true
else
    echo -e "${C_BOLD}[9/9] Bootstrapping daemons and arming Fail-Closed PF Kill-Switch...${C_RESET}"
    printf 'on\n' > "${DESIRED_STATE_FILE}"
    chown root:wheel "${DESIRED_STATE_FILE}"
    chmod 644 "${DESIRED_STATE_FILE}"

    launchctl enable system/com.vpnguard.pf 2>/dev/null || true
    launchctl enable system/com.vpnguard.xray 2>/dev/null || true
    launchctl enable system/com.vpnguard.singbox 2>/dev/null || true

    launchctl bootout system/com.vpnguard.pf 2>/dev/null || true
    launchctl bootstrap system /Library/LaunchDaemons/com.vpnguard.pf.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/com.vpnguard.pf.plist 2>/dev/null || true

    /usr/local/libexec/vpnguard-pf-boot.sh on --no-dns-sync

    launchctl bootout system/com.vpnguard.xray 2>/dev/null || true
    launchctl bootstrap system /Library/LaunchDaemons/com.vpnguard.xray.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/com.vpnguard.xray.plist 2>/dev/null || true

    launchctl bootout system/com.vpnguard.singbox 2>/dev/null || true
    launchctl bootstrap system /Library/LaunchDaemons/com.vpnguard.singbox.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/com.vpnguard.singbox.plist 2>/dev/null || true

    launchctl kickstart -k system/com.vpnguard.xray 2>/dev/null || true
    launchctl kickstart -k system/com.vpnguard.singbox 2>/dev/null || true

    /usr/local/bin/vpnguard dns-sync || true
fi

if [[ -x "/usr/local/libexec/vpnguard-netwatch" && -f "/Library/LaunchDaemons/com.vpnguard.netwatch.plist" ]]; then
    launchctl enable system/com.vpnguard.netwatch 2>/dev/null || true
    launchctl bootout system/com.vpnguard.netwatch 2>/dev/null || true
    launchctl bootstrap system /Library/LaunchDaemons/com.vpnguard.netwatch.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/com.vpnguard.netwatch.plist 2>/dev/null || true
fi

# Persist backend source hash so update.sh & GitHubReleaseUpdater match identically
(
    cd "${SCRIPT_DIR}"
    find src bin install.sh -type f \
        ! -name 'vpnguard-xray' ! -name 'vpnguard-exec' \
        ! -name 'xray.json' ! -name 'servers.json' \
        ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '.DS_Store' \
        -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}' > /usr/local/etc/vpnguard/backend.sha256
)
chown root:wheel /usr/local/etc/vpnguard/backend.sha256 2>/dev/null || true
chmod 644 /usr/local/etc/vpnguard/backend.sha256 2>/dev/null || true

if [[ "${BACKEND_ONLY}" -eq 1 ]]; then
    echo -e "\n${C_BOLD}${C_GREEN}✓ VPNGuard 3.0 backend update completed successfully.${C_RESET}\n"
    exit 0
fi

echo -e "\n${C_BOLD}${C_GREEN}🎉 VPNGuard 3.0 Unified System-Wide Installation Completed Successfully!${C_RESET}\n"
echo -e "${C_YELLOW}[i] Note:${C_RESET} User '${TARGET_USER}' was removed from group 'vpnguard' (GID 888) to enforce browser profile isolation."
echo -e "    Log out and log back in (or reboot) for active shell/GUI sessions to drop cached GID 888."
echo -e "Commands:"
echo -e "  • Check status:        ${C_CYAN}vpnguard status${C_RESET}"
echo -e "  • Arm protection:      ${C_CYAN}sudo vpnguard on${C_RESET}"
echo -e "  • Disarm for Wi-Fi:    ${C_CYAN}sudo vpnguard off${C_RESET}\n"
