#!/bin/bash
# ==============================================================================
# uninstall.sh - Clean uninstaller for VPNGuard 3.0 on macOS
# ==============================================================================
set -euo pipefail

C_RESET="\033[0m"
C_BOLD="\033[1m"
C_RED="\033[31m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_CYAN="\033[36m"

echo -e "\n${C_BOLD}${C_CYAN}=== 🛡️  Uninstalling VPNGuard 3.0 ===${C_RESET}\n"

if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}[!] Error: This uninstaller must be run as root.${C_RESET}"
    echo -e "${C_YELLOW}[i] Please run: sudo ./uninstall.sh${C_RESET}\n"
    exit 1
fi

TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_HOME=$(dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "/Users/${TARGET_USER}")

# 0. Restore system DNS if backup exists
echo -e "${C_BOLD}[1/7] Restoring system DNS settings (if managed)...${C_RESET}"
if [[ -x "/usr/local/bin/vpnguard" ]]; then
    /usr/local/bin/vpnguard off >/dev/null 2>&1 || true
fi

# 1. Unload and remove LaunchDaemons
echo -e "${C_BOLD}[2/7] Stopping and removing LaunchDaemons & LaunchAgent...${C_RESET}"
launchctl bootout system/com.vpnguard.xray 2>/dev/null || true
launchctl unload /Library/LaunchDaemons/com.vpnguard.xray.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.vpnguard.xray.plist

launchctl bootout system/com.vpnguard.singbox 2>/dev/null || true
launchctl unload /Library/LaunchDaemons/com.vpnguard.singbox.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.vpnguard.singbox.plist

launchctl bootout system/com.vpnguard.pf 2>/dev/null || true
launchctl unload /Library/LaunchDaemons/com.vpnguard.pf.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.vpnguard.pf.plist

rm -f /usr/local/libexec/vpnguard-pf-boot.sh
rm -f /usr/local/libexec/vpnguard-xray
rm -f /usr/local/libexec/vpnguard-singbox

if [[ -n "${TARGET_HOME}" && -f "${TARGET_HOME}/Library/LaunchAgents/com.vpnguard.app.plist" ]]; then
    rm -f "${TARGET_HOME}/Library/LaunchAgents/com.vpnguard.app.plist"
fi
echo -e "    ${C_GREEN}✓ LaunchDaemons stopped and removed${C_RESET}"

# 2. Flush and remove PF anchor
echo -e "${C_BOLD}[3/7] Flushing Packet Filter anchors 'vpnguard/egress' & 'vpnguard'...${C_RESET}"
pfctl -a "vpnguard/egress" -F all 2>/dev/null || true
pfctl -a vpnguard -F all 2>/dev/null || true
rm -f /etc/pf.anchors/vpnguard
rm -rf /var/run/vpnguard
rm -rf /var/db/vpnguard
echo -e "    ${C_GREEN}✓ PF anchors flushed and removed${C_RESET}"

# 3. Restore /etc/pf.conf
echo -e "${C_BOLD}[4/7] Restoring /etc/pf.conf...${C_RESET}"
PF_CONF="/etc/pf.conf"
if [[ -f "${PF_CONF}.vpnguard.bak" ]]; then
    cp "${PF_CONF}.vpnguard.bak" "${PF_CONF}"
    rm -f "${PF_CONF}.vpnguard.bak"
    echo -e "    ${C_GREEN}✓ Restored ${PF_CONF} from backup${C_RESET}"
else
    sed -i '' '/vpnguard/d' "${PF_CONF}" 2>/dev/null || true
    echo -e "    ${C_GREEN}✓ Cleaned vpnguard lines from ${PF_CONF}${C_RESET}"
fi
pfctl -f /etc/pf.conf 2>/dev/null || true

# 4. Backup servers.json if present, then remove binaries, configs, logs and app
echo -e "${C_BOLD}[5/7] Removing installed binaries, configs, and logs...${C_RESET}"
if [[ -f "/usr/local/etc/vpnguard/servers.json" && -n "${TARGET_HOME}" ]]; then
    BACKUP_DIR="${TARGET_HOME}/.vpnguard-backup"
    mkdir -p "${BACKUP_DIR}"
    chmod 700 "${BACKUP_DIR}"
    BACKUP_FILE="${BACKUP_DIR}/servers_$(date '+%Y%m%d_%H%M%S').json"
    cp "/usr/local/etc/vpnguard/servers.json" "${BACKUP_FILE}"
    chown -R "${TARGET_USER}":staff "${BACKUP_DIR}"
    chmod 600 "${BACKUP_FILE}"
    echo -e "    ${C_YELLOW}[i] Backed up servers.json to ${BACKUP_FILE}${C_RESET}"
fi

rm -f /usr/local/bin/vpnguard-exec
rm -f /usr/local/bin/vpnguard
rm -f /usr/local/bin/vpnguard-browser
rm -rf /usr/local/share/vpnguard
rm -rf /usr/local/etc/vpnguard
rm -f /var/log/vpnguard.log /var/log/vpnguard-xray.log /var/log/vpnguard-singbox.log
rm -rf /Applications/VPNGuard.app
echo -e "    ${C_GREEN}✓ Binaries, configs, logs, and app removed${C_RESET}"

# 5. Remove sudoers rule
echo -e "${C_BOLD}[6/7] Removing sudoers rule...${C_RESET}"
rm -f /etc/sudoers.d/vpnguard
echo -e "    ${C_GREEN}✓ Removed /etc/sudoers.d/vpnguard${C_RESET}"

# 6. Delete groups and system user
echo -e "${C_BOLD}[7/7] Removing DirectoryService users and groups (888, 889, 890)...${C_RESET}"
dscl . -delete /Users/_vpnguard_proxy 2>/dev/null || true
dscl . -delete /Groups/vpnguard 2>/dev/null || true
dscl . -delete /Groups/vpnguard-proxy 2>/dev/null || true
dscl . -delete /Groups/vpnguard-tun 2>/dev/null || true
echo -e "    ${C_GREEN}✓ User '_vpnguard_proxy' and groups 888/889/890 removed${C_RESET}"

echo -e "\n${C_BOLD}${C_GREEN}✓ VPNGuard 3.0 has been completely uninstalled.${C_RESET}\n"
