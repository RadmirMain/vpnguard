#!/bin/bash
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

RUN_DIR="/var/run/vpnguard"
TOKEN_FILE="${RUN_DIR}/pf.token"
DESIRED_STATE_FILE="/var/db/vpnguard/desired_state"
ANCHOR_FILE="/etc/pf.anchors/vpnguard"
EGRESS_FILE="/usr/local/etc/vpnguard/pf.egress.conf"
XRAY_CONF="/usr/local/etc/vpnguard/xray.json"
LOG_FILE="/var/log/vpnguard.log"

ACTION="on"
SKIP_DNS_SYNC=0
for arg in "$@"; do
    case "${arg}" in
        --no-dns-sync) SKIP_DNS_SYNC=1 ;;
        on|off|flush|stop) ACTION="${arg}" ;;
    esac
done

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "${LOG_FILE}" 2>/dev/null || echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

mkdir -p "${RUN_DIR}"
chmod 755 "${RUN_DIR}"

if [[ "${ACTION}" == "off" || "${ACTION}" == "flush" || "${ACTION}" == "stop" ]]; then
    log "Flushing VPNGuard PF anchor rules (Kill-Switch OFF)..."
    # Flush anchors STRICTLY BEFORE releasing PF token so block rules never remain active under another service's PF token
    pfctl -a "vpnguard/egress" -F all 2>&1 | while read -r line; do log "pfctl egress flush: ${line}"; done || true
    pfctl -a vpnguard -F all 2>&1 | while read -r line; do log "pfctl flush: ${line}"; done || true
    if [[ -f "${TOKEN_FILE}" ]]; then
        TOKEN=$(tr -d '[:space:]' < "${TOKEN_FILE}" 2>/dev/null || true)
        if [[ -n "${TOKEN}" ]]; then
            pfctl -X "${TOKEN}" 2>/dev/null || true
        fi
        rm -f "${TOKEN_FILE}"
    fi
    echo "VPNGuard PF rules flushed (Kill-Switch OFF)."
    exit 0
fi

# Respect persistent desired_state=off on system boot / LaunchDaemon load
if [[ -f "${DESIRED_STATE_FILE}" ]]; then
    DESIRED_STATE=$(tr -d '[:space:]' < "${DESIRED_STATE_FILE}" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    if [[ "${DESIRED_STATE}" == "off" ]]; then
        log "Desired state is OFF; skipping PF bootstrap."
        echo "VPNGuard desired_state is OFF; skipping PF bootstrap."
        exit 0
    fi
fi

log "Starting VPNGuard PF bootstrap..."

# 1. Enable PF using reference counting (-E); reuse existing token only if PF is currently Enabled
PF_ENABLED=0
if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    PF_ENABLED=1
fi

EXISTING_TOKEN=""
if [[ -f "${TOKEN_FILE}" ]]; then
    EXISTING_TOKEN=$(tr -d '[:space:]' < "${TOKEN_FILE}" 2>/dev/null || true)
fi

if [[ "${PF_ENABLED}" -eq 1 && -n "${EXISTING_TOKEN}" ]]; then
    log "PF already Enabled; reusing existing reference token ${EXISTING_TOKEN}."
else
    ENABLE_OUT=$(pfctl -E 2>&1 || true)
    log "pfctl -E output: ${ENABLE_OUT}"
    TOKEN=$(echo "${ENABLE_OUT}" | grep -i "Token" | awk '{print $NF}' || true)
    if [[ -n "${TOKEN}" ]]; then
        echo "${TOKEN}" > "${TOKEN_FILE}"
        chmod 600 "${TOKEN_FILE}"
        log "Saved PF reference token: ${TOKEN}"
    fi
fi

# 2. Self-healing check: ensure anchor is in /etc/pf.conf strictly before anchor "com.apple/*"
PF_CONF="/etc/pf.conf"
if [[ -f "${PF_CONF}" ]]; then
    NEEDS_REORDER=$(awk '
        /^anchor "vpnguard"/ { vg_line = NR }
        /^anchor "com\.apple\/\*"/ { apple_line = NR }
        END {
            if (vg_line == 0 || apple_line == 0 || vg_line > apple_line) print "1";
            else print "0";
        }
    ' "${PF_CONF}")

    if [[ "${NEEDS_REORDER}" == "1" ]]; then
        log "Restoring and re-ordering anchor in ${PF_CONF}..."
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
        pfctl -f "${PF_CONF}" 2>/dev/null || true
        log "Reloaded ${PF_CONF}"
    fi
fi

if [[ ! -f "${ANCHOR_FILE}" ]]; then
    log "Error: ${ANCHOR_FILE} not found!"
    exit 1
fi

if ANCHOR_OUT=$(pfctl -a vpnguard -f "${ANCHOR_FILE}" 2>&1); then
    [[ -n "${ANCHOR_OUT}" ]] && log "pfctl anchor: ${ANCHOR_OUT}"
    log "Anchor 'vpnguard' successfully loaded."
else
    log "Error: failed to load anchor 'vpnguard': ${ANCHOR_OUT}"
    exit 1
fi

# 3. Load dynamic egress sub-anchor (vpnguard/egress) for GID 889
if [[ ! -f "${EGRESS_FILE}" && -f "${XRAY_CONF}" && -x "/usr/local/bin/vpnguard" ]]; then
    /usr/local/bin/vpnguard server sync-pf 2>/dev/null || true
fi

if [[ -f "${EGRESS_FILE}" ]]; then
    if EGRESS_OUT=$(pfctl -a "vpnguard/egress" -f "${EGRESS_FILE}" 2>&1); then
        [[ -n "${EGRESS_OUT}" ]] && log "pfctl egress: ${EGRESS_OUT}"
        log "Sub-anchor 'vpnguard/egress' successfully loaded from ${EGRESS_FILE}."
    else
        log "Error: failed to load sub-anchor 'vpnguard/egress': ${EGRESS_OUT}"
        exit 1
    fi
else
    log "Warning: ${EGRESS_FILE} not found; Xray egress sub-anchor is empty."
fi

RULES_COUNT=$(pfctl -a vpnguard -s rules 2>/dev/null | wc -l | tr -d ' ')
log "Anchor 'vpnguard' has ${RULES_COUNT} active rules."

# 4. On cold boot / LaunchDaemon start, ensure system DNS is synced to 1.1.1.1 (do not skip if sing-box is still starting)
if [[ "${SKIP_DNS_SYNC}" -eq 0 && -x "/usr/local/bin/vpnguard" ]]; then
    for _ in 1 2 3 4 5 6; do
        if ifconfig utun99 >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    if DNS_OUT=$(/usr/local/bin/vpnguard dns-sync 2>&1); then
        log "Cold boot dns-sync: ${DNS_OUT}"
    else
        log "Warning: cold boot dns-sync failed: ${DNS_OUT}"
    fi
fi

echo "VPNGuard PF rules initialized successfully."
