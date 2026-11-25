#!/bin/bash
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

RUN_DIR="/var/run/vpnguard"
TOKEN_FILE="${RUN_DIR}/pf.token"
ANCHOR_FILE="/etc/pf.anchors/vpnguard"
EGRESS_FILE="/usr/local/etc/vpnguard/pf.egress.conf"
XRAY_CONF="/usr/local/etc/vpnguard/xray.json"
LOG_FILE="/var/log/vpnguard.log"

ACTION="${1:-on}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "${LOG_FILE}" 2>/dev/null || echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

mkdir -p "${RUN_DIR}"
chmod 755 "${RUN_DIR}"

if [[ "${ACTION}" == "off" || "${ACTION}" == "flush" || "${ACTION}" == "stop" ]]; then
    log "Flushing VPNGuard PF anchor rules (Kill-Switch OFF)..."
    pfctl -a "vpnguard/egress" -F all 2>&1 | while read -r line; do log "pfctl egress flush: ${line}"; done || true
    pfctl -a vpnguard -F all 2>&1 | while read -r line; do log "pfctl flush: ${line}"; done || true
    if [[ -f "${TOKEN_FILE}" ]]; then
        TOKEN=$(cat "${TOKEN_FILE}" 2>/dev/null || true)
        if [[ -n "${TOKEN}" ]]; then
            pfctl -X "${TOKEN}" 2>/dev/null || true
            rm -f "${TOKEN_FILE}"
        fi
    fi
    pfctl -d 2>/dev/null || true
    echo "VPNGuard PF rules flushed (Kill-Switch OFF)."
    exit 0
fi

log "Starting VPNGuard PF bootstrap..."

# 1. Enable PF using reference counting (-E)
ENABLE_OUT=$(pfctl -E 2>&1 || true)
log "pfctl -E output: ${ENABLE_OUT}"

TOKEN=$(echo "${ENABLE_OUT}" | grep -i "Token" | awk '{print $NF}' || true)
if [[ -n "${TOKEN}" ]]; then
    echo "${TOKEN}" > "${TOKEN_FILE}"
    chmod 600 "${TOKEN_FILE}"
    log "Saved PF reference token: ${TOKEN}"
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

if pfctl -a vpnguard -f "${ANCHOR_FILE}" 2>&1 | while read -r line; do log "pfctl anchor: ${line}"; done; then
    log "Anchor 'vpnguard' successfully loaded."
else
    log "Warning: failed to load anchor 'vpnguard'"
fi

# 3. Load dynamic egress sub-anchor (vpnguard/egress) for GID 889
if [[ ! -f "${EGRESS_FILE}" && -f "${XRAY_CONF}" && -x "/usr/local/bin/vpnguard" ]]; then
    /usr/local/bin/vpnguard server sync-pf 2>/dev/null || true
fi

if [[ -f "${EGRESS_FILE}" ]]; then
    if pfctl -a "vpnguard/egress" -f "${EGRESS_FILE}" 2>&1 | while read -r line; do log "pfctl egress: ${line}"; done; then
        log "Sub-anchor 'vpnguard/egress' successfully loaded from ${EGRESS_FILE}."
    else
        log "Warning: failed to load sub-anchor 'vpnguard/egress'"
    fi
else
    log "Warning: ${EGRESS_FILE} not found; Xray egress sub-anchor is empty."
fi

RULES_COUNT=$(pfctl -a vpnguard -s rules 2>/dev/null | wc -l | tr -d ' ')
log "Anchor 'vpnguard' has ${RULES_COUNT} active rules."

echo "VPNGuard PF rules initialized successfully."
