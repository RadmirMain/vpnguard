#!/bin/bash
# ==============================================================================
# update.sh - Native Two-Stage Updater for VPNGuard 3.0 (User Build + Touch ID Backend)
# ==============================================================================
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
    echo "[!] Do not run update.sh as root/sudo. Run it as your regular user; Touch ID will be requested only if backend files changed." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PKG_DIR="${SCRIPT_DIR}/app/VPNGuardApp"
APP_BUNDLE_NAME="VPNGuard.app"
TARGET_APP="/Applications/${APP_BUNDLE_NAME}"
INSTALLED_BACKEND_HASH_FILE="/usr/local/etc/vpnguard/backend.sha256"
INSTALLED_FRONTEND_HASH_FILE="${TARGET_APP}/Contents/Resources/frontend.sha256"

DO_PULL=1
FORCE_APP=0
FORCE_BACKEND=0
CHECK_ONLY=0
FROM_APP_PID=""
RELAUNCH=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            CHECK_ONLY=1
            shift
            ;;
        --no-pull)
            DO_PULL=0
            shift
            ;;
        --force)
            FORCE_APP=1
            FORCE_BACKEND=1
            shift
            ;;
        --force-app)
            FORCE_APP=1
            shift
            ;;
        --force-backend)
            FORCE_BACKEND=1
            shift
            ;;
        --from-app-pid)
            FROM_APP_PID="${2:-}"
            RELAUNCH=1
            shift 2
            ;;
        --relaunch)
            RELAUNCH=1
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

compute_backend_hash() {
    (
        cd "${SCRIPT_DIR}"
        find src bin install.sh -type f \
            ! -name 'vpnguard-xray' ! -name 'vpnguard-exec' \
            ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '.DS_Store' \
            -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}'
    )
}

compute_frontend_hash() {
    (
        cd "${APP_PKG_DIR}"
        find Package.swift build_app.sh Resources Sources -type f \
            ! -name '.DS_Store' \
            -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}'
    )
}

read_trimmed_file() {
    local f="$1"
    if [[ -f "${f}" ]]; then
        tr -d '[:space:]' < "${f}" 2>/dev/null || true
    fi
}

REMOTE_AHEAD_COUNT=0
LOCAL_DIRTY=0
GIT_HEAD_SHORT=""

if [[ -d "${SCRIPT_DIR}/.git" ]]; then
    cd "${SCRIPT_DIR}"
    GIT_HEAD_SHORT="$(git rev-parse --short HEAD 2>/dev/null || true)"
    if [[ -n "$(git status --porcelain 2>/dev/null || true)" ]]; then
        LOCAL_DIRTY=1
    fi
    if [[ "${DO_PULL}" -eq 1 ]] && git remote get-url origin &>/dev/null; then
        if [[ "${CHECK_ONLY}" -eq 1 ]]; then
            python3 -c '
import os, subprocess, sys
env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
try:
    subprocess.run(
        ["git", "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=5", "fetch", "--quiet", "origin"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
except Exception:
    pass
' 2>/dev/null || true
            if git rev-parse --abbrev-ref '@{u}' &>/dev/null; then
                REMOTE_AHEAD_COUNT="$(git rev-list --count 'HEAD..@{u}' 2>/dev/null || echo 0)"
            fi
        else
            echo "==> [1/4] Checking repository updates..."
            if [[ "${LOCAL_DIRTY}" -eq 0 ]]; then
                echo "    Pulling latest changes from origin..."
                git pull --ff-only
                GIT_HEAD_SHORT="$(git rev-parse --short HEAD 2>/dev/null || true)"
            else
                echo "    [i] Local uncommitted changes detected; skipping git pull and checking local workspace hashes."
            fi
        fi
    elif [[ "${CHECK_ONLY}" -eq 0 ]]; then
        echo "==> [1/4] Skipping git pull; checking local workspace hashes."
    fi
fi

CURRENT_BACKEND_HASH="$(compute_backend_hash)"
INSTALLED_BACKEND_HASH="$(read_trimmed_file "${INSTALLED_BACKEND_HASH_FILE}")"
CURRENT_FRONTEND_HASH="$(compute_frontend_hash)"
INSTALLED_FRONTEND_HASH="$(read_trimmed_file "${INSTALLED_FRONTEND_HASH_FILE}")"

NEEDS_BACKEND_UPDATE=0
if [[ "${FORCE_BACKEND}" -eq 1 || -z "${INSTALLED_BACKEND_HASH}" || "${CURRENT_BACKEND_HASH}" != "${INSTALLED_BACKEND_HASH}" ]]; then
    NEEDS_BACKEND_UPDATE=1
fi

NEEDS_FRONTEND_UPDATE=0
if [[ "${FORCE_APP}" -eq 1 || ! -d "${TARGET_APP}" || -z "${INSTALLED_FRONTEND_HASH}" || "${CURRENT_FRONTEND_HASH}" != "${INSTALLED_FRONTEND_HASH}" ]]; then
    NEEDS_FRONTEND_UPDATE=1
fi

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    UPDATE_AVAILABLE=false
    if [[ "${NEEDS_BACKEND_UPDATE}" -eq 1 || "${NEEDS_FRONTEND_UPDATE}" -eq 1 || "${REMOTE_AHEAD_COUNT}" -gt 0 ]]; then
        UPDATE_AVAILABLE=true
    fi
    python3 -c '
import json, sys
print(json.dumps({
    "updateAvailable": sys.argv[1] == "true",
    "backendUpdateNeeded": sys.argv[2] == "1",
    "frontendUpdateNeeded": sys.argv[3] == "1",
    "remoteAheadCount": int(sys.argv[4]),
    "localDirty": sys.argv[5] == "1",
    "headCommit": sys.argv[6],
    "installedBackendHash": sys.argv[7][:12],
    "currentBackendHash": sys.argv[8][:12],
    "installedFrontendHash": sys.argv[9][:12],
    "currentFrontendHash": sys.argv[10][:12],
}, indent=2))
' "${UPDATE_AVAILABLE}" "${NEEDS_BACKEND_UPDATE}" "${NEEDS_FRONTEND_UPDATE}" "${REMOTE_AHEAD_COUNT}" "${LOCAL_DIRTY}" "${GIT_HEAD_SHORT}" "${INSTALLED_BACKEND_HASH}" "${CURRENT_BACKEND_HASH}" "${INSTALLED_FRONTEND_HASH}" "${CURRENT_FRONTEND_HASH}"
    exit 0
fi

echo "==> [2/4] Comparing installed version vs workspace..."
if [[ "${NEEDS_BACKEND_UPDATE}" -eq 0 && "${NEEDS_FRONTEND_UPDATE}" -eq 0 ]]; then
    echo "    ✓ VPNGuard is already up to date (backend: ${CURRENT_BACKEND_HASH:0:12}, app: ${CURRENT_FRONTEND_HASH:0:12})."
    echo "VPNGUARD_UP_TO_DATE"
    exit 0
fi

STAGING_ROOT=""
STAGED_APP=""

if [[ "${NEEDS_FRONTEND_UPDATE}" -eq 1 ]]; then
    echo "==> [3/4] Building ${APP_BUNDLE_NAME} as user $(id -un)..."
    STAGING_ROOT="$(mktemp -d "/tmp/vpnguard-update.XXXXXX")"
    STAGED_APP="${STAGING_ROOT}/${APP_BUNDLE_NAME}"

    cd "${APP_PKG_DIR}"
    swift build -c release --arch arm64

    mkdir -p "${STAGED_APP}/Contents/MacOS" "${STAGED_APP}/Contents/Resources"
    cp "${APP_PKG_DIR}/.build/release/VPNGuardApp" "${STAGED_APP}/Contents/MacOS/VPNGuardApp"
    chmod +x "${STAGED_APP}/Contents/MacOS/VPNGuardApp"
    cp "${APP_PKG_DIR}/Resources/Info.plist" "${STAGED_APP}/Contents/Info.plist"
    if [[ -f "${APP_PKG_DIR}/Resources/AppIcon.icns" ]]; then
        cp "${APP_PKG_DIR}/Resources/AppIcon.icns" "${STAGED_APP}/Contents/Resources/AppIcon.icns"
    fi
    echo -n "APPL????" > "${STAGED_APP}/Contents/PkgInfo"
    printf '%s\n' "${CURRENT_FRONTEND_HASH}" > "${STAGED_APP}/Contents/Resources/frontend.sha256"

    # Strip extended attributes strictly BEFORE ad-hoc codesign
    xattr -cr "${STAGED_APP}" 2>/dev/null || true
    codesign --force --deep --sign - "${STAGED_APP}"
else
    echo "==> [3/4] App bundle unchanged (${CURRENT_FRONTEND_HASH:0:12}); skipping Swift build."
fi

if [[ "${NEEDS_BACKEND_UPDATE}" -eq 1 ]]; then
    echo "==> [3.5/4] Updating system backend via macOS Authorization (Touch ID / Password)..."
    if ! osascript - "${SCRIPT_DIR}/install.sh" <<'APPLESCRIPT'
on run argv
    set installerPath to item 1 of argv
    do shell script (quoted form of installerPath) & " --backend-only" with administrator privileges
end run
APPLESCRIPT
    then
        [[ -n "${STAGING_ROOT}" ]] && rm -rf "${STAGING_ROOT}"
        echo "[!] Backend installation cancelled or failed." >&2
        exit 1
    fi
else
    echo "    ✓ Backend files unchanged (${CURRENT_BACKEND_HASH:0:12}); Touch ID elevation skipped."
fi

if [[ "${NEEDS_FRONTEND_UPDATE}" -eq 1 ]]; then
    echo "==> [4/4] Installing ${APP_BUNDLE_NAME} atomically..."
    if [[ -n "${FROM_APP_PID}" ]]; then
        nohup /bin/bash -c '
            OLD_PID="$1"
            STAGING_ROOT="$2"
            STAGED_APP="$3"
            TARGET_APP="$4"

            for _ in $(seq 1 50); do
                if ! kill -0 "${OLD_PID}" 2>/dev/null; then
                    break
                fi
                sleep 0.2
            done
            if kill -0 "${OLD_PID}" 2>/dev/null; then
                kill -TERM "${OLD_PID}" 2>/dev/null || true
                for _ in $(seq 1 25); do
                    if ! kill -0 "${OLD_PID}" 2>/dev/null; then
                        break
                    fi
                    sleep 0.2
                done
            fi

            BACKUP_APP="/Applications/.VPNGuard.app.old.$$"
            NEW_APP="/Applications/.VPNGuard.app.new.$$"
            rm -rf "${NEW_APP}" "${BACKUP_APP}"
            cp -R "${STAGED_APP}" "${NEW_APP}"
            if [[ -d "${TARGET_APP}" ]]; then
                mv "${TARGET_APP}" "${BACKUP_APP}"
            fi
            mv "${NEW_APP}" "${TARGET_APP}"
            rm -rf "${BACKUP_APP}" "${STAGING_ROOT}"
            open -a "${TARGET_APP}"
        ' _ "${FROM_APP_PID}" "${STAGING_ROOT}" "${STAGED_APP}" "${TARGET_APP}" </dev/null >/tmp/vpnguard-update-relaunch.log 2>&1 &
        echo "VPNGUARD_RELAUNCH_SCHEDULED"
    else
        BACKUP_APP="/Applications/.VPNGuard.app.old.$$"
        NEW_APP="/Applications/.VPNGuard.app.new.$$"
        rm -rf "${NEW_APP}" "${BACKUP_APP}"
        cp -R "${STAGED_APP}" "${NEW_APP}"
        if [[ -d "${TARGET_APP}" ]]; then
            mv "${TARGET_APP}" "${BACKUP_APP}"
        fi
        mv "${NEW_APP}" "${TARGET_APP}"
        rm -rf "${BACKUP_APP}" "${STAGING_ROOT}"
        if [[ "${RELAUNCH}" -eq 1 ]]; then
            killall VPNGuardApp 2>/dev/null || true
            sleep 0.5
            open -a "${TARGET_APP}"
        fi
        echo "==> Update completed successfully!"
    fi
else
    echo "==> [4/4] Backend updated; app restart not required."
fi
