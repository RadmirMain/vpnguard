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
            ! -name 'xray.json' ! -name 'servers.json' \
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
FETCH_FAILED=0

if [[ -d "${SCRIPT_DIR}/.git" ]]; then
    cd "${SCRIPT_DIR}"
    GIT_HEAD_SHORT="$(git rev-parse --short HEAD 2>/dev/null || true)"
    if [[ -n "$(git status --porcelain 2>/dev/null || true)" ]]; then
        LOCAL_DIRTY=1
    fi
    if [[ "${DO_PULL}" -eq 1 ]] && git remote get-url origin &>/dev/null; then
        if [[ "${CHECK_ONLY}" -eq 1 ]]; then
            if ! python3 -c '
import os, subprocess, sys
env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
try:
    res = subprocess.run(
        ["git", "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=5", "fetch", "--quiet", "origin"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    sys.exit(0 if res.returncode == 0 else 1)
except Exception:
    sys.exit(1)
' 2>/dev/null; then
                FETCH_FAILED=1
            fi
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
    "fetchFailed": sys.argv[11] == "1",
}, indent=2))
' "${UPDATE_AVAILABLE}" "${NEEDS_BACKEND_UPDATE}" "${NEEDS_FRONTEND_UPDATE}" "${REMOTE_AHEAD_COUNT}" "${LOCAL_DIRTY}" "${GIT_HEAD_SHORT}" "${INSTALLED_BACKEND_HASH}" "${CURRENT_BACKEND_HASH}" "${INSTALLED_FRONTEND_HASH}" "${CURRENT_FRONTEND_HASH}" "${FETCH_FAILED}"
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
BACKEND_STAGE_ROOT=""

cleanup() {
    [[ -n "${BACKEND_STAGE_ROOT}" ]] && rm -rf "${BACKEND_STAGE_ROOT}" || true
    [[ -n "${STAGING_ROOT}" ]] && rm -rf "${STAGING_ROOT}" || true
}
trap cleanup EXIT

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
    if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
        APP_VER="$(tr -d '[:space:]' < "${SCRIPT_DIR}/VERSION")"
        /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${APP_VER}" "${STAGED_APP}/Contents/Info.plist"
    fi
    if [[ -f "${APP_PKG_DIR}/Resources/AppIcon.icns" ]]; then
        cp "${APP_PKG_DIR}/Resources/AppIcon.icns" "${STAGED_APP}/Contents/Resources/AppIcon.icns"
    fi
    echo -n "APPL????" > "${STAGED_APP}/Contents/PkgInfo"
    printf '%s\n' "${CURRENT_FRONTEND_HASH}" > "${STAGED_APP}/Contents/Resources/frontend.sha256"

    mkdir -p "${STAGED_APP}/Contents/Resources/backend/libexec"
    cp "${SCRIPT_DIR}/install.sh" "${STAGED_APP}/Contents/Resources/backend/install.sh"
    chmod +x "${STAGED_APP}/Contents/Resources/backend/install.sh"
    rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='xray/xray.json' --exclude='servers.json' --exclude='.DS_Store' "${SCRIPT_DIR}/src" "${STAGED_APP}/Contents/Resources/backend/"
    rsync -a --exclude='.DS_Store' "${SCRIPT_DIR}/bin" "${STAGED_APP}/Contents/Resources/backend/"
    clang -Wall -Wextra -Werror -O2 -arch arm64 -o "${STAGED_APP}/Contents/Resources/backend/libexec/vpnguard-exec" "${SCRIPT_DIR}/src/vpnguard_exec.c"
    printf '%s\n' "${CURRENT_BACKEND_HASH}" > "${STAGED_APP}/Contents/Resources/backend/backend.sha256"

    # Strip extended attributes strictly BEFORE ad-hoc codesign
    xattr -cr "${STAGED_APP}" 2>/dev/null || true
    codesign --force --deep --sign - "${STAGED_APP}"
else
    echo "==> [3/4] App bundle unchanged (${CURRENT_FRONTEND_HASH:0:12}); skipping Swift build."
fi

if [[ "${NEEDS_BACKEND_UPDATE}" -eq 1 ]]; then
    echo "==> [3.5/4] Updating system backend via macOS Authorization (Touch ID / Password)..."
    if [[ -n "${STAGED_APP}" && -x "${STAGED_APP}/Contents/Resources/backend/install.sh" ]]; then
        BACKEND_INSTALLER="${STAGED_APP}/Contents/Resources/backend/install.sh"
    else
        # Stage outside TCC-protected folders (e.g. ~/Desktop) so osascript administrator shell can read it
        BACKEND_STAGE_ROOT="$(mktemp -d "/tmp/vpnguard-backend.XXXXXX")"
        cp "${SCRIPT_DIR}/install.sh" "${BACKEND_STAGE_ROOT}/install.sh"
        chmod +x "${BACKEND_STAGE_ROOT}/install.sh"
        rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='xray/xray.json' --exclude='servers.json' --exclude='.DS_Store' "${SCRIPT_DIR}/src" "${BACKEND_STAGE_ROOT}/"
        rsync -a --exclude='.DS_Store' "${SCRIPT_DIR}/bin" "${BACKEND_STAGE_ROOT}/"
        printf '%s\n' "${CURRENT_BACKEND_HASH}" > "${BACKEND_STAGE_ROOT}/backend.sha256"
        BACKEND_INSTALLER="${BACKEND_STAGE_ROOT}/install.sh"
    fi

    if ! (cd / && osascript - "${BACKEND_INSTALLER}" <<'APPLESCRIPT'
on run argv
    set installerPath to item 1 of argv
    do shell script "cd / && " & (quoted form of installerPath) & " --backend-only" with administrator privileges
end run
APPLESCRIPT
    )
    then
        echo "[!] Backend installation cancelled or failed." >&2
        exit 1
    fi
    if [[ -n "${BACKEND_STAGE_ROOT}" ]]; then
        rm -rf "${BACKEND_STAGE_ROOT}"
        BACKEND_STAGE_ROOT=""
    fi

    if pgrep -x vpnguard-xray >/dev/null 2>&1 || pgrep -x vpnguard-singbox >/dev/null 2>&1 || ifconfig utun99 >/dev/null 2>&1; then
        echo "    [i] Active VPN detected: reconnect VPNGuard (Off -> On) to apply updated backend binaries/configs cleanly."
    fi
else
    echo "    ✓ Backend files unchanged (${CURRENT_BACKEND_HASH:0:12}); Touch ID elevation skipped."
fi

if [[ "${NEEDS_FRONTEND_UPDATE}" -eq 1 ]]; then
    echo "==> [4/4] Installing ${APP_BUNDLE_NAME} atomically..."
    if [[ -n "${FROM_APP_PID}" ]]; then
        RELAUNCH_LOG_DIR="${HOME}/Library/Logs/VPNGuard"
        mkdir -p "${RELAUNCH_LOG_DIR}"
        RELAUNCH_LOG_FILE="${RELAUNCH_LOG_DIR}/update-relaunch.log"

        nohup /bin/bash -c '
            OLD_PID="$1"
            STAGING_ROOT="$2"
            STAGED_APP="$3"
            TARGET_APP="$4"
            BACKUP_APP="/Applications/.VPNGuard.app.old.$$"
            NEW_APP="/Applications/.VPNGuard.app.new.$$"

            relaunch_cleanup() {
                rm -rf "${NEW_APP}" "${STAGING_ROOT}" 2>/dev/null || true
            }
            trap relaunch_cleanup EXIT

            # Wait up to 10s for graceful exit, then SIGTERM (3s), then SIGKILL (0.5s)
            for _ in $(seq 1 50); do
                if ! kill -0 "${OLD_PID}" 2>/dev/null; then
                    break
                fi
                sleep 0.2
            done
            if kill -0 "${OLD_PID}" 2>/dev/null; then
                kill -TERM "${OLD_PID}" 2>/dev/null || true
                for _ in $(seq 1 15); do
                    if ! kill -0 "${OLD_PID}" 2>/dev/null; then
                        break
                    fi
                    sleep 0.2
                done
            fi
            if kill -0 "${OLD_PID}" 2>/dev/null; then
                kill -KILL "${OLD_PID}" 2>/dev/null || true
                sleep 0.5
            fi

            rm -rf "${NEW_APP}" "${BACKUP_APP}"
            cp -R "${STAGED_APP}" "${NEW_APP}"
            if [[ -d "${TARGET_APP}" ]]; then
                mv "${TARGET_APP}" "${BACKUP_APP}"
            fi
            if mv "${NEW_APP}" "${TARGET_APP}"; then
                rm -rf "${BACKUP_APP}"
            else
                if [[ -d "${BACKUP_APP}" ]]; then
                    mv "${BACKUP_APP}" "${TARGET_APP}" || true
                fi
                exit 1
            fi
            open -a "${TARGET_APP}"
        ' _ "${FROM_APP_PID}" "${STAGING_ROOT}" "${STAGED_APP}" "${TARGET_APP}" </dev/null >"${RELAUNCH_LOG_FILE}" 2>&1 &
        # Hand off STAGING_ROOT cleanup to the detached relaunch script
        STAGING_ROOT=""
        echo "VPNGUARD_RELAUNCH_SCHEDULED"
    else
        BACKUP_APP="/Applications/.VPNGuard.app.old.$$"
        NEW_APP="/Applications/.VPNGuard.app.new.$$"
        rm -rf "${NEW_APP}" "${BACKUP_APP}"
        cp -R "${STAGED_APP}" "${NEW_APP}"
        if [[ -d "${TARGET_APP}" ]]; then
            mv "${TARGET_APP}" "${BACKUP_APP}"
        fi
        if mv "${NEW_APP}" "${TARGET_APP}"; then
            rm -rf "${BACKUP_APP}"
        else
            if [[ -d "${BACKUP_APP}" ]]; then
                mv "${BACKUP_APP}" "${TARGET_APP}" || true
            fi
            rm -rf "${NEW_APP}"
            exit 1
        fi
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
