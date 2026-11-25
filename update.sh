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
INSTALLED_HASH_FILE="/usr/local/etc/vpnguard/backend.sha256"

DO_PULL=1
FORCE_BACKEND=0
FROM_APP_PID=""
RELAUNCH=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-pull)
            DO_PULL=0
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

echo "==> [1/4] Checking repository updates..."
if [[ "${DO_PULL}" -eq 1 && -d "${SCRIPT_DIR}/.git" ]]; then
    cd "${SCRIPT_DIR}"
    if git remote get-url origin &>/dev/null; then
        if [[ -z "$(git status --porcelain)" ]]; then
            echo "    Pulling latest changes from origin..."
            git pull --ff-only
        else
            echo "    [i] Local uncommitted changes detected; skipping git pull and building local workspace."
        fi
    else
        echo "    [i] No git remote 'origin' configured; building local workspace."
    fi
else
    echo "    [i] Skipping git pull; building local workspace."
fi

echo "==> [2/4] Checking backend changes..."
CURRENT_BACKEND_HASH="$(compute_backend_hash)"
INSTALLED_BACKEND_HASH=""
if [[ -f "${INSTALLED_HASH_FILE}" ]]; then
    INSTALLED_BACKEND_HASH="$(tr -d '[:space:]' < "${INSTALLED_HASH_FILE}" || true)"
fi

NEEDS_BACKEND_UPDATE=0
if [[ "${FORCE_BACKEND}" -eq 1 || -z "${INSTALLED_BACKEND_HASH}" || "${CURRENT_BACKEND_HASH}" != "${INSTALLED_BACKEND_HASH}" ]]; then
    NEEDS_BACKEND_UPDATE=1
    echo "    [i] Backend update required (installed: ${INSTALLED_BACKEND_HASH:-none}, current: ${CURRENT_BACKEND_HASH})."
else
    echo "    ✓ Backend files unchanged (${CURRENT_BACKEND_HASH:0:12}); Touch ID elevation skipped."
fi

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

# Strip extended attributes strictly BEFORE ad-hoc codesign
xattr -cr "${STAGED_APP}" 2>/dev/null || true
codesign --force --deep --sign - "${STAGED_APP}"

if [[ "${NEEDS_BACKEND_UPDATE}" -eq 1 ]]; then
    echo "==> [3.5/4] Updating system backend via macOS Authorization (Touch ID / Password)..."
    if ! osascript - "${SCRIPT_DIR}/install.sh" <<'APPLESCRIPT'
on run argv
    set installerPath to item 1 of argv
    do shell script (quoted form of installerPath) & " --backend-only" with administrator privileges
end run
APPLESCRIPT
    then
        rm -rf "${STAGING_ROOT}"
        echo "[!] Backend installation cancelled or failed." >&2
        exit 1
    fi
fi

echo "==> [4/4] Installing ${APP_BUNDLE_NAME} atomically..."
if [[ -n "${FROM_APP_PID}" ]]; then
    # Detach helper to wait for old GUI process exit, swap bundle, and relaunch
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
    echo "==> Staging ready; detached relauncher started for PID ${FROM_APP_PID}."
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
