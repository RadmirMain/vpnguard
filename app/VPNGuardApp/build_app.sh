#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
APP_BUNDLE_NAME="VPNGuard.app"
BUILD_DIR="${SCRIPT_DIR}/.build/release"
STAGING_ROOT="$(mktemp -d "/tmp/vpnguard-build.XXXXXX")"
OUTPUT_APP="${STAGING_ROOT}/${APP_BUNDLE_NAME}"
TARGET_APP="/Applications/${APP_BUNDLE_NAME}"

VERSION="3.0.0"
if [[ -f "${REPO_ROOT}/VERSION" ]]; then
    VERSION="$(tr -d '[:space:]' < "${REPO_ROOT}/VERSION")"
fi

cleanup() {
    rm -rf "${STAGING_ROOT}"
}
trap cleanup EXIT

echo "==> Building VPNGuardApp v${VERSION} (Release arm64)..."
cd "${SCRIPT_DIR}"
swift build -c release --arch arm64

echo "==> Assembling ${APP_BUNDLE_NAME} in ${STAGING_ROOT}..."
mkdir -p "${OUTPUT_APP}/Contents/MacOS"
mkdir -p "${OUTPUT_APP}/Contents/Resources"

cp "${BUILD_DIR}/VPNGuardApp" "${OUTPUT_APP}/Contents/MacOS/VPNGuardApp"
chmod +x "${OUTPUT_APP}/Contents/MacOS/VPNGuardApp"

cp "${SCRIPT_DIR}/Resources/Info.plist" "${OUTPUT_APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${VERSION}" "${OUTPUT_APP}/Contents/Info.plist"

if [[ -f "${SCRIPT_DIR}/Resources/AppIcon.icns" ]]; then
    cp "${SCRIPT_DIR}/Resources/AppIcon.icns" "${OUTPUT_APP}/Contents/Resources/AppIcon.icns"
fi

echo -n "APPL????" > "${OUTPUT_APP}/Contents/PkgInfo"

# Frontend hash
(
    cd "${SCRIPT_DIR}"
    find Package.swift build_app.sh Resources Sources -type f \
        ! -name '.DS_Store' \
        -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}' > "${OUTPUT_APP}/Contents/Resources/frontend.sha256"
)

# Bundle backend payload + prebuilt vpnguard-exec + canonical backend.sha256 inside Resources/backend
BACKEND_DEST="${OUTPUT_APP}/Contents/Resources/backend"
mkdir -p "${BACKEND_DEST}/libexec"
if [[ -f "${REPO_ROOT}/install.sh" ]]; then
    cp "${REPO_ROOT}/install.sh" "${BACKEND_DEST}/install.sh"
    chmod +x "${BACKEND_DEST}/install.sh"
fi
if [[ -d "${REPO_ROOT}/src" ]]; then
    rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='xray/xray.json' --exclude='servers.json' --exclude='.DS_Store' "${REPO_ROOT}/src" "${BACKEND_DEST}/"
fi
if [[ -d "${REPO_ROOT}/bin" ]]; then
    rsync -a --exclude='.DS_Store' "${REPO_ROOT}/bin" "${BACKEND_DEST}/"
fi
if [[ -f "${REPO_ROOT}/src/vpnguard_exec.c" ]]; then
    clang -Wall -Wextra -Werror -O2 -arch arm64 -o "${BACKEND_DEST}/libexec/vpnguard-exec" "${REPO_ROOT}/src/vpnguard_exec.c"
fi
(
    cd "${REPO_ROOT}"
    find src bin install.sh -type f \
        ! -name 'vpnguard-xray' ! -name 'vpnguard-exec' \
        ! -name 'xray.json' ! -name 'servers.json' \
        ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '.DS_Store' \
        -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}' > "${BACKEND_DEST}/backend.sha256"
)

echo "==> Stripping extended attributes & ad-hoc signing ${APP_BUNDLE_NAME}..."
xattr -cr "${OUTPUT_APP}" 2>/dev/null || true
codesign --force --deep --sign - "${OUTPUT_APP}"

echo "==> Installing atomically to ${TARGET_APP}..."
BACKUP_APP="/Applications/.${APP_BUNDLE_NAME}.old.$$"
STAGED_TARGET="/Applications/.${APP_BUNDLE_NAME}.new.$$"
rm -rf "${STAGED_TARGET}" "${BACKUP_APP}"
cp -R "${OUTPUT_APP}" "${STAGED_TARGET}"

if [[ -d "${TARGET_APP}" ]]; then
    mv "${TARGET_APP}" "${BACKUP_APP}"
fi
mv "${STAGED_TARGET}" "${TARGET_APP}"
rm -rf "${BACKUP_APP}"

echo "==> VPNGuard.app v${VERSION} build and installation completed successfully!"
echo "    (Auto-start at login is managed via ~/Library/LaunchAgents/com.vpnguard.app.plist inside the app)"
ls -ld "${TARGET_APP}"
