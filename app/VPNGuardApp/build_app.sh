#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_BUNDLE_NAME="VPNGuard.app"
BUILD_DIR="${SCRIPT_DIR}/.build/release"
OUTPUT_APP="${SCRIPT_DIR}/${APP_BUNDLE_NAME}"

echo "==> Building VPNGuardApp (Release arm64)..."
cd "${SCRIPT_DIR}"
swift build -c release --arch arm64

echo "==> Assembling ${APP_BUNDLE_NAME}..."
rm -rf "${OUTPUT_APP}"
mkdir -p "${OUTPUT_APP}/Contents/MacOS"
mkdir -p "${OUTPUT_APP}/Contents/Resources"

cp "${BUILD_DIR}/VPNGuardApp" "${OUTPUT_APP}/Contents/MacOS/VPNGuardApp"
chmod +x "${OUTPUT_APP}/Contents/MacOS/VPNGuardApp"

cp "${SCRIPT_DIR}/Resources/Info.plist" "${OUTPUT_APP}/Contents/Info.plist"

if [[ -f "${SCRIPT_DIR}/Resources/AppIcon.icns" ]]; then
    cp "${SCRIPT_DIR}/Resources/AppIcon.icns" "${OUTPUT_APP}/Contents/Resources/AppIcon.icns"
fi

echo -n "APPL????" > "${OUTPUT_APP}/Contents/PkgInfo"

echo "==> Ad-hoc signing ${APP_BUNDLE_NAME}..."
codesign --force --deep --sign - "${OUTPUT_APP}"

echo "==> Installing to /Applications/${APP_BUNDLE_NAME}..."
rm -rf "/Applications/${APP_BUNDLE_NAME}"
cp -R "${OUTPUT_APP}" "/Applications/${APP_BUNDLE_NAME}"
rm -rf "${OUTPUT_APP}"

echo "==> VPNGuard.app build and installation completed successfully!"
echo "    (Auto-start at login is managed via ~/Library/LaunchAgents/com.vpnguard.app.plist inside the app)"
ls -ld "/Applications/${APP_BUNDLE_NAME}"
