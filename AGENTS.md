# AGENTS.md — VPNGuard 3.0 Repository Guide for AI Agents

This file is the primary operational reference for AI coding agents working in `~/Desktop/Business/Кодинг/VPNGuard` (GitHub: `RadmirMain/vpnguard`).
For user setup and CLI reference see [README.md](README.md). For deep architectural diagrams and PF/sing-box specifications see [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Repository Layout
- `VERSION` / `LICENSE` — Single source of truth for app version (`CFBundleShortVersionString`) and MIT license.
- `.github/workflows/release.yml` — CI/CD workflow on `macos-14`: runs Swift/Python unit tests, builds `VPNGuard.app` with bundled `backend/`, packages via `ditto`, computes `.sha256`, signs with Ed25519 (`RELEASE_SIGNING_PRIVATE_KEY` secret -> `.sig`), and publishes to GitHub Releases.
- `src/vpnguard.py` — Main Python 3 CLI & privileged control plane (installed to `/usr/local/share/vpnguard/src/vpnguard.py` and invoked via `/usr/local/bin/vpnguard`).
- `src/vpnguard_exec.c` — C setuid-root sandbox launcher (`04750 root:admin`, GID `888`, compiled by `install.sh`).
- `src/browser/vpnguard-browser` — Hardened Chromium launcher inside GID `888`.
- `src/pf/` — PF anchor rules (`vpnguard.pf.conf`), boot script (`vpnguard-pf-boot.sh`), and LaunchDaemon plist.
- `src/singbox/`, `src/xray/` — LaunchDaemon plists and example/template configs (`*.example.json`).
- `app/VPNGuardApp/` — SwiftUI macOS 14+ application (`Package.swift`, `Sources/VPNGuardApp/`, `Tests/VPNGuardAppTests/`, `build_app.sh`).
- `install.sh` / `uninstall.sh` / `update.sh` — System installer, clean uninstaller, and two-stage updater.
- `tests/` — Python `unittest` suite (`test_*.py`) and manual live checks (`live_test.sh`).

## 2. Hard Invariants (Never Violate)
1. **Fail-Closed Routing**:
   - `sing-box.json` MUST keep `route.final == "xray-upstream"`; never add an unconditional `direct` catch-all rule.
   - `xray.json` MUST NOT contain `freedom` or `direct` outbounds.
   - Local listeners are strictly loopback-only (`127.0.0.1:18088`, `127.0.0.1:18089`, `127.0.0.1:9090`).
2. **Strict `sudoers` (Zero Wildcards)**:
   - `/etc/sudoers.d/vpnguard` MUST contain only exact-match commands (zero `*`).
   - Mutating inputs (`rules apply`, `server import-vless`, `server activate`, `server delete`, `server update`) MUST use `--stdin` with `read_stdin_bounded()`.
   - `vpnguard logs --json` MUST accept no arbitrary file/line arguments and MUST pass all outputs through `redact_sensitive_text()`.
3. **Triple-GID Isolation & Bypass Workers**:
   - `GID 888` (`vpnguard`): sandboxed CLI/browser jail (`vpnguard-exec` explicitly rejects `real_uid == 0`).
   - `GID 889` (`_vpnguard_proxy`): headless Xray daemon; outbound allowed only to `vpnguard/egress`.
   - `GID 890` (`vpnguard-tun`): headless `sing-box` daemon (`utun99`); PF allows IPv4 TCP/UDP egress.
   - Any direct bypass probe while `utun99` is active (`server ping`, `server sync-pf` UDP DNS) MUST run inside `_run_in_gid890_worker()` (`setgroups([890])` -> `setgid(890)` -> `setuid(nobody)` in that exact order) with `IP_BOUND_IF = 25` on the physical interface from `netstat -rn -f inet`.
4. **macOS App Signing, Releases & Launch Behavior**:
   - `VPNGuard.app` uses ad-hoc signing (`codesign --force --deep --sign -`).
   - Write `Contents/Resources/frontend.sha256`, bundle `Contents/Resources/backend/` (with `backend.sha256`), set `CFBundleShortVersionString` from `VERSION`, and run `xattr -cr` **strictly before** `codesign`. Never mutate bundle files or `Info.plist` after signing.
   - `GitHubReleaseUpdater` verifies Ed25519 `.sig` against its embedded public key and `.sha256` before extraction, stages onto `/Applications`, and relaunches without `open -n`.
   - Store mutable user preferences (`sourceRepoPath`, `autoFailoverEnabled`) in `UserDefaults`, never `Info.plist`.
   - Login autostart uses solely `~/Library/LaunchAgents/com.vpnguard.app.plist` (never `SMAppService` or `System Events` Login Items).
   - Launch `vpnguard-browser` directly as the console user (never via `sudo`) and redirect stdout/stderr to a log file (never leave an undrained `Pipe()` on Chromium).
5. **Installer & Updater Safety**:
   - `install.sh` MUST resolve `TARGET_USER` via `SUDO_USER` -> `stat -f '%Su' /dev/console` -> `id -un` (because `osascript ... with administrator privileges` leaves `SUDO_USER` empty).
   - `update.sh` runs `swift build` as the normal user in `/tmp`, elevates via Touch ID only when `backend.sha256` changes, and uses `LC_ALL=C sort -z` with `find ... -print0 | xargs -0`.
   - Wi-Fi pause timer uses wall-clock `/var/run/vpnguard/pause_until` + single `/var/run/vpnguard/pause_watcher.pid`, cleared on `vpnguard on` / `vpnguard off`.
6. **No Real Secrets in Git**:
   - Never commit real `vless://` URIs, UUIDs, Reality keys, `api_secret`, or production relay IPs/domains. Use RFC 5737 test IPs (`203.0.113.0/24`), dummy UUIDs, and `example.com` in tests and `*.example.json`.

## 3. Standard Verification Commands
Run after any code change before committing:
```bash
python3 -m py_compile src/vpnguard.py
bash -n install.sh uninstall.sh update.sh src/pf/vpnguard-pf-boot.sh src/browser/vpnguard-browser app/VPNGuardApp/build_app.sh tests/live_test.sh
pfctl -n -v -f src/pf/vpnguard.pf.conf
python3 -m unittest discover -s tests -v
swift test --package-path app/VPNGuardApp
swift build --package-path app/VPNGuardApp -c release --arch arm64
```
Live check on a configured host:
```bash
./update.sh --check --no-pull
sudo -n /usr/local/bin/vpnguard test --json
```
