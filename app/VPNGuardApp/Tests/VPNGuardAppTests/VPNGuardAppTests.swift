import XCTest
import CryptoKit
@testable import VPNGuardApp

final class VPNGuardAppTests: XCTestCase {
    func testVlessParserRealityValid() {
        let uri = "vless://a3b98c76-2f1d-4e5a-8b9c-123456789abc@1.2.3.4:8443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=abc123&sni=www.microsoft.com#Germany%20VPS"
        let result = VlessPreviewParser.parse(uri: uri)
        switch result {
        case .success(let preview):
            XCTAssertEqual(preview.name, "Germany VPS")
            XCTAssertEqual(preview.host, "1.2.3.4")
            XCTAssertEqual(preview.port, 8443)
            XCTAssertEqual(preview.transport, "tcp")
            XCTAssertEqual(preview.security, "reality")
            XCTAssertEqual(preview.sni, "www.microsoft.com")
            XCTAssertEqual(preview.flow, "xtls-rprx-vision")
        case .failure(let err):
            XCTFail("Unexpected parse failure: \(err)")
        }
    }

    func testVlessParserRejectsInvalidPort() {
        let uri = "vless://a3b98c76-2f1d-4e5a-8b9c-123456789abc@1.2.3.4:99999?security=tls#BadPort"
        let result = VlessPreviewParser.parse(uri: uri)
        if case .success = result {
            XCTFail("Expected invalid port 99999 to fail")
        }
    }

    func testVlessParserJsonOutbound() {
        let json = """
        {
          "remarks": "India XHTTP",
          "outbounds": [{
            "protocol": "vless",
            "settings": { "vnext": [{ "address": "203.0.113.20", "port": 443, "users": [{"id": "00000000-0000-4000-8000-000000000002"}] }] },
            "streamSettings": { "network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "cdn.example.com"} }
          }]
        }
        """
        let result = VlessPreviewParser.parse(uri: json)
        switch result {
        case .success(let preview):
            XCTAssertEqual(preview.name, "India XHTTP")
            XCTAssertEqual(preview.host, "203.0.113.20")
            XCTAssertEqual(preview.transport, "xhttp")
            XCTAssertEqual(preview.sni, "cdn.example.com")
        case .failure(let err):
            XCTFail("Unexpected JSON parse failure: \(err)")
        }
    }

    func testClashConnectionHelpers() {
        let meta = ClashMetadata(
            network: "tcp",
            destinationIP: "1.1.1.1",
            destinationPort: "443",
            host: "api.anthropic.com",
            processPath: "/Applications/Claude.app/Contents/MacOS/Claude"
        )
        let conn = ClashConnection(
            id: "1",
            metadata: meta,
            upload: 100,
            download: 200,
            start: "2026-11-25T12:00:00Z",
            chains: ["xray-upstream"]
        )
        XCTAssertTrue(conn.isProxy)
        XCTAssertEqual(conn.processName, "Claude")
        XCTAssertEqual(conn.destinationDisplay, "api.anthropic.com:443")
    }

    func testSystemStatusDecodesWithAndWithoutPauseUntil() throws {
        let baseJson = """
        {
          "isProtectionOn": false,
          "pfEnabled": false,
          "pfRulesCount": 0,
          "pfBlockedPackets": 0,
          "xrayRunning": { "running": true, "pid": 123, "gid": "889", "user": "_vpnguard_proxy" },
          "singboxRunning": { "running": false, "pid": null, "gid": null, "user": null },
          "utunInterface": null,
          "exitIp": null,
          "exitLocation": null,
          "relayIp": null,
          "activeServerId": null,
          "activeServerName": null,
          "clashApiUrl": "127.0.0.1:9090",
          "clashApiSecret": "abc"
        }
        """
        let statusWithout = try JSONDecoder().decode(SystemStatus.self, from: Data(baseJson.utf8))
        XCTAssertNil(statusWithout.pauseUntil)

        let withPauseJson = baseJson.replacingOccurrences(of: "\"clashApiSecret\": \"abc\"", with: "\"clashApiSecret\": \"abc\",\n  \"pauseUntil\": 1800000300")
        let statusWith = try JSONDecoder().decode(SystemStatus.self, from: Data(withPauseJson.utf8))
        XCTAssertEqual(statusWith.pauseUntil, 1800000300)
    }

    func testCanonicalProcessTargetAndDomainHelpers() {
        let nested = VPNGuardViewModel.canonicalProcessTarget(
            from: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper"
        )
        XCTAssertEqual(nested.name, "Cursor")
        XCTAssertEqual(nested.path, "/Applications/Cursor.app")

        let cli = VPNGuardViewModel.canonicalProcessTarget(from: "/opt/homebrew/bin/node")
        XCTAssertEqual(cli.name, "node")
        XCTAssertEqual(cli.path, "/opt/homebrew/bin/node")

        XCTAssertTrue(VPNGuardViewModel.isValidDomainHost("api.anthropic.com"))
        XCTAssertFalse(VPNGuardViewModel.isValidDomainHost("1.1.1.1"))
        XCTAssertFalse(VPNGuardViewModel.isValidDomainHost("—"))
        XCTAssertEqual(VPNGuardViewModel.rootDomain(from: "api.anthropic.com"), "anthropic.com")
        XCTAssertNil(VPNGuardViewModel.rootDomain(from: "anthropic.com"))
    }

    func testDiagnosticsSnapshotDecoding() throws {
        let json = """
        {
          "generatedAt": "2026-11-25T18:00:00Z",
          "logs": { "singbox": "ok", "xray": "ok", "pf": "ok" },
          "system": { "pfRules": "pass", "dns": "nameserver", "utun": "utun99" }
        }
        """
        let snap = try JSONDecoder().decode(DiagnosticsLogsSnapshot.self, from: Data(json.utf8))
        XCTAssertEqual(snap.logs.singbox, "ok")
        XCTAssertEqual(snap.system.utun, "utun99")
    }

    func testServerPingAndUpdateCheckDecoding() throws {
        let pingJson = """
        [
          {"id": "s1", "name": "Fast", "host": "203.0.113.10", "ip": "203.0.113.10", "port": 443, "latencyMs": 32, "reachable": true, "error": null},
          {"id": "s2", "name": "Down", "host": "203.0.113.20", "ip": "203.0.113.20", "port": 443, "latencyMs": null, "reachable": false, "error": "timed out"}
        ]
        """
        let pings = try JSONDecoder().decode([ServerPingResult].self, from: Data(pingJson.utf8))
        XCTAssertEqual(pings.count, 2)
        XCTAssertTrue(pings[0].reachable)
        XCTAssertEqual(pings[0].latencyMs, 32)
        XCTAssertFalse(pings[1].reachable)

        let updJson = """
        {
          "updateAvailable": false,
          "backendUpdateNeeded": false,
          "frontendUpdateNeeded": false,
          "remoteAheadCount": 0,
          "localDirty": false,
          "headCommit": "8fc61f4",
          "installedBackendHash": "abcdef123456",
          "currentBackendHash": "abcdef123456",
          "installedFrontendHash": "123456abcdef",
          "currentFrontendHash": "123456abcdef"
        }
        """
        let upd = try JSONDecoder().decode(UpdateCheckResult.self, from: Data(updJson.utf8))
        XCTAssertFalse(upd.updateAvailable)
        XCTAssertEqual(upd.headCommit, "8fc61f4")
    }

    func testVGFormattersAndByteFormatter() {
        XCTAssertEqual(ByteFormatter.formatSpeed(0), "0 Б/с")
        XCTAssertEqual(ByteFormatter.format(512), "512 Б")
        XCTAssertEqual(ByteFormatter.formatSpeed(2048), "2.0 КБ/с")

        XCTAssertEqual(VGFormatters.formatPID(40868), "40868")
        XCTAssertEqual(VGFormatters.formatPID(nil), "—")

        XCTAssertEqual(VGFormatters.formatProtocol("xhttp"), "XHTTP")
        XCTAssertEqual(VGFormatters.formatProtocol("reality"), "Reality")
        XCTAssertEqual(VGFormatters.formatProtocol("tls"), "TLS")

        let ansi = "\u{001B}[32mINFO\u{001B}[0m connected"
        XCTAssertEqual(VGFormatters.stripANSI(ansi), "INFO connected")
    }

    func testGitHubReleaseSemanticVersionComparisonAndDecoding() throws {
        XCTAssertEqual(GitHubReleaseUpdater.compareSemanticVersions("3.1.0", "3.0.0"), 1)
        XCTAssertEqual(GitHubReleaseUpdater.compareSemanticVersions("3.0.0", "3.0.0"), 0)
        XCTAssertEqual(GitHubReleaseUpdater.compareSemanticVersions("3.0.10", "3.0.2"), 1)
        XCTAssertEqual(GitHubReleaseUpdater.compareSemanticVersions("2.9.9", "3.0.0"), -1)

        let json = """
        {
          "tag_name": "v3.1.0",
          "name": "VPNGuard v3.1.0",
          "html_url": "https://github.com/RadmirMain/vpnguard/releases/tag/v3.1.0",
          "assets": [
            { "name": "VPNGuard-macos-arm64.zip", "browser_download_url": "https://example.com/app.zip", "size": 5200000 },
            { "name": "VPNGuard-macos-arm64.zip.sha256", "browser_download_url": "https://example.com/app.zip.sha256", "size": 90 }
          ]
        }
        """
        let release = try JSONDecoder().decode(GitHubReleaseInfo.self, from: Data(json.utf8))
        XCTAssertEqual(release.cleanVersion, "3.1.0")
        XCTAssertEqual(release.zipAsset?.name, "VPNGuard-macos-arm64.zip")
        XCTAssertEqual(release.sha256Asset?.name, "VPNGuard-macos-arm64.zip.sha256")

        // Verify Ed25519 signature helper
        let priv = Curve25519.Signing.PrivateKey()
        let pubB64 = priv.publicKey.rawRepresentation.base64EncodedString()
        let payload = Data("VPNGuard release archive".utf8)
        let sig = try priv.signature(for: payload).base64EncodedString()
        XCTAssertTrue(GitHubReleaseUpdater.verifyEd25519Signature(data: payload, signatureBase64: sig, publicKeyBase64: pubB64))
        XCTAssertFalse(GitHubReleaseUpdater.verifyEd25519Signature(data: Data("tampered".utf8), signatureBase64: sig, publicKeyBase64: pubB64))
    }

    func testProtectionStateInvariantsAndUpdateFetchFailedDecoding() throws {
        XCTAssertFalse(ProtectionState.off.isProtectionActive)
        XCTAssertFalse(ProtectionState.off.isTogglingPower)

        XCTAssertFalse(ProtectionState.turningOn.isProtectionActive)
        XCTAssertTrue(ProtectionState.turningOn.isTogglingPower)

        let loadingState = ProtectionState.on(exitIP: .loading)
        XCTAssertTrue(loadingState.isProtectionActive)
        XCTAssertFalse(loadingState.isTogglingPower)
        XCTAssertTrue(loadingState.isResolvingExitIP)

        let resolvedState = ProtectionState.on(exitIP: .resolved("203.0.113.1"))
        XCTAssertTrue(resolvedState.isProtectionActive)
        XCTAssertFalse(resolvedState.isResolvingExitIP)

        let updJson = """
        {
          "updateAvailable": false,
          "backendUpdateNeeded": false,
          "frontendUpdateNeeded": false,
          "remoteAheadCount": 0,
          "localDirty": false,
          "headCommit": "ba4d92c",
          "installedBackendHash": "abcdef123456",
          "currentBackendHash": "abcdef123456",
          "installedFrontendHash": "123456abcdef",
          "currentFrontendHash": "123456abcdef",
          "fetchFailed": true
        }
        """
        let upd = try JSONDecoder().decode(UpdateCheckResult.self, from: Data(updJson.utf8))
        XCTAssertEqual(upd.fetchFailed, true)
    }
}
