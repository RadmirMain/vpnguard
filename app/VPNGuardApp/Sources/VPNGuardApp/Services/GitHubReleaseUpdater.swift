import Foundation
import CryptoKit
import AppKit

public struct GitHubReleaseAsset: Codable, Equatable {
    public let name: String
    public let browserDownloadUrl: String
    public let size: Int64

    enum CodingKeys: String, CodingKey {
        case name
        case browserDownloadUrl = "browser_download_url"
        case size
    }
}

public struct GitHubReleaseInfo: Codable, Equatable {
    public let tagName: String
    public let name: String?
    public let body: String?
    public let htmlUrl: String
    public let publishedAt: String?
    public let assets: [GitHubReleaseAsset]

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case name
        case body
        case htmlUrl = "html_url"
        case publishedAt = "published_at"
        case assets
    }

    public var cleanVersion: String {
        tagName.trimmingCharacters(in: CharacterSet(charactersIn: "vV "))
    }

    public var zipAsset: GitHubReleaseAsset? {
        assets.first(where: { $0.name == "VPNGuard-macos-arm64.zip" })
            ?? assets.first(where: { $0.name.hasSuffix(".zip") && $0.name.localizedCaseInsensitiveContains("VPNGuard") })
    }

    public var sha256Asset: GitHubReleaseAsset? {
        assets.first(where: { $0.name == "VPNGuard-macos-arm64.zip.sha256" })
            ?? assets.first(where: { $0.name.hasSuffix(".sha256") })
    }

    public var sigAsset: GitHubReleaseAsset? {
        assets.first(where: { $0.name == "VPNGuard-macos-arm64.zip.sig" })
            ?? assets.first(where: { $0.name.hasSuffix(".sig") })
    }
}

public enum GitHubReleaseStatus: Equatable {
    case idle
    case checking
    case upToDate(currentVersion: String, latestVersion: String)
    case updateAvailable(GitHubReleaseInfo)
    case noReleasesYet
    case error(String)
}

public enum GitHubReleaseInstallStage: Equatable {
    case idle
    case downloading
    case verifying
    case extracting
    case relaunching
    case failed(String)

    public var description: String {
        switch self {
        case .idle: return ""
        case .downloading: return "Загрузка релиза с GitHub…"
        case .verifying: return "Проверка подписи Ed25519 и SHA-256…"
        case .extracting: return "Распаковка и подготовка /Applications…"
        case .relaunching: return "Атомарная замена и перезапуск…"
        case .failed(let msg): return msg
        }
    }
}

@MainActor
public final class GitHubReleaseUpdater: ObservableObject {
    public static let shared = GitHubReleaseUpdater()

    @Published public var status: GitHubReleaseStatus = .idle
    @Published public var installStage: GitHubReleaseInstallStage = .idle
    @Published public var backendSyncNeeded: Bool = false
    @Published public var isSyncingBackend: Bool = false

    private let repoOwner = "RadmirMain"
    private let repoName = "vpnguard"
    private let lastCheckDefaultsKey = "vpnguard.lastGitHubReleaseCheck"
    private let etagDefaultsKey = "vpnguard.lastGitHubReleaseETag"
    private let cachedReleaseDefaultsKey = "vpnguard.cachedGitHubReleaseJSON"
    private let installedBackendHashPath = "/usr/local/etc/vpnguard/backend.sha256"

    /// Embedded Ed25519 public key (raw 32-byte base64) matching GitHub Secret RELEASE_SIGNING_PRIVATE_KEY
    nonisolated public static let embeddedPublicKeyBase64 = "9EF8EzgwRHn1V2Y2pEJZY5UTB02mGfwqKW8zadYuoGI="

    private init() {
        checkBundledBackendSync()
    }

    public var currentVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "3.0.0"
    }

    public var isUpdateAvailable: Bool {
        if case .updateAvailable = status { return true }
        return false
    }

    public var isInstalling: Bool {
        switch installStage {
        case .downloading, .verifying, .extracting, .relaunching:
            return true
        case .idle, .failed:
            return false
        }
    }

    // MARK: - Bundled Backend Skew Detection
    public func checkBundledBackendSync() {
        guard let bundledHashUrl = Bundle.main.url(forResource: "backend.sha256", withExtension: nil, subdirectory: "backend"),
              let bundledHash = try? String(contentsOf: bundledHashUrl, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines),
              !bundledHash.isEmpty else {
            backendSyncNeeded = false
            return
        }

        let installedHash = (try? String(contentsOfFile: installedBackendHashPath, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        backendSyncNeeded = (installedHash != bundledHash)
    }

    public func installBundledBackendWithTouchID() async -> Bool {
        guard !isSyncingBackend else { return false }
        guard let installScriptUrl = Bundle.main.url(forResource: "install.sh", withExtension: nil, subdirectory: "backend") else {
            return false
        }

        isSyncingBackend = true
        defer { isSyncingBackend = false }

        let escaped = installScriptUrl.path.replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript = "do shell script \"cd / && \\\"\(escaped)\\\" --backend-only\" with administrator privileges"

        let exitCode = await Task.detached(priority: .userInitiated) {
            Self.runProcess("/usr/bin/osascript", args: ["-e", appleScript])
        }.value

        checkBundledBackendSync()
        return exitCode == 0 && !backendSyncNeeded
    }

    // MARK: - Daily & Manual GitHub Release Check (ETag + 403 HTML Fallback)
    public func checkIfDailyDue() async {
        let lastCheck = UserDefaults.standard.object(forKey: lastCheckDefaultsKey) as? Date ?? .distantPast
        if Date().timeIntervalSince(lastCheck) > 86_400 {
            await checkForRelease(silent: true)
        }
    }

    public func checkForRelease(silent: Bool = false) async {
        guard status != .checking, !isInstalling else { return }
        if !silent {
            status = .checking
        }

        let urlString = "https://api.github.com/repos/\(repoOwner)/\(repoName)/releases/latest"
        guard let url = URL(string: urlString) else {
            if !silent { status = .error("Некорректный URL GitHub API") }
            return
        }

        var request = URLRequest(url: url, timeoutInterval: 10.0)
        request.setValue("VPNGuard-macOS/\(currentVersion)", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        if let savedETag = UserDefaults.standard.string(forKey: etagDefaultsKey), !savedETag.isEmpty {
            request.setValue(savedETag, forHTTPHeaderField: "If-None-Match")
        }

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                if !silent { status = .error("Некорректный ответ сервера") }
                return
            }

            UserDefaults.standard.set(Date(), forKey: lastCheckDefaultsKey)

            if http.statusCode == 304,
               let cachedData = UserDefaults.standard.data(forKey: cachedReleaseDefaultsKey),
               let cachedRelease = try? JSONDecoder().decode(GitHubReleaseInfo.self, from: cachedData) {
                applyReleaseInfo(cachedRelease)
                return
            }

            if http.statusCode == 404 {
                status = .noReleasesYet
                return
            }

            if http.statusCode == 403 || http.statusCode == 429 {
                // Rate limit fallback via HEAD redirect (zero API quota)
                if let fallbackRelease = await checkLatestViaRedirect() {
                    applyReleaseInfo(fallbackRelease)
                    return
                }
                if !silent { status = .error("Превышен лимит GitHub API (\(http.statusCode))") }
                return
            }

            guard (200..<300).contains(http.statusCode) else {
                if !silent { status = .error("GitHub API вернул код \(http.statusCode)") }
                return
            }

            if let etag = http.value(forHTTPHeaderField: "ETag") {
                UserDefaults.standard.set(etag, forKey: etagDefaultsKey)
            }
            UserDefaults.standard.set(data, forKey: cachedReleaseDefaultsKey)

            let release = try JSONDecoder().decode(GitHubReleaseInfo.self, from: data)
            applyReleaseInfo(release)
        } catch {
            if !silent {
                status = .error("Ошибка сети: \(error.localizedDescription)")
            }
        }
    }

    private func applyReleaseInfo(_ release: GitHubReleaseInfo) {
        if Self.compareSemanticVersions(release.cleanVersion, currentVersion) > 0, release.zipAsset != nil {
            status = .updateAvailable(release)
        } else {
            status = .upToDate(currentVersion: currentVersion, latestVersion: release.cleanVersion)
        }
    }

    private func checkLatestViaRedirect() async -> GitHubReleaseInfo? {
        guard let url = URL(string: "https://github.com/\(repoOwner)/\(repoName)/releases/latest") else {
            return nil
        }
        var req = URLRequest(url: url, timeoutInterval: 10.0)
        req.httpMethod = "HEAD"
        req.setValue("VPNGuard-macOS/\(currentVersion)", forHTTPHeaderField: "User-Agent")

        guard let (_, resp) = try? await URLSession.shared.data(for: req),
              let finalUrl = resp.url,
              finalUrl.path.contains("/releases/tag/") else {
            return nil
        }

        let tag = finalUrl.lastPathComponent
        let baseDownload = "https://github.com/\(repoOwner)/\(repoName)/releases/download/\(tag)"
        return GitHubReleaseInfo(
            tagName: tag,
            name: "VPNGuard \(tag)",
            body: nil,
            htmlUrl: finalUrl.absoluteString,
            publishedAt: nil,
            assets: [
                GitHubReleaseAsset(name: "VPNGuard-macos-arm64.zip", browserDownloadUrl: "\(baseDownload)/VPNGuard-macos-arm64.zip", size: 0),
                GitHubReleaseAsset(name: "VPNGuard-macos-arm64.zip.sha256", browserDownloadUrl: "\(baseDownload)/VPNGuard-macos-arm64.zip.sha256", size: 0),
                GitHubReleaseAsset(name: "VPNGuard-macos-arm64.zip.sig", browserDownloadUrl: "\(baseDownload)/VPNGuard-macos-arm64.zip.sig", size: 0)
            ]
        )
    }

    // MARK: - Download, Verify (Ed25519 + SHA-256 + codesign) & Atomic Staging Install
    public func downloadAndInstall(release: GitHubReleaseInfo) async {
        guard !isInstalling else { return }
        guard let zipAsset = release.zipAsset,
              let zipUrl = URL(string: zipAsset.browserDownloadUrl) else {
            installStage = .failed("В релизе не найден архив VPNGuard.app (.zip)")
            return
        }

        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("vpnguard-release-\(UUID().uuidString)")
        let zipLocalUrl = tempRoot.appendingPathComponent(zipAsset.name)
        let extractedDir = tempRoot.appendingPathComponent("extracted")
        let applicationsStaging = "/Applications/.VPNGuard.app.staging.\(ProcessInfo.processInfo.processIdentifier)"

        do {
            try FileManager.default.createDirectory(at: extractedDir, withIntermediateDirectories: true)

            // 1. Download ZIP
            installStage = .downloading
            let (downloadedTemp, response) = try await URLSession.shared.download(from: zipUrl)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                installStage = .failed("Не удалось скачать релиз")
                try? FileManager.default.removeItem(at: tempRoot)
                return
            }
            try FileManager.default.moveItem(at: downloadedTemp, to: zipLocalUrl)
            let zipData = try Data(contentsOf: zipLocalUrl)

            // 2. Cryptographic Verification: Ed25519 (.sig) + SHA-256 (.sha256)
            installStage = .verifying

            guard let sigAsset = release.sigAsset,
                  let sigUrl = URL(string: sigAsset.browserDownloadUrl) else {
                installStage = .failed("В релизе отсутствует криптографическая подпись (.sig)")
                try? FileManager.default.removeItem(at: tempRoot)
                return
            }

            let (sigDataRaw, sigResp) = try await URLSession.shared.data(from: sigUrl)
            guard let sigHttp = sigResp as? HTTPURLResponse,
                  (200..<300).contains(sigHttp.statusCode),
                  let sigString = String(data: sigDataRaw, encoding: .utf8),
                  Self.verifyEd25519Signature(data: zipData, signatureBase64: sigString) else {
                installStage = .failed("Подпись Ed25519 не прошла проверку — обновление отклонено")
                try? FileManager.default.removeItem(at: tempRoot)
                return
            }

            if let shaAsset = release.sha256Asset,
               let shaUrl = URL(string: shaAsset.browserDownloadUrl) {
                let (shaData, shaResp) = try await URLSession.shared.data(from: shaUrl)
                if let shaHttp = shaResp as? HTTPURLResponse, (200..<300).contains(shaHttp.statusCode),
                   let expectedRaw = String(data: shaData, encoding: .utf8) {
                    let expectedHash = expectedRaw
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                        .components(separatedBy: .whitespaces)
                        .first?
                        .lowercased() ?? ""

                    let actualHash = SHA256.hash(data: zipData).map { String(format: "%02x", $0) }.joined()
                    guard !expectedHash.isEmpty, actualHash == expectedHash else {
                        installStage = .failed("Контрольная сумма SHA-256 не совпадает")
                        try? FileManager.default.removeItem(at: tempRoot)
                        return
                    }
                }
            }

            // 3. Extract via ditto and stage onto /Applications volume
            installStage = .extracting
            let extractOk = await Task.detached(priority: .userInitiated) {
                Self.runProcess("/usr/bin/ditto", args: ["-x", "-k", zipLocalUrl.path, extractedDir.path]) == 0
            }.value

            guard extractOk else {
                installStage = .failed("Не удалось распаковать архив релиза")
                try? FileManager.default.removeItem(at: tempRoot)
                return
            }

            let newAppUrl = extractedDir.appendingPathComponent("VPNGuard.app")
            let binaryPath = newAppUrl.appendingPathComponent("Contents/MacOS/VPNGuardApp").path
            guard FileManager.default.fileExists(atPath: binaryPath) else {
                installStage = .failed("В архиве отсутствует VPNGuard.app")
                try? FileManager.default.removeItem(at: tempRoot)
                return
            }

            // Strip quarantine attribute before signature verification and launch
            _ = await Task.detached(priority: .userInitiated) {
                Self.runProcess("/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", newAppUrl.path])
            }.value

            let signOk = await Task.detached(priority: .userInitiated) {
                Self.runProcess("/usr/bin/codesign", args: ["--verify", "--deep", newAppUrl.path]) == 0
            }.value

            guard signOk else {
                installStage = .failed("Проверка подписи бандла VPNGuard.app не пройдена")
                try? FileManager.default.removeItem(at: tempRoot)
                return
            }

            // Stage directly on /Applications volume so final rename is atomic
            try? FileManager.default.removeItem(atPath: applicationsStaging)
            let copyOk = await Task.detached(priority: .userInitiated) {
                let ok = Self.runProcess("/usr/bin/ditto", args: [newAppUrl.path, applicationsStaging]) == 0
                if ok {
                    _ = Self.runProcess("/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", applicationsStaging])
                }
                return ok
            }.value
            try? FileManager.default.removeItem(at: tempRoot)

            guard copyOk else {
                installStage = .failed("Нет прав на запись в /Applications")
                try? FileManager.default.removeItem(atPath: applicationsStaging)
                return
            }

            // 4. Atomic replacement with backup & bounded 10s PID wait, relaunch without -n
            installStage = .relaunching
            Self.replaceAndRelaunch(stagedAppPath: applicationsStaging)
        } catch {
            installStage = .failed(error.localizedDescription)
            try? FileManager.default.removeItem(at: tempRoot)
            try? FileManager.default.removeItem(atPath: applicationsStaging)
        }
    }

    nonisolated public static func verifyEd25519Signature(
        data: Data,
        signatureBase64: String,
        publicKeyBase64: String = embeddedPublicKeyBase64
    ) -> Bool {
        let cleanSig = signatureBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let pubData = Data(base64Encoded: publicKeyBase64),
              let sigData = Data(base64Encoded: cleanSig),
              let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubData) else {
            return false
        }
        return pubKey.isValidSignature(sigData, for: data)
    }

    nonisolated public static func compareSemanticVersions(_ lhs: String, _ rhs: String) -> Int {
        let lParts = lhs.split(separator: ".").compactMap { Int($0) }
        let rParts = rhs.split(separator: ".").compactMap { Int($0) }
        let count = max(lParts.count, rParts.count)
        for i in 0..<count {
            let l = i < lParts.count ? lParts[i] : 0
            let r = i < rParts.count ? rParts[i] : 0
            if l != r {
                return l > r ? 1 : -1
            }
        }
        return 0
    }

    nonisolated private static func runProcess(_ executable: String, args: [String]) -> Int32 {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = args
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
            return proc.terminationStatus
        } catch {
            return -1
        }
    }

    private static func replaceAndRelaunch(stagedAppPath: String) {
        let pid = ProcessInfo.processInfo.processIdentifier
        let targetApp = "/Applications/VPNGuard.app"
        let backupApp = "/Applications/.VPNGuard.app.backup.\(pid)"
        let script = """
        for _ in $(seq 1 100); do
            kill -0 \(pid) 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 \(pid) 2>/dev/null; then
            kill -9 \(pid) 2>/dev/null || true
            sleep 0.2
        fi
        rm -rf "\(backupApp)"
        if [ -d "\(targetApp)" ]; then
            mv "\(targetApp)" "\(backupApp)" || { rm -rf "\(stagedAppPath)"; exit 1; }
        fi
        if mv "\(stagedAppPath)" "\(targetApp)"; then
            rm -rf "\(backupApp)"
        else
            [ -d "\(backupApp)" ] && mv "\(backupApp)" "\(targetApp)"
            rm -rf "\(stagedAppPath)"
            exit 1
        fi
        open "\(targetApp)"
        """
        let logDir = (NSHomeDirectory() as NSString).appendingPathComponent("Library/Logs/VPNGuard")
        try? FileManager.default.createDirectory(atPath: logDir, withIntermediateDirectories: true)
        let logPath = (logDir as NSString).appendingPathComponent("github-update-relaunch.log")
        let logHandle = FileHandle(forWritingAtPath: logPath) ?? {
            FileManager.default.createFile(atPath: logPath, contents: nil)
            return FileHandle(forWritingAtPath: logPath)
        }()
        try? logHandle?.truncate(atOffset: 0)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/nohup")
        proc.arguments = ["/bin/bash", "-c", script]
        proc.standardInput = FileHandle.nullDevice
        proc.standardOutput = logHandle ?? FileHandle.nullDevice
        proc.standardError = logHandle ?? FileHandle.nullDevice
        try? proc.run()

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            NSApp.terminate(nil)
        }
    }
}
