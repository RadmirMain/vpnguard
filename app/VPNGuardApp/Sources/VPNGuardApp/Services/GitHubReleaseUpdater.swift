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
        case .verifying: return "Проверка SHA-256 и подписи…"
        case .extracting: return "Распаковка VPNGuard.app…"
        case .relaunching: return "Установка и перезапуск…"
        case .failed(let msg): return msg
        }
    }
}

@MainActor
public final class GitHubReleaseUpdater: ObservableObject {
    public static let shared = GitHubReleaseUpdater()

    @Published public var status: GitHubReleaseStatus = .idle
    @Published public var installStage: GitHubReleaseInstallStage = .idle

    private let repoOwner = "RadmirMain"
    private let repoName = "vpnguard"
    private let lastCheckDefaultsKey = "vpnguard.lastGitHubReleaseCheck"

    private init() {}

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

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                if !silent { status = .error("Некорректный ответ сервера") }
                return
            }

            UserDefaults.standard.set(Date(), forKey: lastCheckDefaultsKey)

            if http.statusCode == 404 {
                status = .noReleasesYet
                return
            }
            guard (200..<300).contains(http.statusCode) else {
                if !silent { status = .error("GitHub API вернул код \(http.statusCode)") }
                return
            }

            let release = try JSONDecoder().decode(GitHubReleaseInfo.self, from: data)
            if Self.compareSemanticVersions(release.cleanVersion, currentVersion) > 0, release.zipAsset != nil {
                status = .updateAvailable(release)
            } else {
                status = .upToDate(currentVersion: currentVersion, latestVersion: release.cleanVersion)
            }
        } catch {
            if !silent {
                status = .error("Ошибка сети: \(error.localizedDescription)")
            }
        }
    }

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

            // 2. Verify SHA-256 if .sha256 asset is provided
            installStage = .verifying
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

                    let actualData = try Data(contentsOf: zipLocalUrl)
                    let digest = SHA256.hash(data: actualData)
                    let actualHash = digest.map { String(format: "%02x", $0) }.joined()

                    guard !expectedHash.isEmpty, actualHash == expectedHash else {
                        installStage = .failed("Ошибка проверки контрольной суммы SHA-256")
                        try? FileManager.default.removeItem(at: tempRoot)
                        return
                    }
                }
            }

            // 3. Extract with ditto
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

            let signOk = await Task.detached(priority: .userInitiated) {
                Self.runProcess("/usr/bin/codesign", args: ["--verify", "--deep", newAppUrl.path]) == 0
            }.value

            guard signOk else {
                installStage = .failed("Проверка подписи VPNGuard.app не пройдена")
                try? FileManager.default.removeItem(at: tempRoot)
                return
            }

            // 4. Atomic replacement after current PID exits, then relaunch without -n
            installStage = .relaunching
            Self.replaceAndRelaunch(newAppPath: newAppUrl.path, cleanupDir: tempRoot.path)
        } catch {
            installStage = .failed(error.localizedDescription)
            try? FileManager.default.removeItem(at: tempRoot)
        }
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

    private static func replaceAndRelaunch(newAppPath: String, cleanupDir: String) {
        let pid = ProcessInfo.processInfo.processIdentifier
        let targetApp = "/Applications/VPNGuard.app"
        let script = """
        while kill -0 \(pid) 2>/dev/null; do sleep 0.1; done
        rm -rf "\(targetApp)"
        mv "\(newAppPath)" "\(targetApp)"
        rm -rf "\(cleanupDir)"
        open "\(targetApp)"
        """
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/bash")
        proc.arguments = ["-c", script]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            NSApp.terminate(nil)
        }
    }
}
