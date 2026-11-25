import Foundation
import Darwin

public enum VPNGuardError: LocalizedError {
    case commandFailed(String)
    case decodingError(String)
    case invalidConfig(String)

    public var errorDescription: String? {
        switch self {
        case .commandFailed(let msg): return msg
        case .decodingError(let msg): return "Ошибка обработки данных: \(msg)"
        case .invalidConfig(let msg): return "Некорректная конфигурация: \(msg)"
        }
    }
}

public final class VPNGuardService {
    public static let shared = VPNGuardService()

    private let executor = CLIExecutor.shared
    private let jsonDecoder = JSONDecoder()
    private let jsonEncoder: JSONEncoder = {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        return enc
    }()

    private init() {}

    // MARK: - Native Local Helpers (No sudo)
    public func isUtunInterfaceUp(name: String = "utun99") -> Bool {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return false
        }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let cur = ptr {
            let flags = Int32(cur.pointee.ifa_flags)
            let isUp = (flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING)
            if isUp, let cName = cur.pointee.ifa_name {
                let ifName = String(cString: cName)
                if ifName == name {
                    return true
                }
            }
            ptr = cur.pointee.ifa_next
        }
        return false
    }

    public func readLocalApiSecret() -> String? {
        let path = "/usr/local/etc/vpnguard/api_secret"
        guard let raw = try? String(contentsOfFile: path, encoding: .utf8) else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    public func readLocalPauseUntil() -> Date? {
        let path = "/var/run/vpnguard/pause_until"
        guard let raw = try? String(contentsOfFile: path, encoding: .utf8),
              let ts = TimeInterval(raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              ts > Date().timeIntervalSince1970 else {
            return nil
        }
        return Date(timeIntervalSince1970: ts)
    }

    // MARK: - Status
    public func fetchStatus(fast: Bool = false) async throws -> SystemStatus {
        let args = fast ? ["status", "--json", "--fast"] : ["status", "--json"]
        let result = await executor.execute(arguments: args, timeout: fast ? 10.0 : 20.0)
        guard !result.stdout.isEmpty else {
            throw VPNGuardError.commandFailed(result.stderr.isEmpty ? "Команда status не вернула данных" : result.stderr)
        }

        guard let data = result.stdout.data(using: .utf8) else {
            throw VPNGuardError.decodingError("Не удалось прочитать вывод как UTF-8")
        }

        do {
            return try jsonDecoder.decode(SystemStatus.self, from: data)
        } catch {
            throw VPNGuardError.decodingError(error.localizedDescription)
        }
    }

    // MARK: - Power & DNS Control
    public func turnOn() async throws {
        let result = await executor.execute(arguments: ["on"], timeout: 30.0)
        if !result.isSuccess {
            let details = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(details.isEmpty ? "Не удалось включить защиту" : details)
        }
    }

    public func turnOff() async throws {
        let result = await executor.execute(arguments: ["off"], timeout: 25.0)
        if !result.isSuccess {
            let details = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(details.isEmpty ? "Не удалось отключить защиту" : details)
        }
    }

    public func syncDns() async throws {
        let result = await executor.execute(arguments: ["dns-sync"], timeout: 15.0)
        if !result.isSuccess {
            let details = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(details.isEmpty ? "Не удалось синхронизировать DNS" : details)
        }
    }

    public func pauseProtection(seconds: Int = 300) async throws -> Date {
        let allowed = (seconds == 900) ? "900" : "300"
        let result = await executor.execute(arguments: ["pause", allowed], timeout: 25.0)
        guard result.isSuccess else {
            let details = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(details.isEmpty ? "Не удалось поставить защиту на паузу" : details)
        }
        if let data = result.stdout.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let ts = obj["pauseUntil"] as? TimeInterval {
            return Date(timeIntervalSince1970: ts)
        }
        return Date().addingTimeInterval(TimeInterval(seconds))
    }

    public func resumeIfExpired() async throws {
        let result = await executor.execute(arguments: ["resume-if-expired"], timeout: 30.0)
        if !result.isSuccess {
            let details = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(details.isEmpty ? "Не удалось восстановить защиту" : details)
        }
    }

    // MARK: - Sandbox Launchers (Direct user execution, NEVER sudo)
    public func launchProtectedBrowser() async throws {
        let browserPath = "/usr/local/bin/vpnguard-browser"
        guard FileManager.default.isExecutableFile(atPath: browserPath) else {
            throw VPNGuardError.commandFailed("Не найден \(browserPath). Выполните установку/обновление бэкенда.")
        }
        try await launchDetachedProcess(executablePath: browserPath, arguments: [], logPath: "/tmp/vpnguard-browser-launch.log")
    }

    private func launchDetachedProcess(executablePath: String, arguments: [String], logPath: String) async throws {
        FileManager.default.createFile(atPath: logPath, contents: nil, attributes: nil)
        guard let logHandle = FileHandle(forWritingAtPath: logPath) else {
            throw VPNGuardError.commandFailed("Не удалось открыть лог запуска \(logPath)")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = logHandle
        process.standardError = logHandle

        do {
            try process.run()
        } catch {
            try? logHandle.close()
            throw VPNGuardError.commandFailed("Ошибка запуска: \(error.localizedDescription)")
        }

        // Close parent descriptor immediately so child never blocks on pipe buffers
        try? logHandle.close()

        // Check briefly if fail-closed pre-flight rejected launch (e.g. PF off or no Chrome)
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        if !process.isRunning && process.terminationStatus != 0 {
            let rawLog = (try? String(contentsOfFile: logPath, encoding: .utf8)) ?? ""
            let snippet = String(rawLog.trimmingCharacters(in: .whitespacesAndNewlines).prefix(300))
            throw VPNGuardError.commandFailed(snippet.isEmpty ? "Процесс завершился с кодом \(process.terminationStatus)" : snippet)
        }
    }

    // MARK: - Native App & Backend Updater
    public func runUpdateScript(repoPath: String, forceBackend: Bool) async throws -> String {
        let scriptPath = (repoPath as NSString).appendingPathComponent("update.sh")
        guard FileManager.default.isExecutableFile(atPath: scriptPath) else {
            throw VPNGuardError.commandFailed("Скрипт обновления не найден по пути: \(scriptPath)")
        }

        let currentPid = ProcessInfo.processInfo.processIdentifier
        var args = [scriptPath, "--from-app-pid", "\(currentPid)"]
        if forceBackend {
            args.append("--force-backend")
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/bash")
                process.arguments = args
                var env = ProcessInfo.processInfo.environment
                env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
                process.environment = env

                let outPipe = Pipe()
                let errPipe = Pipe()
                process.standardOutput = outPipe
                process.standardError = errPipe

                do {
                    try process.run()
                } catch {
                    continuation.resume(throwing: VPNGuardError.commandFailed(error.localizedDescription))
                    return
                }

                let lock = NSLock()
                var outData = Data()
                var errData = Data()
                let ioGroup = DispatchGroup()

                ioGroup.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    let d = outPipe.fileHandleForReading.readDataToEndOfFile()
                    lock.lock()
                    outData = d
                    lock.unlock()
                    ioGroup.leave()
                }

                ioGroup.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    let d = errPipe.fileHandleForReading.readDataToEndOfFile()
                    lock.lock()
                    errData = d
                    lock.unlock()
                    ioGroup.leave()
                }

                process.waitUntilExit()
                ioGroup.wait()

                let outStr = String(data: outData, encoding: .utf8) ?? ""
                let errStr = String(data: errData, encoding: .utf8) ?? ""
                let combined = [outStr, errStr].filter { !$0.isEmpty }.joined(separator: "\n")

                if process.terminationStatus == 0 {
                    continuation.resume(returning: combined)
                } else {
                    continuation.resume(throwing: VPNGuardError.commandFailed(combined.isEmpty ? "Ошибка обновления (код \(process.terminationStatus))" : combined))
                }
            }
        }
    }

    // MARK: - Rules (via stdin)
    public func fetchRules() async throws -> UserRules {
        let result = await executor.execute(arguments: ["rules", "get"], timeout: 15.0)
        guard result.isSuccess, let data = result.stdout.data(using: .utf8) else {
            throw VPNGuardError.commandFailed(result.stderr.isEmpty ? "Не удалось получить список правил" : result.stderr)
        }

        do {
            return try jsonDecoder.decode(UserRules.self, from: data)
        } catch {
            throw VPNGuardError.decodingError("Ошибка парсинга rules.json: \(error.localizedDescription)")
        }
    }

    public func applyRules(_ rules: UserRules) async throws {
        let data = try jsonEncoder.encode(rules)
        let result = await executor.execute(arguments: ["rules", "apply", "--stdin"], stdinData: data, timeout: 30.0)
        if !result.isSuccess {
            let errorDetails = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(errorDetails.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    // MARK: - Server Update (via stdin)
    public func updateServer(xrayConfigText: String) async throws -> String {
        guard let data = xrayConfigText.data(using: .utf8),
              let _ = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw VPNGuardError.invalidConfig("Введенный текст не является валидным JSON")
        }

        let result = await executor.execute(arguments: ["server", "update", "--stdin"], stdinData: data, timeout: 30.0)
        if !result.isSuccess {
            let errorDetails = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(errorDetails.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Server Profiles (via stdin)
    public func listServers() async throws -> [ServerProfile] {
        let result = await executor.execute(arguments: ["server", "list", "--json"], timeout: 15.0)
        guard result.isSuccess else {
            let errorDetails = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed("Не удалось получить список серверов: \(errorDetails)")
        }
        guard let data = result.stdout.data(using: .utf8) else {
            throw VPNGuardError.commandFailed("Пустой ответ от сервера")
        }
        do {
            return try jsonDecoder.decode([ServerProfile].self, from: data)
        } catch {
            throw VPNGuardError.decodingError("Ошибка парсинга списка серверов: \(error.localizedDescription)")
        }
    }

    public func importVless(uriText: String) async throws -> ServerProfile {
        let trimmed = uriText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else {
            throw VPNGuardError.invalidConfig("Ссылка VLESS не может быть пустой")
        }

        let result = await executor.execute(arguments: ["server", "import-vless", "--stdin"], stdinData: data, timeout: 25.0)
        guard result.isSuccess else {
            let errorDetails = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(errorDetails.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        guard let outData = result.stdout.data(using: .utf8) else {
            throw VPNGuardError.commandFailed("Не удалось прочитать ответ добавления сервера")
        }

        let response = try jsonDecoder.decode(ImportVlessResponse.self, from: outData)
        guard let server = response.server else {
            throw VPNGuardError.commandFailed(response.message ?? "Не удалось импортировать профиль")
        }
        return server
    }

    public func activateServer(id: String) async throws {
        guard let data = id.data(using: .utf8) else {
            throw VPNGuardError.invalidConfig("Некорректный ID сервера")
        }
        let result = await executor.execute(arguments: ["server", "activate", "--stdin"], stdinData: data, timeout: 30.0)
        guard result.isSuccess else {
            let errorDetails = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(errorDetails.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    public func deleteServer(id: String) async throws {
        guard let data = id.data(using: .utf8) else {
            throw VPNGuardError.invalidConfig("Некорректный ID сервера")
        }
        let result = await executor.execute(arguments: ["server", "delete", "--stdin"], stdinData: data, timeout: 15.0)
        guard result.isSuccess else {
            let errorDetails = result.stderr.isEmpty ? result.stdout : result.stderr
            throw VPNGuardError.commandFailed(errorDetails.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    // MARK: - Audit Test
    public func runAudit() async throws -> AuditReport {
        let result = await executor.execute(arguments: ["test", "--json"], timeout: 60.0)
        guard let data = result.stdout.data(using: .utf8), !data.isEmpty else {
            let msg = result.stderr.isEmpty ? "Не удалось получить результат тестирования" : result.stderr
            throw VPNGuardError.commandFailed(msg)
        }

        do {
            return try jsonDecoder.decode(AuditReport.self, from: data)
        } catch {
            throw VPNGuardError.decodingError("Ошибка парсинга аудита: \(error.localizedDescription)")
        }
    }

    // MARK: - Sanitized Diagnostics & Logs
    public func fetchDiagnosticLogs() async throws -> DiagnosticsLogsSnapshot {
        let result = await executor.execute(arguments: ["logs", "--json"], timeout: 20.0)
        guard result.isSuccess, let data = result.stdout.data(using: .utf8), !data.isEmpty else {
            let msg = result.stderr.isEmpty ? "Не удалось получить диагностические логи" : result.stderr
            throw VPNGuardError.commandFailed(msg.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        do {
            return try jsonDecoder.decode(DiagnosticsLogsSnapshot.self, from: data)
        } catch {
            throw VPNGuardError.decodingError("Ошибка парсинга логов: \(error.localizedDescription)")
        }
    }
}
