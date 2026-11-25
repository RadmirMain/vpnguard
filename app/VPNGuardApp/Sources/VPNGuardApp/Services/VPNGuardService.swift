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
}
