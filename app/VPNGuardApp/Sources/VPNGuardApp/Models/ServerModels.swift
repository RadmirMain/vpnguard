import Foundation

public struct ServerProfile: Codable, Identifiable, Equatable {
    public let id: String
    public let name: String
    public let host: String
    public let port: Int
    public let transport: String
    public let security: String
    public let sni: String?
    public let flow: String?
    public let isActive: Bool

    public init(
        id: String,
        name: String,
        host: String,
        port: Int,
        transport: String,
        security: String,
        sni: String? = nil,
        flow: String? = nil,
        isActive: Bool = false
    ) {
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.transport = transport
        self.security = security
        self.sni = sni
        self.flow = flow
        self.isActive = isActive
    }
}

public struct ImportVlessResponse: Codable {
    public let status: String
    public let server: ServerProfile?
    public let message: String?
}

public struct ServerPingResult: Codable, Identifiable, Equatable {
    public let id: String
    public let name: String
    public let host: String
    public let ip: String?
    public let port: Int
    public let latencyMs: Int?
    public let reachable: Bool
    public let error: String?
}

public struct UpdateCheckResult: Codable, Equatable {
    public let updateAvailable: Bool
    public let backendUpdateNeeded: Bool
    public let frontendUpdateNeeded: Bool
    public let remoteAheadCount: Int
    public let localDirty: Bool
    public let headCommit: String
    public let installedBackendHash: String
    public let currentBackendHash: String
    public let installedFrontendHash: String
    public let currentFrontendHash: String
}

public struct VlessParsedPreview: Equatable {
    public let name: String
    public let host: String
    public let port: Int
    public let transport: String
    public let security: String
    public let sni: String
    public let flow: String
}

public enum VlessParseError: LocalizedError, Equatable {
    case invalid(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalid(let msg): return msg
        }
    }
}

public enum VlessPreviewParser {
    public static func parse(uri: String) -> Result<VlessParsedPreview, VlessParseError> {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") {
            return parseJson(jsonString: trimmed)
        }
        guard trimmed.hasPrefix("vless://") else {
            return .failure(.invalid("Вставьте vless:// ссылку или JSON-конфиг сервера"))
        }

        // Split #remark
        let hashParts = trimmed.components(separatedBy: "#")
        let beforeHash = hashParts[0]
        let rawRemark = hashParts.count > 1 ? hashParts.dropFirst().joined(separator: "#") : ""
        let remark = rawRemark.removingPercentEncoding?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        // Split ?query
        let queryParts = beforeHash.components(separatedBy: "?")
        let mainPart = queryParts[0]
        let queryString = queryParts.count > 1 ? queryParts.dropFirst().joined(separator: "?") : ""

        // Parse query params
        var params: [String: String] = [:]
        for item in queryString.components(separatedBy: "&") {
            let pair = item.components(separatedBy: "=")
            if pair.count >= 2 {
                let key = pair[0].lowercased()
                let val = pair.dropFirst().joined(separator: "=").removingPercentEncoding ?? pair[1]
                params[key] = val
            }
        }

        // UUID & host:port
        guard mainPart.count > 8 else {
            return .failure(.invalid("Слишком короткая ссылка VLESS"))
        }
        let afterScheme = String(mainPart.dropFirst(8))
        let atParts = afterScheme.components(separatedBy: "@")
        guard atParts.count == 2 else {
            return .failure(.invalid("Отсутствует разделитель '@' между UUID и адресом"))
        }

        let uuidStr = atParts[0].trimmingCharacters(in: .whitespacesAndNewlines)
        guard UUID(uuidString: uuidStr) != nil else {
            return .failure(.invalid("Некорректный UUID пользователя"))
        }

        let hostPortStr = atParts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        var host = ""
        var port = 443

        if hostPortStr.hasPrefix("[") {
            let closeBracket = hostPortStr.components(separatedBy: "]:")
            if closeBracket.count == 2 {
                host = String(closeBracket[0].dropFirst())
                guard let parsedPort = Int(closeBracket[1].trimmingCharacters(in: .whitespacesAndNewlines)),
                      (1...65535).contains(parsedPort) else {
                    return .failure(.invalid("Некорректный порт (допустимо 1–65535)"))
                }
                port = parsedPort
            } else {
                host = hostPortStr.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            }
        } else {
            let hpParts = hostPortStr.components(separatedBy: ":")
            host = hpParts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            if hpParts.count > 1 {
                guard let parsedPort = Int(hpParts[1].trimmingCharacters(in: .whitespacesAndNewlines)),
                      (1...65535).contains(parsedPort) else {
                    return .failure(.invalid("Некорректный порт (допустимо 1–65535)"))
                }
                port = parsedPort
            }
        }

        guard !host.isEmpty else {
            return .failure(.invalid("Адрес хоста не может быть пустым"))
        }

        let transport = (params["type"] ?? "tcp").lowercased()
        let security = (params["security"] ?? "none").lowercased()
        let sni = params["sni"] ?? params["servername"] ?? host
        let flow = params["flow"] ?? ""
        let name = remark.isEmpty ? "\(host):\(port)" : remark

        if security == "reality" {
            guard let pbk = params["pbk"] ?? params["publickey"], !pbk.isEmpty else {
                return .failure(.invalid("Для Reality требуется публичный ключ (pbk)"))
            }
        }

        return .success(VlessParsedPreview(
            name: name,
            host: host,
            port: port,
            transport: transport,
            security: security,
            sni: sni,
            flow: flow
        ))
    }

    public static func parseJson(jsonString: String) -> Result<VlessParsedPreview, VlessParseError> {
        guard let data = jsonString.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .failure(.invalid("Невалидный JSON формат"))
        }

        let name = (root["remarks"] as? String) ?? (root["name"] as? String) ?? "Импортированный сервер"

        var outbounds = root["outbounds"] as? [[String: Any]] ?? []
        if outbounds.isEmpty, root["protocol"] != nil {
            outbounds = [root]
        }

        guard let proxyOut = outbounds.first(where: { out in
            let proto = (out["protocol"] as? String)?.lowercased() ?? ""
            let tag = (out["tag"] as? String)?.lowercased() ?? ""
            if proto == "freedom" || proto == "direct" || tag == "direct" { return false }
            return proto == "vless" || proto == "vmess" || proto == "trojan" || proto == "shadowsocks" || tag == "proxy"
        }) else {
            return .failure(.invalid("Не найден outbound прокси (vless/vmess/trojan/shadowsocks)"))
        }

        var host = ""
        var port = 443
        var flow = ""

        let settings = proxyOut["settings"] as? [String: Any] ?? [:]
        if let vnext = settings["vnext"] as? [[String: Any]], let firstV = vnext.first {
            host = (firstV["address"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            port = (firstV["port"] as? Int) ?? 443
            if let users = firstV["users"] as? [[String: Any]], let u = users.first {
                flow = (u["flow"] as? String) ?? ""
            }
        } else if let servers = settings["servers"] as? [[String: Any]], let firstS = servers.first {
            host = (firstS["address"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            port = (firstS["port"] as? Int) ?? 443
        }

        guard !host.isEmpty else {
            return .failure(.invalid("В outbound отсутствует адрес сервера"))
        }

        let stream = proxyOut["streamSettings"] as? [String: Any] ?? [:]
        let transport = (stream["network"] as? String)?.lowercased() ?? "tcp"
        let security = (stream["security"] as? String)?.lowercased() ?? "none"

        var sni = host
        if security == "reality", let r = stream["realitySettings"] as? [String: Any] {
            sni = (r["serverName"] as? String) ?? host
        } else if security == "tls", let t = stream["tlsSettings"] as? [String: Any] {
            sni = (t["serverName"] as? String) ?? host
        }

        return .success(VlessParsedPreview(
            name: name,
            host: host,
            port: port,
            transport: transport,
            security: security,
            sni: sni,
            flow: flow
        ))
    }
}
