import Foundation

public struct ClashConnectionSnapshot: Codable {
    public let downloadTotal: Int64
    public let uploadTotal: Int64
    public let connections: [ClashConnection]
    public let memory: Int64?

    enum CodingKeys: String, CodingKey {
        case downloadTotal
        case uploadTotal
        case connections
        case memory
    }

    public init(downloadTotal: Int64 = 0, uploadTotal: Int64 = 0, connections: [ClashConnection] = [], memory: Int64? = nil) {
        self.downloadTotal = downloadTotal
        self.uploadTotal = uploadTotal
        self.connections = connections
        self.memory = memory
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.downloadTotal = try container.decodeIfPresent(Int64.self, forKey: .downloadTotal) ?? 0
        self.uploadTotal = try container.decodeIfPresent(Int64.self, forKey: .uploadTotal) ?? 0
        self.connections = try container.decodeIfPresent([ClashConnection].self, forKey: .connections) ?? []
        self.memory = try container.decodeIfPresent(Int64.self, forKey: .memory)
    }
}

public struct ClashMetadata: Codable, Equatable {
    public let network: String?
    public let type: String?
    public let sourceIP: String?
    public let destinationIP: String?
    public let sourcePort: String?
    public let destinationPort: String?
    public let host: String?
    public let dnsMode: String?
    public let processPath: String?
    
    public init(
        network: String? = nil,
        type: String? = nil,
        sourceIP: String? = nil,
        destinationIP: String? = nil,
        sourcePort: String? = nil,
        destinationPort: String? = nil,
        host: String? = nil,
        dnsMode: String? = nil,
        processPath: String? = nil
    ) {
        self.network = network
        self.type = type
        self.sourceIP = sourceIP
        self.destinationIP = destinationIP
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.host = host
        self.dnsMode = dnsMode
        self.processPath = processPath
    }
}

public struct ClashConnection: Codable, Identifiable, Equatable {
    public let id: String
    public let metadata: ClashMetadata
    public let upload: Int64
    public let download: Int64
    public let start: String
    public let chains: [String]?
    public let rule: String?
    public let rulePayload: String?
    
    public init(
        id: String,
        metadata: ClashMetadata,
        upload: Int64,
        download: Int64,
        start: String,
        chains: [String]? = nil,
        rule: String? = nil,
        rulePayload: String? = nil
    ) {
        self.id = id
        self.metadata = metadata
        self.upload = upload
        self.download = download
        self.start = start
        self.chains = chains
        self.rule = rule
        self.rulePayload = rulePayload
    }
    
    // MARK: - Helper Presentation Properties
    public var processName: String {
        if let path = metadata.processPath, !path.isEmpty {
            let lastComponent = (path as NSString).lastPathComponent
            if !lastComponent.isEmpty {
                return lastComponent
            }
        }
        return "Системный / Фоновый"
    }
    
    public var destinationHost: String {
        if let h = metadata.host, !h.isEmpty {
            return h
        }
        return metadata.destinationIP ?? "—"
    }
    
    public var destinationDisplay: String {
        let dest = destinationHost
        if let port = metadata.destinationPort, !port.isEmpty {
            return "\(dest):\(port)"
        }
        return dest
    }
    
    public var outboundTag: String {
        if let chain = chains?.first, !chain.isEmpty {
            return chain
        }
        return rulePayload ?? "—"
    }
    
    public var isProxy: Bool {
        if let chain = chains?.first {
            return chain.contains("xray") || chain.contains("proxy")
        }
        return false
    }
    
    public var formattedUpload: String {
        ByteFormatter.format(upload)
    }
    
    public var formattedDownload: String {
        ByteFormatter.format(download)
    }
    
    private static let isoFormatterWithFractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let isoFormatterStandard: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    public var formattedDuration: String {
        let startDate = Self.isoFormatterWithFractional.date(from: start)
            ?? Self.isoFormatterStandard.date(from: start)

        guard let sDate = startDate else { return "—" }
        let duration = max(0, Int(Date().timeIntervalSince(sDate)))

        let minutes = duration / 60
        let seconds = duration % 60
        if minutes > 0 {
            return "\(minutes)м \(seconds)с"
        } else {
            return "\(seconds)с"
        }
    }
}

public enum ByteFormatter {
    public static func format(_ bytes: Int64) -> String {
        let b = max(0, bytes)
        if b < 1024 {
            return "\(b) Б"
        }
        let kb = Double(b) / 1024.0
        if kb < 1024.0 {
            return String(format: "%.1f КБ", kb)
        }
        let mb = kb / 1024.0
        if mb < 1024.0 {
            return String(format: "%.1f МБ", mb)
        }
        let gb = mb / 1024.0
        return String(format: "%.2f ГБ", gb)
    }

    public static func formatSpeed(_ bytesPerSec: Int64) -> String {
        let b = max(0, bytesPerSec)
        if b == 0 {
            return "0 Б/с"
        }
        return "\(format(b))/с"
    }
}
