import Foundation

public struct DiagnosticsLogsContent: Codable, Equatable {
    public let singbox: String
    public let xray: String
    public let pf: String

    public init(singbox: String = "", xray: String = "", pf: String = "") {
        self.singbox = singbox
        self.xray = xray
        self.pf = pf
    }
}

public struct DiagnosticsSystemContent: Codable, Equatable {
    public let pfRules: String
    public let dns: String
    public let utun: String

    public init(pfRules: String = "", dns: String = "", utun: String = "") {
        self.pfRules = pfRules
        self.dns = dns
        self.utun = utun
    }
}

public struct DiagnosticsLogsSnapshot: Codable, Equatable {
    public let generatedAt: String
    public let logs: DiagnosticsLogsContent
    public let system: DiagnosticsSystemContent
}
