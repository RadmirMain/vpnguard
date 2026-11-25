import Foundation

public struct DaemonProcessInfo: Codable, Equatable {
    public let running: Bool
    public let pid: Int?
    public let gid: String?
    public let user: String?
    
    public init(running: Bool, pid: Int?, gid: String?, user: String?) {
        self.running = running
        self.pid = pid
        self.gid = gid
        self.user = user
    }
    
    enum CodingKeys: String, CodingKey {
        case running, pid, gid, user
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        running = try container.decode(Bool.self, forKey: .running)
        pid = try container.decodeIfPresent(Int.self, forKey: .pid)
        user = try container.decodeIfPresent(String.self, forKey: .user)
        
        if let intGid = try? container.decodeIfPresent(Int.self, forKey: .gid) {
            gid = String(intGid)
        } else {
            gid = try container.decodeIfPresent(String.self, forKey: .gid)
        }
    }
}

public struct SystemStatus: Codable, Equatable {
    public let isProtectionOn: Bool
    public let pfEnabled: Bool
    public let pfRulesCount: Int
    public let pfBlockedPackets: Int
    public let xrayRunning: DaemonProcessInfo
    public let singboxRunning: DaemonProcessInfo
    public let utunInterface: String?
    public let exitIp: String?
    public let exitLocation: String?
    public let relayIp: String?
    public let activeServerId: String?
    public let activeServerName: String?
    public let clashApiUrl: String?
    public let clashApiSecret: String?
    public let pauseUntil: TimeInterval?
    
    public static var initial: SystemStatus {
        SystemStatus(
            isProtectionOn: false,
            pfEnabled: false,
            pfRulesCount: 0,
            pfBlockedPackets: 0,
            xrayRunning: DaemonProcessInfo(running: false, pid: nil, gid: nil, user: nil),
            singboxRunning: DaemonProcessInfo(running: false, pid: nil, gid: nil, user: nil),
            utunInterface: nil,
            exitIp: nil,
            exitLocation: nil,
            relayIp: nil,
            activeServerId: nil,
            activeServerName: nil,
            clashApiUrl: nil,
            clashApiSecret: nil,
            pauseUntil: nil
        )
    }
}
