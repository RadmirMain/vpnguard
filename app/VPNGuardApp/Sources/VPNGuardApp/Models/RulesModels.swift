import Foundation

public enum RuleAction: String, Codable, CaseIterable, Identifiable {
    case proxy = "proxy"
    case direct = "direct"
    case block = "block"
    
    public var id: String { rawValue }
    
    public var displayName: String {
        switch self {
        case .proxy: return "Туннель"
        case .direct: return "Напрямую"
        case .block: return "Блок"
        }
    }
    
    public var iconName: String {
        switch self {
        case .proxy: return "shield.fill"
        case .direct: return "arrow.triangle.turn.up.right.diamond.fill"
        case .block: return "xmark.octagon.fill"
        }
    }
}

public struct AppRule: Codable, Identifiable, Equatable {
    public var id: String
    public var name: String
    public var bundlePath: String
    public var action: RuleAction
    public var enabled: Bool
    
    public init(id: String = UUID().uuidString, name: String, bundlePath: String, action: RuleAction = .proxy, enabled: Bool = true) {
        self.id = id
        self.name = name
        self.bundlePath = bundlePath
        self.action = action
        self.enabled = enabled
    }
}

public struct DomainRule: Codable, Identifiable, Equatable {
    public var id: String
    public var domain: String
    public var action: RuleAction
    public var enabled: Bool
    
    public init(id: String = UUID().uuidString, domain: String, action: RuleAction = .proxy, enabled: Bool = true) {
        self.id = id
        self.domain = domain
        self.action = action
        self.enabled = enabled
    }
}

public struct PresetsConfig: Codable, Equatable {
    public var aiServicesProxy: Bool
    public var ruDirect: Bool
    public var blockQuic: Bool
    
    public init(aiServicesProxy: Bool = true, ruDirect: Bool = true, blockQuic: Bool = true) {
        self.aiServicesProxy = aiServicesProxy
        self.ruDirect = ruDirect
        self.blockQuic = blockQuic
    }
}

public struct UserRules: Codable, Equatable {
    public var apps: [AppRule]
    public var domains: [DomainRule]
    public var presets: PresetsConfig
    
    public init(apps: [AppRule], domains: [DomainRule], presets: PresetsConfig) {
        self.apps = apps
        self.domains = domains
        self.presets = presets
    }
    
    public static var empty: UserRules {
        UserRules(
            apps: [],
            domains: [],
            presets: PresetsConfig(aiServicesProxy: true, ruDirect: true, blockQuic: true)
        )
    }
}
