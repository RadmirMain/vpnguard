import Foundation

public enum AuditStatus: String, Codable, Equatable {
    case pass
    case degraded
    case fail
    case unknown
}

public struct AuditTestItem: Codable, Identifiable, Equatable {
    public let id: Int
    public let name: String
    public let passed: Bool
    public let status: AuditStatus
    public let details: String
    
    public init(id: Int, name: String, passed: Bool, status: AuditStatus? = nil, details: String) {
        self.id = id
        self.name = name
        self.passed = passed
        self.status = status ?? (passed ? .pass : .fail)
        self.details = details
    }

    enum CodingKeys: String, CodingKey {
        case id, name, passed, status, details
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(Int.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        passed = try container.decode(Bool.self, forKey: .passed)
        status = try container.decodeIfPresent(AuditStatus.self, forKey: .status) ?? (passed ? .pass : .fail)
        details = try container.decode(String.self, forKey: .details)
    }
}

public struct AuditReport: Codable, Equatable {
    public let passed: Bool
    public let total: Int
    public let passedCount: Int
    public let degradedCount: Int
    public let unknownCount: Int
    public let failedCount: Int
    public let tests: [AuditTestItem]
    
    public init(
        passed: Bool,
        total: Int,
        passedCount: Int,
        degradedCount: Int = 0,
        unknownCount: Int = 0,
        failedCount: Int,
        tests: [AuditTestItem]
    ) {
        self.passed = passed
        self.total = total
        self.passedCount = passedCount
        self.degradedCount = degradedCount
        self.unknownCount = unknownCount
        self.failedCount = failedCount
        self.tests = tests
    }

    enum CodingKeys: String, CodingKey {
        case passed, total, passedCount, degradedCount, unknownCount, failedCount, tests
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        passed = try container.decode(Bool.self, forKey: .passed)
        total = try container.decode(Int.self, forKey: .total)
        passedCount = try container.decode(Int.self, forKey: .passedCount)
        tests = try container.decode([AuditTestItem].self, forKey: .tests)
        degradedCount = try container.decodeIfPresent(Int.self, forKey: .degradedCount)
            ?? tests.filter { $0.status == .degraded }.count
        unknownCount = try container.decodeIfPresent(Int.self, forKey: .unknownCount)
            ?? tests.filter { $0.status == .unknown }.count
        failedCount = try container.decodeIfPresent(Int.self, forKey: .failedCount)
            ?? tests.filter { $0.status == .fail }.count
    }
}
