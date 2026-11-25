import Foundation

public struct AuditTestItem: Codable, Identifiable, Equatable {
    public let id: Int
    public let name: String
    public let passed: Bool
    public let details: String
    
    public init(id: Int, name: String, passed: Bool, details: String) {
        self.id = id
        self.name = name
        self.passed = passed
        self.details = details
    }
}

public struct AuditReport: Codable, Equatable {
    public let passed: Bool
    public let total: Int
    public let passedCount: Int
    public let failedCount: Int
    public let tests: [AuditTestItem]
    
    public init(passed: Bool, total: Int, passedCount: Int, failedCount: Int, tests: [AuditTestItem]) {
        self.passed = passed
        self.total = total
        self.passedCount = passedCount
        self.failedCount = failedCount
        self.tests = tests
    }
}
