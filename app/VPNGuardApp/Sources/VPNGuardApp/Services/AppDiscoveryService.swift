import Foundation
import AppKit

public struct DiscoveredApp: Identifiable, Hashable {
    public var id: String { path }
    public let name: String
    public let path: String
    public let bundleIdentifier: String?
    
    public init(name: String, path: String, bundleIdentifier: String?) {
        self.name = name
        self.path = path
        self.bundleIdentifier = bundleIdentifier
    }
}

public final class AppDiscoveryService {
    public static let shared = AppDiscoveryService()
    
    private init() {}
    
    public func scanInstalledApps() async -> [DiscoveredApp] {
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var foundApps: [DiscoveredApp] = []
                let fileManager = FileManager.default
                
                let searchDirs = [
                    "/Applications",
                    "/System/Applications",
                    NSHomeDirectory() + "/Applications"
                ]
                
                var seenPaths = Set<String>()
                
                for dir in searchDirs {
                    guard let contents = try? fileManager.contentsOfDirectory(atPath: dir) else { continue }
                    for item in contents where item.hasSuffix(".app") {
                        let fullPath = (dir as NSString).appendingPathComponent(item)
                        guard !seenPaths.contains(fullPath) else { continue }
                        seenPaths.insert(fullPath)
                        
                        let name = (item as NSString).deletingPathExtension
                        let bundle = Bundle(path: fullPath)
                        let bundleId = bundle?.bundleIdentifier
                        
                        foundApps.append(DiscoveredApp(
                            name: name,
                            path: fullPath,
                            bundleIdentifier: bundleId
                        ))
                    }
                }
                
                foundApps.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                continuation.resume(returning: foundApps)
            }
        }
    }
}
