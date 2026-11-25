import Foundation
import SwiftUI

private struct ClashTrafficFrame: Codable {
    let up: Int64
    let down: Int64
}

@MainActor
public final class TrafficMonitorService: ObservableObject {
    public static let shared = TrafficMonitorService()

    // MARK: - Published Properties
    @Published public var isMonitoring: Bool = false
    @Published public var isConnected: Bool = false
    @Published public var connections: [ClashConnection] = []
    @Published public var downloadTotal: Int64 = 0
    @Published public var uploadTotal: Int64 = 0
    @Published public var uploadSpeed: Int64 = 0
    @Published public var downloadSpeed: Int64 = 0
    @Published public var lastError: String? = nil
    @Published public var lastUpdated: Date? = nil

    // MARK: - Internal Configuration
    private var apiUrl: String = "127.0.0.1:9090"
    private var apiSecret: String = ""

    private var connectionsTask: Task<Void, Never>?
    private var trafficTask: Task<Void, Never>?
    private var connectionsWs: URLSessionWebSocketTask?
    private var trafficWs: URLSessionWebSocketTask?

    private let urlSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 4.0
        config.timeoutIntervalForResource = 0
        return URLSession(configuration: config)
    }()

    private let decoder = JSONDecoder()

    private init() {
        if let localSecret = VPNGuardService.shared.readLocalApiSecret() {
            self.apiSecret = localSecret
        }
    }

    // MARK: - Configuration
    public func configure(url: String?, secret: String?) {
        var changed = false
        if let u = url, !u.isEmpty, u != self.apiUrl {
            self.apiUrl = u
            changed = true
        }
        if let s = secret, !s.isEmpty, s != self.apiSecret {
            self.apiSecret = s
            changed = true
        }
        if changed && isMonitoring {
            restartWebSockets()
        }
    }

    // MARK: - Lifecycle Controls
    public func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true
        if apiSecret.isEmpty, let localSecret = VPNGuardService.shared.readLocalApiSecret() {
            apiSecret = localSecret
        }
        restartWebSockets()
    }

    public func stopMonitoring() {
        isMonitoring = false
        cancelTasks()
        uploadSpeed = 0
        downloadSpeed = 0
    }

    private func cancelTasks() {
        connectionsTask?.cancel()
        trafficTask?.cancel()
        connectionsTask = nil
        trafficTask = nil
        connectionsWs?.cancel(with: .normalClosure, reason: nil)
        trafficWs?.cancel(with: .normalClosure, reason: nil)
        connectionsWs = nil
        trafficWs = nil
    }

    private func restartWebSockets() {
        cancelTasks()
        connectionsTask = Task { [weak self] in
            await self?.runConnectionsStream()
        }
        trafficTask = Task { [weak self] in
            await self?.runTrafficStream()
        }
    }

    // MARK: - WebSocket Streams
    private func makeWebSocketRequest(path: String) -> URLRequest? {
        guard let url = URL(string: "ws://\(apiUrl)\(path)") else { return nil }
        var req = URLRequest(url: url)
        if !apiSecret.isEmpty {
            req.setValue("Bearer \(apiSecret)", forHTTPHeaderField: "Authorization")
        }
        return req
    }

    private func runConnectionsStream() async {
        // Immediate HTTP snapshot for instant first paint
        await fetchConnectionsOnce()

        while isMonitoring && !Task.isCancelled {
            guard let req = makeWebSocketRequest(path: "/connections") else {
                self.isConnected = false
                self.lastError = "Некорректный адрес Clash API"
                return
            }

            let ws = urlSession.webSocketTask(with: req)
            self.connectionsWs = ws
            ws.resume()

            do {
                while isMonitoring && !Task.isCancelled {
                    let message = try await ws.receive()
                    let payloadData: Data?
                    switch message {
                    case .string(let text):
                        payloadData = text.data(using: .utf8)
                    case .data(let data):
                        payloadData = data
                    @unknown default:
                        payloadData = nil
                    }

                    if let data = payloadData {
                        let snapshot = try decoder.decode(ClashConnectionSnapshot.self, from: data)
                        self.isConnected = true
                        self.lastError = nil
                        self.lastUpdated = Date()
                        self.uploadTotal = snapshot.uploadTotal
                        self.downloadTotal = snapshot.downloadTotal
                        self.connections = snapshot.connections
                    }
                }
            } catch {
                if !Task.isCancelled && isMonitoring {
                    self.isConnected = false
                    self.lastError = "Clash API переподключение: \(error.localizedDescription)"
                }
            }

            ws.cancel(with: .goingAway, reason: nil)
            if self.connectionsWs === ws {
                self.connectionsWs = nil
            }
            if isMonitoring && !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
            }
        }
    }

    private func runTrafficStream() async {
        while isMonitoring && !Task.isCancelled {
            guard let req = makeWebSocketRequest(path: "/traffic") else { return }
            let ws = urlSession.webSocketTask(with: req)
            self.trafficWs = ws
            ws.resume()

            do {
                while isMonitoring && !Task.isCancelled {
                    let message = try await ws.receive()
                    let payloadData: Data?
                    switch message {
                    case .string(let text):
                        payloadData = text.data(using: .utf8)
                    case .data(let data):
                        payloadData = data
                    @unknown default:
                        payloadData = nil
                    }

                    if let data = payloadData {
                        let frame = try decoder.decode(ClashTrafficFrame.self, from: data)
                        self.uploadSpeed = frame.up
                        self.downloadSpeed = frame.down
                    }
                }
            } catch {
                if !Task.isCancelled && isMonitoring {
                    self.uploadSpeed = 0
                    self.downloadSpeed = 0
                }
            }

            ws.cancel(with: .goingAway, reason: nil)
            if self.trafficWs === ws {
                self.trafficWs = nil
            }
            if isMonitoring && !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
            }
        }
    }

    // MARK: - One-Shot HTTP Snapshot Fallback
    public func fetchConnectionsOnce() async {
        guard let requestUrl = URL(string: "http://\(apiUrl)/connections") else {
            self.isConnected = false
            self.lastError = "Некорректный адрес Clash API"
            return
        }

        var request = URLRequest(url: requestUrl)
        request.httpMethod = "GET"
        if !apiSecret.isEmpty {
            request.setValue("Bearer \(apiSecret)", forHTTPHeaderField: "Authorization")
        }

        do {
            let (data, response) = try await urlSession.data(for: request)
            guard let httpResp = response as? HTTPURLResponse else { return }

            if httpResp.statusCode == 200 {
                let snapshot = try decoder.decode(ClashConnectionSnapshot.self, from: data)
                self.isConnected = true
                self.lastError = nil
                self.lastUpdated = Date()
                self.uploadTotal = snapshot.uploadTotal
                self.downloadTotal = snapshot.downloadTotal
                self.connections = snapshot.connections
            } else if httpResp.statusCode == 401 {
                self.isConnected = false
                self.lastError = "401 Unauthorized: неверный секрет токена Clash API"
            } else {
                self.isConnected = false
                self.lastError = "Ошибка Clash API: HTTP \(httpResp.statusCode)"
            }
        } catch {
            self.isConnected = false
            self.lastError = error.localizedDescription
        }
    }

    // MARK: - Close Connection
    public func closeConnection(id: String) async -> Bool {
        let endpoint = "http://\(apiUrl)/connections/\(id)"
        guard let requestUrl = URL(string: endpoint) else { return false }

        var request = URLRequest(url: requestUrl)
        request.httpMethod = "DELETE"
        if !apiSecret.isEmpty {
            request.setValue("Bearer \(apiSecret)", forHTTPHeaderField: "Authorization")
        }

        do {
            let (_, response) = try await urlSession.data(for: request)
            if let httpResp = response as? HTTPURLResponse, (200...204).contains(httpResp.statusCode) {
                self.connections.removeAll { $0.id == id }
                return true
            }
        } catch {}
        return false
    }

    // MARK: - Close All Connections
    public func closeAllConnections() async -> Bool {
        let endpoint = "http://\(apiUrl)/connections"
        guard let requestUrl = URL(string: endpoint) else { return false }

        var request = URLRequest(url: requestUrl)
        request.httpMethod = "DELETE"
        if !apiSecret.isEmpty {
            request.setValue("Bearer \(apiSecret)", forHTTPHeaderField: "Authorization")
        }

        do {
            let (_, response) = try await urlSession.data(for: request)
            if let httpResp = response as? HTTPURLResponse, (200...204).contains(httpResp.statusCode) {
                self.connections.removeAll()
                return true
            }
        } catch {}
        return false
    }
}
