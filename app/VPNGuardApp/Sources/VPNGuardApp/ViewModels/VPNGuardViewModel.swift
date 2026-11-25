import Foundation
import SwiftUI
import Combine
import Network

@MainActor
public final class VPNGuardViewModel: ObservableObject {
    // MARK: - Published Properties
    @Published public var status: SystemStatus = .initial
    @Published public var isProtectionActive: Bool = false
    @Published public var statusError: String? = nil
    @Published public var isTogglingPower: Bool = false
    @Published public var isApplyingRules: Bool = false
    @Published public var isRunningAudit: Bool = false
    @Published public var isUpdatingServer: Bool = false
    @Published public var servers: [ServerProfile] = []
    @Published public var isLoadingServers: Bool = false
    @Published public var activatingServerId: String? = nil

    // Rules State
    @Published public var rules: UserRules = .empty
    @Published public var hasUnappliedChanges: Bool = false
    @Published public var lastAppliedRules: UserRules = .empty

    // Audit State
    @Published public var auditReport: AuditReport? = nil

    // UI Messages
    @Published public var toastMessage: String? = nil
    @Published public var toastIsError: Bool = false

    // System Integration
    @Published public var launchAtLogin: Bool = false

    // Services & Timers
    private let service = VPNGuardService.shared
    private var nativeProbeCancellable: AnyCancellable?
    private var periodicSyncCancellable: AnyCancellable?
    private var pathMonitor: NWPathMonitor?
    private var lastPathSignature: String? = nil
    private var networkChangeTask: Task<Void, Never>?

    public init() {
        checkLaunchAtLoginStatus()

        if let localSecret = service.readLocalApiSecret() {
            TrafficMonitorService.shared.configure(url: "127.0.0.1:9090", secret: localSecret)
        }

        Task {
            await refreshStatus(fast: false)
            await loadRules()
            await loadServers()
        }
        startTimers()
        startNetworkMonitor()
    }

    deinit {
        nativeProbeCancellable?.cancel()
        periodicSyncCancellable?.cancel()
        networkChangeTask?.cancel()
        pathMonitor?.cancel()
    }

    // MARK: - Hybrid Status Polling (Zero external HTTP spam)
    public func startTimers() {
        nativeProbeCancellable?.cancel()
        periodicSyncCancellable?.cancel()

        // Fast native interface probe every 2.5s (no sudo, no network I/O)
        nativeProbeCancellable = Timer.publish(every: 2.5, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                let utunUp = self.service.isUtunInterfaceUp(name: "utun99")
                if !utunUp && self.isProtectionActive && !self.isTogglingPower {
                    self.isProtectionActive = false
                    Task { await self.refreshStatus(fast: true) }
                } else if utunUp && !self.isProtectionActive && !self.isTogglingPower {
                    Task { await self.refreshStatus(fast: true) }
                }
            }

        // Fast CLI sync every 45s for PF counters & daemon PIDs (skips ipinfo.io)
        periodicSyncCancellable = Timer.publish(every: 45.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                Task { [weak self] in
                    await self?.refreshStatus(fast: true)
                }
            }
    }

    // MARK: - NWPathMonitor for Automatic Network-Switch DNS Sync
    private func startNetworkMonitor() {
        let monitor = NWPathMonitor()
        self.pathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            let interfaces = path.availableInterfaces
                .filter { !$0.name.hasPrefix("utun") }
                .map { "\($0.name):\($0.type)" }
                .sorted()
                .joined(separator: ",")
            let gateways = path.gateways.map(\.debugDescription).sorted().joined(separator: ",")
            let signature = "\(path.status)|\(interfaces)|\(gateways)"

            Task { @MainActor [weak self] in
                guard let self else { return }
                if self.lastPathSignature == nil {
                    self.lastPathSignature = signature
                    return
                }
                guard signature != self.lastPathSignature else { return }
                self.lastPathSignature = signature

                guard path.status == .satisfied else { return }
                self.networkChangeTask?.cancel()
                self.networkChangeTask = Task { @MainActor [weak self] in
                    try? await Task.sleep(nanoseconds: 1_200_000_000)
                    guard let self, !Task.isCancelled else { return }
                    if self.isProtectionActive || self.service.isUtunInterfaceUp(name: "utun99") {
                        try? await self.service.syncDns()
                        await self.refreshStatus(fast: false)
                    }
                }
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
    }

    public func refreshStatus(fast: Bool = true) async {
        do {
            let newStatus = try await service.fetchStatus(fast: fast)
            // Preserve previously known external IP when doing --fast refresh
            if fast, newStatus.exitIp == nil, self.status.isProtectionOn == newStatus.isProtectionOn,
               newStatus.isProtectionOn, let prevIp = self.status.exitIp {
                self.status = SystemStatus(
                    isProtectionOn: newStatus.isProtectionOn,
                    pfEnabled: newStatus.pfEnabled,
                    pfRulesCount: newStatus.pfRulesCount,
                    pfBlockedPackets: newStatus.pfBlockedPackets,
                    xrayRunning: newStatus.xrayRunning,
                    singboxRunning: newStatus.singboxRunning,
                    utunInterface: newStatus.utunInterface,
                    exitIp: prevIp,
                    exitLocation: self.status.exitLocation,
                    relayIp: newStatus.relayIp,
                    activeServerId: newStatus.activeServerId,
                    activeServerName: newStatus.activeServerName,
                    clashApiUrl: newStatus.clashApiUrl,
                    clashApiSecret: newStatus.clashApiSecret
                )
            } else {
                self.status = newStatus
            }
            self.isProtectionActive = newStatus.isProtectionOn
            self.statusError = nil
            TrafficMonitorService.shared.configure(url: newStatus.clashApiUrl, secret: newStatus.clashApiSecret)
        } catch {
            self.statusError = error.localizedDescription
            self.isProtectionActive = false
        }
    }

    // MARK: - Power Toggle
    public func toggleProtection() async {
        guard !isTogglingPower else { return }
        isTogglingPower = true
        let targetState = !isProtectionActive

        do {
            if targetState {
                showToast("Включение защиты VPNGuard...", isError: false)
                try await service.turnOn()
            } else {
                showToast("Отключение защиты...", isError: false)
                try await service.turnOff()
            }
            await refreshStatus(fast: !targetState)
            showToast(targetState ? "Защита VPNGuard активирована" : "Защита отключена", isError: false)
        } catch {
            showToast(error.localizedDescription, isError: true)
            await refreshStatus(fast: true)
        }
        isTogglingPower = false
    }

    // MARK: - Rules Management
    public func loadRules() async {
        do {
            let loadedRules = try await service.fetchRules()
            self.rules = loadedRules
            self.lastAppliedRules = loadedRules
            self.hasUnappliedChanges = false
        } catch {
            showToast("Не удалось загрузить правила: \(error.localizedDescription)", isError: true)
        }
    }

    public func applyChanges() async {
        guard !isApplyingRules else { return }
        isApplyingRules = true

        do {
            try await service.applyRules(rules)
            self.lastAppliedRules = rules
            self.hasUnappliedChanges = false
            showToast("Правила успешно применены в sing-box", isError: false)
            await refreshStatus(fast: true)
        } catch {
            showToast("Ошибка применения правил: \(error.localizedDescription)", isError: true)
        }
        isApplyingRules = false
    }

    public func discardChanges() {
        self.rules = self.lastAppliedRules
        self.hasUnappliedChanges = false
    }

    // MARK: - App Rules
    public func addApp(name: String, bundlePath: String, action: RuleAction = .proxy) {
        guard !rules.apps.contains(where: { $0.bundlePath == bundlePath }) else {
            showToast("Приложение уже добавлено", isError: true)
            return
        }
        let newRule = AppRule(name: name, bundlePath: bundlePath, action: action, enabled: true)
        rules.apps.append(newRule)
        hasUnappliedChanges = true
    }

    public func removeApp(at indexSet: IndexSet) {
        rules.apps.remove(atOffsets: indexSet)
        hasUnappliedChanges = true
    }

    public func removeApp(id: String) {
        rules.apps.removeAll(where: { $0.id == id })
        hasUnappliedChanges = true
    }

    // MARK: - Domain Rules
    public func addDomain(input: String, action: RuleAction = .proxy) {
        let cleaned = sanitizeDomain(input)
        guard !cleaned.isEmpty else { return }

        if rules.domains.contains(where: { $0.domain == cleaned }) {
            showToast("Домен \(cleaned) уже присутствует в списке", isError: true)
            return
        }

        let newRule = DomainRule(domain: cleaned, action: action, enabled: true)
        rules.domains.append(newRule)
        hasUnappliedChanges = true
    }

    public func removeDomain(id: String) {
        rules.domains.removeAll(where: { $0.id == id })
        hasUnappliedChanges = true
    }

    public func removeDomain(at indexSet: IndexSet) {
        rules.domains.remove(atOffsets: indexSet)
        hasUnappliedChanges = true
    }

    public func sanitizeDomain(_ input: String) -> String {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if text.hasPrefix("https://") { text = String(text.dropFirst(8)) }
        if text.hasPrefix("http://") { text = String(text.dropFirst(7)) }
        if let slashIndex = text.firstIndex(of: "/") { text = String(text[..<slashIndex]) }
        if let colonIndex = text.firstIndex(of: ":") { text = String(text[..<colonIndex]) }
        if text.hasPrefix("www.") { text = String(text.dropFirst(4)) }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Server Update
    public func updateServerConfig(jsonText: String) async -> Bool {
        guard !isUpdatingServer else { return false }
        isUpdatingServer = true
        defer { isUpdatingServer = false }

        do {
            _ = try await service.updateServer(xrayConfigText: jsonText)
            showToast("Сервер обновлен и проверен", isError: false)
            await refreshStatus(fast: false)
            await loadRules()
            await loadServers()
            return true
        } catch {
            showToast(error.localizedDescription, isError: true)
            return false
        }
    }

    // MARK: - Server Profiles
    public var activeServer: ServerProfile? {
        return servers.first(where: { $0.isActive })
    }

    public func loadServers() async {
        isLoadingServers = true
        defer { isLoadingServers = false }
        do {
            let list = try await service.listServers()
            self.servers = list
        } catch {
            print("[VPNGuardViewModel] Failed to load servers: \(error)")
        }
    }

    public func importVless(uri: String, activateImmediately: Bool) async -> Bool {
        do {
            let created = try await service.importVless(uriText: uri)
            showToast("Сервер «\(created.name)» добавлен", isError: false)
            if activateImmediately {
                _ = await activateServer(id: created.id)
            } else {
                await loadServers()
            }
            return true
        } catch {
            showToast("Ошибка импорта: \(error.localizedDescription)", isError: true)
            return false
        }
    }

    public func activateServer(id: String) async -> Bool {
        activatingServerId = id
        defer { activatingServerId = nil }

        do {
            try await service.activateServer(id: id)
            showToast("Сервер переключен успешно", isError: false)
            await loadServers()
            await refreshStatus(fast: false)
            await loadRules()
            return true
        } catch {
            showToast("Ошибка активации: \(error.localizedDescription)", isError: true)
            await loadServers()
            await refreshStatus(fast: true)
            return false
        }
    }

    public func deleteServer(id: String) async -> Bool {
        do {
            try await service.deleteServer(id: id)
            showToast("Профиль сервера удален", isError: false)
            await loadServers()
            return true
        } catch {
            showToast("Ошибка удаления: \(error.localizedDescription)", isError: true)
            return false
        }
    }

    // MARK: - Audit
    public func runSecurityAudit() async {
        guard !isRunningAudit else { return }
        isRunningAudit = true
        auditReport = nil

        do {
            let report = try await service.runAudit()
            self.auditReport = report
            if report.passed {
                showToast("Все проверки пройдены: Утечек нет!", isError: false)
            } else {
                showToast("Обнаружены несоответствия в тестах (\(report.failedCount))", isError: true)
            }
        } catch {
            showToast("Ошибка запуска аудита: \(error.localizedDescription)", isError: true)
        }
        isRunningAudit = false
    }

    // MARK: - Launch At Login (Single LaunchAgent mechanism for ad-hoc builds)
    private var launchAgentPlistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.vpnguard.app.plist")
    }

    public func checkLaunchAtLoginStatus() {
        self.launchAtLogin = FileManager.default.fileExists(atPath: launchAgentPlistURL.path)
    }

    public func setLaunchAtLogin(_ enabled: Bool) {
        if enabled {
            installLaunchAgent()
            self.launchAtLogin = FileManager.default.fileExists(atPath: launchAgentPlistURL.path)
            showToast(self.launchAtLogin ? "Автозапуск при входе включен" : "Не удалось создать LaunchAgent", isError: !self.launchAtLogin)
        } else {
            removeLaunchAgent()
            self.launchAtLogin = false
            showToast("Автозапуск при входе выключен")
        }
    }

    private func installLaunchAgent() {
        let launchAgentsDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")
        try? FileManager.default.createDirectory(at: launchAgentsDir, withIntermediateDirectories: true)

        let appPath = Bundle.main.bundlePath.hasSuffix(".app") ? Bundle.main.bundlePath : "/Applications/VPNGuard.app"
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.vpnguard.app</string>
            <key>ProgramArguments</key>
            <array>
                <string>/usr/bin/open</string>
                <string>-a</string>
                <string>\(appPath)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>ProcessType</key>
            <string>Interactive</string>
        </dict>
        </plist>
        """
        try? plistContent.write(to: launchAgentPlistURL, atomically: true, encoding: .utf8)
    }

    private func removeLaunchAgent() {
        try? FileManager.default.removeItem(at: launchAgentPlistURL)
    }

    // MARK: - Toast Helpers
    public func showToast(_ message: String, isError: Bool = false) {
        self.toastMessage = message
        self.toastIsError = isError

        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) { [weak self] in
            if self?.toastMessage == message {
                self?.toastMessage = nil
            }
        }
    }
}
