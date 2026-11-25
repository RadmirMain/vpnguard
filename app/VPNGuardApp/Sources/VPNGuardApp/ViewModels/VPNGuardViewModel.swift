import Foundation
import SwiftUI
import AppKit
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

    // Audit & Diagnostics State
    @Published public var auditReport: AuditReport? = nil
    @Published public var diagnosticsSnapshot: DiagnosticsLogsSnapshot? = nil
    @Published public var isLoadingDiagnostics: Bool = false
    @Published public var requestedNavigationSection: NavigationSection? = nil

    // UI Messages
    @Published public var toastMessage: String? = nil
    @Published public var toastIsError: Bool = false

    // System Integration
    @Published public var launchAtLogin: Bool = false

    // Wi-Fi Captive Portal Pause State
    @Published public var pauseEndDate: Date? = nil
    @Published public var pauseRemainingSeconds: Int = 0
    @Published public var isTogglingPause: Bool = false
    @Published public var isLaunchingBrowser: Bool = false

    // Self-Update State (stored in UserDefaults so ad-hoc signature stays intact)
    private static let sourceRepoPathKey = "sourceRepoPath"
    private static let autoFailoverKey = "autoFailoverEnabled"
    @Published public var sourceRepoPath: String
    @Published public var isUpdatingApp: Bool = false
    @Published public var isCheckingUpdates: Bool = false
    @Published public var updateCheckResult: UpdateCheckResult? = nil
    @Published public var updateLogOutput: String? = nil

    // Server Ping & Tunnel Health / Auto-Failover State
    @Published public var serverLatencies: [String: ServerPingResult] = [:]
    @Published public var isPingingServers: Bool = false
    @Published public var tunnelHealthOk: Bool? = nil
    @Published public var tunnelLatencyMs: Int? = nil
    @Published public var lastHealthCheckAt: Date? = nil
    @Published public var autoFailoverEnabled: Bool {
        didSet {
            UserDefaults.standard.set(autoFailoverEnabled, forKey: Self.autoFailoverKey)
            if !autoFailoverEnabled {
                failoverAttemptedServerIds.removeAll()
                failoverCooldownUntil = nil
            }
        }
    }
    @Published public var failoverCooldownUntil: Date? = nil
    @Published public var isRunningFailover: Bool = false

    // Services & Timers
    private let service = VPNGuardService.shared
    private var nativeProbeCancellable: AnyCancellable?
    private var periodicSyncCancellable: AnyCancellable?
    private var healthProbeCancellable: AnyCancellable?
    private var pauseCountdownCancellable: AnyCancellable?
    private var wakeObserver: NSObjectProtocol?
    private var pathMonitor: NWPathMonitor?
    private var lastPathSignature: String? = nil
    private var networkChangeTask: Task<Void, Never>?
    private var isResumingFromPause: Bool = false
    private var isNetworkSatisfied: Bool = true
    private var isCheckingHealth: Bool = false
    private var wakeGraceUntil: Date? = nil
    private var failoverAttemptedServerIds: Set<String> = []

    public init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates = [
            home.appendingPathComponent("Desktop/Business/Кодинг/VPNGuard").path,
            home.appendingPathComponent("Developer/vpnguard").path
        ]
        let defaultRepo = candidates.first(where: {
            FileManager.default.fileExists(atPath: ($0 as NSString).appendingPathComponent("update.sh"))
        }) ?? candidates[0]
        let storedRepo = UserDefaults.standard.string(forKey: Self.sourceRepoPathKey)
        if let storedRepo, !storedRepo.isEmpty,
           FileManager.default.fileExists(atPath: (storedRepo as NSString).appendingPathComponent("update.sh")) {
            self.sourceRepoPath = storedRepo
        } else {
            self.sourceRepoPath = defaultRepo
        }
        self.autoFailoverEnabled = UserDefaults.standard.bool(forKey: Self.autoFailoverKey)

        checkLaunchAtLoginStatus()

        if let initialPauseEnd = service.readLocalPauseUntil() {
            setPauseEndDate(initialPauseEnd)
        }

        if let localSecret = service.readLocalApiSecret() {
            TrafficMonitorService.shared.configure(url: "127.0.0.1:9090", secret: localSecret)
        }

        Task {
            await refreshStatus(fast: false)
            await loadRules()
            await loadServers()
            await runTunnelHealthCheck(allowFailover: false)
        }
        startTimers()
        startNetworkMonitor()
        startWakeObserver()
    }

    deinit {
        nativeProbeCancellable?.cancel()
        periodicSyncCancellable?.cancel()
        healthProbeCancellable?.cancel()
        pauseCountdownCancellable?.cancel()
        networkChangeTask?.cancel()
        pathMonitor?.cancel()
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
        }
    }

    // MARK: - Hybrid Status Polling (Zero external HTTP spam)
    public func startTimers() {
        nativeProbeCancellable?.cancel()
        periodicSyncCancellable?.cancel()
        healthProbeCancellable?.cancel()

        // Fast native interface probe every 2.5s (no sudo, no network I/O)
        nativeProbeCancellable = Timer.publish(every: 2.5, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                let utunUp = self.service.isUtunInterfaceUp(name: "utun99")
                if !utunUp && self.isProtectionActive && !self.isTogglingPower && !self.isTogglingPause {
                    self.isProtectionActive = false
                    self.tunnelHealthOk = nil
                    self.tunnelLatencyMs = nil
                    Task { await self.refreshStatus(fast: true) }
                } else if utunUp && !self.isProtectionActive && !self.isTogglingPower && !self.isTogglingPause {
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

        // Real tunnel liveness probe every 25s via 127.0.0.1:18089
        healthProbeCancellable = Timer.publish(every: 25.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                Task { [weak self] in
                    await self?.runTunnelHealthCheck(allowFailover: true)
                }
            }
    }

    // MARK: - NWPathMonitor for Automatic Network-Switch DNS & PF Sync
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
            let satisfied = (path.status == .satisfied)

            Task { @MainActor [weak self] in
                guard let self else { return }
                self.isNetworkSatisfied = satisfied
                if self.lastPathSignature == nil {
                    self.lastPathSignature = signature
                    return
                }
                guard signature != self.lastPathSignature else { return }
                self.lastPathSignature = signature

                guard satisfied else { return }
                self.networkChangeTask?.cancel()
                self.networkChangeTask = Task { @MainActor [weak self] in
                    // Debounce 2.5s (and honor 6s wake grace) to avoid spamming syncDns/syncPfEgress on Wi-Fi flaps
                    let graceDelay = max(0.0, self?.wakeGraceUntil?.timeIntervalSinceNow ?? 0.0)
                    let totalNs = UInt64(max(2.5, graceDelay) * 1_000_000_000.0)
                    try? await Task.sleep(nanoseconds: totalNs)
                    guard let self, !Task.isCancelled, self.isNetworkSatisfied else { return }
                    if self.isProtectionActive || self.service.isUtunInterfaceUp(name: "utun99") {
                        try? await self.service.syncDns()
                        try? await self.service.syncPfEgress()
                        await self.refreshStatus(fast: false)
                        await self.runTunnelHealthCheck(allowFailover: false)
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
                    clashApiSecret: newStatus.clashApiSecret,
                    pauseUntil: newStatus.pauseUntil
                )
            } else {
                self.status = newStatus
            }
            self.isProtectionActive = newStatus.isProtectionOn
            self.statusError = nil
            if newStatus.isProtectionOn {
                setPauseEndDate(nil)
            } else if let ts = newStatus.pauseUntil, ts > Date().timeIntervalSince1970 {
                setPauseEndDate(Date(timeIntervalSince1970: ts))
            } else if let localEnd = service.readLocalPauseUntil() {
                setPauseEndDate(localEnd)
            } else {
                setPauseEndDate(nil)
            }
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
                setPauseEndDate(nil)
            } else {
                showToast("Отключение защиты...", isError: false)
                try await service.turnOff()
                setPauseEndDate(nil)
            }
            await refreshStatus(fast: !targetState)
            showToast(targetState ? "Защита VPNGuard активирована" : "Защита отключена", isError: false)
        } catch {
            showToast(error.localizedDescription, isError: true)
            await refreshStatus(fast: true)
        }
        isTogglingPower = false
    }

    // MARK: - Wi-Fi Captive Portal Pause
    public var menuBarPauseText: String? {
        guard pauseRemainingSeconds > 0 else { return nil }
        let mins = pauseRemainingSeconds / 60
        let secs = pauseRemainingSeconds % 60
        return String(format: "%02d:%02d", mins, secs)
    }

    public func pauseForWifi(seconds: Int = 300) async {
        guard !isTogglingPause && !isTogglingPower else { return }
        isTogglingPause = true
        defer { isTogglingPause = false }

        do {
            showToast("Пауза защиты для входа в Wi-Fi...", isError: false)
            let endDate = try await service.pauseProtection(seconds: seconds)
            setPauseEndDate(endDate)
            await refreshStatus(fast: true)
            let mins = seconds / 60
            showToast("Пауза на \(mins) мин активна. Защита включится автоматически.", isError: false)
        } catch {
            showToast("Ошибка паузы: \(error.localizedDescription)", isError: true)
            await refreshStatus(fast: true)
        }
    }

    public func resumeFromPauseNow() async {
        guard !isTogglingPause && !isTogglingPower else { return }
        isTogglingPause = true
        defer { isTogglingPause = false }

        do {
            showToast("Возобновление защиты VPNGuard...", isError: false)
            try await service.turnOn()
            setPauseEndDate(nil)
            await refreshStatus(fast: false)
            showToast("Защита VPNGuard восстановлена", isError: false)
        } catch {
            showToast("Ошибка возобновления: \(error.localizedDescription)", isError: true)
            await refreshStatus(fast: true)
        }
    }

    private func setPauseEndDate(_ date: Date?) {
        pauseEndDate = date
        pauseCountdownCancellable?.cancel()
        pauseCountdownCancellable = nil

        guard let target = date else {
            pauseRemainingSeconds = 0
            return
        }

        let rem = max(0, Int(ceil(target.timeIntervalSinceNow)))
        pauseRemainingSeconds = rem
        if rem == 0 {
            Task { await handlePauseExpiration() }
            return
        }

        pauseCountdownCancellable = Timer.publish(every: 1.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self, let end = self.pauseEndDate else { return }
                let left = max(0, Int(ceil(end.timeIntervalSinceNow)))
                self.pauseRemainingSeconds = left
                if left <= 0 {
                    self.pauseCountdownCancellable?.cancel()
                    self.pauseCountdownCancellable = nil
                    Task { await self.handlePauseExpiration() }
                }
            }
    }

    private func startWakeObserver() {
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.wakeGraceUntil = Date().addingTimeInterval(6.0)
                if let end = self.pauseEndDate, end.timeIntervalSinceNow <= 0 {
                    await self.handlePauseExpiration()
                } else if let localEnd = self.service.readLocalPauseUntil() {
                    self.setPauseEndDate(localEnd)
                } else {
                    try? await self.service.resumeIfExpired()
                    await self.refreshStatus(fast: true)
                }
                // Re-probe tunnel health cleanly once Wi-Fi settles after 6s wake grace
                try? await Task.sleep(nanoseconds: 6_200_000_000)
                await self.runTunnelHealthCheck(allowFailover: true)
            }
        }
    }

    private func handlePauseExpiration() async {
        guard !isResumingFromPause else { return }
        isResumingFromPause = true
        defer { isResumingFromPause = false }

        do {
            try await service.resumeIfExpired()
            setPauseEndDate(nil)
            await refreshStatus(fast: false)
            if isProtectionActive {
                showToast("Пауза завершена: защита снова активна", isError: false)
            }
        } catch {
            await refreshStatus(fast: true)
        }
    }

    // MARK: - Sandbox Browser Launcher (Non-root GID 888)
    public func launchProtectedBrowser() async {
        guard !isLaunchingBrowser else { return }
        isLaunchingBrowser = true
        defer { isLaunchingBrowser = false }

        do {
            showToast("Запуск защищённого браузера (GID 888)...", isError: false)
            try await service.launchProtectedBrowser()
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    // MARK: - Self-Update (UserDefaults sourceRepoPath)
    public func setSourceRepoPath(_ path: String) {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        sourceRepoPath = trimmed
        UserDefaults.standard.set(trimmed, forKey: Self.sourceRepoPathKey)
        updateCheckResult = nil
    }

    public func checkForUpdates() async {
        guard !isCheckingUpdates && !isUpdatingApp else { return }
        isCheckingUpdates = true
        defer { isCheckingUpdates = false }

        do {
            let check = try await service.checkForUpdates(repoPath: sourceRepoPath)
            updateCheckResult = check
        } catch {
            updateCheckResult = nil
            updateLogOutput = error.localizedDescription
        }
    }

    public func triggerAppUpdate(forceApp: Bool = false, forceBackend: Bool = false) async {
        guard !isUpdatingApp else { return }
        isUpdatingApp = true
        updateLogOutput = "Проверка и обновление из \(sourceRepoPath)..."

        do {
            let output = try await service.runUpdateScript(
                repoPath: sourceRepoPath,
                forceApp: forceApp,
                forceBackend: forceBackend
            )
            updateLogOutput = output
            if output.contains("VPNGUARD_RELAUNCH_SCHEDULED") {
                showToast("Обновление собрано. Перезапуск VPNGuard...", isError: false)
                try? await Task.sleep(nanoseconds: 400_000_000)
                NSApp.terminate(nil)
            } else if output.contains("VPNGUARD_UP_TO_DATE") {
                isUpdatingApp = false
                await checkForUpdates()
                showToast("Актуальная версия уже установлена", isError: false)
            } else {
                isUpdatingApp = false
                await checkForUpdates()
                await refreshStatus(fast: true)
                showToast("Обновление завершено", isError: false)
            }
        } catch {
            updateLogOutput = error.localizedDescription
            showToast("Ошибка обновления: \(error.localizedDescription)", isError: true)
            isUpdatingApp = false
        }
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

    // MARK: - 1-Click Rules Helpers (Traffic Monitor)
    nonisolated public static func canonicalProcessTarget(from processPath: String) -> (name: String, path: String) {
        let trimmed = processPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return ("Unknown", "") }

        // Find FIRST '.app' segment so nested helpers like Cursor Helper.app map to /Applications/Cursor.app
        let components = (trimmed as NSString).pathComponents
        var acc: [String] = []
        for comp in components {
            acc.append(comp)
            if comp.lowercased().hasSuffix(".app") {
                let appBundlePath = NSString.path(withComponents: acc)
                let appName = (comp as NSString).deletingPathExtension
                return (appName.isEmpty ? comp : appName, appBundlePath)
            }
        }

        let binName = (trimmed as NSString).lastPathComponent
        return (binName.isEmpty ? trimmed : binName, trimmed)
    }

    nonisolated public static func isValidDomainHost(_ host: String) -> Bool {
        let cleaned = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty, cleaned != "—", cleaned.contains(".") else { return false }
        // Reject raw IPv4 / IPv6 literals
        var sin = in_addr()
        var sin6 = in6_addr()
        if inet_pton(AF_INET, cleaned, &sin) == 1 || inet_pton(AF_INET6, cleaned, &sin6) == 1 {
            return false
        }
        return !cleaned.contains(":")
    }

    nonisolated public static func rootDomain(from host: String) -> String? {
        let cleaned = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard isValidDomainHost(cleaned) else { return nil }
        let parts = cleaned.split(separator: ".").map(String.init)
        guard parts.count >= 3 else { return nil }
        return parts.suffix(2).joined(separator: ".")
    }

    public func upsertDomainRule(domain input: String, action: RuleAction, applyImmediately: Bool = true) async {
        let cleaned = sanitizeDomain(input)
        guard Self.isValidDomainHost(cleaned) else {
            showToast("Некорректный домен для правила: \(input)", isError: true)
            return
        }

        if let idx = rules.domains.firstIndex(where: { $0.domain.caseInsensitiveCompare(cleaned) == .orderedSame }) {
            rules.domains[idx].action = action
            rules.domains[idx].enabled = true
        } else {
            rules.domains.append(DomainRule(domain: cleaned, action: action, enabled: true))
        }
        hasUnappliedChanges = true

        if applyImmediately {
            await applyChanges()
        }
    }

    public func upsertAppRule(processPath: String, action: RuleAction, applyImmediately: Bool = true) async {
        let target = Self.canonicalProcessTarget(from: processPath)
        guard !target.path.isEmpty else {
            showToast("Путь процесса не определён", isError: true)
            return
        }

        if let idx = rules.apps.firstIndex(where: { $0.bundlePath == target.path }) {
            rules.apps[idx].action = action
            rules.apps[idx].enabled = true
        } else {
            rules.apps.append(AppRule(name: target.name, bundlePath: target.path, action: action, enabled: true))
        }
        hasUnappliedChanges = true

        if applyImmediately {
            await applyChanges()
        }
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

    // MARK: - Server Ping (GID 890 + IP_BOUND_IF) & Auto-Failover
    public func pingAllServers(silent: Bool = false) async {
        guard !isPingingServers else { return }
        isPingingServers = true
        defer { isPingingServers = false }

        do {
            let results = try await service.pingServers()
            var map: [String: ServerPingResult] = [:]
            for item in results {
                map[item.id] = item
            }
            self.serverLatencies = map
            if !silent {
                let reachableCount = results.filter(\.reachable).count
                showToast("Пинг завершён: доступно \(reachableCount) из \(results.count)", isError: false)
            }
        } catch {
            if !silent {
                showToast("Ошибка пинга серверов: \(error.localizedDescription)", isError: true)
            }
        }
    }

    public func sortServersByPing() {
        servers.sort { a, b in
            if a.isActive != b.isActive {
                return a.isActive
            }
            let latA = serverLatencies[a.id]?.latencyMs ?? Int.max
            let latB = serverLatencies[b.id]?.latencyMs ?? Int.max
            if latA != latB {
                return latA < latB
            }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
    }

    public func runTunnelHealthCheck(allowFailover: Bool) async {
        guard isProtectionActive, !isTogglingPower, !isTogglingPause, !isUpdatingApp else {
            if !isProtectionActive {
                tunnelHealthOk = nil
                tunnelLatencyMs = nil
            }
            return
        }
        if let wakeGrace = wakeGraceUntil, wakeGrace.timeIntervalSinceNow > 0 {
            return
        }
        guard !isCheckingHealth else { return }
        isCheckingHealth = true
        defer { isCheckingHealth = false }

        let probe = await service.measureTunnelHealth()
        lastHealthCheckAt = Date()
        if probe.ok {
            tunnelHealthOk = true
            tunnelLatencyMs = probe.latencyMs
            failoverAttemptedServerIds.removeAll()
            return
        }

        tunnelHealthOk = false
        tunnelLatencyMs = nil

        guard allowFailover,
              autoFailoverEnabled,
              isNetworkSatisfied,
              !isRunningFailover,
              servers.count > 1 else {
            return
        }

        if let cooldown = failoverCooldownUntil {
            if cooldown.timeIntervalSinceNow > 0 {
                return
            }
            failoverCooldownUntil = nil
            failoverAttemptedServerIds.removeAll()
        }

        await performAutoFailoverSequence()
    }

    private func performAutoFailoverSequence() async {
        isRunningFailover = true
        defer { isRunningFailover = false }

        // Require 2 more failed probes (3 consecutive failures total, 3s apart)
        for _ in 0..<2 {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard isProtectionActive, isNetworkSatisfied, !isTogglingPower, !isTogglingPause else { return }
            let retry = await service.measureTunnelHealth()
            if retry.ok {
                tunnelHealthOk = true
                tunnelLatencyMs = retry.latencyMs
                return
            }
        }

        // Step 1: Re-resolve active server IP & refresh PF vpnguard/egress before switching
        try? await service.syncPfEgress()
        let afterResync = await service.measureTunnelHealth()
        if afterResync.ok {
            tunnelHealthOk = true
            tunnelLatencyMs = afterResync.latencyMs
            showToast("IP релея обновлён в PF, связь восстановлена", isError: false)
            return
        }

        // Step 2: Ping all servers directly via GID 890 + IP_BOUND_IF and pick best untested server
        if let activeId = activeServer?.id ?? status.activeServerId {
            failoverAttemptedServerIds.insert(activeId)
        }

        await pingAllServers(silent: true)
        let candidates = servers
            .filter { !failoverAttemptedServerIds.contains($0.id) }
            .compactMap { srv -> (server: ServerProfile, latency: Int)? in
                guard let ping = serverLatencies[srv.id], ping.reachable, let lat = ping.latencyMs else {
                    return nil
                }
                return (srv, lat)
            }
            .sorted { $0.latency < $1.latency }

        guard let best = candidates.first else {
            // Completed 1 full circle: enter 5-minute failover cooldown while keeping PF Kill-Switch ARMED
            failoverCooldownUntil = Date().addingTimeInterval(300)
            failoverAttemptedServerIds.removeAll()
            let msg = "Доступных резервных серверов не найдено. Kill-Switch остаётся активным; автопереключение на паузе 5 мин."
            showToast(msg, isError: true)
            service.sendUserNotification(title: "VPNGuard Auto-Failover", message: msg)
            return
        }

        showToast("Переключение на резервный сервер «\(best.server.name)» (\(best.latency) мс)...", isError: false)
        let switched = await activateServer(id: best.server.id)
        if switched {
            let verify = await service.measureTunnelHealth()
            tunnelHealthOk = verify.ok
            tunnelLatencyMs = verify.latencyMs
            service.sendUserNotification(
                title: "VPNGuard Auto-Failover",
                message: "Переключено на «\(best.server.name)» (\(best.latency) мс)"
            )
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

    public func loadDiagnosticsLogs(silent: Bool = false) async {
        guard !isLoadingDiagnostics else { return }
        isLoadingDiagnostics = true
        defer { isLoadingDiagnostics = false }

        do {
            diagnosticsSnapshot = try await service.fetchDiagnosticLogs()
        } catch {
            if !silent {
                showToast("Ошибка чтения логов: \(error.localizedDescription)", isError: true)
            }
        }
    }

    public func copyDiagnosticsMarkdownReport() {
        var lines: [String] = []
        lines.append("# VPNGuard Diagnostic Report")
        lines.append("")
        lines.append("- **Generated:** \(diagnosticsSnapshot?.generatedAt ?? ISO8601DateFormatter().string(from: Date()))")
        lines.append("- **Protection Active:** \(isProtectionActive)")
        lines.append("- **PF Enabled:** \(status.pfEnabled) (Rules: \(status.pfRulesCount), Blocked packets: \(status.pfBlockedPackets))")
        lines.append("- **Xray:** running=\(status.xrayRunning.running), pid=\(status.xrayRunning.pid.map(String.init) ?? "none")")
        lines.append("- **sing-box:** running=\(status.singboxRunning.running), pid=\(status.singboxRunning.pid.map(String.init) ?? "none"), utun=\(status.utunInterface ?? "none")")
        lines.append("- **Active Server:** \(activeServer?.name ?? status.activeServerName ?? "none")")
        lines.append("")

        if let report = auditReport {
            lines.append("## 12-Point Leak Audit (\(report.passedCount)/\(report.total))")
            for item in report.tests {
                lines.append("- [\(item.passed ? "x" : " ")] **\(item.name)** — \(item.details)")
            }
            lines.append("")
        }

        if let snap = diagnosticsSnapshot {
            lines.append("## PF Rules")
            lines.append("```")
            lines.append(snap.system.pfRules)
            lines.append("```")
            lines.append("")
            lines.append("## utun99")
            lines.append("```")
            lines.append(snap.system.utun)
            lines.append("```")
            lines.append("")
            lines.append("## DNS (scutil --dns)")
            lines.append("```")
            lines.append(snap.system.dns)
            lines.append("```")
            lines.append("")
            lines.append("## sing-box Log (tail 150)")
            lines.append("```")
            lines.append(snap.logs.singbox)
            lines.append("```")
            lines.append("")
            lines.append("## Xray Log (tail 150)")
            lines.append("```")
            lines.append(snap.logs.xray)
            lines.append("```")
            lines.append("")
            lines.append("## PF / Boot Log (tail 150)")
            lines.append("```")
            lines.append(snap.logs.pf)
            lines.append("```")
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
        showToast("Markdown-отчёт скопирован в буфер", isError: false)
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
