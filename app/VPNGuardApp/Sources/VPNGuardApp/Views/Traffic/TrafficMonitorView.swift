import SwiftUI
import AppKit

private struct GroupedTrafficEntry: Identifiable {
    let id: String
    let processName: String
    let processPath: String?
    let destinationHost: String
    let destinationIp: String?
    let isProxy: Bool
    let outboundTag: String
    let connectionCount: Int
    let totalDownload: Int64
    let totalUpload: Int64
    let connectionIds: [String]
    let sampleConnection: ClashConnection
}

public struct TrafficMonitorView: View {
    @ObservedObject var vm: VPNGuardViewModel
    @ObservedObject private var monitor = TrafficMonitorService.shared
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var searchText: String = ""
    @State private var selectedFilter: FilterRoute = .all
    @State private var groupByProcessAndHost: Bool = true
    @State private var connectionToClose: ClashConnection? = nil
    @State private var inspectedConnection: ClashConnection? = nil
    @State private var showCloseAllAlert: Bool = false
    @State private var isHoveringList: Bool = false
    @State private var frozenConnections: [ClashConnection] = []
    @State private var cachedFilteredConnections: [ClashConnection] = []
    @State private var cachedGroupedEntries: [GroupedTrafficEntry] = []

    enum FilterRoute: String, CaseIterable, Identifiable {
        case all = "Все"
        case proxy = "VPN"
        case direct = "Direct"

        var id: String { rawValue }
    }

    public init(vm: VPNGuardViewModel) {
        self.vm = vm
    }

    private func recomputeConnectionLists() {
        let source = isHoveringList ? frozenConnections : monitor.connections
        let query = searchText.lowercased()
        let filtered = source.filter { conn in
            switch selectedFilter {
            case .all:
                break
            case .proxy:
                if !conn.isProxy { return false }
            case .direct:
                if conn.isProxy { return false }
            }

            if !query.isEmpty {
                let matchesProcess = conn.processName.lowercased().contains(query)
                let matchesPath = conn.metadata.processPath?.lowercased().contains(query) ?? false
                let matchesHost = conn.destinationHost.lowercased().contains(query)
                let matchesIp = conn.metadata.destinationIP?.contains(query) ?? false
                let matchesPort = conn.metadata.destinationPort?.contains(query) ?? false
                return matchesProcess || matchesPath || matchesHost || matchesIp || matchesPort
            }

            return true
        }

        cachedFilteredConnections = filtered

        var buckets: [String: [ClashConnection]] = [:]
        for conn in filtered {
            let canonical = conn.metadata.processPath.map { VPNGuardViewModel.canonicalProcessTarget(from: $0).path } ?? conn.processName
            let key = "\(canonical)|\(conn.destinationHost)|\(conn.isProxy ? "1" : "0")"
            buckets[key, default: []].append(conn)
        }
        cachedGroupedEntries = buckets.map { key, items in
            let first = items[0]
            let canonicalName = first.metadata.processPath.map { VPNGuardViewModel.canonicalProcessTarget(from: $0).name } ?? first.processName
            let totalDown = items.reduce(Int64(0)) { $0 + $1.download }
            let totalUp = items.reduce(Int64(0)) { $0 + $1.upload }
            return GroupedTrafficEntry(
                id: key,
                processName: canonicalName,
                processPath: first.metadata.processPath,
                destinationHost: first.destinationHost,
                destinationIp: first.metadata.destinationIP,
                isProxy: first.isProxy,
                outboundTag: first.outboundTag,
                connectionCount: items.count,
                totalDownload: totalDown,
                totalUpload: totalUp,
                connectionIds: items.map(\.id),
                sampleConnection: first
            )
        }
        .sorted { ($0.totalDownload + $0.totalUpload) > ($1.totalDownload + $1.totalUpload) }
    }

    private var headerSubtitle: String {
        if monitor.isConnected {
            return "Clash API подключён (127.0.0.1:9090)"
        } else if let error = monitor.lastError {
            return "Ошибка подключения: \(error)"
        }
        return "Ожидание запуска sing-box…"
    }

    public var body: some View {
        VStack(spacing: 0) {
            VGPageHeader(
                title: "Монитор трафика",
                subtitle: headerSubtitle
            ) {
                HStack(spacing: 8) {
                    VGStatusBadge(
                        monitor.isConnected ? "Подключено" : "Ожидание",
                        tone: monitor.isConnected ? .protected : .warning,
                        showDot: true
                    )

                    Button {
                        if monitor.isMonitoring {
                            monitor.stopMonitoring()
                        } else {
                            monitor.startMonitoring()
                        }
                    } label: {
                        Label(
                            monitor.isMonitoring ? "Пауза" : "Возобновить",
                            systemImage: monitor.isMonitoring ? "pause.fill" : "play.fill"
                        )
                        .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)

                    Button(role: .destructive) {
                        showCloseAllAlert = true
                    } label: {
                        Label("Разорвать все", systemImage: "xmark.circle")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .disabled(monitor.connections.isEmpty)
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: VGTheme.sectionSpacing) {
                    metricsGrid

                    // Search, Filter & Grouping Toolbar (no acid green button)
                    HStack(spacing: 10) {
                        VGSearchField("Поиск по процессу, домену или IP…", text: $searchText)

                        Picker("", selection: $selectedFilter) {
                            ForEach(FilterRoute.allCases) { filter in
                                Text(filter.rawValue).tag(filter)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.segmented)
                        .frame(width: 210)
                        .fixedSize()

                        Button {
                            withAnimation(VGTokens.Motion.snappy(reduceMotion: reduceMotion)) {
                                groupByProcessAndHost.toggle()
                            }
                        } label: {
                            HStack(spacing: VGPrimitives.Space.s6) {
                                Image(systemName: "square.stack.3d.up")
                                    .font(VGTokens.Typography.caption)
                                    .accessibilityHidden(true)
                                Text("Группировать")
                                    .font(VGTokens.Typography.captionEmphasis)
                            }
                            .foregroundStyle(groupByProcessAndHost ? VGTokens.Colors.textPrimary : VGTokens.Colors.textSecondary)
                            .padding(.horizontal, VGPrimitives.Space.s10)
                            .padding(.vertical, VGPrimitives.Space.s6)
                        }
                        .buttonStyle(VGSurfaceButtonStyle(isHighlighted: groupByProcessAndHost, highlightTint: VGTokens.Colors.accentPrimary))
                        .help("Группировать повторяющиеся потоки по приложению и домену")
                    }

                    connectionsSection
                }
                .padding(VGTheme.pagePadding)
            }
        }
        .onAppear {
            if let url = vm.status.clashApiUrl, let secret = vm.status.clashApiSecret {
                monitor.configure(url: url, secret: secret)
            }
            monitor.startMonitoring()
            recomputeConnectionLists()
        }
        .onDisappear {
            monitor.stopMonitoring()
        }
        .onChange(of: monitor.connectionsVersion) { _, _ in
            if !isHoveringList {
                recomputeConnectionLists()
            }
        }
        .onChange(of: searchText) { _, _ in
            recomputeConnectionLists()
        }
        .onChange(of: selectedFilter) { _, _ in
            recomputeConnectionLists()
        }
        .onChange(of: isHoveringList) { _, _ in
            recomputeConnectionLists()
        }
        .alert("Закрыть соединение?", isPresented: Binding(
            get: { connectionToClose != nil },
            set: { if !$0 { connectionToClose = nil } }
        )) {
            Button("Отмена", role: .cancel) {
                connectionToClose = nil
            }
            Button("Закрыть", role: .destructive) {
                if let conn = connectionToClose {
                    let targetId = conn.id
                    Task {
                        if await monitor.closeConnection(id: targetId) {
                            frozenConnections.removeAll { $0.id == targetId }
                            recomputeConnectionLists()
                        }
                    }
                }
                connectionToClose = nil
            }
        } message: {
            if let conn = connectionToClose {
                Text("Разорвать соединение процесса \(conn.processName) с \(conn.destinationDisplay)?")
            }
        }
        .alert("Закрыть все соединения?", isPresented: $showCloseAllAlert) {
            Button("Отмена", role: .cancel) {}
            Button("Закрыть все", role: .destructive) {
                Task {
                    if await monitor.closeAllConnections() {
                        frozenConnections.removeAll()
                        recomputeConnectionLists()
                    }
                }
            }
        } message: {
            Text("Это действие принудительно разорвёт все текущие сетевые сессии, проходящие через sing-box.")
        }
        .sheet(item: $inspectedConnection) { snapshot in
            connectionInspectorSheet(snapshot: snapshot)
        }
    }

    // MARK: - Metrics Grid
    private var metricsGrid: some View {
        Grid(horizontalSpacing: 14, verticalSpacing: 14) {
            GridRow {
                metricCard(
                    title: "Загрузка",
                    icon: "arrow.down.circle.fill",
                    tint: VGTokens.Colors.accentPrimary,
                    value: VGFormatters.formatSpeed(monitor.downloadSpeed),
                    subtitle: "Всего: \(VGFormatters.formatBytes(monitor.downloadTotal))"
                )

                metricCard(
                    title: "Отдача",
                    icon: "arrow.up.circle.fill",
                    tint: VGTokens.Colors.accentSecondary,
                    value: VGFormatters.formatSpeed(monitor.uploadSpeed),
                    subtitle: "Всего: \(VGFormatters.formatBytes(monitor.uploadTotal))"
                )

                metricCard(
                    title: "Соединения",
                    icon: "network",
                    tint: VGTokens.Colors.statusProtected,
                    value: "\(monitor.connections.count)",
                    subtitle: "Отфильтровано: \(cachedFilteredConnections.count)"
                )
            }
        }
    }

    private func metricCard(title: String, icon: String, tint: Color, value: String, subtitle: String) -> some View {
        VGCard(padding: 14) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Image(systemName: icon)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(tint)
                    Text(title)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.secondary)
                    Spacer()
                }

                Text(value)
                    .font(.system(size: 20, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(.primary)
                    .lineLimit(1)

                Text(subtitle)
                    .font(.system(size: 11))
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Connections Section
    private var connectionsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            VGSectionHeader(
                groupByProcessAndHost
                    ? "Группы соединений (\(cachedGroupedEntries.count) из \(cachedFilteredConnections.count))"
                    : "Активные сессии (\(cachedFilteredConnections.count))"
            ) {
                if isHoveringList {
                    VGStatusBadge("Пауза при наведении", tone: .warning, showDot: true)
                } else {
                    Text("Правый клик или переключатель VPN/Direct — правило в 1 клик")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
            }

            if !monitor.isConnected && monitor.connections.isEmpty && monitor.lastError == nil {
                VGCard(padding: VGTokens.Spacing.cardPadding) {
                    VGLoadingStateView("Подключение к Clash API (sing-box)…")
                }
            } else if let err = monitor.lastError, monitor.connections.isEmpty {
                VGErrorBanner(
                    message: "Ошибка подключения к Clash API: \(err)",
                    retryTitle: "Повторить"
                ) {
                    monitor.startMonitoring()
                }
            } else if cachedFilteredConnections.isEmpty {
                VGCard(padding: VGTokens.Spacing.cardPadding) {
                    VGEmptyStateView(
                        icon: "network.slash",
                        title: searchText.isEmpty ? "Нет активных соединений" : "Ничего не найдено",
                        message: searchText.isEmpty
                            ? "Все сетевые сессии завершены или sing-box находится в режиме ожидания."
                            : "Попробуйте изменить поисковый запрос или фильтр маршрутизации."
                    )
                }
            } else {
                VGCard(padding: 0) {
                    LazyVStack(spacing: 0) {
                        if groupByProcessAndHost {
                            ForEach(Array(cachedGroupedEntries.enumerated()), id: \.element.id) { index, entry in
                                groupedConnectionRow(entry)
                                if index < cachedGroupedEntries.count - 1 {
                                    Divider().opacity(0.45)
                                }
                            }
                        } else {
                            ForEach(Array(cachedFilteredConnections.enumerated()), id: \.element.id) { index, conn in
                                connectionRow(conn)
                                if index < cachedFilteredConnections.count - 1 {
                                    Divider().opacity(0.45)
                                }
                            }
                        }
                    }
                }
                .onHover { hovering in
                    if hovering {
                        frozenConnections = monitor.connections
                    }
                    isHoveringList = hovering
                }
            }
        }
    }

    // MARK: - Grouped Row
    private func groupedConnectionRow(_ entry: GroupedTrafficEntry) -> some View {
        let hasDomain = VPNGuardViewModel.isValidDomainHost(entry.destinationHost)
        let hasPath = !(entry.processPath ?? "").isEmpty

        return HStack(spacing: 12) {
            // Process Icon & Short Name (full path in tooltip)
            HStack(spacing: 10) {
                processIconView(path: entry.processPath, isProxy: entry.isProxy)
                    .frame(width: 24, height: 24)

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 5) {
                        Text(entry.processName)
                            .font(.system(size: 12, weight: .semibold))
                            .lineLimit(1)

                        if entry.connectionCount > 1 {
                            Text("×\(entry.connectionCount)")
                                .font(VGTokens.Typography.badge.monospaced())
                                .monospacedDigit()
                                .foregroundStyle(VGTokens.Colors.textSecondary)
                                .padding(.horizontal, VGPrimitives.Space.s4)
                                .padding(.vertical, 1)
                                .background(VGTokens.Colors.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTokens.Radius.mini, style: .continuous))
                        }
                    }

                    if let subtitle = shortProcessSubtitle(entry.processPath) {
                        Text(subtitle)
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }
            }
            .frame(width: 175, alignment: .leading)
            .help(entry.processPath ?? entry.processName)

            Divider().frame(height: 24).opacity(0.45)

            // Destination
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.destinationHost)
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .monospacedDigit()
                    .lineLimit(1)
                    .truncationMode(.middle)

                if let ip = entry.destinationIp, ip != entry.destinationHost {
                    Text(ip)
                        .font(.system(size: 10, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Data Transfer
            VStack(alignment: .trailing, spacing: 2) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.down")
                        .font(.system(size: 9))
                        .foregroundStyle(VGTheme.accentPrimary)
                    Text(VGFormatters.formatBytes(entry.totalDownload))
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                }
                HStack(spacing: 4) {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 9))
                        .foregroundStyle(.secondary)
                    Text(VGFormatters.formatBytes(entry.totalUpload))
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                }
            }
            .frame(width: 82, alignment: .trailing)

            // Unified Route Switcher [VPN | Direct]
            routeSwitcherControl(
                host: entry.destinationHost,
                processPath: entry.processPath,
                isProxy: entry.isProxy,
                hasDomain: hasDomain,
                hasPath: hasPath
            )

            // Inspect route (keyboard & VoiceOver accessible)
            Button {
                inspectedConnection = entry.sampleConnection
            } label: {
                Image(systemName: "info.circle")
                    .font(VGTokens.Typography.body)
            }
            .buttonStyle(VGIconButtonStyle())
            .help("Инспектор маршрута (Explain)")
            .accessibilityLabel("Инспектор маршрута для \(entry.processName)")

            // Close group connections in parallel
            Button {
                let ids = entry.connectionIds
                let service = monitor
                Task {
                    let closedIds = await withTaskGroup(of: String?.self, returning: Set<String>.self) { group in
                        for id in ids {
                            group.addTask {
                                let ok = await service.closeConnection(id: id)
                                return ok ? id : nil
                            }
                        }
                        var result: Set<String> = []
                        for await closedId in group {
                            if let closedId {
                                result.insert(closedId)
                            }
                        }
                        return result
                    }
                    if !closedIds.isEmpty {
                        frozenConnections.removeAll { closedIds.contains($0.id) }
                        recomputeConnectionLists()
                    }
                }
            } label: {
                Image(systemName: "xmark.circle")
                    .font(VGTokens.Typography.body)
            }
            .buttonStyle(VGIconButtonStyle(isDestructive: true))
            .help("Разорвать все соединения этой группы")
            .accessibilityLabel("Разорвать все соединения \(entry.processName) к \(entry.destinationHost)")
        }
        .padding(.horizontal, VGComponentTokens.Row.horizontalPadding)
        .padding(.vertical, VGComponentTokens.Row.verticalPadding)
        .vgHoverRow(cornerRadius: 0)
        .accessibilityElement(children: .contain)
        .accessibilityAction(named: "Открыть инспектор маршрута") {
            inspectedConnection = entry.sampleConnection
        }
        .contextMenu {
            Button("Инспектор маршрута (Explain)") {
                inspectedConnection = entry.sampleConnection
            }
            Divider()
            ruleContextMenuItems(host: entry.destinationHost, processPath: entry.processPath)
        }
    }

    // MARK: - Single Connection Row
    private func connectionRow(_ conn: ClashConnection) -> some View {
        let hasDomain = VPNGuardViewModel.isValidDomainHost(conn.destinationHost)
        let hasPath = !(conn.metadata.processPath ?? "").isEmpty

        return HStack(spacing: 12) {
            HStack(spacing: 10) {
                processIconView(path: conn.metadata.processPath, isProxy: conn.isProxy)
                    .frame(width: 24, height: 24)

                VStack(alignment: .leading, spacing: 2) {
                    Text(conn.processName)
                        .font(.system(size: 12, weight: .semibold))
                        .lineLimit(1)

                    if let subtitle = shortProcessSubtitle(conn.metadata.processPath) {
                        Text(subtitle)
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }
            }
            .frame(width: 175, alignment: .leading)
            .help(conn.metadata.processPath ?? conn.processName)

            Divider().frame(height: 24).opacity(0.45)

            VStack(alignment: .leading, spacing: 2) {
                Text(conn.destinationDisplay)
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .monospacedDigit()
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: 6) {
                    Text((conn.metadata.network ?? "TCP").uppercased())
                        .font(VGTokens.Typography.badge)
                        .foregroundStyle(VGTokens.Colors.textSecondary)
                        .padding(.horizontal, VGPrimitives.Space.s4)
                        .padding(.vertical, 1)
                        .background(VGTokens.Colors.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTokens.Radius.mini, style: .continuous))

                    if let ip = conn.metadata.destinationIP, ip != conn.metadata.host {
                        Text(ip)
                            .font(.system(size: 10, design: .monospaced))
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            VStack(alignment: .trailing, spacing: 2) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.down")
                        .font(.system(size: 9))
                        .foregroundStyle(VGTheme.accentPrimary)
                    Text(conn.formattedDownload)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                }
                HStack(spacing: 4) {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 9))
                        .foregroundStyle(.secondary)
                    Text(conn.formattedUpload)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                }
            }
            .frame(width: 82, alignment: .trailing)

            routeSwitcherControl(
                host: conn.destinationHost,
                processPath: conn.metadata.processPath,
                isProxy: conn.isProxy,
                hasDomain: hasDomain,
                hasPath: hasPath
            )

            Text(conn.formattedDuration)
                .font(.system(size: 11, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .frame(width: 48, alignment: .trailing)

            Button {
                inspectedConnection = conn
            } label: {
                Image(systemName: "info.circle")
                    .font(VGTokens.Typography.body)
            }
            .buttonStyle(VGIconButtonStyle())
            .help("Инспектор маршрута (Explain)")
            .accessibilityLabel("Инспектор маршрута для \(conn.processName)")

            Button {
                connectionToClose = conn
            } label: {
                Image(systemName: "xmark.circle")
                    .font(VGTokens.Typography.body)
            }
            .buttonStyle(VGIconButtonStyle(isDestructive: true))
            .help("Разорвать это соединение")
            .accessibilityLabel("Разорвать соединение \(conn.processName) с \(conn.destinationDisplay)")
        }
        .padding(.horizontal, VGComponentTokens.Row.horizontalPadding)
        .padding(.vertical, VGComponentTokens.Row.verticalPadding)
        .vgHoverRow(cornerRadius: 0)
        .accessibilityElement(children: .contain)
        .accessibilityAction(named: "Открыть инспектор маршрута") {
            inspectedConnection = conn
        }
        .contextMenu {
            Button("Инспектор маршрута (Explain)") {
                inspectedConnection = conn
            }
            Divider()
            ruleContextMenuItems(host: conn.destinationHost, processPath: conn.metadata.processPath)
            Divider()
            Button("Разорвать соединение", role: .destructive) {
                connectionToClose = conn
            }
        }
    }

    // MARK: - Unified [VPN | Direct] Route Switcher
    @ViewBuilder
    private func routeSwitcherControl(
        host: String,
        processPath: String?,
        isProxy: Bool,
        hasDomain: Bool,
        hasPath: Bool
    ) -> some View {
        if hasDomain || hasPath {
            HStack(spacing: 2) {
                Button {
                    guard !isProxy else { return }
                    Task {
                        if hasDomain {
                            await vm.upsertDomainRule(domain: host, action: .proxy, applyImmediately: true)
                        } else if let p = processPath {
                            await vm.upsertAppRule(processPath: p, action: .proxy, applyImmediately: true)
                        }
                    }
                } label: {
                    Text("VPN")
                        .font(VGTokens.Typography.badge)
                        .padding(.horizontal, VGPrimitives.Space.s8)
                        .padding(.vertical, VGPrimitives.Space.s4)
                        .background(
                            RoundedRectangle(cornerRadius: VGTokens.Radius.mini, style: .continuous)
                                .fill(isProxy ? VGTokens.Colors.accentPrimary.opacity(0.22) : .clear)
                        )
                        .foregroundStyle(isProxy ? VGTokens.Colors.accentPrimary : VGTokens.Colors.textSecondary)
                }
                .buttonStyle(.borderless)
                .disabled(vm.isApplyingRules)
                .help(isProxy ? "Маршрут: через VPN" : (hasDomain ? "Переключить \(host) на VPN" : "Переключить процесс на VPN"))
                .accessibilityLabel(hasDomain ? "Направить \(host) через VPN" : "Направить процесс через VPN")

                Button {
                    guard isProxy else { return }
                    Task {
                        if hasDomain {
                            await vm.upsertDomainRule(domain: host, action: .direct, applyImmediately: true)
                        } else if let p = processPath {
                            await vm.upsertAppRule(processPath: p, action: .direct, applyImmediately: true)
                        }
                    }
                } label: {
                    Text("Direct")
                        .font(VGTokens.Typography.badge)
                        .padding(.horizontal, VGPrimitives.Space.s8)
                        .padding(.vertical, VGPrimitives.Space.s4)
                        .background(
                            RoundedRectangle(cornerRadius: VGTokens.Radius.mini, style: .continuous)
                                .fill(!isProxy ? VGTokens.Colors.statusProtected.opacity(0.22) : .clear)
                        )
                        .foregroundStyle(!isProxy ? VGTokens.Colors.statusProtected : VGTokens.Colors.textSecondary)
                }
                .buttonStyle(.borderless)
                .disabled(vm.isApplyingRules)
                .help(!isProxy ? "Маршрут: напрямую (Direct)" : (hasDomain ? "Переключить \(host) на Direct" : "Переключить процесс на Direct"))
                .accessibilityLabel(hasDomain ? "Направить \(host) напрямую" : "Направить процесс напрямую")
            }
            .padding(2)
            .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous)
                    .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.5)
            )
        } else {
            VGStatusBadge(isProxy ? "VPN" : "Direct", tone: isProxy ? .accent : .protected, showDot: true)
        }
    }

    @ViewBuilder
    private func ruleContextMenuItems(host: String, processPath: String?) -> some View {
        if VPNGuardViewModel.isValidDomainHost(host) {
            Section("Домен: \(host)") {
                Button("Домен «\(host)» → Через VPN") {
                    Task { await vm.upsertDomainRule(domain: host, action: .proxy, applyImmediately: true) }
                }
                Button("Домен «\(host)» → Напрямую (Direct)") {
                    Task { await vm.upsertDomainRule(domain: host, action: .direct, applyImmediately: true) }
                }
                Button("Домен «\(host)» → Заблокировать") {
                    Task { await vm.upsertDomainRule(domain: host, action: .block, applyImmediately: true) }
                }

                if let root = VPNGuardViewModel.rootDomain(from: host), root != host.lowercased() {
                    Button("Весь «\(root)» → Через VPN") {
                        Task { await vm.upsertDomainRule(domain: root, action: .proxy, applyImmediately: true) }
                    }
                    Button("Весь «\(root)» → Напрямую (Direct)") {
                        Task { await vm.upsertDomainRule(domain: root, action: .direct, applyImmediately: true) }
                    }
                }
            }
        }

        if let path = processPath, !path.isEmpty {
            let target = VPNGuardViewModel.canonicalProcessTarget(from: path)
            Section("Приложение: \(target.name)") {
                Button("Приложение «\(target.name)» → Через VPN") {
                    Task { await vm.upsertAppRule(processPath: path, action: .proxy, applyImmediately: true) }
                }
                Button("Приложение «\(target.name)» → Напрямую (Direct)") {
                    Task { await vm.upsertAppRule(processPath: path, action: .direct, applyImmediately: true) }
                }
                Button("Приложение «\(target.name)» → Заблокировать") {
                    Task { await vm.upsertAppRule(processPath: path, action: .block, applyImmediately: true) }
                }
                Button("Копировать путь (\(target.path))") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(target.path, forType: .string)
                    vm.showToast("Путь скопирован в буфер", isError: false)
                }
            }
        }

        if !host.isEmpty && host != "—" {
            Button("Копировать хост (\(host))") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(host, forType: .string)
                vm.showToast("Хост скопирован", isError: false)
            }
        }
    }

    @ViewBuilder
    private func processIconView(path: String?, isProxy: Bool) -> some View {
        if let path, let appRange = path.range(of: ".app") {
            let appBundlePath = String(path[..<appRange.upperBound])
            if let cachedIcon = AppIconCache.shared.icon(forAppPath: appBundlePath) {
                Image(nsImage: cachedIcon)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
            } else {
                fallbackProcessIcon(isProxy: isProxy)
            }
        } else {
            fallbackProcessIcon(isProxy: isProxy)
        }
    }

    private func fallbackProcessIcon(isProxy: Bool) -> some View {
        Image(systemName: isProxy ? "shield.fill" : "globe")
            .font(.system(size: 14))
            .foregroundStyle(isProxy ? VGTheme.accentPrimary : VGTheme.statusProtected)
    }

    // MARK: - Live Runtime Route Inspector Sheet
    @ViewBuilder
    private func connectionInspectorSheet(snapshot: ClashConnection) -> some View {
        let liveConn = monitor.connections.first(where: { $0.id == snapshot.id })
        let conn = liveConn ?? snapshot
        let isActive = (liveConn != nil)

        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                processIconView(path: conn.metadata.processPath, isProxy: conn.isProxy)
                    .frame(width: 28, height: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Инспектор маршрута (Live Runtime)")
                        .font(.system(size: 14, weight: .semibold))
                    Text("\(conn.processName) → \(conn.destinationDisplay)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                VGStatusBadge(
                    isActive ? "Активно" : "Завершено",
                    tone: isActive ? .protected : .neutral,
                    showDot: true
                )
            }

            Divider().opacity(0.45)

            VStack(alignment: .leading, spacing: 10) {
                inspectorStepRow(
                    step: "1. Процесс / Хост",
                    value: "\(conn.processName) · \(conn.destinationDisplay)",
                    detail: [conn.metadata.processPath, conn.metadata.destinationIP.map { "IP: \($0)" }, conn.metadata.network?.uppercased()]
                        .compactMap { $0 }
                        .joined(separator: " | ")
                )
                inspectorStepRow(
                    step: "2. Сработавшее правило",
                    value: conn.ruleDisplay,
                    detail: "Вычислено sing-box в реальном времени (Clash API)"
                )
                inspectorStepRow(
                    step: "3. DNS",
                    value: conn.dnsDisplay,
                    detail: "Режим DNS из метаданных соединения"
                )
                inspectorStepRow(
                    step: "4. Маршрут / Выход",
                    value: conn.chainsDisplay,
                    detail: conn.isProxy ? "Через VPN-туннель (xray-upstream)" : "Прямой выход (Direct / LAN)"
                )
            }

            HStack {
                Spacer()
                Button("Закрыть") {
                    inspectedConnection = nil
                }
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding(18)
        .frame(width: 480)
    }

    private func inspectorStepRow(step: String, value: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(step)
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .textSelection(.enabled)
            if !detail.isEmpty {
                Text(detail)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
    }

    private func shortProcessSubtitle(_ path: String?) -> String? {
        guard let path, !path.isEmpty else { return nil }
        if let appRange = path.range(of: ".app") {
            let appPath = String(path[..<appRange.upperBound])
            return (appPath as NSString).lastPathComponent
        }
        return (path as NSString).deletingLastPathComponent
    }
}
