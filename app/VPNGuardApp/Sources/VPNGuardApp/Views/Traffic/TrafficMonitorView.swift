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
}

public struct TrafficMonitorView: View {
    @ObservedObject var vm: VPNGuardViewModel
    @StateObject private var monitor = TrafficMonitorService.shared
    
    @State private var searchText: String = ""
    @State private var selectedFilter: FilterRoute = .all
    @State private var groupByProcessAndHost: Bool = true
    @State private var connectionToClose: ClashConnection? = nil
    @State private var showCloseAllAlert: Bool = false
    @State private var isHoveringList: Bool = false
    @State private var frozenConnections: [ClashConnection] = []
    
    enum FilterRoute: String, CaseIterable, Identifiable {
        case all = "Все"
        case proxy = "Прокси (Xray)"
        case direct = "Прямые (Direct)"
        
        var id: String { rawValue }
    }
    
    public init(vm: VPNGuardViewModel) {
        self.vm = vm
    }
    
    private var sourceConnections: [ClashConnection] {
        isHoveringList ? frozenConnections : monitor.connections
    }

    private var filteredConnections: [ClashConnection] {
        sourceConnections.filter { conn in
            // Filter by route
            switch selectedFilter {
            case .all:
                break
            case .proxy:
                if !conn.isProxy { return false }
            case .direct:
                if conn.isProxy { return false }
            }
            
            // Search text filter
            if !searchText.isEmpty {
                let query = searchText.lowercased()
                let matchesProcess = conn.processName.lowercased().contains(query)
                let matchesPath = conn.metadata.processPath?.lowercased().contains(query) ?? false
                let matchesHost = conn.destinationHost.lowercased().contains(query)
                let matchesIp = conn.metadata.destinationIP?.contains(query) ?? false
                let matchesPort = conn.metadata.destinationPort?.contains(query) ?? false
                return matchesProcess || matchesPath || matchesHost || matchesIp || matchesPort
            }
            
            return true
        }
    }

    private var groupedEntries: [GroupedTrafficEntry] {
        var buckets: [String: [ClashConnection]] = [:]
        for conn in filteredConnections {
            let canonical = conn.metadata.processPath.map { VPNGuardViewModel.canonicalProcessTarget(from: $0).path } ?? conn.processName
            let key = "\(canonical)|\(conn.destinationHost)|\(conn.isProxy ? "1" : "0")"
            buckets[key, default: []].append(conn)
        }
        return buckets.map { key, items in
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
                connectionIds: items.map(\.id)
            )
        }
        .sorted { ($0.totalDownload + $0.totalUpload) > ($1.totalDownload + $1.totalUpload) }
    }
    
    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header & Connection Status
                headerSection
                
                // Realtime Rate Metrics Grid
                metricsGrid
                
                // Search & Filter Toolbar
                filterBar
                
                // Active Connections List
                connectionsSection
            }
            .padding(24)
        }
        .background(Color(NSColor.windowBackgroundColor))
        .onAppear {
            if let url = vm.status.clashApiUrl, let secret = vm.status.clashApiSecret {
                monitor.configure(url: url, secret: secret)
            }
            monitor.startMonitoring()
        }
        .onDisappear {
            monitor.stopMonitoring()
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
                    Task {
                        await monitor.closeConnection(id: conn.id)
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
                    await monitor.closeAllConnections()
                }
            }
        } message: {
            Text("Это действие принудительно разорвёт все текущие сетевые сессии, проходящие через sing-box.")
        }
    }
    
    // MARK: - Header
    private var headerSection: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Монитор трафика")
                    .font(.system(size: 24, weight: .bold))
                
                HStack(spacing: 6) {
                    Circle()
                        .fill(monitor.isConnected ? Color.green : Color.orange)
                        .frame(width: 8, height: 8)
                    
                    if monitor.isConnected {
                        Text("Подключено к sing-box Clash API (127.0.0.1:9090)")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    } else if let error = monitor.lastError {
                        Text("Ошибка: \(error)")
                            .font(.system(size: 12))
                            .foregroundColor(.red)
                    } else {
                        Text("Ожидание запуска sing-box daemon...")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    }
                }
            }
            
            Spacer()
            
            // Action Buttons
            HStack(spacing: 10) {
                Button(action: {
                    if monitor.isMonitoring {
                        monitor.stopMonitoring()
                    } else {
                        monitor.startMonitoring()
                    }
                }) {
                    Label(monitor.isMonitoring ? "Пауза" : "Возобновить", systemImage: monitor.isMonitoring ? "pause.fill" : "play.fill")
                        .font(.system(size: 12, weight: .medium))
                }
                .buttonStyle(.bordered)
                
                Button(role: .destructive, action: {
                    showCloseAllAlert = true
                }) {
                    Label("Разорвать все", systemImage: "xmark.circle")
                        .font(.system(size: 12, weight: .medium))
                }
                .buttonStyle(.bordered)
                .disabled(monitor.connections.isEmpty)
            }
        }
    }
    
    // MARK: - Metrics Grid
    private var metricsGrid: some View {
        LazyVGrid(columns: [
            GridItem(.flexible(), spacing: 14),
            GridItem(.flexible(), spacing: 14),
            GridItem(.flexible(), spacing: 14)
        ], spacing: 14) {
            // Download Rate
            GlassCard {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.system(size: 18))
                            .foregroundColor(.cyan)
                        Text("Загрузка")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    
                    Text(ByteFormatter.formatSpeed(monitor.downloadSpeed))
                        .font(.system(size: 22, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)
                    
                    Text("Всего: \(ByteFormatter.format(monitor.downloadTotal))")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            
            // Upload Rate
            GlassCard {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 18))
                            .foregroundColor(.indigo)
                        Text("Отдача")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    
                    Text(ByteFormatter.formatSpeed(monitor.uploadSpeed))
                        .font(.system(size: 22, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)
                    
                    Text("Всего: \(ByteFormatter.format(monitor.uploadTotal))")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            
            // Active Connections Count
            GlassCard {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "network")
                            .font(.system(size: 18))
                            .foregroundColor(.blue)
                        Text("Соединения")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    
                    Text("\(monitor.connections.count)")
                        .font(.system(size: 22, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)
                    
                    Text("Отфильтровано: \(filteredConnections.count)")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
    
    // MARK: - Filter Bar
    private var filterBar: some View {
        HStack(spacing: 12) {
            // Search
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Поиск по процессу, домену или IP...", text: $searchText)
                    .textFieldStyle(.plain)
                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.primary.opacity(0.1), lineWidth: 1)
            )
            
            // Segmented Picker
            Picker("", selection: $selectedFilter) {
                ForEach(FilterRoute.allCases) { filter in
                    Text(filter.rawValue).tag(filter)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 260)

            Toggle(isOn: $groupByProcessAndHost) {
                Label("Группировать", systemImage: "square.stack.3d.up")
                    .font(.system(size: 11, weight: .medium))
            }
            .toggleStyle(.button)
            .help("Группировать повторяющиеся потоки по приложению и домену")
        }
    }
    
    // MARK: - Connections Section
    private var connectionsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(groupByProcessAndHost
                     ? "Группы соединений (\(groupedEntries.count) из \(filteredConnections.count) потоков)"
                     : "Активные сессии (\(filteredConnections.count))")
                    .font(.headline)
                    .foregroundColor(.secondary)
                if isHoveringList {
                    Text("• Пауза обновления (наведение)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.orange)
                }
                Spacer()
                Text("Правый клик или кнопки VPN/Direct — правило в 1 клик")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }

            if filteredConnections.isEmpty {
                emptyStateView
            } else {
                LazyVStack(spacing: 8) {
                    if groupByProcessAndHost {
                        ForEach(groupedEntries) { entry in
                            groupedConnectionRow(entry)
                        }
                    } else {
                        ForEach(filteredConnections) { conn in
                            connectionRow(conn)
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
    
    // MARK: - Connection Rows & 1-Click Rules
    private func groupedConnectionRow(_ entry: GroupedTrafficEntry) -> some View {
        let hasDomain = VPNGuardViewModel.isValidDomainHost(entry.destinationHost)
        let hasPath = !(entry.processPath ?? "").isEmpty

        return GlassCard(padding: 12) {
            HStack(spacing: 12) {
                HStack(spacing: 10) {
                    Image(systemName: entry.isProxy ? "shield.fill" : "globe")
                        .font(.system(size: 16))
                        .foregroundColor(entry.isProxy ? .indigo : .green)
                        .frame(width: 24)

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(entry.processName)
                                .font(.system(size: 13, weight: .semibold))
                                .lineLimit(1)
                            if entry.connectionCount > 1 {
                                Text("×\(entry.connectionCount)")
                                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(Color.primary.opacity(0.08), in: Capsule())
                            }
                        }

                        if let path = entry.processPath, !path.isEmpty {
                            Text(VPNGuardViewModel.canonicalProcessTarget(from: path).path)
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
                .frame(width: 190, alignment: .leading)

                Divider().frame(height: 28)

                VStack(alignment: .leading, spacing: 2) {
                    Text(entry.destinationHost)
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if let ip = entry.destinationIp, ip != entry.destinationHost {
                        Text(ip)
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                HStack(spacing: 4) {
                    Circle()
                        .fill(entry.isProxy ? Color.indigo : Color.green)
                        .frame(width: 6, height: 6)
                    Text(entry.outboundTag)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(entry.isProxy ? .indigo : .green)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background((entry.isProxy ? Color.indigo : Color.green).opacity(0.1))
                .cornerRadius(6)
                .frame(width: 115, alignment: .center)

                VStack(alignment: .trailing, spacing: 2) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.down")
                            .font(.system(size: 9))
                            .foregroundColor(.cyan)
                        Text(ByteFormatter.format(entry.totalDownload))
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                    }
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.up")
                            .font(.system(size: 9))
                            .foregroundColor(.indigo)
                        Text(ByteFormatter.format(entry.totalUpload))
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                    }
                }
                .frame(width: 85, alignment: .trailing)

                oneClickRouteButtons(
                    host: entry.destinationHost,
                    processPath: entry.processPath,
                    isProxy: entry.isProxy,
                    hasDomain: hasDomain,
                    hasPath: hasPath
                )

                Button {
                    Task {
                        for id in entry.connectionIds {
                            _ = await monitor.closeConnection(id: id)
                        }
                    }
                } label: {
                    Image(systemName: "xmark.circle")
                        .font(.system(size: 14))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help("Разорвать все соединения этой группы")
            }
        }
        .contextMenu {
            ruleContextMenuItems(host: entry.destinationHost, processPath: entry.processPath)
            Divider()
            Button("Разорвать соединения (\(entry.connectionCount))", role: .destructive) {
                Task {
                    for id in entry.connectionIds {
                        _ = await monitor.closeConnection(id: id)
                    }
                }
            }
        }
    }

    private func connectionRow(_ conn: ClashConnection) -> some View {
        let hasDomain = VPNGuardViewModel.isValidDomainHost(conn.destinationHost)
        let hasPath = !(conn.metadata.processPath ?? "").isEmpty

        return GlassCard(padding: 12) {
            HStack(spacing: 12) {
                // Process Icon & Name
                HStack(spacing: 10) {
                    Image(systemName: conn.isProxy ? "shield.fill" : "globe")
                        .font(.system(size: 16))
                        .foregroundColor(conn.isProxy ? .indigo : .green)
                        .frame(width: 24)
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text(conn.processName)
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                        
                        if let path = conn.metadata.processPath, !path.isEmpty {
                            Text(path)
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
                .frame(width: 170, alignment: .leading)
                
                Divider()
                    .frame(height: 28)
                
                // Destination Host / Port
                VStack(alignment: .leading, spacing: 2) {
                    Text(conn.destinationDisplay)
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    
                    HStack(spacing: 4) {
                        Text(conn.metadata.network?.uppercased() ?? "TCP")
                            .font(.system(size: 9, weight: .bold))
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(Color.secondary.opacity(0.15))
                            .cornerRadius(3)
                        
                        if let ip = conn.metadata.destinationIP, ip != conn.metadata.host {
                            Text(ip)
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                
                // Route / Outbound Badge
                HStack(spacing: 4) {
                    Circle()
                        .fill(conn.isProxy ? Color.indigo : Color.green)
                        .frame(width: 6, height: 6)
                    Text(conn.outboundTag)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(conn.isProxy ? .indigo : .green)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background((conn.isProxy ? Color.indigo : Color.green).opacity(0.1))
                .cornerRadius(6)
                .frame(width: 115, alignment: .center)
                
                // Data Transfer
                VStack(alignment: .trailing, spacing: 2) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.down")
                            .font(.system(size: 9))
                            .foregroundColor(.cyan)
                        Text(conn.formattedDownload)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                    }
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.up")
                            .font(.system(size: 9))
                            .foregroundColor(.indigo)
                        Text(conn.formattedUpload)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                    }
                }
                .frame(width: 85, alignment: .trailing)

                oneClickRouteButtons(
                    host: conn.destinationHost,
                    processPath: conn.metadata.processPath,
                    isProxy: conn.isProxy,
                    hasDomain: hasDomain,
                    hasPath: hasPath
                )

                // Duration
                Text(conn.formattedDuration)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .frame(width: 48, alignment: .trailing)
                
                // Close Connection Button
                Button(action: {
                    connectionToClose = conn
                }) {
                    Image(systemName: "xmark.circle")
                        .font(.system(size: 14))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help("Разорвать это соединение")
            }
        }
        .contextMenu {
            ruleContextMenuItems(host: conn.destinationHost, processPath: conn.metadata.processPath)
            Divider()
            Button("Разорвать соединение", role: .destructive) {
                connectionToClose = conn
            }
        }
    }

    @ViewBuilder
    private func oneClickRouteButtons(host: String, processPath: String?, isProxy: Bool, hasDomain: Bool, hasPath: Bool) -> some View {
        if hasDomain || hasPath {
            HStack(spacing: 4) {
                Button {
                    Task {
                        if hasDomain {
                            await vm.upsertDomainRule(domain: host, action: .direct, applyImmediately: true)
                        } else if let p = processPath {
                            await vm.upsertAppRule(processPath: p, action: .direct, applyImmediately: true)
                        }
                    }
                } label: {
                    Text("Direct")
                        .font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(Color.green.opacity(isProxy ? 0.14 : 0.25), in: RoundedRectangle(cornerRadius: 5))
                        .foregroundColor(.green)
                }
                .buttonStyle(.plain)
                .disabled(vm.isApplyingRules)
                .help(hasDomain ? "Направить домен \(host) напрямую (РФ / Direct)" : "Направить процесс напрямую")

                Button {
                    Task {
                        if hasDomain {
                            await vm.upsertDomainRule(domain: host, action: .proxy, applyImmediately: true)
                        } else if let p = processPath {
                            await vm.upsertAppRule(processPath: p, action: .proxy, applyImmediately: true)
                        }
                    }
                } label: {
                    Text("VPN")
                        .font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(Color.indigo.opacity(isProxy ? 0.25 : 0.14), in: RoundedRectangle(cornerRadius: 5))
                        .foregroundColor(.indigo)
                }
                .buttonStyle(.plain)
                .disabled(vm.isApplyingRules)
                .help(hasDomain ? "Направить домен \(host) через VPN" : "Направить процесс через VPN")
            }
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
                vm.showToast("Хост скопирован в буфер", isError: false)
            }
        }
    }
    
    // MARK: - Empty State
    private var emptyStateView: some View {
        GlassCard(padding: 40) {
            VStack(spacing: 12) {
                Image(systemName: "network.slash")
                    .font(.system(size: 36))
                    .foregroundColor(.secondary.opacity(0.6))
                
                Text(searchText.isEmpty ? "Нет активных соединений" : "Ничего не найдено")
                    .font(.system(size: 15, weight: .semibold))
                
                Text(searchText.isEmpty ?
                     "Все сетевые сессии завершены или sing-box находится в режиме ожидания." :
                     "Попробуйте изменить поисковый запрос или фильтр маршрутизации.")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
        }
    }
}
