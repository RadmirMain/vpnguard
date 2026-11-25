import SwiftUI

public struct ServerConfigView: View {
    @ObservedObject var vm: VPNGuardViewModel
    
    // Quick VLESS Import state
    @State private var vlessInput: String = ""
    @State private var isImporting: Bool = false
    
    // Raw JSON state
    @State private var isRawJsonExpanded: Bool = false
    @State private var serverJsonText: String = ""
    @State private var showingRawJsonConfirmation: Bool = false
    
    // Server Deletion state
    @State private var serverToDelete: ServerProfile? = nil
    @State private var showingDeleteConfirmation: Bool = false

    private var parsedPreview: Result<VlessParsedPreview, VlessParseError>? {
        let trimmed = vlessInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        return VlessPreviewParser.parse(uri: trimmed)
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                // MARK: - Header
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Управление Upstream Серверами")
                            .font(.title2.bold())
                        Text("Быстрое переключение между релеем и личным VPS (VLESS Reality / TLS)")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()

                    Button {
                        Task {
                            await vm.pingAllServers()
                        }
                    } label: {
                        HStack(spacing: 4) {
                            if vm.isPingingServers {
                                ProgressView()
                                    .scaleEffect(0.6)
                            } else {
                                Image(systemName: "speedometer")
                            }
                            Text("Пинг серверов")
                        }
                        .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isPingingServers || vm.servers.isEmpty)

                    if !vm.serverLatencies.isEmpty {
                        Button {
                            vm.sortServersByPing()
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.up.arrow.down")
                                Text("По скорости")
                            }
                            .font(.system(size: 12, weight: .medium))
                        }
                        .buttonStyle(.bordered)
                    }
                    
                    Button {
                        Task {
                            await vm.loadServers()
                            await vm.refreshStatus(fast: false)
                        }
                    } label: {
                        HStack(spacing: 4) {
                            if vm.isLoadingServers {
                                ProgressView()
                                    .scaleEffect(0.6)
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                            Text("Обновить")
                        }
                        .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isLoadingServers)
                }

                // MARK: - Failover & Tunnel Health Banner
                autoFailoverSection
                
                // MARK: - Section 1: Quick VLESS / JSON Import
                quickImportSection
                
                // MARK: - Section 2: Active Server Switcher
                activeServerSwitcherSection
                
                // MARK: - Section 3: Saved Server Profiles
                savedServersSection
                
                // MARK: - Section 4: Advanced Mode (Raw JSON)
                advancedRawJsonSection
            }
            .padding(24)
        }
        .confirmationDialog(
            "Удалить профиль сервера?",
            isPresented: $showingDeleteConfirmation,
            presenting: serverToDelete
        ) { server in
            Button("Удалить «\(server.name)»", role: .destructive) {
                Task {
                    await vm.deleteServer(id: server.id)
                }
            }
            Button("Отмена", role: .cancel) {}
        } message: { server in
            Text("Вы уверены, что хотите удалить сервер «\(server.name)» (\(server.host):\(server.port))?")
        }
        .confirmationDialog(
            "Применить новую конфигурацию сервера?",
            isPresented: $showingRawJsonConfirmation,
            titleVisibility: .visible
        ) {
            Button("Проверить и обновить", role: .none) {
                Task {
                    let success = await vm.updateServerConfig(jsonText: serverJsonText)
                    if success {
                        serverJsonText = ""
                    }
                }
            }
            Button("Отмена", role: .cancel) {}
        } message: {
            Text("Конфиг будет протестирован через Xray test. В случае успеха демоны Xray и sing-box будут безопасно перезапущены.")
        }
    }
    
    // MARK: - Auto-Failover & Ping Helpers
    private var autoFailoverSection: some View {
        GlassCard(padding: 14) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill((vm.tunnelHealthOk == false ? Color.red : Color.green).opacity(0.14))
                        .frame(width: 34, height: 34)
                    Image(systemName: vm.isRunningFailover ? "arrow.triangle.2.circlepath" : "waveform.path.ecg")
                        .font(.system(size: 15))
                        .foregroundColor(vm.tunnelHealthOk == false ? .red : .green)
                }

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text("Автопереключение при обрыве (Auto-Failover)")
                            .font(.system(size: 13, weight: .bold))

                        if let ok = vm.tunnelHealthOk {
                            let label = ok ? "Туннель ОК · \(vm.tunnelLatencyMs ?? 0) мс" : "Туннель не отвечает"
                            ServerBadgeCapsule(text: label, color: ok ? .green : .red)
                        }
                    }

                    if let cooldown = vm.failoverCooldownUntil, cooldown.timeIntervalSinceNow > 0 {
                        let secs = Int(ceil(cooldown.timeIntervalSinceNow))
                        Text("Пауза цикла failover (\(secs)с). PF Kill-Switch остаётся активным.")
                            .font(.system(size: 11))
                            .foregroundColor(.orange)
                    } else {
                        Text("При 3 сбоях подряд: ре-синк PF egress, затем выбор самого быстрого доступного сервера (GID 890 пинг)")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()

                Toggle("", isOn: $vm.autoFailoverEnabled)
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .disabled(vm.servers.count < 2)
                    .help(vm.servers.count < 2 ? "Добавьте минимум 2 сервера для автопереключения" : "Включить автопереключение при обрыве")
            }
        }
    }

    @ViewBuilder
    private func latencyBadge(for ping: ServerPingResult) -> some View {
        if ping.reachable, let ms = ping.latencyMs {
            let color: Color = ms < 120 ? .green : (ms < 250 ? .orange : .red)
            ServerBadgeCapsule(text: "\(ms) мс", color: color)
        } else {
            ServerBadgeCapsule(text: "Недоступен", color: .red)
        }
    }

    // MARK: - Quick Import View
    private var quickImportSection: some View {
        GlassCard(padding: 18) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.blue.opacity(0.15))
                            .frame(width: 32, height: 32)
                        Image(systemName: "link.badge.plus")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(.blue)
                    }
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Быстрый импорт VLESS ссылки")
                            .font(.system(size: 14, weight: .bold))
                        Text("Поддерживаются Reality, TLS поверх TCP, xhttp, WS, gRPC")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                }
                
                // Input row
                HStack(spacing: 8) {
                    TextField("vless://<uuid>@<host>:<port>?security=reality...", text: $vlessInput)
                        .font(.system(size: 12, design: .monospaced))
                        .textFieldStyle(.plain)
                        .padding(8)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color.primary.opacity(0.15), lineWidth: 1)
                        )
                    
                    Button {
                        if let clip = NSPasteboard.general.string(forType: .string) {
                            vlessInput = clip.trimmingCharacters(in: .whitespacesAndNewlines)
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "doc.on.clipboard")
                            Text("Вставить")
                        }
                        .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                }
                
                // Live Preview Card
                if let preview = parsedPreview {
                    switch preview {
                    case .success(let parsed):
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text(parsed.name)
                                    .font(.system(size: 13, weight: .bold))
                                Spacer()
                                Text("\(parsed.host):\(parsed.port)")
                                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                            
                            HStack(spacing: 6) {
                                ServerBadgeCapsule(text: "VLESS", color: .indigo)
                                ServerBadgeCapsule(text: parsed.transport.uppercased(), color: .cyan)
                                ServerBadgeCapsule(text: parsed.security.capitalized, color: .purple)
                                if !parsed.flow.isEmpty {
                                    ServerBadgeCapsule(text: parsed.flow, color: .blue)
                                }
                                if !parsed.sni.isEmpty {
                                    ServerBadgeCapsule(text: "SNI: \(parsed.sni)", color: .gray)
                                }
                            }
                        }
                        .padding(12)
                        .background(Color.green.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color.green.opacity(0.25), lineWidth: 1)
                        )
                        
                    case .failure(let error):
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text(error.localizedDescription)
                                .font(.system(size: 12))
                                .foregroundColor(.secondary)
                            Spacer()
                        }
                        .padding(10)
                        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color.orange.opacity(0.2), lineWidth: 1)
                        )
                    }
                }
                
                // Action Buttons
                HStack {
                    Button("Очистить") {
                        vlessInput = ""
                    }
                    .buttonStyle(.plain)
                    .foregroundColor(.secondary)
                    .font(.system(size: 12))
                    .disabled(vlessInput.isEmpty)
                    
                    Spacer()
                    
                    Button {
                        importVlessAction(activateImmediately: false)
                    } label: {
                        Text("Добавить")
                            .font(.system(size: 12, weight: .semibold))
                            .padding(.horizontal, 14)
                            .padding(.vertical, 6)
                    }
                    .buttonStyle(.bordered)
                    .disabled(!isValidVless || isImporting)
                    
                    Button {
                        importVlessAction(activateImmediately: true)
                    } label: {
                        HStack(spacing: 5) {
                            if isImporting {
                                ProgressView()
                                    .scaleEffect(0.6)
                            }
                            Image(systemName: "bolt.fill")
                            Text("Добавить и подключить")
                        }
                        .font(.system(size: 12, weight: .semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                        .background(Color.blue.gradient, in: RoundedRectangle(cornerRadius: 6))
                        .foregroundColor(.white)
                    }
                    .buttonStyle(.plain)
                    .disabled(!isValidVless || isImporting)
                }
            }
        }
    }
    
    private var isValidVless: Bool {
        if case .success = parsedPreview {
            return true
        }
        return false
    }
    
    private func importVlessAction(activateImmediately: Bool) {
        guard !vlessInput.isEmpty else { return }
        isImporting = true
        let uri = vlessInput
        Task {
            let success = await vm.importVless(uri: uri, activateImmediately: activateImmediately)
            if success {
                vlessInput = ""
            }
            isImporting = false
        }
    }

    // MARK: - Active Server Switcher Section
    private var activeServerSwitcherSection: some View {
        GlassCard(padding: 18) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.green.opacity(0.15))
                            .frame(width: 32, height: 32)
                        Image(systemName: "arrow.triangle.swap")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(.green)
                    }
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Переключатель активного сервера")
                            .font(.system(size: 14, weight: .bold))
                        Text("Атомарное переключение PF Kill-Switch (GID 889) и Xray без утечки трафика")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                }
                
                if vm.servers.isEmpty {
                    Text("Нет доступных серверов для переключения")
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                } else {
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                        ForEach(vm.servers) { server in
                            serverSwitcherCard(server: server)
                        }
                    }
                }
            }
        }
    }
    
    private func serverSwitcherCard(server: ServerProfile) -> some View {
        Button {
            if !server.isActive && vm.activatingServerId == nil {
                Task {
                    await vm.activateServer(id: server.id)
                }
            }
        } label: {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(server.isActive ? Color.green.opacity(0.2) : Color.primary.opacity(0.06))
                        .frame(width: 36, height: 36)
                    
                    if vm.activatingServerId == server.id {
                        ProgressView()
                            .scaleEffect(0.7)
                    } else if server.isActive {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                            .font(.system(size: 18))
                    } else {
                        Image(systemName: "circle")
                            .foregroundColor(.secondary)
                            .font(.system(size: 18))
                    }
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 4) {
                        if let flag = serverFlag(for: server) {
                            Text(flag)
                        }
                        Text(server.name)
                            .font(.system(size: 13, weight: .bold))
                            .lineLimit(1)
                    }
                    Text("Входной релей: \(server.host):\(server.port) • \(server.transport.uppercased())")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                
                Spacer()

                if let ping = vm.serverLatencies[server.id] {
                    latencyBadge(for: ping)
                }
                
                if server.isActive {
                    Text("АКТИВЕН")
                        .font(.system(size: 10, weight: .bold))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(Color.green.opacity(0.15), in: Capsule())
                        .foregroundColor(.green)
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(server.isActive ? Color.green.opacity(0.08) : Color.primary.opacity(0.03))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(server.isActive ? Color.green.opacity(0.4) : Color.primary.opacity(0.1), lineWidth: server.isActive ? 1.5 : 1)
            )
        }
        .buttonStyle(.plain)
        .disabled(server.isActive || vm.activatingServerId != nil)
    }
    
    private func startsWithFlagEmoji(_ text: String) -> Bool {
        guard let firstScalar = text.unicodeScalars.first else { return false }
        return (0x1F1E6...0x1F1FF).contains(firstScalar.value) || firstScalar.value == 0x1F310
    }

    private func serverFlag(for server: ServerProfile) -> String? {
        if startsWithFlagEmoji(server.name) {
            return nil
        }
        let text = server.name.lowercased()
        if text.contains("индия") || text.contains("india") {
            return "🇮🇳"
        }
        if text.contains("россия") || text.contains("russia") {
            return "🇷🇺"
        }
        if text.contains("германия") || text.contains("germany") {
            return "🇩🇪"
        }
        if text.contains("сша") || text.contains("usa") || text.contains("united states") {
            return "🇺🇸"
        }
        return "🌐"
    }

    // MARK: - Saved Servers Section
    private var savedServersSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Сохранённые серверы (\(vm.servers.count))")
                    .font(.headline)
                
                Spacer()
                
                if let active = vm.servers.first(where: { $0.isActive }) {
                    HStack(spacing: 5) {
                        Circle()
                            .fill(Color.green)
                            .frame(width: 7, height: 7)
                        Text("Активен: \(active.name)")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                    }
                }
            }
            
            if vm.servers.isEmpty {
                GlassCard(padding: 20) {
                    VStack(spacing: 8) {
                        Image(systemName: "server.rack")
                            .font(.system(size: 28))
                            .foregroundColor(.secondary)
                        Text("Нет сохранённых профилей серверов")
                            .font(.system(size: 13, weight: .medium))
                        Text("Вставьте vless:// ссылку выше, чтобы добавить профиль")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                }
            } else {
                ForEach(vm.servers) { server in
                    serverRowCard(server: server)
                }
            }
        }
    }
    
    private func serverRowCard(server: ServerProfile) -> some View {
        GlassCard(padding: 16) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .center) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 7)
                            .fill(server.isActive ? Color.green.opacity(0.15) : Color.indigo.opacity(0.12))
                            .frame(width: 32, height: 32)
                        Image(systemName: server.isActive ? "checkmark.shield.fill" : "server.rack")
                            .font(.system(size: 15))
                            .foregroundColor(server.isActive ? .green : .indigo)
                    }
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text(server.name)
                            .font(.system(size: 13, weight: .bold))
                        Text("\(server.host):\(server.port)")
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                    
                    if server.isActive {
                        HStack(spacing: 5) {
                            Circle()
                                .fill(Color.green)
                                .frame(width: 8, height: 8)
                            Text("Активен")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.green)
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.green.opacity(0.12), in: Capsule())
                    } else {
                        HStack(spacing: 8) {
                            Button {
                                Task {
                                    await vm.activateServer(id: server.id)
                                }
                            } label: {
                                HStack(spacing: 5) {
                                    if vm.activatingServerId == server.id {
                                        ProgressView()
                                            .scaleEffect(0.6)
                                    } else {
                                        Image(systemName: "bolt.fill")
                                    }
                                    Text("Подключить")
                                }
                                .font(.system(size: 11, weight: .semibold))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(Color.blue.gradient, in: RoundedRectangle(cornerRadius: 6))
                                .foregroundColor(.white)
                            }
                            .buttonStyle(.plain)
                            .disabled(vm.activatingServerId != nil)
                            
                            Button {
                                serverToDelete = server
                                showingDeleteConfirmation = true
                            } label: {
                                Image(systemName: "trash")
                                    .font(.system(size: 12))
                                    .foregroundColor(.red.opacity(0.8))
                                    .padding(6)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                
                Divider().opacity(0.4)
                
                HStack(spacing: 6) {
                    ServerBadgeCapsule(text: "VLESS", color: .indigo)
                    ServerBadgeCapsule(text: server.transport.uppercased(), color: .cyan)
                    ServerBadgeCapsule(text: server.security.capitalized, color: .purple)
                    
                    if let flow = server.flow, !flow.isEmpty {
                        ServerBadgeCapsule(text: flow, color: .blue)
                    }
                    if let sni = server.sni, !sni.isEmpty {
                        ServerBadgeCapsule(text: "SNI: \(sni)", color: .gray)
                    }
                    if let ping = vm.serverLatencies[server.id] {
                        latencyBadge(for: ping)
                    }
                    
                    Spacer()
                }
            }
        }
    }

    // MARK: - Advanced Raw JSON Mode
    private var advancedRawJsonSection: some View {
        GlassCard(padding: 16) {
            DisclosureGroup(isExpanded: $isRawJsonExpanded) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Вставьте сырой JSON-конфиг Xray-core. Прямые маршруты (freedom/direct) будут автоматически удалены, а IP обновлен в таблице PF.")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .padding(.top, 4)
                    
                    TextEditor(text: $serverJsonText)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(minHeight: 140)
                        .padding(8)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 6))
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(Color.primary.opacity(0.12), lineWidth: 1)
                        )
                    
                    HStack {
                        Button("Очистить") {
                            serverJsonText = ""
                        }
                        .buttonStyle(.bordered)
                        .disabled(serverJsonText.isEmpty)
                        
                        Spacer()
                        
                        Button {
                            showingRawJsonConfirmation = true
                        } label: {
                            HStack(spacing: 6) {
                                if vm.isUpdatingServer {
                                    ProgressView()
                                        .scaleEffect(0.6)
                                }
                                Image(systemName: "arrow.triangle.2.circlepath")
                                Text("Проверить и применить")
                            }
                            .font(.system(size: 12, weight: .semibold))
                            .padding(.horizontal, 14)
                            .padding(.vertical, 6)
                            .background(Color.blue.gradient, in: RoundedRectangle(cornerRadius: 6))
                            .foregroundColor(.white)
                        }
                        .buttonStyle(.plain)
                        .disabled(serverJsonText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || vm.isUpdatingServer)
                    }
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "curlybraces")
                        .foregroundColor(.secondary)
                    Text("Расширенный режим (JSON)")
                        .font(.system(size: 13, weight: .medium))
                    Spacer()
                }
            }
        }
    }
}

// MARK: - Badge Capsule Helper
private struct ServerBadgeCapsule: View {
    let text: String
    let color: Color
    
    var body: some View {
        Text(text)
            .font(.system(size: 10, weight: .bold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundColor(color)
            .overlay(
                Capsule().stroke(color.opacity(0.3), lineWidth: 0.5)
            )
    }
}
