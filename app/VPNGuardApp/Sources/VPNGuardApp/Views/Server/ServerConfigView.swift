import SwiftUI
import AppKit

public struct ServerConfigView: View {
    @ObservedObject var vm: VPNGuardViewModel

    @State private var showingAddSheet: Bool = false
    @State private var serverToDelete: ServerProfile? = nil
    @State private var showingDeleteConfirmation: Bool = false

    public var body: some View {
        VStack(spacing: 0) {
            VGPageHeader(
                title: "Серверы",
                subtitle: "Профили Upstream-серверов (VLESS, Reality, TLS, XHTTP) и Auto-Failover"
            ) {
                HStack(spacing: 8) {
                    Button {
                        Task { await vm.pingAllServers() }
                    } label: {
                        HStack(spacing: 5) {
                            if vm.isPingingServers {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: "speedometer")
                            }
                            Text("Пинг")
                        }
                        .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isPingingServers || vm.servers.isEmpty)
                    .help("Измерить задержку до всех серверов через GID 890")

                    Button {
                        Task {
                            await vm.loadServers()
                            await vm.refreshStatus(fast: false)
                        }
                    } label: {
                        HStack(spacing: 5) {
                            if vm.isLoadingServers {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                            Text("Обновить")
                        }
                        .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isLoadingServers)

                    Button {
                        showingAddSheet = true
                    } label: {
                        Label("Добавить сервер", systemImage: "plus")
                            .font(.system(size: 12, weight: .semibold))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(VGTheme.accentPrimary, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                            .foregroundStyle(.white)
                    }
                    .buttonStyle(.plain)
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: VGTheme.sectionSpacing) {
                    // Auto-Failover Compact Card
                    autoFailoverSection

                    // Unified Server Profiles List
                    if vm.servers.isEmpty {
                        VGCard(padding: 20) {
                            VGEmptyStateView(
                                icon: "server.rack",
                                title: "Нет сохранённых серверов",
                                message: "Добавьте профиль по ссылке vless:// или через JSON-конфигурацию Xray.",
                                actionTitle: "Добавить сервер"
                            ) {
                                showingAddSheet = true
                            }
                        }
                    } else {
                        VStack(alignment: .leading, spacing: 12) {
                            VGSectionHeader("Серверы (\(vm.servers.count))") {
                                if let active = vm.servers.first(where: { $0.isActive }) {
                                    VGStatusBadge("Активен: \(active.name)", tone: .protected, showDot: true)
                                }
                            }

                            LazyVStack(spacing: 10) {
                                ForEach(vm.servers) { server in
                                    serverCard(server: server)
                                }
                            }
                        }
                    }
                }
                .padding(VGTheme.pagePadding)
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            AddServerSheet(vm: vm)
        }
        .confirmationDialog(
            "Удалить профиль сервера?",
            isPresented: $showingDeleteConfirmation,
            presenting: serverToDelete
        ) { server in
            Button("Удалить «\(server.name)»", role: .destructive) {
                Task { await vm.deleteServer(id: server.id) }
            }
            Button("Отмена", role: .cancel) {}
        } message: { server in
            Text("Вы уверены, что хотите удалить сервер «\(server.name)» (\(server.host):\(server.port))?")
        }
    }

    // MARK: - Auto-Failover Section
    private var autoFailoverSection: some View {
        let isFailed = vm.tunnelHealthOk == false
        return VGCard(padding: 14) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                        .fill((isFailed ? VGTheme.statusDanger : VGTheme.statusProtected).opacity(0.14))
                        .frame(width: 34, height: 34)
                    Image(systemName: vm.isRunningFailover ? "arrow.triangle.2.circlepath" : "waveform.path.ecg")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(isFailed ? VGTheme.statusDanger : VGTheme.statusProtected)
                }

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text("Автопереключение при обрыве (Auto-Failover)")
                            .font(.system(size: 13, weight: .semibold))

                        if let ok = vm.tunnelHealthOk {
                            VGStatusBadge(
                                ok ? "Туннель ОК · \(vm.tunnelLatencyMs ?? 0) мс" : "Туннель не отвечает",
                                tone: ok ? .protected : .danger,
                                showDot: true
                            )
                        }
                    }

                    if let cooldown = vm.failoverCooldownUntil, cooldown.timeIntervalSinceNow > 0 {
                        let secs = Int(ceil(cooldown.timeIntervalSinceNow))
                        Text("Пауза цикла failover (\(secs)с). PF Kill-Switch остаётся активным.")
                            .font(.system(size: 11))
                            .monospacedDigit()
                            .foregroundStyle(VGTheme.statusWarning)
                    } else {
                        Text("При 3 сбоях подряд: ре-синк PF, затем выбор самого быстрого доступного сервера")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()

                Toggle("", isOn: $vm.autoFailoverEnabled)
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .labelsHidden()
                    .disabled(vm.servers.count < 2)
                    .help(vm.servers.count < 2 ? "Добавьте минимум 2 сервера для автопереключения" : "Включить автопереключение при обрыве")
            }
        }
    }

    // MARK: - Unified Server Card
    private func serverCard(server: ServerProfile) -> some View {
        VGCard(
            padding: 16,
            accentBorder: server.isActive ? VGTheme.statusProtected.opacity(0.4) : nil
        ) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .center, spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                            .fill((server.isActive ? VGTheme.statusProtected : VGTheme.accentPrimary).opacity(0.14))
                            .frame(width: 36, height: 36)
                        if let flag = serverFlag(for: server) {
                            Text(flag)
                                .font(.system(size: 18))
                        } else {
                            Image(systemName: server.isActive ? "checkmark.shield.fill" : "server.rack")
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(server.isActive ? VGTheme.statusProtected : VGTheme.accentPrimary)
                        }
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text(server.name)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(.primary)
                            .lineLimit(1)

                        Text("\(server.host):\(server.port)")
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }

                    Spacer(minLength: 12)

                    if let ping = vm.serverLatencies[server.id] {
                        latencyBadge(for: ping)
                    }

                    if server.isActive {
                        VGStatusBadge("Активен", tone: .protected, showDot: true)
                    } else {
                        HStack(spacing: 8) {
                            Button {
                                Task { await vm.activateServer(id: server.id) }
                            } label: {
                                HStack(spacing: 5) {
                                    if vm.activatingServerId == server.id {
                                        ProgressView().controlSize(.mini)
                                    } else {
                                        Image(systemName: "bolt.fill")
                                            .font(.system(size: 10))
                                    }
                                    Text("Подключить")
                                }
                                .font(.system(size: 12, weight: .semibold))
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(VGTheme.accentPrimary, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                                .foregroundStyle(.white)
                            }
                            .buttonStyle(.plain)
                            .disabled(vm.activatingServerId != nil)

                            Button {
                                serverToDelete = server
                                showingDeleteConfirmation = true
                            } label: {
                                Image(systemName: "trash")
                                    .font(.system(size: 12))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 28, height: 28)
                                    .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                            }
                            .buttonStyle(.plain)
                            .help("Удалить профиль сервера")
                        }
                    }
                }

                Divider().opacity(0.45)

                HStack(spacing: 6) {
                    VGStatusBadge("VLESS", tone: .neutral)
                    VGStatusBadge(VGFormatters.formatProtocol(server.transport), tone: .neutral)
                    VGStatusBadge(VGFormatters.formatProtocol(server.security), tone: .neutral)

                    if let flow = server.flow, !flow.isEmpty {
                        VGStatusBadge(VGFormatters.formatProtocol(flow), tone: .neutral)
                    }
                    if let sni = server.sni, !sni.isEmpty {
                        VGStatusBadge("SNI: \(sni)", tone: .neutral)
                    }

                    Spacer()
                }
            }
        }
        .contextMenu {
            if !server.isActive {
                Button {
                    Task { await vm.activateServer(id: server.id) }
                } label: {
                    Label("Подключить", systemImage: "bolt.fill")
                }
            }

            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("\(server.host):\(server.port)", forType: .string)
                vm.showToast("Адрес сервера скопирован", isError: false)
            } label: {
                Label("Копировать адрес", systemImage: "doc.on.doc")
            }

            if !server.isActive {
                Divider()
                Button(role: .destructive) {
                    serverToDelete = server
                    showingDeleteConfirmation = true
                } label: {
                    Label("Удалить профиль", systemImage: "trash")
                }
            }
        }
    }

    @ViewBuilder
    private func latencyBadge(for ping: ServerPingResult) -> some View {
        if ping.reachable, let ms = ping.latencyMs {
            let tone: VGStatusBadge.Tone = ms < 150 ? .protected : (ms < 400 ? .warning : .danger)
            VGStatusBadge("\(ms) мс", tone: tone)
        } else {
            VGStatusBadge("Недоступен", tone: .danger)
        }
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
        if text.contains("индия") || text.contains("india") { return "🇮🇳" }
        if text.contains("россия") || text.contains("russia") { return "🇷🇺" }
        if text.contains("германия") || text.contains("germany") { return "🇩🇪" }
        if text.contains("сша") || text.contains("usa") || text.contains("united states") { return "🇺🇸" }
        return nil
    }
}

// MARK: - Add Server Sheet (VLESS URI + Advanced JSON)
private struct AddServerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var vm: VPNGuardViewModel

    enum ImportMode: String, CaseIterable, Identifiable {
        case vless = "VLESS-ссылка"
        case json = "JSON-конфиг"

        var id: String { rawValue }
    }

    @State private var mode: ImportMode = .vless
    @State private var vlessInput: String = ""
    @State private var isImporting: Bool = false
    @State private var serverJsonText: String = ""
    @State private var showingRawJsonConfirmation: Bool = false

    private var parsedPreview: Result<VlessParsedPreview, VlessParseError>? {
        let trimmed = vlessInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        return VlessPreviewParser.parse(uri: trimmed)
    }

    private var isValidVless: Bool {
        if case .success = parsedPreview { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Добавить сервер")
                        .font(.system(size: 16, weight: .semibold))
                    Text("Импорт профиля VLESS или ручная конфигурация Xray")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Picker("", selection: $mode) {
                    ForEach(ImportMode.allCases) { item in
                        Text(item.rawValue).tag(item)
                    }
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .frame(width: 220)
                .fixedSize()
            }
            .padding(VGTheme.sheetPadding)

            Divider().opacity(0.6)

            Group {
                if mode == .vless {
                    vlessContent
                } else {
                    jsonContent
                }
            }
            .padding(VGTheme.sheetPadding)

            Divider().opacity(0.6)

            HStack {
                Button("Закрыть") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                if mode == .vless {
                    Button("Добавить") {
                        importVlessAction(activateImmediately: false)
                    }
                    .buttonStyle(.bordered)
                    .disabled(!isValidVless || isImporting)

                    Button {
                        importVlessAction(activateImmediately: true)
                    } label: {
                        HStack(spacing: 5) {
                            if isImporting {
                                ProgressView().controlSize(.small)
                            }
                            Text("Добавить и подключить")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!isValidVless || isImporting)
                } else {
                    Button {
                        showingRawJsonConfirmation = true
                    } label: {
                        HStack(spacing: 5) {
                            if vm.isUpdatingServer {
                                ProgressView().controlSize(.small)
                            }
                            Text("Проверить и применить")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(serverJsonText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || vm.isUpdatingServer)
                }
            }
            .padding(VGTheme.sheetPadding)
        }
        .frame(width: 560)
        .background(VGTheme.backgroundContent)
        .confirmationDialog(
            "Применить новую конфигурацию сервера?",
            isPresented: $showingRawJsonConfirmation,
            titleVisibility: .visible
        ) {
            Button("Проверить и обновить") {
                Task {
                    let success = await vm.updateServerConfig(jsonText: serverJsonText)
                    if success {
                        serverJsonText = ""
                        dismiss()
                    }
                }
            }
            Button("Отмена", role: .cancel) {}
        } message: {
            Text("Конфиг будет протестирован через Xray test. В случае успеха демоны Xray и sing-box будут безопасно перезапущены.")
        }
    }

    private var vlessContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                TextField("vless://<uuid>@<host>:<port>?security=reality…", text: $vlessInput)
                    .font(.system(size: 12, design: .monospaced))
                    .textFieldStyle(.plain)
                    .padding(9)
                    .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                            .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                    )

                Button {
                    if let clip = NSPasteboard.general.string(forType: .string) {
                        vlessInput = clip.trimmingCharacters(in: .whitespacesAndNewlines)
                    }
                } label: {
                    Label("Вставить", systemImage: "doc.on.clipboard")
                        .font(.system(size: 12, weight: .medium))
                }
                .buttonStyle(.bordered)
            }

            if let preview = parsedPreview {
                switch preview {
                case .success(let parsed):
                    VGCard(padding: 12, accentBorder: VGTheme.statusProtected.opacity(0.35)) {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(VGTheme.statusProtected)
                                Text(parsed.name)
                                    .font(.system(size: 13, weight: .semibold))
                                Spacer()
                                Text("\(parsed.host):\(parsed.port)")
                                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                                    .monospacedDigit()
                                    .foregroundStyle(.secondary)
                            }

                            HStack(spacing: 6) {
                                VGStatusBadge("VLESS", tone: .neutral)
                                VGStatusBadge(VGFormatters.formatProtocol(parsed.transport), tone: .neutral)
                                VGStatusBadge(VGFormatters.formatProtocol(parsed.security), tone: .neutral)
                                if !parsed.flow.isEmpty {
                                    VGStatusBadge(VGFormatters.formatProtocol(parsed.flow), tone: .neutral)
                                }
                                if !parsed.sni.isEmpty {
                                    VGStatusBadge("SNI: \(parsed.sni)", tone: .neutral)
                                }
                            }
                        }
                    }

                case .failure(let error):
                    VGCard(padding: 12, accentBorder: VGTheme.statusWarning.opacity(0.35)) {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(VGTheme.statusWarning)
                            Text(error.localizedDescription)
                                .font(.system(size: 12))
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                    }
                }
            } else {
                Text("Поддерживаются Reality, TLS поверх TCP, XHTTP, WS и gRPC.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var jsonContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Вставьте JSON-конфиг Xray-core. Прямые маршруты (freedom/direct) будут удалены автоматически.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)

            TextEditor(text: $serverJsonText)
                .font(.system(size: 11, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(8)
                .frame(height: 180)
                .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                        .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                )
        }
    }

    private func importVlessAction(activateImmediately: Bool) {
        guard !vlessInput.isEmpty else { return }
        isImporting = true
        let uri = vlessInput
        Task {
            let success = await vm.importVless(uri: uri, activateImmediately: activateImmediately)
            isImporting = false
            if success {
                dismiss()
            }
        }
    }
}
