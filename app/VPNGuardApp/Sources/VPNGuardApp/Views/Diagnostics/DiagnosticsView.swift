import SwiftUI
import AppKit

public struct DiagnosticsView: View {
    @ObservedObject var vm: VPNGuardViewModel

    enum SubTab: String, CaseIterable, Identifiable {
        case audit = "Аудит утечек"
        case logs = "Системные логи"

        var id: String { rawValue }
    }

    enum LogSource: String, CaseIterable, Identifiable {
        case singbox = "sing-box"
        case xray = "Xray"
        case pf = "PF / Boot"
        case pfRules = "PF Rules"
        case dns = "DNS (scutil)"
        case utun = "utun99"

        var id: String { rawValue }
    }

    @State private var selectedTab: SubTab = .audit
    @State private var selectedSource: LogSource = .singbox
    @State private var autoRefreshEnabled: Bool = false
    @State private var wordWrapEnabled: Bool = true
    @State private var logSearchQuery: String = ""
    @State private var autoRefreshTask: Task<Void, Never>? = nil
    @State private var renderedAttributedLogs: AttributedString = AttributedString()
    @State private var renderTask: Task<Void, Never>? = nil

    public init(vm: VPNGuardViewModel) {
        self.vm = vm
    }

    private var currentRawText: String {
        guard let snap = vm.diagnosticsSnapshot else {
            return "Нажмите «Обновить», чтобы загрузить последние 150 строк логов и состояние PF/DNS/utun99."
        }
        switch selectedSource {
        case .singbox: return snap.logs.singbox
        case .xray: return snap.logs.xray
        case .pf: return snap.logs.pf
        case .pfRules: return snap.system.pfRules
        case .dns: return snap.system.dns
        case .utun: return snap.system.utun
        }
    }

    private var filteredRawText: String {
        let cleaned = VGFormatters.stripANSI(currentRawText)
        let query = logSearchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return cleaned }
        let matched = cleaned
            .components(separatedBy: .newlines)
            .filter { $0.localizedCaseInsensitiveContains(query) }
        return matched.isEmpty ? "(Совпадений по «\(query)» не найдено)" : matched.joined(separator: "\n")
    }

    private var auditTabLabel: String {
        if let report = vm.auditReport {
            return "Аудит утечек (\(report.passedCount)/\(report.total))"
        }
        return "Аудит утечек"
    }

    public var body: some View {
        VStack(spacing: 0) {
            VGPageHeader(
                title: "Диагностика и логи",
                subtitle: "12-точечный аудит утечек и санитизированные логи сервисов"
            ) {
                HStack(spacing: 10) {
                    Picker("", selection: $selectedTab) {
                        Text(auditTabLabel).tag(SubTab.audit)
                        Text(SubTab.logs.rawValue).tag(SubTab.logs)
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    .frame(width: 280)
                    .fixedSize()

                    Button {
                        vm.copyDiagnosticsMarkdownReport()
                    } label: {
                        Label("Отчёт MD", systemImage: "doc.on.doc")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .help("Скопировать сводный диагностический отчёт в Markdown")
                }
            }

            if selectedTab == .audit {
                ScrollView {
                    auditSection
                        .padding(VGTheme.pagePadding)
                }
            } else {
                logsSection
                    .padding(VGTheme.pagePadding)
            }
        }
        .onAppear {
            if vm.diagnosticsSnapshot == nil {
                Task { await vm.loadDiagnosticsLogs(silent: true) }
            }
            scheduleLogRender(debounced: false)
            updateAutoRefreshLoop()
        }
        .onDisappear {
            renderTask?.cancel()
            renderTask = nil
            stopAutoRefreshLoop()
        }
        .onChange(of: autoRefreshEnabled) { _, _ in
            updateAutoRefreshLoop()
        }
        .onChange(of: selectedTab) { _, nextTab in
            updateAutoRefreshLoop()
            if nextTab == .logs {
                scheduleLogRender(debounced: false)
            }
        }
        .onChange(of: selectedSource) { _, _ in
            scheduleLogRender(debounced: false)
        }
        .onChange(of: vm.diagnosticsSnapshot?.generatedAt) { _, _ in
            scheduleLogRender(debounced: false)
        }
        .onChange(of: logSearchQuery) { _, _ in
            scheduleLogRender(debounced: true)
        }
    }

    // MARK: - 12-Point Audit Checklist
    private var auditSection: some View {
        VGCard(padding: 18) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Комплексный аудит утечек (vpnguard test)")
                            .font(.system(size: 14, weight: .semibold))
                        Text("Проверка ядра PF, изоляции GID 888/889/890, mDNS, utun99 и выходного IP")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    if let report = vm.auditReport {
                        VGCopyButton(
                            formatAuditPlain(report),
                            label: "Скопировать отчёт",
                            helpText: "Скопировать результаты аудита"
                        )
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                                .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                        )
                    }

                    Button {
                        Task { await vm.runSecurityAudit() }
                    } label: {
                        HStack(spacing: 6) {
                            if vm.isRunningAudit {
                                ProgressView().controlSize(.small)
                                Text("Выполняется…")
                            } else {
                                Image(systemName: "play.fill")
                                    .font(.system(size: 10))
                                Text("Проверить утечки")
                            }
                        }
                        .font(.system(size: 12, weight: .semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 7)
                        .background(VGTheme.accentPrimary, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                        .foregroundStyle(.white)
                    }
                    .buttonStyle(.plain)
                    .disabled(vm.isRunningAudit)
                }

                if let report = vm.auditReport {
                    Divider().opacity(0.45)

                    HStack(spacing: 8) {
                        Image(systemName: report.passed ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(report.passed ? VGTheme.statusProtected : VGTheme.statusWarning)
                        Text(report.passed
                             ? "Все \(report.total) проверок успешно пройдены: утечек нет"
                             : "Пройдено \(report.passedCount) из \(report.total) проверок")
                            .font(.system(size: 12, weight: .semibold))
                            .monospacedDigit()
                            .foregroundStyle(report.passed ? VGTheme.statusProtected : VGTheme.statusWarning)
                        Spacer()
                    }

                    LazyVStack(spacing: 6) {
                        ForEach(report.tests) { test in
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: test.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .font(.system(size: 13))
                                    .foregroundStyle(test.passed ? VGTheme.statusProtected : VGTheme.statusDanger)
                                    .padding(.top, 1)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(test.name)
                                        .font(.system(size: 12, weight: .semibold))
                                    Text(test.details)
                                        .font(.system(size: 11))
                                        .foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 8)

                                VGStatusBadge(
                                    test.passed ? "PASS" : "FAIL",
                                    tone: test.passed ? .protected : .danger
                                )
                            }
                            .padding(10)
                            .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                        }
                    }
                } else if !vm.isRunningAudit {
                    HStack(spacing: 8) {
                        Image(systemName: "info.circle")
                            .foregroundStyle(.secondary)
                        Text("Нажмите «Проверить утечки», чтобы выполнить 12 активных тестов изоляции.")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(10)
                    .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                }
            }
        }
    }

    // MARK: - Full-Height Logs Viewer
    private var logsSection: some View {
        VGCard(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Системные логи (последние 150 строк)")
                            .font(.system(size: 14, weight: .semibold))
                        if let snap = vm.diagnosticsSnapshot {
                            Text("Обновлено в \(VGFormatters.formatLocalTimeFromISO(snap.generatedAt))")
                                .font(.system(size: 11))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                    }

                    Spacer()

                    Toggle("Перенос строк", isOn: $wordWrapEnabled)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                        .font(.system(size: 11))

                    Toggle("Авто (5с)", isOn: $autoRefreshEnabled)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                        .font(.system(size: 11))

                    Button {
                        Task { await vm.loadDiagnosticsLogs(silent: false) }
                    } label: {
                        HStack(spacing: 5) {
                            if vm.isLoadingDiagnostics {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                            Text("Обновить")
                        }
                        .font(.system(size: 11, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isLoadingDiagnostics)
                }

                HStack(spacing: 10) {
                    Picker("", selection: $selectedSource) {
                        ForEach(LogSource.allCases) { src in
                            Text(src.rawValue).tag(src)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)

                    VGSearchField("Фильтр строк…", text: $logSearchQuery)
                        .frame(width: 200)
                }

                // Clean ANSI-stripped & highlighted log viewer (rendered asynchronously off body)
                Group {
                    if wordWrapEnabled {
                        ScrollView(.vertical) {
                            Text(renderedAttributedLogs)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(12)
                        }
                    } else {
                        ScrollView([.vertical, .horizontal]) {
                            Text(renderedAttributedLogs)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: true, vertical: false)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(12)
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                        .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                )

                HStack {
                    Spacer()
                    VGCopyButton(
                        filteredRawText,
                        label: "Копировать «\(selectedSource.rawValue)»",
                        helpText: "Скопировать содержимое текущей вкладки логов"
                    )
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                            .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                    )
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func formatAuditPlain(_ report: AuditReport) -> String {
        var lines: [String] = ["VPNGuard Audit: \(report.passedCount)/\(report.total) PASS"]
        for item in report.tests {
            lines.append("[\(item.passed ? "PASS" : "FAIL")] \(item.name): \(item.details)")
        }
        return lines.joined(separator: "\n")
    }

    private func scheduleLogRender(debounced: Bool) {
        renderTask?.cancel()
        let rawText = filteredRawText
        let query = logSearchQuery
        renderTask = Task { @MainActor in
            if debounced {
                try? await Task.sleep(nanoseconds: 120_000_000)
                guard !Task.isCancelled else { return }
            }
            let rendered = await Task.detached(priority: .userInitiated) {
                VGFormatters.attributedLogs(from: rawText, searchQuery: query)
            }.value
            guard !Task.isCancelled else { return }
            self.renderedAttributedLogs = rendered
        }
    }

    private func updateAutoRefreshLoop() {
        stopAutoRefreshLoop()
        guard selectedTab == .logs && autoRefreshEnabled else { return }
        autoRefreshTask = Task { @MainActor in
            while !Task.isCancelled && autoRefreshEnabled && selectedTab == .logs {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard !Task.isCancelled && autoRefreshEnabled && selectedTab == .logs else { break }
                await vm.loadDiagnosticsLogs(silent: true)
            }
        }
    }

    private func stopAutoRefreshLoop() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
    }
}
