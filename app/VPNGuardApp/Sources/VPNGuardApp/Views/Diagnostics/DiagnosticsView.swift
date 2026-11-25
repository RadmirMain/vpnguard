import SwiftUI
import AppKit

public struct DiagnosticsView: View {
    @ObservedObject var vm: VPNGuardViewModel

    enum LogSource: String, CaseIterable, Identifiable {
        case singbox = "sing-box"
        case xray = "Xray"
        case pf = "PF / Boot"
        case pfRules = "PF Rules"
        case dns = "DNS (scutil)"
        case utun = "utun99"

        var id: String { rawValue }
    }

    @State private var selectedSource: LogSource = .singbox
    @State private var autoRefreshEnabled: Bool = false
    @State private var logSearchQuery: String = ""
    @State private var autoRefreshTask: Task<Void, Never>? = nil

    public init(vm: VPNGuardViewModel) {
        self.vm = vm
    }

    private var currentRawText: String {
        guard let snap = vm.diagnosticsSnapshot else {
            return "Нажмите «Обновить логи», чтобы загрузить последние 150 строк логов и состояние PF/DNS/utun99."
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

    private var filteredLogText: String {
        let query = logSearchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return currentRawText }
        let matched = currentRawText
            .components(separatedBy: .newlines)
            .filter { $0.localizedCaseInsensitiveContains(query) }
        return matched.isEmpty ? "(Совпадений по «\(query)» не найдено)" : matched.joined(separator: "\n")
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerSection
                auditSection
                logsSection
            }
            .padding(24)
        }
        .onAppear {
            if vm.diagnosticsSnapshot == nil {
                Task { await vm.loadDiagnosticsLogs(silent: true) }
            }
            updateAutoRefreshLoop()
        }
        .onDisappear {
            stopAutoRefreshLoop()
        }
        .onChange(of: autoRefreshEnabled) { _, _ in
            updateAutoRefreshLoop()
        }
    }

    // MARK: - Header
    private var headerSection: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Диагностика и логи")
                    .font(.title2.bold())
                Text("12-точечный аудит утечек и санитизированные логи сервисов (без секретов и UUID)")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()

            HStack(spacing: 8) {
                Button {
                    vm.copyDiagnosticsMarkdownReport()
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "doc.on.doc")
                        Text("Скопировать отчёт")
                    }
                    .font(.system(size: 12, weight: .medium))
                }
                .buttonStyle(.bordered)
                .help("Скопировать сводный диагностический отчёт в Markdown")
            }
        }
    }

    // MARK: - 12-Point Audit Checklist
    private var auditSection: some View {
        GlassCard(padding: 18) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Комплексный аудит утечек (vpnguard test)")
                            .font(.system(size: 14, weight: .bold))
                        Text("Проверка ядра PF, изоляции GID 888/889/890, mDNS, utun99 и выходного IP")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }

                    Spacer()

                    Button {
                        Task { await vm.runSecurityAudit() }
                    } label: {
                        HStack(spacing: 6) {
                            if vm.isRunningAudit {
                                ProgressView().scaleEffect(0.65)
                                Text("Выполняется...")
                            } else {
                                Image(systemName: "play.fill")
                                Text("Проверить утечки")
                            }
                        }
                        .font(.system(size: 12, weight: .semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 7)
                        .background(Color.blue.gradient, in: RoundedRectangle(cornerRadius: 8))
                        .foregroundColor(.white)
                    }
                    .buttonStyle(.plain)
                    .disabled(vm.isRunningAudit)
                }

                if let report = vm.auditReport {
                    VStack(spacing: 8) {
                        HStack {
                            Image(systemName: report.passed ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                .foregroundColor(report.passed ? .green : .orange)
                            Text(report.passed
                                 ? "Все \(report.total) проверок успешно пройдены: утечек нет"
                                 : "Пройдено \(report.passedCount) из \(report.total) проверок")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(report.passed ? .green : .orange)
                            Spacer()
                        }

                        ForEach(report.tests) { test in
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: test.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .font(.system(size: 13))
                                    .foregroundColor(test.passed ? .green : .red)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(test.name)
                                        .font(.system(size: 12, weight: .semibold))
                                    Text(test.details)
                                        .font(.system(size: 11))
                                        .foregroundColor(.secondary)
                                }
                                Spacer()

                                Text(test.passed ? "PASS" : "FAIL")
                                    .font(.system(size: 10, weight: .bold))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(test.passed ? Color.green.opacity(0.15) : Color.red.opacity(0.15), in: Capsule())
                                    .foregroundColor(test.passed ? .green : .red)
                            }
                            .padding(8)
                            .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
                        }
                    }
                } else if !vm.isRunningAudit {
                    Text("Нажмите «Проверить утечки», чтобы выполнить 12 активных тестов изоляции.")
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - Logs & System State Viewer
    private var logsSection: some View {
        GlassCard(padding: 18) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Логи и состояние сети (последние 150 строк)")
                            .font(.system(size: 14, weight: .bold))
                        if let snap = vm.diagnosticsSnapshot {
                            Text("Обновлено: \(snap.generatedAt)")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }

                    Spacer()

                    Toggle("Авто (5с)", isOn: $autoRefreshEnabled)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                        .font(.system(size: 11))

                    Button {
                        Task { await vm.loadDiagnosticsLogs(silent: false) }
                    } label: {
                        HStack(spacing: 5) {
                            if vm.isLoadingDiagnostics {
                                ProgressView().scaleEffect(0.6)
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
                    Picker("Источник", selection: $selectedSource) {
                        ForEach(LogSource.allCases) { src in
                            Text(src.rawValue).tag(src)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()

                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.secondary)
                            .font(.system(size: 11))
                        TextField("Фильтр строк...", text: $logSearchQuery)
                            .textFieldStyle(.plain)
                            .font(.system(size: 11))
                        if !logSearchQuery.isEmpty {
                            Button {
                                logSearchQuery = ""
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.secondary)
                                    .font(.system(size: 11))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 6))
                    .frame(width: 190)
                }

                ScrollView([.vertical, .horizontal]) {
                    Text(filteredLogText)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
                .frame(height: 300)
                .background(Color.black.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.primary.opacity(0.1), lineWidth: 1)
                )

                HStack {
                    Spacer()
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(filteredLogText, forType: .string)
                        vm.showToast("Содержимое «\(selectedSource.rawValue)» скопировано", isError: false)
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "doc.on.clipboard")
                            Text("Копировать вкладку «\(selectedSource.rawValue)»")
                        }
                        .font(.system(size: 11, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
    }

    private func updateAutoRefreshLoop() {
        stopAutoRefreshLoop()
        guard autoRefreshEnabled else { return }
        autoRefreshTask = Task { @MainActor in
            while !Task.isCancelled && autoRefreshEnabled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard !Task.isCancelled && autoRefreshEnabled else { break }
                await vm.loadDiagnosticsLogs(silent: true)
            }
        }
    }

    private func stopAutoRefreshLoop() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
    }
}
