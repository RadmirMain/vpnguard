import SwiftUI
import AppKit

public enum NavigationSection: String, CaseIterable, Identifiable {
    case dashboard = "Обзор"
    case apps = "Приложения"
    case websites = "Сайты и домены"
    case traffic = "Монитор трафика"
    case server = "Сервер"
    case diagnostics = "Диагностика и логи"
    
    public var id: String { rawValue }
    
    public var iconName: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .apps: return "app.badge.checkmark"
        case .websites: return "globe"
        case .traffic: return "waveform.path.ecg"
        case .server: return "server.rack"
        case .diagnostics: return "stethoscope"
        }
    }
}

public struct MainContainerView: View {
    @ObservedObject var vm: VPNGuardViewModel
    @State private var selectedSection: NavigationSection? = .dashboard
    @State private var showingUpdateSheet: Bool = false
    
    public init(vm: VPNGuardViewModel) {
        self.vm = vm
    }
    
    public var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                List(NavigationSection.allCases, selection: $selectedSection) { section in
                    NavigationLink(value: section) {
                        Label(section.rawValue, systemImage: section.iconName)
                            .font(.system(size: 13, weight: .medium))
                    }
                }
                .listStyle(.sidebar)
                
                Spacer()
                
                Divider()
                
                // Sidebar Footer: Launch at Login
                VStack(alignment: .leading, spacing: 8) {
                    Toggle("Запуск при входе", isOn: Binding(
                        get: { vm.launchAtLogin },
                        set: { vm.setLaunchAtLogin($0) }
                    ))
                    .toggleStyle(.checkbox)
                    .font(.system(size: 11))
                    
                    HStack(spacing: 4) {
                        Circle()
                            .fill(vm.isProtectionActive ? Color.green : (vm.pauseRemainingSeconds > 0 ? Color.orange : Color.red))
                            .frame(width: 6, height: 6)
                        if let countdown = vm.menuBarPauseText {
                            Text("Пауза Wi-Fi (\(countdown))")
                                .font(.system(size: 10))
                                .monospacedDigit()
                                .foregroundColor(.orange)
                        } else {
                            Text(vm.isProtectionActive ? "Защита активна" : "Защита отключена")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                    }

                    Button {
                        showingUpdateSheet = true
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "arrow.triangle.2.circlepath.circle")
                                .font(.system(size: 12))
                            Text("Обновить VPNGuard...")
                                .font(.system(size: 11, weight: .medium))
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 5)
                        .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 6))
                    }
                    .buttonStyle(.plain)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210, max: 250)
        } detail: {
            ZStack(alignment: .bottom) {
                Group {
                    switch selectedSection ?? .dashboard {
                    case .dashboard:
                        DashboardView(vm: vm)
                    case .apps:
                        AppsManagementView(vm: vm)
                    case .websites:
                        WebsitesManagementView(vm: vm)
                    case .traffic:
                        TrafficMonitorView(vm: vm)
                    case .server:
                        ServerConfigView(vm: vm)
                    case .diagnostics:
                        DiagnosticsView(vm: vm)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                
                // Floating Toast
                if let toast = vm.toastMessage {
                    ToastView(message: toast, isError: vm.toastIsError)
                        .padding(.bottom, 20)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        .animation(.easeInOut(duration: 0.25), value: vm.toastMessage)
                }
            }
        }
        .frame(minWidth: 800, minHeight: 540)
        .onChange(of: vm.requestedNavigationSection) { _, next in
            if let next {
                selectedSection = next
                vm.requestedNavigationSection = nil
            }
        }
        .onDisappear {
            TrafficMonitorService.shared.stopMonitoring()
        }
        .sheet(isPresented: $showingUpdateSheet) {
            AppUpdateSheetView(vm: vm)
        }
    }
}

private struct AppUpdateSheetView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var vm: VPNGuardViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Обновление и обслуживание VPNGuard")
                        .font(.headline)
                    Text("Сборка SwiftUI без sudo • Touch ID запрашивается только при изменении бэкенда")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Button("Закрыть") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Папка репозитория (sourceRepoPath)")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.secondary)

                HStack(spacing: 8) {
                    Text(vm.sourceRepoPath)
                        .font(.system(size: 12, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))

                    Button("Выбрать...") {
                        chooseRepoFolder()
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isUpdatingApp)

                    Button {
                        Task { await vm.checkForUpdates() }
                    } label: {
                        if vm.isCheckingUpdates {
                            ProgressView().scaleEffect(0.6)
                        } else {
                            Image(systemName: "arrow.clockwise")
                        }
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isCheckingUpdates || vm.isUpdatingApp)
                    .help("Проверить наличие обновлений")
                }
            }

            if let check = vm.updateCheckResult {
                GlassCard(padding: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Image(systemName: check.updateAvailable ? "arrow.down.circle.fill" : "checkmark.seal.fill")
                                .foregroundColor(check.updateAvailable ? .blue : .green)
                            Text(check.updateAvailable ? "Доступны изменения для установки" : "Установлена актуальная версия")
                                .font(.system(size: 12, weight: .semibold))
                            Spacer()
                            if !check.headCommit.isEmpty {
                                Text("HEAD \(check.headCommit)")
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                        }

                        HStack(spacing: 12) {
                            Label(
                                check.frontendUpdateNeeded ? "Приложение: есть изменения" : "Приложение: актуально",
                                systemImage: check.frontendUpdateNeeded ? "app.badge" : "checkmark.circle"
                            )
                            .font(.system(size: 11))
                            .foregroundColor(check.frontendUpdateNeeded ? .orange : .green)

                            Label(
                                check.backendUpdateNeeded ? "Бэкенд: требуется Touch ID" : "Бэкенд: актуален",
                                systemImage: check.backendUpdateNeeded ? "lock.shield" : "checkmark.circle"
                            )
                            .font(.system(size: 11))
                            .foregroundColor(check.backendUpdateNeeded ? .orange : .green)

                            if check.remoteAheadCount > 0 {
                                Text("Git: +\(check.remoteAheadCount)")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(.blue)
                            }
                        }
                    }
                }
            }

            if let output = vm.updateLogOutput, !output.isEmpty {
                ScrollView {
                    Text(output)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(8)
                }
                .frame(height: 120)
                .background(Color.black.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
            }

            HStack {
                Button {
                    Task { await vm.triggerAppUpdate(forceApp: false, forceBackend: true) }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "wrench.and.screwdriver")
                        Text("Переустановить демоны (Touch ID)")
                    }
                    .font(.system(size: 12, weight: .medium))
                }
                .buttonStyle(.bordered)
                .disabled(vm.isUpdatingApp)

                Spacer()

                let isUpToDate = (vm.updateCheckResult?.updateAvailable == false)
                if isUpToDate {
                    Button("Пересобрать принудительно") {
                        Task { await vm.triggerAppUpdate(forceApp: true, forceBackend: false) }
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isUpdatingApp)
                }

                Button {
                    Task { await vm.triggerAppUpdate(forceApp: false, forceBackend: false) }
                } label: {
                    HStack(spacing: 6) {
                        if vm.isUpdatingApp {
                            ProgressView()
                                .scaleEffect(0.6)
                        } else {
                            Image(systemName: isUpToDate ? "checkmark.circle" : "arrow.triangle.2.circlepath")
                        }
                        Text(vm.isUpdatingApp ? "Обновление..." : (isUpToDate ? "Уже актуально" : "Установить обновление"))
                    }
                    .font(.system(size: 12, weight: .semibold))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 7)
                    .background((isUpToDate ? Color.green : Color.blue).gradient, in: RoundedRectangle(cornerRadius: 8))
                    .foregroundColor(.white)
                }
                .buttonStyle(.plain)
                .disabled(vm.isUpdatingApp || vm.isCheckingUpdates || isUpToDate)
            }
        }
        .padding(20)
        .frame(width: 580)
        .task {
            await vm.checkForUpdates()
        }
    }

    private func chooseRepoFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: vm.sourceRepoPath)
        if panel.runModal() == .OK, let url = panel.url {
            vm.setSourceRepoPath(url.path)
            Task { await vm.checkForUpdates() }
        }
    }
}
