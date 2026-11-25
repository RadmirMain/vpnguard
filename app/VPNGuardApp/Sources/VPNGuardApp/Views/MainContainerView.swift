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
    @State private var selectedSection: NavigationSection = .dashboard
    @State private var showingUpdateSheet: Bool = false

    public init(vm: VPNGuardViewModel) {
        self.vm = vm
    }

    public var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                // Brand Header
                HStack(spacing: 8) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(vm.isProtectionActive ? VGTheme.statusProtected : .secondary)
                    Text("VPNGuard")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 10)

                // Native-styled monochrome sidebar items
                VStack(spacing: 3) {
                    ForEach(NavigationSection.allCases) { section in
                        SidebarNavItem(
                            section: section,
                            isSelected: selectedSection == section
                        ) {
                            withAnimation(.snappy(duration: 0.2)) {
                                selectedSection = section
                            }
                        }
                    }
                }
                .padding(.horizontal, 10)

                Spacer()

                Divider().opacity(0.6)

                // Sidebar Footer: Status + Launch at Login + Updates
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 7) {
                        Circle()
                            .fill(vm.isProtectionActive ? VGTheme.statusProtected : (vm.pauseRemainingSeconds > 0 ? VGTheme.statusWarning : VGTheme.statusDanger))
                            .frame(width: 7, height: 7)

                        if let countdown = vm.menuBarPauseText {
                            Text("Пауза Wi-Fi (\(countdown))")
                                .font(.system(size: 11, weight: .medium))
                                .monospacedDigit()
                                .foregroundStyle(VGTheme.statusWarning)
                        } else {
                            Text(vm.isProtectionActive ? "Защита активна" : "Защита отключена")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(.primary)
                        }
                        Spacer()
                    }

                    Toggle("Запуск при входе", isOn: Binding(
                        get: { vm.launchAtLogin },
                        set: { vm.setLaunchAtLogin($0) }
                    ))
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)

                    let hasUpdate = vm.updateCheckResult?.updateAvailable == true
                    Button {
                        showingUpdateSheet = true
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "arrow.triangle.2.circlepath")
                                .font(.system(size: 11))
                            Text(hasUpdate ? "Доступно обновление" : "Обновление…")
                                .font(.system(size: 11, weight: hasUpdate ? .semibold : .medium))
                            Spacer()
                            if hasUpdate {
                                Circle()
                                    .fill(VGTheme.accentPrimary)
                                    .frame(width: 7, height: 7)
                            }
                        }
                        .foregroundStyle(hasUpdate ? .primary : .secondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .background(
                            RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                                .fill(hasUpdate ? VGTheme.accentPrimary.opacity(0.14) : VGTheme.surfaceLevel1)
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                                .strokeBorder(hasUpdate ? VGTheme.accentPrimary.opacity(0.3) : VGTheme.borderSubtle, lineWidth: 0.75)
                        )
                    }
                    .buttonStyle(.plain)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationSplitViewColumnWidth(min: 196, ideal: 212, max: 248)
        } detail: {
            ZStack(alignment: .bottom) {
                Group {
                    switch selectedSection {
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
                .background(VGTheme.backgroundContent)

                // Floating Toast
                if let toast = vm.toastMessage {
                    ToastView(message: toast, isError: vm.toastIsError)
                        .padding(.bottom, 20)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.snappy(duration: 0.2), value: vm.toastMessage)
        }
        .frame(minWidth: 820, minHeight: 560)
        .onChange(of: vm.requestedNavigationSection) { _, next in
            if let next {
                withAnimation(.snappy(duration: 0.2)) {
                    selectedSection = next
                }
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

private struct SidebarNavItem: View {
    let section: NavigationSection
    let isSelected: Bool
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: section.iconName)
                    .font(.system(size: 13, weight: isSelected ? .semibold : .regular))
                    .foregroundStyle(isSelected ? .primary : .secondary)
                    .frame(width: 18, alignment: .center)

                Text(section.rawValue)
                    .font(.system(size: 13, weight: isSelected ? .semibold : .medium))
                    .foregroundStyle(isSelected ? .primary : .secondary)

                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                    .fill(isSelected ? VGTheme.sidebarSelection : (isHovered ? VGTheme.surfaceLevel1 : .clear))
            )
            .contentShape(RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
    }
}

private struct AppUpdateSheetView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var vm: VPNGuardViewModel

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Обновление и обслуживание")
                        .font(.system(size: 16, weight: .semibold))
                    Text("Сборка SwiftUI без sudo • Touch ID запрашивается только при изменении бэкенда")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(VGTheme.sheetPadding)

            Divider().opacity(0.6)

            // Body
            VStack(alignment: .leading, spacing: 14) {
                VGCard(padding: 14) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Папка репозитория")
                            .font(.system(size: 12, weight: .semibold))

                        HStack(spacing: 8) {
                            Text(vm.sourceRepoPath)
                                .font(.system(size: 11, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 7)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))

                            Button("Выбрать…") {
                                chooseRepoFolder()
                            }
                            .buttonStyle(.bordered)
                            .disabled(vm.isUpdatingApp)

                            Button {
                                Task { await vm.checkForUpdates() }
                            } label: {
                                if vm.isCheckingUpdates {
                                    ProgressView().controlSize(.small)
                                } else {
                                    Image(systemName: "arrow.clockwise")
                                }
                            }
                            .buttonStyle(.bordered)
                            .disabled(vm.isCheckingUpdates || vm.isUpdatingApp)
                            .help("Проверить наличие обновлений")
                        }
                    }
                }

                if let check = vm.updateCheckResult {
                    VGCard(
                        padding: 14,
                        accentBorder: check.updateAvailable ? VGTheme.accentPrimary.opacity(0.35) : VGTheme.statusProtected.opacity(0.28)
                    ) {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Image(systemName: check.updateAvailable ? "arrow.down.circle.fill" : "checkmark.seal.fill")
                                    .foregroundStyle(check.updateAvailable ? VGTheme.accentPrimary : VGTheme.statusProtected)
                                Text(check.updateAvailable ? "Доступны изменения для установки" : "Установлена актуальная версия")
                                    .font(.system(size: 12, weight: .semibold))
                                Spacer()
                                if !check.headCommit.isEmpty {
                                    VGStatusBadge("HEAD \(check.headCommit)", tone: .neutral)
                                }
                            }

                            HStack(spacing: 12) {
                                VGStatusBadge(
                                    check.frontendUpdateNeeded ? "Приложение: есть изменения" : "Приложение: актуально",
                                    tone: check.frontendUpdateNeeded ? .warning : .protected
                                )

                                VGStatusBadge(
                                    check.backendUpdateNeeded ? "Бэкенд: требуется Touch ID" : "Бэкенд: актуален",
                                    tone: check.backendUpdateNeeded ? .warning : .protected
                                )

                                if check.remoteAheadCount > 0 {
                                    VGStatusBadge("Git: +\(check.remoteAheadCount)", tone: .accent)
                                }
                            }
                        }
                    }
                }

                if let output = vm.updateLogOutput, !output.isEmpty {
                    ScrollView {
                        Text(VGFormatters.stripANSI(output))
                            .font(.system(size: 11, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                            .padding(10)
                    }
                    .frame(height: 120)
                    .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                            .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                    )
                }
            }
            .padding(VGTheme.sheetPadding)

            Divider().opacity(0.6)

            // Footer
            HStack(spacing: 10) {
                Button("Закрыть") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .disabled(vm.isUpdatingApp)

                Button {
                    Task { await vm.triggerAppUpdate(forceApp: false, forceBackend: true) }
                } label: {
                    Label("Переустановить демоны (Touch ID)", systemImage: "wrench.and.screwdriver")
                        .font(.system(size: 12, weight: .medium))
                }
                .buttonStyle(.bordered)
                .disabled(vm.isUpdatingApp)

                Spacer()

                let isUpToDate = (vm.updateCheckResult?.updateAvailable == false)
                if isUpToDate {
                    Button("Пересобрать") {
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
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: isUpToDate ? "checkmark.circle" : "arrow.triangle.2.circlepath")
                        }
                        Text(vm.isUpdatingApp ? "Обновление…" : (isUpToDate ? "Актуально" : "Установить обновление"))
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.isUpdatingApp || vm.isCheckingUpdates || isUpToDate)
            }
            .padding(VGTheme.sheetPadding)
        }
        .frame(width: 580)
        .background(VGTheme.backgroundContent)
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
