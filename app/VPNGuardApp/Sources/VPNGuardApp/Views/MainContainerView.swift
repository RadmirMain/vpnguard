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
    @ObservedObject private var releaseUpdater = GitHubReleaseUpdater.shared
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
                            .fill(vm.isProtectionActive ? VGTheme.statusProtected : ((vm.pauseRemainingSeconds > 0 || vm.isTunnelRecovering) ? VGTheme.statusWarning : VGTheme.statusDanger))
                            .frame(width: 7, height: 7)

                        if let countdown = vm.menuBarPauseText {
                            Text("Пауза Wi-Fi (\(countdown))")
                                .font(.system(size: 11, weight: .medium))
                                .monospacedDigit()
                                .foregroundStyle(VGTheme.statusWarning)
                        } else if vm.isTunnelRecovering {
                            Text("Kill-Switch активен")
                                .font(.system(size: 11, weight: .medium))
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

                    let hasUpdate = releaseUpdater.isUpdateAvailable || releaseUpdater.backendSyncNeeded || (vm.updateCheckResult?.updateAvailable == true)
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
        .onChange(of: vm.requestedOpenUpdateSheet) { _, open in
            if open {
                showingUpdateSheet = true
                vm.requestedOpenUpdateSheet = false
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
    @ObservedObject private var releaseUpdater = GitHubReleaseUpdater.shared
    @State private var showDevTools: Bool = false
    @State private var showGitHubEmptyInfo: Bool = false

    private var preferLocalChannel: Bool {
        releaseUpdater.status == .noReleasesYet && vm.hasLocalUpdateScript && vm.updateCheckResult != nil
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Обновление и обслуживание")
                        .font(.system(size: 16, weight: .semibold))
                    Text("Версия \(releaseUpdater.currentVersion) • Проверка релизов GitHub и локальной сборки")
                        .font(.system(size: 12))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(VGTheme.sheetPadding)

            Divider().opacity(0.6)

            // Body
            VStack(alignment: .leading, spacing: 14) {
                if releaseUpdater.backendSyncNeeded {
                    VGCard(padding: 14, accentBorder: VGTheme.statusWarning.opacity(0.4)) {
                        HStack(spacing: 12) {
                            Image(systemName: "wrench.and.screwdriver.fill")
                                .foregroundStyle(VGTheme.statusWarning)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Требуется обновление системного бэкенда")
                                    .font(.system(size: 12, weight: .semibold))
                                Text("Версия приложения обновилась — синхронизируйте PF/CLI/демоны через Touch ID")
                                    .font(.system(size: 11))
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button {
                                Task {
                                    let ok = await releaseUpdater.installBundledBackendWithTouchID()
                                    vm.showToast(ok ? "Системные компоненты обновлены" : "Не удалось обновить бэкенд", isError: !ok)
                                }
                            } label: {
                                HStack(spacing: 5) {
                                    if releaseUpdater.isSyncingBackend {
                                        ProgressView().controlSize(.small)
                                    }
                                    Text("Обновить (Touch ID)")
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                            .disabled(releaseUpdater.isSyncingBackend)
                        }
                    }
                }

                if preferLocalChannel {
                    localRepoPrimaryCard

                    VGCard(padding: 14) {
                        DisclosureGroup(isExpanded: $showGitHubEmptyInfo) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Релизы на GitHub ещё не опубликованы.")
                                    .font(.system(size: 12, weight: .medium))
                                Text("Создайте и отправьте тег (например, git tag v3.0.1 && git push --tags), чтобы активировать автообновление через GitHub Releases.")
                                    .font(.system(size: 11))
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.top, 6)
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "shippingbox")
                                    .font(.system(size: 12))
                                    .foregroundStyle(.secondary)
                                Text("GitHub Releases (релизы не опубликованы)")
                                    .font(.system(size: 12, weight: .medium))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } else {
                    // GitHub Releases Card (Primary User Flow)
                    gitHubReleaseCard

                    // Developer Local Repo Section
                    VGCard(padding: 14) {
                        DisclosureGroup(isExpanded: $showDevTools) {
                            localRepoControls
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "hammer")
                                    .font(.system(size: 12))
                                    .foregroundStyle(.secondary)
                                Text("Локальная пересборка из репозитория (для разработки)")
                                    .font(.system(size: 12, weight: .medium))
                                Spacer()
                                if vm.updateCheckResult?.updateAvailable == true {
                                    VGStatusBadge("Есть изменения", tone: .warning)
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
                    .frame(height: 100)
                    .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
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
                .disabled(vm.isUpdatingApp || releaseUpdater.isInstalling)

                Spacer()

                Button {
                    Task {
                        await releaseUpdater.checkForRelease(silent: false)
                        if vm.hasLocalUpdateScript {
                            await vm.checkForUpdates()
                        }
                    }
                } label: {
                    HStack(spacing: 5) {
                        if releaseUpdater.status == .checking || vm.isCheckingUpdates {
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: "arrow.clockwise")
                        }
                        Text("Проверить")
                    }
                }
                .buttonStyle(.bordered)
                .disabled(releaseUpdater.status == .checking || releaseUpdater.isInstalling || vm.isUpdatingApp)

                if case .updateAvailable(let release) = releaseUpdater.status {
                    Button {
                        Task { await releaseUpdater.downloadAndInstall(release: release) }
                    } label: {
                        HStack(spacing: 6) {
                            if releaseUpdater.isInstalling {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: "arrow.down.circle.fill")
                            }
                            Text(releaseUpdater.isInstalling ? releaseUpdater.installStage.description : "Скачать и обновить до \(release.cleanVersion)")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(releaseUpdater.isInstalling)
                } else if vm.updateCheckResult?.updateAvailable == true {
                    Button {
                        Task { await vm.triggerAppUpdate(forceApp: false, forceBackend: false) }
                    } label: {
                        HStack(spacing: 6) {
                            if vm.isUpdatingApp {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: "arrow.triangle.2.circlepath")
                            }
                            Text(vm.isUpdatingApp ? "Обновление…" : "Установить локальное обновление")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(vm.isUpdatingApp)
                }
            }
            .padding(VGTheme.sheetPadding)
        }
        .frame(width: 580)
        .background(VGTheme.backgroundContent)
        .task {
            await releaseUpdater.checkForRelease(silent: false)
            if vm.hasLocalUpdateScript {
                await vm.checkForUpdates()
            }
        }
    }

    private var localRepoPrimaryCard: some View {
        let check = vm.updateCheckResult
        let hasUpdates = check?.updateAvailable == true
        let fetchFailed = check?.fetchFailed == true
        return VGCard(
            padding: 14,
            accentBorder: hasUpdates ? VGTheme.accentPrimary.opacity(0.35) : nil
        ) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Image(systemName: hasUpdates ? "arrow.triangle.2.circlepath.circle.fill" : (fetchFailed ? "exclamationmark.triangle.fill" : "checkmark.seal.fill"))
                        .foregroundStyle(hasUpdates ? VGTheme.accentPrimary : (fetchFailed ? VGTheme.statusWarning : VGTheme.statusProtected))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(hasUpdates ? "Доступно локальное обновление" : (fetchFailed ? "Не удалось проверить origin (git fetch)" : "Локальная сборка актуальна"))
                            .font(.system(size: 12, weight: .semibold))
                        if let check {
                            Text("Ветка HEAD \(check.headCommit.isEmpty ? "—" : check.headCommit) • новых коммитов: \(check.remoteAheadCount)")
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                }
                localRepoControls
            }
        }
    }

    private var localRepoControls: some View {
        VStack(alignment: .leading, spacing: 10) {
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
            }
            .padding(.top, 4)

            if let check = vm.updateCheckResult {
                HStack(spacing: 8) {
                    VGStatusBadge(
                        check.frontendUpdateNeeded ? "Приложение: изменено" : "Приложение: актуально",
                        tone: check.frontendUpdateNeeded ? .warning : .protected
                    )
                    VGStatusBadge(
                        check.backendUpdateNeeded ? "Бэкенд: нужен Touch ID" : "Бэкенд: актуален",
                        tone: check.backendUpdateNeeded ? .warning : .protected
                    )
                    if check.fetchFailed == true {
                        VGStatusBadge("git fetch: ошибка сети", tone: .warning)
                    } else if !check.headCommit.isEmpty {
                        VGStatusBadge("HEAD \(check.headCommit)", tone: .neutral)
                    }
                }
            }

            HStack(spacing: 8) {
                Button {
                    Task { await vm.triggerAppUpdate(forceApp: false, forceBackend: true) }
                } label: {
                    Label("Переустановить демоны (Touch ID)", systemImage: "wrench.and.screwdriver")
                        .font(.system(size: 11, weight: .medium))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(vm.isUpdatingApp)

                Spacer()

                Button("Пересобрать локально") {
                    Task { await vm.triggerAppUpdate(forceApp: true, forceBackend: false) }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(vm.isUpdatingApp)
            }
        }
    }

    private var gitHubReleaseCard: some View {
        VGCard(
            padding: 14,
            accentBorder: releaseUpdater.isUpdateAvailable ? VGTheme.accentPrimary.opacity(0.35) : nil
        ) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    switch releaseUpdater.status {
                    case .idle, .checking:
                        ProgressView().controlSize(.small)
                        Text("Проверка релизов на GitHub…")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    case .upToDate(let current, let latest):
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundStyle(VGTheme.statusProtected)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Установлена актуальная версия (\(current))")
                                .font(.system(size: 12, weight: .semibold))
                            Text("Последний релиз на GitHub: v\(latest)")
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        }
                    case .updateAvailable(let release):
                        Image(systemName: "arrow.down.app.fill")
                            .foregroundStyle(VGTheme.accentPrimary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Доступен новый релиз VPNGuard v\(release.cleanVersion)")
                                .font(.system(size: 12, weight: .semibold))
                            Text("Готовая сборка с проверкой SHA-256 и автоперезапуском")
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        }
                    case .noReleasesYet:
                        Image(systemName: "shippingbox")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Релизы на GitHub ещё не опубликованы")
                                .font(.system(size: 12, weight: .semibold))
                            Text("Создайте и отправьте тег (например, git tag v3.0.1 && git push --tags)")
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        }
                    case .error(let msg):
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(VGTheme.statusWarning)
                        Text(msg)
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                if releaseUpdater.installStage != .idle {
                    HStack(spacing: 8) {
                        if case .failed = releaseUpdater.installStage {
                            Image(systemName: "xmark.octagon.fill")
                                .foregroundStyle(VGTheme.statusDanger)
                        } else {
                            ProgressView().controlSize(.small)
                        }
                        Text(releaseUpdater.installStage.description)
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle({
                                if case .failed = releaseUpdater.installStage { return VGTheme.statusDanger }
                                return Color.primary
                            }())
                    }
                }
            }
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
