import SwiftUI
import AppKit

public struct MenuBarExtraView: View {
    @ObservedObject var vm: VPNGuardViewModel
    @ObservedObject private var releaseUpdater = GitHubReleaseUpdater.shared
    @State private var copiedBrewCommand = false
    var onOpenSettings: () -> Void

    public init(vm: VPNGuardViewModel, onOpenSettings: @escaping () -> Void) {
        self.vm = vm
        self.onOpenSettings = onOpenSettings
    }

    public var body: some View {
        VStack(spacing: 12) {
            // MARK: - Compact Status Header
            statusHeader

            // MARK: - Inline Popover Error Banner
            if let toast = vm.toastMessage, vm.toastIsError {
                popoverErrorBanner(message: toast)
            }

            // MARK: - Update / Backend Sync Quick Banner
            if releaseUpdater.isUpdateAvailable || releaseUpdater.backendSyncNeeded || vm.updateCheckResult?.updateAvailable == true {
                updateBanner
            }

            // MARK: - Public Wi-Fi Pause Banner / Action
            if let pauseEnd = vm.pauseEndDate, vm.isPauseActive {
                activePauseBanner(endDate: pauseEnd)
            } else if vm.isProtectionActive {
                pauseActionRow
            }

            // MARK: - Connection & Health Card
            VGCard(padding: 12) {
                VStack(alignment: .leading, spacing: 10) {
                    activeServerRow
                    Divider().opacity(0.45)
                    exitIpRow
                    Divider().opacity(0.45)
                    healthRow
                }
            }

            // MARK: - Protected Browser
            protectedBrowserButton

            // MARK: - Bottom Actions
            bottomActions
        }
        .padding(VGComponentTokens.Popover.padding)
        .frame(width: VGComponentTokens.Popover.width)
        .background(VGTokens.Colors.backgroundContent)
        .background(MenuBarWindowAnchor())
        .onAppear {
            vm.refreshBrowserAvailability()
        }
    }

    private func popoverErrorBanner(message: String) -> some View {
        VGCard(padding: 10, accentBorder: VGTheme.statusDanger.opacity(0.45)) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(VGTheme.statusDanger)
                    .padding(.top, 1)

                Text(message)
                    .font(.system(size: 11))
                    .foregroundStyle(.primary)
                    .lineLimit(4)
                    .truncationMode(.tail)
                    .fixedSize(horizontal: false, vertical: true)
                    .help(message)

                Spacer(minLength: 4)

                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(message, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(VGTokens.Typography.caption)
                }
                .buttonStyle(VGIconButtonStyle())
                .help("Скопировать текст ошибки")
                .accessibilityLabel("Скопировать текст ошибки")

                Button {
                    vm.dismissToast()
                } label: {
                    Image(systemName: "xmark")
                        .font(VGTokens.Typography.caption)
                }
                .buttonStyle(VGIconButtonStyle())
                .help("Закрыть уведомление")
                .accessibilityLabel("Закрыть уведомление об ошибке")
            }
        }
    }

    // MARK: - Status Header
    private var statusHeader: some View {
        let isPaused = vm.isPauseActive
        let isRecovering = vm.isTunnelRecovering
        let tint: Color = vm.isProtectionActive
            ? VGTheme.statusProtected
            : ((isPaused || isRecovering) ? VGTheme.statusWarning : VGTheme.statusDanger)

        return VGCard(padding: 12) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(tint.opacity(0.15))
                        .frame(width: 36, height: 36)
                        .shadow(color: vm.isProtectionActive ? tint.opacity(0.28) : .clear, radius: 8)

                    Image(systemName: vm.isProtectionActive ? "shield.lefthalf.filled" : (isPaused ? "pause.circle.fill" : (isRecovering ? "exclamationmark.shield.fill" : "shield.slash.fill")))
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(tint)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(vm.isProtectionActive ? "Защита активна" : (isPaused ? "Авторизация Wi-Fi" : (isRecovering ? "Kill-Switch активен" : "Защита отключена")))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)

                    if let pauseEnd = vm.pauseEndDate, isPaused {
                        TimelineView(.periodic(from: .now, by: 1.0)) { context in
                            let countdown = VGFormatters.formatCountdown(until: pauseEnd, now: context.date) ?? "00:00"
                            Text("Автовозврат через \(countdown)")
                                .font(.system(size: 11))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Text(headerSubtitle)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Spacer(minLength: 8)

                if vm.isTogglingPower {
                    ProgressView()
                        .controlSize(.small)
                        .frame(width: 38, height: 22)
                } else {
                    Toggle("", isOn: Binding(
                        get: { vm.isKillSwitchArmed },
                        set: { _ in
                            Task { await vm.toggleProtection() }
                        }
                    ))
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .labelsHidden()
                    .tint(isRecovering ? VGTheme.statusWarning : VGTheme.statusProtected)
                    .disabled(vm.isTogglingPause)
                    .help(vm.isKillSwitchArmed ? "Отключить защиту VPNGuard" : "Включить защиту VPNGuard")
                }
            }
        }
    }

    private var headerSubtitle: String {
        if let countdown = vm.menuBarPauseText {
            return "Автовозврат через \(countdown)"
        }
        if vm.isProtectionActive {
            if let loc = vm.status.exitLocation, !loc.isEmpty {
                return loc
            }
            return "Туннель и PF Kill-Switch работают"
        }
        if vm.isTunnelRecovering {
            return "PF Kill-Switch активен — туннель восстанавливается"
        }
        return "Прямой доступ без фильтрации"
    }

    private var updateBanner: some View {
        let isBackendSync = releaseUpdater.backendSyncNeeded && !releaseUpdater.isUpdateAvailable
        return VGCard(padding: 10, accentBorder: (isBackendSync ? VGTheme.statusWarning : VGTheme.accentPrimary).opacity(0.35)) {
            HStack(spacing: 10) {
                Image(systemName: isBackendSync ? "wrench.and.screwdriver.fill" : "arrow.down.app.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(isBackendSync ? VGTheme.statusWarning : VGTheme.accentPrimary)

                Text(isBackendSync ? "Нужно обновить демоны" : "Доступно обновление")
                    .font(.system(size: 12, weight: .semibold))

                Spacer()

                Button("Обновить") {
                    vm.requestedOpenUpdateSheet = true
                    onOpenSettings()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
        }
    }

    private func activePauseBanner(endDate: Date) -> some View {
        VGCard(padding: 10, accentBorder: VGTheme.statusWarning.opacity(0.35)) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "wifi.exclamationmark")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(VGTheme.statusWarning)
                    Text("Авторизация Wi-Fi (Captive Portal)")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.primary)
                    Spacer()
                    TimelineView(.periodic(from: .now, by: 1.0)) { context in
                        Text(VGFormatters.formatCountdown(until: endDate, now: context.date) ?? "00:00")
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                            .monospacedDigit()
                            .foregroundStyle(VGTheme.statusWarning)
                    }
                }

                Text("Трафик вне песочницы (GID 888) временно идёт напрямую. Защита вернётся автоматически после входа или по таймеру.")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: VGTokens.Spacing.inlineGap) {
                    Button {
                        Task { await vm.resumeFromPauseNow() }
                    } label: {
                        Text("Вернуть защиту")
                            .font(VGTokens.Typography.captionEmphasis)
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(VGTokens.Colors.statusProtectedFill)
                    .controlSize(.small)
                    .disabled(vm.isTogglingPause)

                    Button {
                        Task { await vm.pauseForWifi(seconds: 900) }
                    } label: {
                        Text("15 мин")
                            .font(VGTokens.Typography.captionEmphasis)
                            .monospacedDigit()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(vm.isTogglingPause)
                }
            }
        }
    }

    private var pauseActionRow: some View {
        Button {
            Task { await vm.pauseForWifi(seconds: 300) }
        } label: {
            HStack(spacing: 8) {
                if vm.isTogglingPause {
                    ProgressView().controlSize(.mini)
                } else {
                    Image(systemName: "wifi")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(VGTheme.statusWarning)
                }
                Text("Авторизация Wi-Fi (Captive Portal)")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.primary)
                Spacer()
                Text("5 мин")
                    .font(VGTokens.Typography.caption)
                    .foregroundStyle(VGTokens.Colors.textSecondary)
            }
            .padding(.horizontal, VGComponentTokens.Row.horizontalPadding)
            .padding(.vertical, VGComponentTokens.Row.verticalPadding)
        }
        .buttonStyle(VGSurfaceButtonStyle())
        .disabled(vm.isTogglingPause || vm.isTogglingPower)
    }

    // MARK: - Active Server Row
    private var activeServerRow: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Активный сервер")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.secondary)

                let serverName = vm.activeServer?.name ?? vm.status.activeServerName ?? "Не выбран"
                Text(serverName)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)

                if let relayIp = vm.status.relayIp, !relayIp.isEmpty {
                    Text("Релей: \(relayIp)")
                        .font(.system(size: 10, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            }

            Spacer(minLength: 8)

            if vm.servers.count > 1 {
                Menu {
                    ForEach(vm.servers) { server in
                        Button {
                            guard !server.isActive else { return }
                            Task { await vm.activateServer(id: server.id) }
                        } label: {
                            HStack {
                                if server.isActive {
                                    Image(systemName: "checkmark")
                                }
                                Text(server.name)
                            }
                        }
                        .disabled(server.isActive)
                    }
                } label: {
                    HStack(spacing: 4) {
                        if vm.activatingServerId != nil {
                            ProgressView().controlSize(.mini)
                        } else {
                            Image(systemName: "arrow.triangle.2.circlepath")
                                .font(.system(size: 10))
                        }
                        Text("Сменить")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous)
                            .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                    )
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .disabled(vm.activatingServerId != nil)
            }
        }
    }

    // MARK: - Exit IP Row
    private var exitIpRow: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Выходной IP")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.secondary)

                HStack(spacing: 6) {
                    if vm.isResolvingExitIP && vm.status.exitIp == nil {
                        ProgressView()
                            .controlSize(.mini)
                    }
                    Text(exitIpDisplayText)
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(vm.status.exitIp != nil ? .primary : .secondary)

                    if let ip = vm.status.exitIp, !ip.isEmpty {
                        VGCopyButton(ip, helpText: "Скопировать выходной IP")
                    }
                }
            }

            Spacer(minLength: 8)

            if let loc = vm.status.exitLocation, !loc.isEmpty {
                Text(loc)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var exitIpDisplayText: String {
        if let ip = vm.status.exitIp, !ip.isEmpty {
            return ip
        }
        switch vm.protectionState {
        case .on(.loading):
            return "Определяется…"
        case .on(.failed):
            return "Не определён"
        case .on(.resolved(let ip)):
            return ip
        case .on(.idle):
            return "Определяется…"
        case .tunnelRecovering:
            return "Восстановление…"
        case .off, .turningOn, .turningOff:
            return "—"
        }
    }

    // MARK: - Compact Health Row
    private var healthRow: some View {
        let tunnelHealthy = vm.status.xrayRunning.running && vm.status.singboxRunning.running

        return HStack(spacing: 8) {
            HStack(spacing: 5) {
                Circle()
                    .fill(tunnelHealthy ? VGTheme.statusProtected : VGTheme.statusDanger)
                    .frame(width: 6, height: 6)

                if vm.isProtectionActive, vm.tunnelHealthOk == true, let ms = vm.tunnelLatencyMs {
                    Text("\(vm.status.utunInterface ?? "utun99") · \(ms) мс")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                } else {
                    Text(tunnelHealthy ? (vm.status.utunInterface ?? "utun99") : "Туннель не активен")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            HStack(spacing: 4) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                Text("Утечек остановлено:")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Text("\(vm.status.pfBlockedPackets)")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .monospacedDigit()
                    .foregroundStyle(.primary)
            }
            .help("Количество попыток утечки, заблокированных PF Kill-Switch")
        }
    }

    // MARK: - Protected Browser
    private var protectedBrowserButton: some View {
        let canLaunch = vm.isProtectionActive && vm.hasSupportedBrowser && !vm.isLaunchingBrowser
        return VStack(alignment: .leading, spacing: 6) {
            Button {
                Task { await vm.launchProtectedBrowser() }
            } label: {
                HStack(spacing: 8) {
                    if vm.isLaunchingBrowser {
                        ProgressView().controlSize(.mini)
                    } else {
                        Image(systemName: "safari")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(canLaunch ? VGTheme.accentPrimary : .secondary)
                    }
                    Text("Открыть защищённый браузер")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(canLaunch ? .primary : .secondary)
                    Spacer()
                    Image(systemName: "arrow.up.right")
                        .font(VGTokens.Typography.caption)
                        .foregroundStyle(VGTokens.Colors.textSecondary)
                        .accessibilityHidden(true)
                }
                .padding(.horizontal, VGComponentTokens.Row.horizontalPadding)
                .padding(.vertical, VGComponentTokens.Row.verticalPadding)
            }
            .buttonStyle(VGSurfaceButtonStyle())
            .disabled(!canLaunch)
            .help(
                !vm.hasSupportedBrowser
                    ? "Установите Chrome, Brave, Edge, Arc, Vivaldi или Chromium (Safari не изолируется)"
                    : (vm.isProtectionActive ? "Запуск изолированного браузера в песочнице" : "Сначала включите защиту VPNGuard")
            )

            if !vm.hasSupportedBrowser {
                HStack(spacing: 6) {
                    Text("Не найден Chrome / Brave / Edge / Arc")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button(copiedBrewCommand ? "Скопировано" : "brew install") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString("brew install --cask brave-browser", forType: .string)
                        copiedBrewCommand = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                            copiedBrewCommand = false
                        }
                    }
                    .buttonStyle(.borderless)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(VGTheme.accentPrimary)
                }
                .padding(.horizontal, 4)
            }
        }
    }

    // MARK: - Bottom Actions
    private var bottomActions: some View {
        HStack(spacing: 8) {
            MenuBarActionButton(title: "Аудит утечек", icon: "checkmark.shield") {
                vm.requestedNavigationSection = .diagnostics
                onOpenSettings()
                Task { await vm.runSecurityAudit() }
            }

            MenuBarActionButton(title: "Настройки…", icon: "gearshape") {
                onOpenSettings()
            }
            .keyboardShortcut(",", modifiers: .command)

            Button {
                NSApp.terminate(nil)
            } label: {
                Image(systemName: "power")
                    .font(VGTokens.Typography.captionEmphasis)
                    .frame(width: 30, height: 28)
            }
            .buttonStyle(VGSurfaceButtonStyle())
            .help("Выход из VPNGuard")
            .accessibilityLabel("Выйти из VPNGuard")
        }
    }
}

private struct MenuBarActionButton: View {
    let title: String
    let icon: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: VGPrimitives.Space.s4) {
                Image(systemName: icon)
                    .font(VGTokens.Typography.caption)
                    .accessibilityHidden(true)
                Text(title)
                    .font(VGTokens.Typography.captionEmphasis)
                    .lineLimit(1)
            }
            .foregroundStyle(VGTokens.Colors.textPrimary)
            .frame(maxWidth: .infinity)
            .frame(height: 28)
        }
        .buttonStyle(VGSurfaceButtonStyle())
    }
}

/// Keeps the MenuBarExtra(.window) top edge pinned below the menu bar when dynamic banners resize the popover.
private struct MenuBarWindowAnchor: NSViewRepresentable {
    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        DispatchQueue.main.async {
            context.coordinator.attach(to: view.window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            context.coordinator.attach(to: nsView.window)
            context.coordinator.reanchorIfNeeded()
        }
    }

    final class Coordinator {
        private weak var window: NSWindow?
        private var observers: [NSObjectProtocol] = []
        private var anchorMaxY: CGFloat?
        private var lastScreenID: ObjectIdentifier?
        private var isAdjustingFrame = false

        deinit {
            removeObservers()
        }

        private func removeObservers() {
            for observer in observers {
                NotificationCenter.default.removeObserver(observer)
            }
            observers.removeAll()
        }

        func attach(to window: NSWindow?) {
            guard let window, self.window !== window else { return }
            removeObservers()
            self.window = window
            resetAnchor(for: window)

            let nc = NotificationCenter.default
            observers.append(nc.addObserver(
                forName: NSWindow.didResizeNotification,
                object: window,
                queue: .main
            ) { [weak self] _ in
                self?.reanchorIfNeeded()
            })
            observers.append(nc.addObserver(
                forName: NSWindow.didBecomeKeyNotification,
                object: window,
                queue: .main
            ) { [weak self] _ in
                guard let self, let win = self.window else { return }
                self.resetAnchor(for: win)
                self.reanchorIfNeeded()
            })
            observers.append(nc.addObserver(
                forName: NSWindow.didChangeScreenNotification,
                object: window,
                queue: .main
            ) { [weak self] _ in
                guard let self, let win = self.window else { return }
                self.resetAnchor(for: win)
                self.reanchorIfNeeded()
            })
        }

        private func resetAnchor(for window: NSWindow) {
            let screen = window.screen ?? NSScreen.main
            self.lastScreenID = screen.map { ObjectIdentifier($0) }
            if let visibleMaxY = screen?.visibleFrame.maxY {
                self.anchorMaxY = window.frame.maxY >= visibleMaxY - 20 ? window.frame.maxY : (visibleMaxY - 4)
            } else {
                self.anchorMaxY = window.frame.maxY
            }
        }

        func reanchorIfNeeded() {
            guard !isAdjustingFrame,
                  let window, window.isVisible,
                  let screen = window.screen ?? NSScreen.main else { return }

            let currentScreenID = ObjectIdentifier(screen)
            if lastScreenID != currentScreenID {
                resetAnchor(for: window)
            }

            let visible = screen.visibleFrame
            let targetMaxY = min(anchorMaxY ?? (visible.maxY - 4), visible.maxY)
            let frame = window.frame
            if frame.maxY < targetMaxY - 6 {
                let newY = max(visible.minY, targetMaxY - frame.height)
                if abs(frame.origin.y - newY) > 0.5 {
                    isAdjustingFrame = true
                    window.setFrameOrigin(NSPoint(x: frame.origin.x, y: newY))
                    isAdjustingFrame = false
                }
            }
        }
    }
}
