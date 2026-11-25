import SwiftUI
import AppKit

public struct MenuBarExtraView: View {
    @ObservedObject var vm: VPNGuardViewModel
    var onOpenSettings: () -> Void

    public init(vm: VPNGuardViewModel, onOpenSettings: @escaping () -> Void) {
        self.vm = vm
        self.onOpenSettings = onOpenSettings
    }

    public var body: some View {
        VStack(spacing: 12) {
            // MARK: - Compact Status Header
            statusHeader

            // MARK: - Update Available Quick Banner
            if vm.updateCheckResult?.updateAvailable == true {
                updateBanner
            }

            // MARK: - Public Wi-Fi Pause Banner / Action
            if let countdown = vm.menuBarPauseText {
                activePauseBanner(countdown: countdown)
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
        .padding(14)
        .frame(width: 356)
        .background(VGTheme.backgroundContent)
    }

    // MARK: - Status Header
    private var statusHeader: some View {
        let isPaused = vm.pauseRemainingSeconds > 0
        let tint: Color = vm.isProtectionActive
            ? VGTheme.statusProtected
            : (isPaused ? VGTheme.statusWarning : VGTheme.statusDanger)

        return VGCard(padding: 12) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(tint.opacity(0.15))
                        .frame(width: 36, height: 36)
                        .shadow(color: vm.isProtectionActive ? tint.opacity(0.28) : .clear, radius: 8)

                    Image(systemName: vm.isProtectionActive ? "shield.lefthalf.filled" : (isPaused ? "pause.circle.fill" : "shield.slash.fill"))
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(tint)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(vm.isProtectionActive ? "Защита активна" : (isPaused ? "Пауза Public Wi-Fi" : "Защита отключена"))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)

                    Text(headerSubtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 8)

                if vm.isTogglingPower {
                    ProgressView()
                        .controlSize(.small)
                        .frame(width: 38, height: 22)
                } else {
                    Toggle("", isOn: Binding(
                        get: { vm.isProtectionActive },
                        set: { _ in
                            Task { await vm.toggleProtection() }
                        }
                    ))
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .labelsHidden()
                    .tint(VGTheme.statusProtected)
                    .disabled(vm.isTogglingPause)
                    .help(vm.isProtectionActive ? "Отключить защиту VPNGuard" : "Включить защиту VPNGuard")
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
        return "Прямой доступ без фильтрации"
    }

    private var updateBanner: some View {
        VGCard(padding: 10, accentBorder: VGTheme.accentPrimary.opacity(0.35)) {
            HStack(spacing: 10) {
                Image(systemName: "arrow.down.app.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(VGTheme.accentPrimary)

                Text("Доступно обновление")
                    .font(.system(size: 12, weight: .semibold))

                Spacer()

                Button("Обновить") {
                    onOpenSettings()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
        }
    }

    private func activePauseBanner(countdown: String) -> some View {
        VGCard(padding: 10, accentBorder: VGTheme.statusWarning.opacity(0.35)) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "wifi.exclamationmark")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(VGTheme.statusWarning)
                    Text("Временный прямой доступ (Wi-Fi)")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(countdown)
                        .font(.system(size: 12, weight: .bold, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(VGTheme.statusWarning)
                }

                HStack(spacing: 8) {
                    Button {
                        Task { await vm.resumeFromPauseNow() }
                    } label: {
                        Text("Вернуть защиту")
                            .font(.system(size: 11, weight: .semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 5)
                            .background(VGTheme.statusProtected.opacity(0.16), in: RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous))
                            .foregroundStyle(VGTheme.statusProtected)
                    }
                    .buttonStyle(.plain)
                    .disabled(vm.isTogglingPause)

                    Button {
                        Task { await vm.pauseForWifi(seconds: 900) }
                    } label: {
                        Text("15 мин")
                            .font(.system(size: 11, weight: .medium))
                            .monospacedDigit()
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(VGTheme.surfaceLevel2, in: RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
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
                Text("Пауза на 5 мин (Public Wi-Fi)")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.primary)
                Spacer()
                Text("Автовозврат")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(VGTheme.surfaceLevel1, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                    .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
            )
        }
        .buttonStyle(.plain)
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
                            Task { await vm.activateServer(id: server.id) }
                        } label: {
                            HStack {
                                if server.isActive {
                                    Image(systemName: "checkmark")
                                }
                                Text(server.name)
                            }
                        }
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
                    Text(vm.status.exitIp ?? (vm.isProtectionActive ? "Определяется…" : "—"))
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
                Text("Утечек:")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Text("\(vm.status.pfBlockedPackets)")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .monospacedDigit()
                    .foregroundStyle(.primary)
            }
        }
    }

    // MARK: - Protected Browser
    private var protectedBrowserButton: some View {
        Button {
            Task { await vm.launchProtectedBrowser() }
        } label: {
            HStack(spacing: 8) {
                if vm.isLaunchingBrowser {
                    ProgressView().controlSize(.mini)
                } else {
                    Image(systemName: "safari")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(vm.isProtectionActive ? VGTheme.accentPrimary : .secondary)
                }
                Text("Открыть защищённый браузер")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(vm.isProtectionActive ? .primary : .secondary)
                Spacer()
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(VGTheme.surfaceLevel1, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                    .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
            )
        }
        .buttonStyle(.plain)
        .disabled(!vm.isProtectionActive || vm.isLaunchingBrowser)
        .help(vm.isProtectionActive ? "Запуск изолированного браузера в песочнице" : "Сначала включите защиту VPNGuard")
    }

    // MARK: - Bottom Actions
    private var bottomActions: some View {
        HStack(spacing: 8) {
            MenuBarActionButton(title: "Аудит утечек", icon: "checkmark.shield") {
                vm.requestedNavigationSection = .diagnostics
                onOpenSettings()
                Task { await vm.runSecurityAudit() }
            }

            MenuBarActionButton(title: "Контрольный центр", icon: "macwindow") {
                onOpenSettings()
            }

            Button {
                NSApp.terminate(nil)
            } label: {
                Image(systemName: "power")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(.secondary)
                    .frame(width: 30, height: 28)
                    .background(VGTheme.surfaceLevel1, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                            .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
                    )
            }
            .buttonStyle(.plain)
            .help("Выход из VPNGuard")
        }
    }
}

private struct MenuBarActionButton: View {
    let title: String
    let icon: String
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 11))
                Text(title)
                    .font(.system(size: 11, weight: .medium))
                    .lineLimit(1)
            }
            .foregroundStyle(.primary)
            .frame(maxWidth: .infinity)
            .frame(height: 28)
            .background(
                RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                    .fill(isHovered ? VGTheme.surfaceHover : VGTheme.surfaceLevel1)
            )
            .overlay(
                RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                    .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
            )
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
    }
}
