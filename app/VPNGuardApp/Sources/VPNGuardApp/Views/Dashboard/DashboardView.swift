import SwiftUI

public struct DashboardView: View {
    @ObservedObject var vm: VPNGuardViewModel

    public var body: some View {
        VStack(spacing: 0) {
            VGPageHeader(
                title: "Обзор",
                subtitle: "Состояние изоляции трафика, демонов и проверка утечек"
            ) {
                HStack(spacing: 8) {
                    Button {
                        Task { await vm.refreshStatus(fast: false) }
                    } label: {
                        Label("Обновить", systemImage: "arrow.clockwise")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .help("Обновить статус и внешний IP")

                    Button {
                        Task { await vm.toggleProtection() }
                    } label: {
                        HStack(spacing: 6) {
                            if vm.isTogglingPower {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: "power")
                                    .font(.system(size: 11, weight: .semibold))
                            }
                            Text(vm.isKillSwitchArmed ? "Отключить" : "Включить")
                                .font(.system(size: 12, weight: .semibold))
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(
                            vm.isKillSwitchArmed
                                ? VGTheme.statusDanger.opacity(0.14)
                                : VGTheme.statusProtected,
                            in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                        )
                        .foregroundStyle(vm.isKillSwitchArmed ? VGTheme.statusDanger : .white)
                        .overlay(
                            RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                                .strokeBorder(
                                    vm.isKillSwitchArmed ? VGTheme.statusDanger.opacity(0.3) : .clear,
                                    lineWidth: 0.75
                                )
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(vm.isTogglingPower)
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: VGTheme.sectionSpacing) {
                    heroStatusCard

                    if let statusErr = vm.statusError {
                        VGCard(padding: 12, accentBorder: VGTheme.statusDanger.opacity(0.35)) {
                            HStack(spacing: 10) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(VGTheme.statusDanger)
                                Text("Ошибка опроса CLI: \(statusErr). Убедитесь, что выполнен `sudo ./install.sh`.")
                                    .font(.system(size: 12))
                                    .foregroundStyle(.primary)
                                Spacer()
                                Button("Повторить") {
                                    Task { await vm.refreshStatus(fast: false) }
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 12) {
                        VGSectionHeader("Компоненты безопасности")

                        Grid(horizontalSpacing: 14, verticalSpacing: 14) {
                            GridRow {
                                daemonCard(
                                    title: "vpnguard-xray",
                                    subtitle: "VLESS XHTTP • GID 889",
                                    isRunning: vm.status.xrayRunning.running,
                                    icon: "bolt.shield",
                                    iconTint: VGTheme.accentPrimary,
                                    details: [
                                        ("PID", VGFormatters.formatPID(vm.status.xrayRunning.pid)),
                                        ("Пользователь", vm.status.xrayRunning.user ?? "_vpnguard_proxy"),
                                        ("Локальные порты", "127.0.0.1:18088 / 18089"),
                                        ("Сервер", vm.activeServer?.name ?? vm.status.activeServerName ?? "—"),
                                        ("Входной релей", vm.status.relayIp ?? "—")
                                    ]
                                )

                                daemonCard(
                                    title: "vpnguard-singbox",
                                    subtitle: "TUN gVisor • GID 890",
                                    isRunning: vm.status.singboxRunning.running,
                                    icon: "network.badge.shield.half.filled",
                                    iconTint: VGTheme.accentPrimary,
                                    details: [
                                        ("PID", VGFormatters.formatPID(vm.status.singboxRunning.pid)),
                                        ("Интерфейс", vm.status.utunInterface ?? "utun99"),
                                        ("IP-адресация", "172.19.0.1/30"),
                                        ("Стек", "gVisor (Hijack-DNS)")
                                    ]
                                )
                            }

                            GridRow {
                                daemonCard(
                                    title: "PF Kill-Switch",
                                    subtitle: "XNU Packet Filter Fail-Closed",
                                    isRunning: vm.status.pfEnabled,
                                    icon: "lock.shield",
                                    iconTint: vm.status.pfEnabled ? VGTheme.statusProtected : VGTheme.statusDanger,
                                    details: [
                                        ("Статус PF", vm.status.pfEnabled ? "Включён" : "Отключён"),
                                        ("Правил в анкоре", "\(vm.status.pfRulesCount)"),
                                        ("Заблокировано", "\(vm.status.pfBlockedPackets) пак."),
                                        ("Изоляция", "Dual-GID 889 / 890")
                                    ]
                                )

                                daemonCard(
                                    title: "Выходной туннель",
                                    subtitle: "Egress & DNS Posture",
                                    isRunning: vm.isProtectionActive && vm.status.exitIp != nil,
                                    icon: "globe.americas.fill",
                                    iconTint: VGTheme.statusProtected,
                                    details: [
                                        ("Выходной IP", vm.status.exitIp ?? "—"),
                                        ("Локация", vm.status.exitLocation ?? "—"),
                                        ("Утечка РФ", vm.isProtectionActive ? "Исключена" : "Не защищено"),
                                        ("DNS-резолв", "1.1.1.1 Remote DoH")
                                    ]
                                )
                            }
                        }
                    }

                    auditSection
                }
                .padding(VGTheme.pagePadding)
            }
        }
    }

    // MARK: - Hero Status Card
    private var heroStatusCard: some View {
        VGCard(
            padding: 18,
            accentBorder: vm.isProtectionActive ? VGTheme.statusProtected.opacity(0.28) : VGTheme.statusWarning.opacity(0.28)
        ) {
            VStack(spacing: 14) {
                HStack(spacing: 16) {
                    ZStack {
                        RoundedRectangle(cornerRadius: VGTheme.radiusCard, style: .continuous)
                            .fill((vm.isProtectionActive ? VGTheme.statusProtected : VGTheme.statusWarning).opacity(0.14))
                            .frame(width: 48, height: 48)

                        Image(systemName: vm.isProtectionActive ? "checkmark.shield.fill" : (vm.isTunnelRecovering ? "exclamationmark.shield.fill" : "shield.slash.fill"))
                            .font(.system(size: 22, weight: .semibold))
                            .foregroundStyle(vm.isProtectionActive ? VGTheme.statusProtected : VGTheme.statusWarning)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text(vm.isProtectionActive ? "Защита VPNGuard активна" : (vm.isTunnelRecovering ? "PF Kill-Switch активен" : "Защита VPNGuard отключена"))
                                .font(.system(size: 16, weight: .semibold))
                                .foregroundStyle(.primary)

                            VGStatusBadge(
                                vm.isProtectionActive ? "Активен" : (vm.isTunnelRecovering ? "Восстановление" : "Отключён"),
                                tone: vm.isProtectionActive ? .protected : .warning,
                                showDot: true
                            )
                        }

                        Text(
                            vm.isProtectionActive
                                ? "Трафик изолирован в Dual-GID туннеле. Защита от утечек и мигания включена."
                                : (vm.isTunnelRecovering
                                    ? "PF Kill-Switch активен — туннель восстанавливается. Прямые утечки заблокированы."
                                    : "Сетевой фильтр деактивирован. Прямой доступ разрешён (режим Captive Portal).")
                        )
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                    }

                    Spacer()
                }

                Divider().opacity(0.5)

                HStack(spacing: 20) {
                    summaryMetric(
                        label: "Сервер",
                        value: vm.activeServer?.name ?? vm.status.activeServerName ?? "—"
                    )

                    Divider().frame(height: 22).opacity(0.5)

                    HStack(spacing: 6) {
                        summaryMetric(
                            label: "Выходной IP",
                            value: vm.status.exitIp ?? "—",
                            monospaced: true
                        )
                        if let ip = vm.status.exitIp, !ip.isEmpty {
                            VGCopyButton(ip, helpText: "Скопировать выходной IP")
                        }
                    }

                    Divider().frame(height: 22).opacity(0.5)

                    summaryMetric(
                        label: "PF Kill-Switch",
                        value: vm.status.pfEnabled
                            ? "Активен (\(vm.status.pfBlockedPackets) блок.)"
                            : "Выключен",
                        monospaced: true
                    )

                    Spacer()
                }
            }
        }
    }

    private func summaryMetric(label: String, value: String, monospaced: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 12, weight: .semibold, design: monospaced ? .monospaced : .default))
                .monospacedDigit()
                .foregroundStyle(.primary)
                .lineLimit(1)
        }
    }

    // MARK: - Daemon Card
    private func daemonCard(
        title: String,
        subtitle: String,
        isRunning: Bool,
        icon: String,
        iconTint: Color,
        details: [(String, String)]
    ) -> some View {
        VGCard(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                            .fill(iconTint.opacity(0.14))
                            .frame(width: 32, height: 32)
                        Image(systemName: icon)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(iconTint)
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text(title)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.primary)
                        Text(subtitle)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    Spacer(minLength: 8)

                    VGStatusBadge(
                        isRunning ? "Активен" : "Отключён",
                        tone: isRunning ? .protected : .danger,
                        showDot: true
                    )
                }

                Divider().opacity(0.45)

                VStack(spacing: 7) {
                    ForEach(details, id: \.0) { label, val in
                        VGKeyValueRow(label, value: val)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .frame(maxHeight: .infinity)
    }

    // MARK: - Audit Section Shortcut
    private var auditSection: some View {
        VGCard(padding: 16) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                        .fill(VGTheme.accentPrimary.opacity(0.14))
                        .frame(width: 36, height: 36)
                    Image(systemName: "stethoscope")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(VGTheme.accentPrimary)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text("Аудит утечек и системные логи")
                        .font(.system(size: 13, weight: .semibold))
                    if let report = vm.auditReport {
                        Text(report.passed
                             ? "Последняя проверка: все \(report.total) тестов пройдены"
                             : "Последняя проверка: пройдено \(report.passedCount) из \(report.total) тестов")
                            .font(.system(size: 12))
                            .monospacedDigit()
                            .foregroundStyle(report.passed ? VGTheme.statusProtected : VGTheme.statusWarning)
                    } else {
                        Text("12-точечная проверка PF, GID 888/889/890, DNS, utun99 и просмотр логов")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()

                Button("Логи и аудит") {
                    vm.requestedNavigationSection = .diagnostics
                }
                .buttonStyle(.bordered)

                Button {
                    vm.requestedNavigationSection = .diagnostics
                    Task { await vm.runSecurityAudit() }
                } label: {
                    HStack(spacing: 6) {
                        if vm.isRunningAudit {
                            ProgressView().controlSize(.small)
                            Text("Аудит…")
                        } else {
                            Image(systemName: "play.fill")
                                .font(.system(size: 10))
                            Text("Проверить утечки")
                        }
                    }
                    .font(.system(size: 12, weight: .semibold))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(VGTheme.accentPrimary, in: RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous))
                    .foregroundStyle(.white)
                }
                .buttonStyle(.plain)
                .disabled(vm.isRunningAudit)
            }
        }
    }
}
