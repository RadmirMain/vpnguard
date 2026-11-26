import SwiftUI

public struct DashboardView: View {
    @ObservedObject var vm: VPNGuardViewModel

    public var body: some View {
        VStack(spacing: 0) {
            VGPageHeader(
                title: "Обзор",
                subtitle: "Состояние изоляции трафика, демонов и проверка утечек"
            ) {
                HStack(spacing: VGTokens.Spacing.inlineGap) {
                    Button {
                        Task { await vm.refreshStatus(fast: false) }
                    } label: {
                        Label("Обновить", systemImage: "arrow.clockwise")
                            .font(VGTokens.Typography.bodyEmphasis)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .help("Обновить статус и внешний IP")

                    Button {
                        Task { await vm.toggleProtection() }
                    } label: {
                        HStack(spacing: VGPrimitives.Space.s6) {
                            if vm.isTogglingPower {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: "power")
                                    .font(VGTokens.Typography.captionEmphasis)
                            }
                            Text(vm.isKillSwitchArmed ? "Отключить" : "Включить")
                                .font(VGTokens.Typography.bodyEmphasis)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(vm.isKillSwitchArmed ? VGTokens.Colors.statusDanger : VGTokens.Colors.statusProtectedFill)
                    .controlSize(.regular)
                    .disabled(vm.isTogglingPower)
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: VGTheme.sectionSpacing) {
                    heroStatusCard

                    if let statusErr = vm.statusError {
                        VGErrorBanner(
                            message: "Ошибка опроса CLI: \(statusErr). Убедитесь, что выполнен `sudo ./install.sh`.",
                            retryTitle: "Повторить"
                        ) {
                            Task { await vm.refreshStatus(fast: false) }
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
        let statusTint = vm.isProtectionActive ? VGTokens.Colors.statusProtected : VGTokens.Colors.statusWarning
        return VGCard(
            padding: VGTokens.Spacing.cardPadding,
            accentBorder: statusTint.opacity(0.28)
        ) {
            VStack(spacing: VGPrimitives.Space.s14) {
                HStack(spacing: VGTokens.Spacing.cardPadding) {
                    ZStack {
                        RoundedRectangle(cornerRadius: VGTokens.Radius.card, style: .continuous)
                            .fill(statusTint.opacity(VGComponentTokens.Badge.fillOpacity))
                            .frame(width: 48, height: 48)

                        Image(systemName: vm.isProtectionActive ? "checkmark.shield.fill" : (vm.isTunnelRecovering ? "exclamationmark.shield.fill" : "shield.slash.fill"))
                            .font(.system(size: 22, weight: .semibold))
                            .foregroundStyle(statusTint)
                    }
                    .accessibilityHidden(true)

                    VStack(alignment: .leading, spacing: VGTokens.Spacing.microGap) {
                        HStack(spacing: VGTokens.Spacing.inlineGap) {
                            Text(vm.isProtectionActive ? "Защита VPNGuard активна" : (vm.isTunnelRecovering ? "PF Kill-Switch активен" : "Защита VPNGuard отключена"))
                                .font(VGTokens.Typography.sectionTitle)
                                .foregroundStyle(VGTokens.Colors.textPrimary)

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
                        .font(VGTokens.Typography.body)
                        .foregroundStyle(VGTokens.Colors.textSecondary)
                    }

                    Spacer()
                }

                Divider().opacity(0.5)

                ViewThatFits(in: .horizontal) {
                    HStack(spacing: VGTokens.Spacing.sectionGap) {
                        summaryMetric(
                            label: "Сервер",
                            value: vm.activeServer?.name ?? vm.status.activeServerName ?? "—"
                        )

                        Divider().frame(height: 22).opacity(0.5)

                        HStack(spacing: VGPrimitives.Space.s6) {
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

                    VStack(alignment: .leading, spacing: VGTokens.Spacing.inlineGap) {
                        summaryMetric(
                            label: "Сервер",
                            value: vm.activeServer?.name ?? vm.status.activeServerName ?? "—"
                        )
                        HStack(spacing: VGPrimitives.Space.s6) {
                            summaryMetric(
                                label: "Выходной IP",
                                value: vm.status.exitIp ?? "—",
                                monospaced: true
                            )
                            if let ip = vm.status.exitIp, !ip.isEmpty {
                                VGCopyButton(ip, helpText: "Скопировать выходной IP")
                            }
                        }
                        summaryMetric(
                            label: "PF Kill-Switch",
                            value: vm.status.pfEnabled
                                ? "Активен (\(vm.status.pfBlockedPackets) блок.)"
                                : "Выключен",
                            monospaced: true
                        )
                    }
                }
            }
        }
    }

    private func summaryMetric(label: String, value: String, monospaced: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
            Text(label)
                .font(VGTokens.Typography.caption)
                .foregroundStyle(VGTokens.Colors.textSecondary)
            Text(value)
                .font(monospaced ? VGTokens.Typography.monoBody.weight(.semibold) : VGTokens.Typography.cardTitle)
                .monospacedDigit()
                .foregroundStyle(VGTokens.Colors.textPrimary)
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
        VGCard(padding: VGTokens.Spacing.cardPadding) {
            VStack(alignment: .leading, spacing: VGTokens.Spacing.gridGap) {
                HStack(spacing: VGPrimitives.Space.s10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: VGTokens.Radius.control, style: .continuous)
                            .fill(iconTint.opacity(VGComponentTokens.Badge.fillOpacity))
                            .frame(width: 32, height: 32)
                        Image(systemName: icon)
                            .font(VGTokens.Typography.cardTitle)
                            .foregroundStyle(iconTint)
                    }
                    .accessibilityHidden(true)

                    VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
                        Text(title)
                            .font(VGTokens.Typography.cardTitle)
                            .foregroundStyle(VGTokens.Colors.textPrimary)
                        Text(subtitle)
                            .font(VGTokens.Typography.caption)
                            .foregroundStyle(VGTokens.Colors.textSecondary)
                            .lineLimit(1)
                    }

                    Spacer(minLength: VGTokens.Spacing.inlineGap)

                    VGStatusBadge(
                        isRunning ? "Активен" : "Отключён",
                        tone: isRunning ? .protected : .danger,
                        showDot: true
                    )
                }

                Divider().opacity(0.45)

                VStack(spacing: VGPrimitives.Space.s6) {
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
        VGCard(padding: VGTokens.Spacing.cardPadding) {
            HStack(spacing: VGPrimitives.Space.s14) {
                ZStack {
                    RoundedRectangle(cornerRadius: VGTokens.Radius.control, style: .continuous)
                        .fill(VGTokens.Colors.accentPrimary.opacity(VGComponentTokens.Badge.fillOpacity))
                        .frame(width: 36, height: 36)
                    Image(systemName: "stethoscope")
                        .font(VGTokens.Typography.sectionTitle)
                        .foregroundStyle(VGTokens.Colors.accentPrimary)
                }
                .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
                    Text("Аудит утечек и системные логи")
                        .font(VGTokens.Typography.cardTitle)
                    if let report = vm.auditReport {
                        Text(report.passed
                             ? "Последняя проверка: все \(report.total) тестов пройдены"
                             : "Последняя проверка: пройдено \(report.passedCount) из \(report.total) тестов")
                            .font(VGTokens.Typography.body)
                            .monospacedDigit()
                            .foregroundStyle(report.passed ? VGTokens.Colors.statusProtected : VGTokens.Colors.statusWarning)
                    } else {
                        Text("12-точечная проверка PF, GID 888/889/890, DNS, utun99 и просмотр логов")
                            .font(VGTokens.Typography.body)
                            .foregroundStyle(VGTokens.Colors.textSecondary)
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
                    HStack(spacing: VGPrimitives.Space.s6) {
                        if vm.isRunningAudit {
                            ProgressView().controlSize(.small)
                            Text("Аудит…")
                        } else {
                            Image(systemName: "play.fill")
                                .font(VGTokens.Typography.caption)
                            Text("Проверить утечки")
                        }
                    }
                    .font(VGTokens.Typography.bodyEmphasis)
                }
                .buttonStyle(.borderedProminent)
                .tint(VGTokens.Colors.accentPrimary)
                .controlSize(.regular)
                .disabled(vm.isRunningAudit)
            }
        }
    }
}
