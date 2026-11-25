import SwiftUI

public struct DashboardView: View {
    @ObservedObject var vm: VPNGuardViewModel
    
    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Main Status Banner
                mainStatusBanner

                if let statusErr = vm.statusError {
                    GlassCard(padding: 12) {
                        HStack(spacing: 10) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text("Ошибка опроса CLI: \(statusErr). Убедитесь, что выполнен `sudo ./install.sh`.")
                                .font(.system(size: 12))
                                .foregroundColor(.primary)
                            Spacer()
                            Button("Повторить") {
                                Task { await vm.refreshStatus(fast: false) }
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                    }
                }
                
                // Daemons & Network Posture Grid
                Text("Компоненты безопасности")
                    .font(.headline)
                    .foregroundColor(.secondary)
                
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)], spacing: 14) {
                    daemonCard(
                        title: "vpnguard-xray",
                        subtitle: "VLESS xhttp / GID 889",
                        isRunning: vm.status.xrayRunning.running,
                        icon: "bolt.shield",
                        color: .indigo,
                        details: [
                            ("PID:", vm.status.xrayRunning.pid != nil ? "\(vm.status.xrayRunning.pid!)" : "—"),
                            ("Пользователь:", vm.status.xrayRunning.user ?? "_vpnguard_proxy"),
                            ("Порты:", "127.0.0.1:18088 / 18089"),
                            ("Сервер:", vm.activeServer?.name ?? vm.status.activeServerName ?? "—"),
                            ("Входной релей:", vm.status.relayIp ?? "—")
                        ]
                    )
                    
                    daemonCard(
                        title: "vpnguard-singbox",
                        subtitle: "TUN gVisor / GID 890",
                        isRunning: vm.status.singboxRunning.running,
                        icon: "network.badge.shield.half.filled",
                        color: .blue,
                        details: [
                            ("PID:", vm.status.singboxRunning.pid != nil ? "\(vm.status.singboxRunning.pid!)" : "—"),
                            ("Интерфейс:", vm.status.utunInterface ?? "utun99"),
                            ("IP адресация:", "172.19.0.1/30"),
                            ("Стек:", "gVisor (Hijack-DNS)")
                        ]
                    )
                    
                    daemonCard(
                        title: "PF Kill-Switch",
                        subtitle: "XNU Packet Filter Fail-Closed",
                        isRunning: vm.status.pfEnabled,
                        icon: "lock.shield",
                        color: .red,
                        details: [
                            ("Статус PF:", vm.status.pfEnabled ? "ENABLED" : "OFF"),
                            ("Правил в анкоре:", "\(vm.status.pfRulesCount)"),
                            ("Заблокировано:", "\(vm.status.pfBlockedPackets) пакетов"),
                            ("Изоляция:", "Dual-GID 889 / 890")
                        ]
                    )
                    
                    daemonCard(
                        title: "Выходной туннель",
                        subtitle: "Egress Posture",
                        isRunning: vm.isProtectionActive && vm.status.exitIp != nil,
                        icon: "globe.americas.fill",
                        color: .teal,
                        details: [
                            ("Выходной IP:", vm.status.exitIp ?? "—"),
                            ("Локация:", vm.status.exitLocation ?? "—"),
                            ("Утечка RU:", "ИСКЛЮЧЕНА (Защищено)"),
                            ("DNS-резолв:", "1.1.1.1 Remote DoH")
                        ]
                    )
                }
                
                // Audit Suite Section
                auditSection
            }
            .padding(24)
        }
    }
    
    // MARK: - Banner
    private var mainStatusBanner: some View {
        GlassCard(padding: 20) {
            HStack(spacing: 20) {
                ZStack {
                    Circle()
                        .fill(vm.isProtectionActive ? Color.green.opacity(0.15) : Color.orange.opacity(0.15))
                        .frame(width: 60, height: 60)
                    
                    Image(systemName: vm.isProtectionActive ? "checkmark.shield.fill" : "shield.slash.fill")
                        .font(.system(size: 30))
                        .foregroundColor(vm.isProtectionActive ? .green : .orange)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(vm.isProtectionActive ? "Защита VPNGuard активна" : "Защита VPNGuard отключена")
                        .font(.title2.bold())
                        .foregroundColor(.primary)
                    
                    Text(vm.isProtectionActive
                         ? "Трафик приложений изолирован в Dual-GID туннеле. Защита от мигания и утечек включена."
                         : "Сетевой фильтр деактивирован. Прямой доступ разрешен (режим Captive Portal).")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Spacer()

                Button {
                    Task {
                        await vm.refreshStatus(fast: false)
                    }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 13, weight: .semibold))
                        .padding(10)
                        .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                }
                .buttonStyle(.plain)
                .help("Обновить статус и внешний IP")

                Button {
                    Task {
                        await vm.toggleProtection()
                    }
                } label: {
                    HStack(spacing: 8) {
                        if vm.isTogglingPower {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "power")
                        }
                        Text(vm.isProtectionActive ? "Отключить" : "Включить")
                    }
                    .font(.system(size: 13, weight: .semibold))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(
                        vm.isProtectionActive
                            ? AnyShapeStyle(Color.red.opacity(0.15))
                            : AnyShapeStyle(Color.green.gradient),
                        in: RoundedRectangle(cornerRadius: 8)
                    )
                    .foregroundColor(vm.isProtectionActive ? .red : .white)
                }
                .buttonStyle(.plain)
                .disabled(vm.isTogglingPower)
            }
        }
    }
    
    // MARK: - Daemon Card
    private func daemonCard(title: String, subtitle: String, isRunning: Bool, icon: String, color: Color, details: [(String, String)]) -> some View {
        GlassCard(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .fill(color.opacity(0.15))
                            .frame(width: 32, height: 32)
                        Image(systemName: icon)
                            .font(.system(size: 16))
                            .foregroundColor(color)
                    }
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title)
                            .font(.system(size: 14, weight: .bold))
                        Text(subtitle)
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                    
                    HStack(spacing: 4) {
                        Circle()
                            .fill(isRunning ? Color.green : Color.red)
                            .frame(width: 6, height: 6)
                        Text(isRunning ? "ACTIVE" : "DOWN")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(isRunning ? .green : .red)
                    }
                }
                
                Divider().opacity(0.5)
                
                VStack(spacing: 6) {
                    ForEach(details, id: \.0) { label, val in
                        HStack {
                            Text(label)
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                            Spacer()
                            Text(val)
                                .font(.system(size: 11, weight: .medium, design: .monospaced))
                        }
                    }
                }
            }
        }
    }
    
    // MARK: - Audit Section (Summary + Shortcut to Diagnostics Tab)
    private var auditSection: some View {
        GlassCard(padding: 16) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.blue.opacity(0.14))
                        .frame(width: 36, height: 36)
                    Image(systemName: "stethoscope")
                        .font(.system(size: 16))
                        .foregroundColor(.blue)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text("Аудит утечек и системные логи")
                        .font(.system(size: 14, weight: .bold))
                    if let report = vm.auditReport {
                        Text(report.passed
                             ? "Последняя проверка: все \(report.total) тестов пройдены"
                             : "Последняя проверка: пройдено \(report.passedCount) из \(report.total) тестов")
                            .font(.system(size: 12))
                            .foregroundColor(report.passed ? .green : .orange)
                    } else {
                        Text("12-точечная проверка PF, GID 888/889/890, DNS, utun99 и просмотр логов")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()

                Button("Открыть вкладку") {
                    vm.requestedNavigationSection = .diagnostics
                }
                .buttonStyle(.bordered)

                Button {
                    vm.requestedNavigationSection = .diagnostics
                    Task {
                        await vm.runSecurityAudit()
                    }
                } label: {
                    HStack(spacing: 6) {
                        if vm.isRunningAudit {
                            ProgressView().scaleEffect(0.65)
                            Text("Аудит...")
                        } else {
                            Image(systemName: "play.fill")
                            Text("Проверить утечки")
                        }
                    }
                    .font(.system(size: 12, weight: .semibold))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color.blue.gradient, in: RoundedRectangle(cornerRadius: 8))
                    .foregroundColor(.white)
                }
                .buttonStyle(.plain)
                .disabled(vm.isRunningAudit)
            }
        }
    }
}
