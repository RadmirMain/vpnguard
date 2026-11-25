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
        VStack(spacing: 14) {
            // Header
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: vm.isProtectionActive ? "shield.fill" : "shield.slash.fill")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(vm.isProtectionActive ? .green : .secondary)
                    
                    Text("VPNGuard")
                        .font(.system(size: 14, weight: .bold))
                }
                
                Spacer()
                
                if let countdown = vm.menuBarPauseText {
                    Text("ПАУЗА \(countdown)")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .monospacedDigit()
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(Color.orange.opacity(0.18), in: Capsule())
                        .foregroundColor(.orange)
                } else {
                    Text(vm.isProtectionActive ? "АКТИВЕН" : "ОТКЛЮЧЕН")
                        .font(.system(size: 10, weight: .bold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(vm.isProtectionActive ? Color.green.opacity(0.15) : Color.orange.opacity(0.15), in: Capsule())
                        .foregroundColor(vm.isProtectionActive ? .green : .orange)
                }
            }
            
            // Master Switch Button
            Button {
                Task {
                    await vm.toggleProtection()
                }
            } label: {
                HStack(spacing: 12) {
                    if vm.isTogglingPower {
                        ProgressView()
                            .scaleEffect(0.8)
                            .frame(width: 24, height: 24)
                    } else {
                        Image(systemName: "power")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundColor(vm.isProtectionActive ? .white : .primary)
                    }
                    
                    Text(vm.isProtectionActive ? "Защита VPNGuard включена" : "Включить защиту VPNGuard")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(vm.isProtectionActive ? .white : .primary)
                    
                    Spacer()
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(
                    vm.isProtectionActive
                        ? AnyShapeStyle(Color.green.gradient)
                        : AnyShapeStyle(Color.primary.opacity(0.06)),
                    in: RoundedRectangle(cornerRadius: 10, style: .continuous)
                )
            }
            .buttonStyle(.plain)
            .disabled(vm.isTogglingPower || vm.isTogglingPause)

            // Wi-Fi Captive Portal Pause / Countdown Controls
            if let countdown = vm.menuBarPauseText {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 6) {
                        Image(systemName: "wifi.exclamationmark")
                            .foregroundColor(.orange)
                            .font(.system(size: 12))
                        Text("Временный прямой доступ (Wi-Fi): \(countdown)")
                            .font(.system(size: 11, weight: .semibold))
                            .monospacedDigit()
                            .foregroundColor(.orange)
                        Spacer()
                    }
                    HStack(spacing: 8) {
                        Button {
                            Task { await vm.resumeFromPauseNow() }
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "shield.fill")
                                Text("Возобновить сейчас")
                            }
                            .font(.system(size: 11, weight: .semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                            .background(Color.green.opacity(0.18), in: RoundedRectangle(cornerRadius: 6))
                            .foregroundColor(.green)
                        }
                        .buttonStyle(.plain)
                        .disabled(vm.isTogglingPause)

                        Button {
                            Task { await vm.pauseForWifi(seconds: 900) }
                        } label: {
                            Text("15 мин")
                                .font(.system(size: 11, weight: .medium))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
                                .foregroundColor(.orange)
                        }
                        .buttonStyle(.plain)
                        .disabled(vm.isTogglingPause)
                        .help("Установить паузу на 15 минут")
                    }
                }
                .padding(10)
                .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.orange.opacity(0.25), lineWidth: 1)
                )
            } else if vm.isProtectionActive {
                Button {
                    Task { await vm.pauseForWifi(seconds: 300) }
                } label: {
                    HStack(spacing: 8) {
                        if vm.isTogglingPause {
                            ProgressView()
                                .scaleEffect(0.6)
                        } else {
                            Image(systemName: "wifi")
                                .font(.system(size: 12))
                                .foregroundColor(.orange)
                        }
                        Text("Пауза на 5 мин (вход в Wi-Fi)")
                            .font(.system(size: 12, weight: .medium))
                        Spacer()
                        Text("Автовозврат")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                }
                .buttonStyle(.plain)
                .disabled(vm.isTogglingPause || vm.isTogglingPower)
            }
            
            // Connection Card
            GlassCard(padding: 12) {
                VStack(alignment: .leading, spacing: 10) {
                    // Active Server row & quick switcher
                    HStack(alignment: .center) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("АКТИВНЫЙ СЕРВЕР")
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.secondary)
                            
                            HStack(spacing: 5) {
                                let serverName = vm.activeServer?.name ?? vm.status.activeServerName ?? "—"
                                Text(serverName)
                                    .font(.system(size: 12, weight: .semibold))
                                    .lineLimit(1)
                            }
                            if let relayIp = vm.status.relayIp, !relayIp.isEmpty {
                                Text("Входной релей: \(relayIp)")
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                        }
                        
                        Spacer()
                        
                        if vm.servers.count > 1 {
                            Menu {
                                ForEach(vm.servers) { server in
                                    Button {
                                        Task {
                                            await vm.activateServer(id: server.id)
                                        }
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
                                HStack(spacing: 3) {
                                    if vm.activatingServerId != nil {
                                        ProgressView()
                                            .scaleEffect(0.5)
                                    } else {
                                        Image(systemName: "arrow.triangle.2.circlepath")
                                            .font(.system(size: 10))
                                    }
                                    Text("Сменить")
                                        .font(.system(size: 11, weight: .medium))
                                }
                                .padding(.horizontal, 7)
                                .padding(.vertical, 4)
                                .background(Color.primary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()
                            .disabled(vm.activatingServerId != nil)
                        }
                    }
                    
                    Divider().opacity(0.4)
                    
                    // Exit IP row
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("ВЫХОДНОЙ IP")
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.secondary)
                            
                            HStack(spacing: 6) {
                                Text(vm.status.exitIp ?? "Определяется...")
                                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                    .foregroundColor(vm.status.exitIp != nil ? .primary : .secondary)
                                
                                if let ip = vm.status.exitIp {
                                    Button {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(ip, forType: .string)
                                        vm.showToast("IP скопирован в буфер", isError: false)
                                    } label: {
                                        Image(systemName: "doc.on.doc")
                                            .font(.system(size: 10))
                                            .foregroundColor(.secondary)
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                        }
                        
                        Spacer()
                        
                        if let loc = vm.status.exitLocation {
                            Text(loc)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.trailing)
                                .lineLimit(2)
                                .frame(maxWidth: 130, alignment: .trailing)
                        }
                    }
                    
                    Divider().opacity(0.4)
                    
                    // Daemons & Leaks
                    VStack(spacing: 6) {
                        HStack {
                            Circle()
                                .fill(vm.status.xrayRunning.running ? Color.green : Color.red)
                                .frame(width: 6, height: 6)
                            Text("Xray VLESS (GID 889):")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                            Spacer()
                            Text(vm.status.xrayRunning.running ? "PID \(vm.status.xrayRunning.pid ?? 0)" : "Не запущен")
                                .font(.system(size: 11, weight: .medium))
                        }
                        
                        HStack {
                            Circle()
                                .fill(vm.status.singboxRunning.running ? Color.green : Color.red)
                                .frame(width: 6, height: 6)
                            Text("sing-box TUN (GID 890):")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                            Spacer()
                            Text(vm.status.singboxRunning.running ? (vm.status.utunInterface ?? "utun") : "Не запущен")
                                .font(.system(size: 11, weight: .medium))
                        }
                        
                        HStack {
                            Image(systemName: "shield.lefthalf.filled")
                                .font(.system(size: 10))
                                .foregroundColor(.blue)
                            Text("Заблокировано утечек:")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                            Spacer()
                            Text("\(vm.status.pfBlockedPackets) пак.")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(.blue)
                        }
                    }
                }
            }
            
            // Protected Browser Sandbox Launcher (GID 888, non-sudo)
            Button {
                Task { await vm.launchProtectedBrowser() }
            } label: {
                HStack(spacing: 8) {
                    if vm.isLaunchingBrowser {
                        ProgressView()
                            .scaleEffect(0.6)
                    } else {
                        Image(systemName: "safari")
                            .font(.system(size: 12))
                            .foregroundColor(vm.isProtectionActive ? .blue : .secondary)
                    }
                    Text("Открыть защищённый браузер")
                        .font(.system(size: 12, weight: .medium))
                    Spacer()
                    Text("GID 888")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.primary.opacity(0.06), in: Capsule())
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.blue.opacity(vm.isProtectionActive ? 0.1 : 0.04), in: RoundedRectangle(cornerRadius: 8))
            }
            .buttonStyle(.plain)
            .disabled(!vm.isProtectionActive || vm.isLaunchingBrowser)
            .help(vm.isProtectionActive ? "Запуск изолированного браузера в GID 888 песочнице" : "Сначала включите защиту VPNGuard")

            // Action Buttons
            HStack(spacing: 8) {
                Button {
                    vm.requestedNavigationSection = .diagnostics
                    onOpenSettings()
                    Task {
                        await vm.runSecurityAudit()
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.shield")
                        Text("Аудит утечек")
                    }
                    .font(.system(size: 11, weight: .medium))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 6))
                }
                .buttonStyle(.plain)
                
                Button {
                    onOpenSettings()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "gearshape")
                        Text("Настройки")
                    }
                    .font(.system(size: 11, weight: .medium))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 6))
                }
                .buttonStyle(.plain)
                
                Button {
                    NSApp.terminate(nil)
                } label: {
                    Image(systemName: "power")
                        .font(.system(size: 11))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
                        .foregroundColor(.red)
                }
                .buttonStyle(.plain)
                .help("Завершить приложение")
            }
        }
        .padding(14)
        .frame(width: 320)
        .background(.ultraThinMaterial)
    }
}
