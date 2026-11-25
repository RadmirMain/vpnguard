import SwiftUI

public enum NavigationSection: String, CaseIterable, Identifiable {
    case dashboard = "Обзор"
    case apps = "Приложения"
    case websites = "Сайты и домены"
    case traffic = "Монитор трафика"
    case server = "Сервер"
    
    public var id: String { rawValue }
    
    public var iconName: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .apps: return "app.badge.checkmark"
        case .websites: return "globe"
        case .traffic: return "waveform.path.ecg"
        case .server: return "server.rack"
        }
    }
}

public struct MainContainerView: View {
    @ObservedObject var vm: VPNGuardViewModel
    @State private var selectedSection: NavigationSection? = .dashboard
    
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
                            .fill(vm.isProtectionActive ? Color.green : Color.orange)
                            .frame(width: 6, height: 6)
                        Text(vm.isProtectionActive ? "Защита активна" : "Защита отключена")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
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
        .onDisappear {
            TrafficMonitorService.shared.stopMonitoring()
        }
    }
}
