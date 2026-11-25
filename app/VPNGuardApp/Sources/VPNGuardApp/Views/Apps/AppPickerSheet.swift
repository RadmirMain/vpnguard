import SwiftUI
import AppKit

public struct AppPickerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var vm: VPNGuardViewModel
    
    @State private var installedApps: [DiscoveredApp] = []
    @State private var searchQuery: String = ""
    @State private var isLoading: Bool = true
    
    public init(vm: VPNGuardViewModel) {
        self.vm = vm
    }
    
    private var filteredApps: [DiscoveredApp] {
        if searchQuery.isEmpty {
            return installedApps
        }
        return installedApps.filter {
            $0.name.localizedCaseInsensitiveContains(searchQuery) ||
            $0.path.localizedCaseInsensitiveContains(searchQuery)
        }
    }
    
    public var body: some View {
        VStack(spacing: 16) {
            // Header
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Добавить приложение")
                        .font(.headline)
                    Text("Выберите программу для маршрутизации через VPNGuard")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                
                Button("Выбрать любой .app...") {
                    openFilePicker()
                }
                .buttonStyle(.bordered)
                
                Button("Закрыть") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20)
            .padding(.top, 16)
            
            // Search field
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Поиск среди установленных приложений...", text: $searchQuery)
                    .textFieldStyle(.plain)
                if !searchQuery.isEmpty {
                    Button {
                        searchQuery = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
            .padding(.horizontal, 20)
            
            // Apps list
            if isLoading {
                Spacer()
                ProgressView("Поиск установленных приложений...")
                Spacer()
            } else if filteredApps.isEmpty {
                Spacer()
                Text("Приложения не найдены")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                List(filteredApps) { app in
                    HStack(spacing: 12) {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                            .resizable()
                            .frame(width: 32, height: 32)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(app.name)
                                .font(.system(size: 13, weight: .semibold))
                            Text(app.path)
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        
                        Spacer()
                        
                        let isAlreadyAdded = vm.rules.apps.contains(where: { $0.bundlePath == app.path })
                        
                        if isAlreadyAdded {
                            Text("Добавлено")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.secondary)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(Color.secondary.opacity(0.1), in: Capsule())
                        } else {
                            Button("Добавить") {
                                vm.addApp(name: app.name, bundlePath: app.path, action: .proxy)
                                dismiss()
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                        }
                    }
                    .padding(.vertical, 4)
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .frame(width: 580, height: 460)
        .task {
            isLoading = true
            installedApps = await AppDiscoveryService.shared.scanInstalledApps()
            isLoading = false
        }
    }
    
    private func openFilePicker() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.application]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        
        if panel.runModal() == .OK, let selectedUrl = panel.url {
            let path = selectedUrl.path
            let name = (selectedUrl.lastPathComponent as NSString).deletingPathExtension
            vm.addApp(name: name, bundlePath: path, action: .proxy)
            dismiss()
        }
    }
}
