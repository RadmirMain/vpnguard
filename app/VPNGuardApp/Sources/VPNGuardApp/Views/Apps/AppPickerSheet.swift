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
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Добавить приложение")
                        .font(.system(size: 16, weight: .semibold))
                    Text("Выберите программу для маршрутизации через VPNGuard")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Выбрать .app…") {
                    openFilePicker()
                }
                .buttonStyle(.bordered)
            }
            .padding(VGTheme.sheetPadding)

            Divider().opacity(0.6)

            VGSearchField("Поиск среди установленных приложений…", text: $searchQuery)
                .padding(.horizontal, VGTheme.sheetPadding)
                .padding(.vertical, 12)

            Divider().opacity(0.5)

            if isLoading {
                VStack(spacing: 10) {
                    Spacer()
                    ProgressView()
                    Text("Поиск установленных приложений…")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if filteredApps.isEmpty {
                VGEmptyStateView(
                    icon: "app.dashed",
                    title: "Приложения не найдены",
                    message: "Попробуйте изменить поисковый запрос или выберите .app вручную."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(filteredApps) { app in
                            let isAlreadyAdded = vm.rules.apps.contains(where: { $0.bundlePath == app.path })

                            HStack(spacing: 12) {
                                Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                                    .resizable()
                                    .frame(width: 28, height: 28)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(app.name)
                                        .font(.system(size: 13, weight: .semibold))
                                        .lineLimit(1)
                                    Text(app.path)
                                        .font(.system(size: 10))
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }

                                Spacer(minLength: 10)

                                if isAlreadyAdded {
                                    VGStatusBadge("Добавлено", tone: .neutral)
                                } else {
                                    Button("Добавить") {
                                        vm.addApp(name: app.name, bundlePath: app.path, action: .proxy)
                                        dismiss()
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.small)
                                }
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .vgHoverRow(cornerRadius: VGTheme.radiusControl)
                        }
                    }
                    .padding(.horizontal, VGTheme.sheetPadding)
                    .padding(.vertical, 12)
                }
            }

            Divider().opacity(0.6)

            HStack {
                Spacer()
                Button("Закрыть") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, VGTheme.sheetPadding)
            .padding(.vertical, 12)
        }
        .frame(width: 580, height: 480)
        .background(VGTheme.backgroundContent)
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
