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
                VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
                    Text("Добавить приложение")
                        .font(VGTokens.Typography.sheetTitle)
                    Text("Выберите программу для маршрутизации через VPNGuard")
                        .font(VGTokens.Typography.caption)
                        .foregroundStyle(VGTokens.Colors.textSecondary)
                }

                Spacer()

                Button("Выбрать .app…") {
                    openFilePicker()
                }
                .buttonStyle(.bordered)
            }
            .padding(VGTokens.Spacing.sheetPadding)

            Divider().opacity(0.6)

            VGSearchField("Поиск среди установленных приложений…", text: $searchQuery)
                .padding(.horizontal, VGTokens.Spacing.sheetPadding)
                .padding(.vertical, VGTokens.Spacing.gridGap)

            Divider().opacity(0.5)

            if isLoading {
                VGLoadingStateView("Поиск установленных приложений…")
            } else if filteredApps.isEmpty {
                VGEmptyStateView(
                    icon: "app.dashed",
                    title: "Приложения не найдены",
                    message: "Попробуйте изменить поисковый запрос или выберите .app вручную."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: VGPrimitives.Space.s6) {
                        ForEach(filteredApps) { app in
                            let isAlreadyAdded = vm.rules.apps.contains(where: { $0.bundlePath == app.path })

                            HStack(spacing: VGTokens.Spacing.gridGap) {
                                Image(nsImage: AppIconCache.shared.iconOrDefault(forAppPath: app.path))
                                    .resizable()
                                    .frame(width: 28, height: 28)

                                VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
                                    Text(app.name)
                                        .font(VGTokens.Typography.cardTitle)
                                        .lineLimit(1)
                                    Text(app.path)
                                        .font(VGTokens.Typography.caption)
                                        .foregroundStyle(VGTokens.Colors.textSecondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }

                                Spacer(minLength: VGPrimitives.Space.s10)

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
                            .padding(.horizontal, VGComponentTokens.Row.horizontalPadding)
                            .padding(.vertical, VGComponentTokens.Row.verticalPadding)
                            .vgHoverRow(cornerRadius: VGComponentTokens.Row.cornerRadius)
                        }
                    }
                    .padding(.horizontal, VGTokens.Spacing.sheetPadding)
                    .padding(.vertical, VGTokens.Spacing.gridGap)
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
            .padding(.horizontal, VGTokens.Spacing.sheetPadding)
            .padding(.vertical, VGTokens.Spacing.gridGap)
        }
        .frame(width: 580, height: 480)
        .background(VGTokens.Colors.backgroundContent)
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
