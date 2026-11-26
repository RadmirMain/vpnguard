import SwiftUI
import AppKit

public struct AppsManagementView: View {
    @ObservedObject var vm: VPNGuardViewModel
    @State private var showingPickerSheet: Bool = false
    @State private var filterQuery: String = ""

    private var filteredApps: [AppRule] {
        vm.rules.apps.filter { app in
            if filterQuery.isEmpty { return true }
            return app.name.localizedCaseInsensitiveContains(filterQuery) ||
                   app.bundlePath.localizedCaseInsensitiveContains(filterQuery)
        }
    }

    private func binding(for app: AppRule) -> Binding<AppRule> {
        Binding(
            get: { vm.rules.apps.first(where: { $0.id == app.id }) ?? app },
            set: { updated in
                if let idx = vm.rules.apps.firstIndex(where: { $0.id == app.id }) {
                    vm.rules.apps[idx] = updated
                }
            }
        )
    }

    public var body: some View {
        VStack(spacing: 0) {
            VGPageHeader(
                title: "Приложения",
                subtitle: "Маршрутизация трафика приложений через туннель, напрямую или с блокировкой"
            ) {
                Button {
                    showingPickerSheet = true
                } label: {
                    Label("Добавить приложение", systemImage: "plus")
                        .font(VGTokens.Typography.bodyEmphasis)
                }
                .buttonStyle(.borderedProminent)
                .tint(VGTokens.Colors.accentPrimary)
                .controlSize(.regular)
            }

            HStack(spacing: 12) {
                VGSearchField("Фильтр добавленных приложений…", text: $filterQuery)
                    .frame(maxWidth: 340)

                Spacer()

                if !vm.rules.apps.isEmpty {
                    Text("Правил: \(filteredApps.count)")
                        .font(.system(size: 11, weight: .medium))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, VGTheme.pagePadding)
            .padding(.vertical, 12)

            Divider().opacity(0.5)

            if vm.rules.apps.isEmpty {
                VGEmptyStateView(
                    icon: "app.badge.checkmark",
                    title: "Нет добавленных приложений",
                    message: "Добавьте приложения, чтобы явно направить их трафик через туннель или в обход VPN.",
                    actionTitle: "Добавить приложение"
                ) {
                    showingPickerSheet = true
                }
            } else if filteredApps.isEmpty {
                VGEmptyStateView(
                    icon: "magnifyingglass",
                    title: "Ничего не найдено",
                    message: "По запросу «\(filterQuery)» нет подходящих приложений."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(filteredApps) { app in
                            AppRuleRow(
                                app: binding(for: app),
                                onChanged: { vm.hasUnappliedChanges = true },
                                onDelete: { vm.removeApp(id: app.id) }
                            )
                        }
                    }
                    .padding(.horizontal, VGTheme.pagePadding)
                    .padding(.vertical, 14)
                }
            }

            if vm.hasUnappliedChanges {
                VGUnsavedChangesBar(
                    isApplying: vm.isApplyingRules,
                    onDiscard: { vm.discardChanges() },
                    onApply: { Task { await vm.applyChanges() } }
                )
                .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.snappy(duration: 0.2), value: vm.hasUnappliedChanges)
        .sheet(isPresented: $showingPickerSheet) {
            AppPickerSheet(vm: vm)
        }
    }
}

private struct AppRuleRow: View {
    @Binding var app: AppRule
    let onChanged: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 14) {
            HStack(spacing: 12) {
                Image(nsImage: AppIconCache.shared.iconOrDefault(forAppPath: app.bundlePath))
                    .resizable()
                    .frame(width: 30, height: 30)

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(app.name)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.primary)
                            .lineLimit(1)

                        if !AppIconCache.shared.exists(app.bundlePath) {
                            VGStatusBadge("Не найдено", tone: .danger)
                        }
                    }

                    Text(app.bundlePath)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .opacity(app.enabled ? 1.0 : 0.45)

            Spacer(minLength: 12)

            Picker("", selection: $app.action) {
                ForEach(RuleAction.allCases) { action in
                    Text(action.displayName).tag(action)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 220)
            .fixedSize()
            .opacity(app.enabled ? 1.0 : 0.45)
            .onChange(of: app.action) { _, _ in
                onChanged()
            }

            Toggle("", isOn: $app.enabled)
                .toggleStyle(.switch)
                .controlSize(.small)
                .labelsHidden()
                .onChange(of: app.enabled) { _, _ in
                    onChanged()
                }
                .help(app.enabled ? "Отключить правило" : "Включить правило")

            Button(action: onDelete) {
                Image(systemName: "trash")
                    .font(VGTokens.Typography.body)
            }
            .buttonStyle(VGIconButtonStyle(isDestructive: true))
            .help("Удалить правило")
            .accessibilityLabel("Удалить правило для \(app.name)")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .vgHoverRow(cornerRadius: VGTheme.radiusControl)
    }
}
