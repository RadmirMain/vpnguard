import SwiftUI

public struct WebsitesManagementView: View {
    @ObservedObject var vm: VPNGuardViewModel

    @State private var newDomainText: String = ""
    @State private var newDomainAction: RuleAction = .proxy
    @State private var selectedFilter: DomainFilter = .all
    @State private var searchDomain: String = ""

    enum DomainFilter: String, CaseIterable, Identifiable {
        case all = "Все"
        case proxy = "Туннель"
        case direct = "Напрямую"
        case block = "Блок"

        var id: String { rawValue }
    }

    private var filteredDomains: [DomainRule] {
        vm.rules.domains.filter { rule in
            if !searchDomain.isEmpty && !rule.domain.localizedCaseInsensitiveContains(searchDomain) {
                return false
            }
            switch selectedFilter {
            case .all: return true
            case .proxy: return rule.action == .proxy
            case .direct: return rule.action == .direct
            case .block: return rule.action == .block
            }
        }
    }

    private func binding(for rule: DomainRule) -> Binding<DomainRule> {
        Binding(
            get: { vm.rules.domains.first(where: { $0.id == rule.id }) ?? rule },
            set: { updated in
                if let idx = vm.rules.domains.firstIndex(where: { $0.id == rule.id }) {
                    vm.rules.domains[idx] = updated
                }
            }
        )
    }

    public var body: some View {
        VStack(spacing: 0) {
            VGPageHeader(
                title: "Сайты и домены",
                subtitle: "Пользовательские правила маршрутизации и системные пресеты"
            )

            VStack(spacing: 12) {
                presetsBlock

                HStack(spacing: 10) {
                    HStack(spacing: 8) {
                        Image(systemName: "globe")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                        TextField("Домен или URL (например, 2ip.io или https://ai.com)…", text: $newDomainText)
                            .textFieldStyle(.plain)
                            .font(.system(size: 12))
                            .onSubmit { addDomainAction() }

                        if !newDomainText.isEmpty {
                            Button {
                                newDomainText = ""
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .font(VGTokens.Typography.caption)
                            }
                            .buttonStyle(VGIconButtonStyle())
                            .help("Очистить поле домена")
                            .accessibilityLabel("Очистить поле домена")
                        }
                    }
                    .padding(.horizontal, VGPrimitives.Space.s10)
                    .padding(.vertical, newDomainText.isEmpty ? VGPrimitives.Space.s6 : VGPrimitives.Space.s2)
                    .frame(minHeight: 30)
                    .background(
                        RoundedRectangle(cornerRadius: VGTokens.Radius.control, style: .continuous)
                            .fill(VGTokens.Colors.surfaceLevel2)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: VGTokens.Radius.control, style: .continuous)
                            .strokeBorder(VGTokens.Colors.borderSubtle, lineWidth: VGComponentTokens.Card.borderWidth)
                    )

                    Picker("", selection: $newDomainAction) {
                        ForEach(RuleAction.allCases) { action in
                            Text(action.displayName).tag(action)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    .frame(minWidth: 190, maxWidth: 220)
                    .fixedSize()

                    Button(action: addDomainAction) {
                        Label("Добавить", systemImage: "plus")
                            .font(VGTokens.Typography.bodyEmphasis)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(VGTokens.Colors.accentPrimary)
                    .controlSize(.regular)
                    .fixedSize()
                    .disabled(newDomainText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }

                ViewThatFits(in: .horizontal) {
                    HStack(spacing: VGTokens.Spacing.gridGap) {
                        Picker("", selection: $selectedFilter) {
                            ForEach(DomainFilter.allCases) { filter in
                                Text(filter.rawValue).tag(filter)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.segmented)
                        .fixedSize()

                        Spacer(minLength: VGTokens.Spacing.inlineGap)

                        VGSearchField("Поиск по доменам…", text: $searchDomain)
                            .frame(minWidth: 180, maxWidth: 240)
                    }

                    VStack(alignment: .leading, spacing: VGTokens.Spacing.inlineGap) {
                        Picker("", selection: $selectedFilter) {
                            ForEach(DomainFilter.allCases) { filter in
                                Text(filter.rawValue).tag(filter)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.segmented)

                        VGSearchField("Поиск по доменам…", text: $searchDomain)
                    }
                }
            }
            .padding(.horizontal, VGTheme.pagePadding)
            .padding(.vertical, 14)

            Divider().opacity(0.5)

            if vm.rules.domains.isEmpty {
                VGEmptyStateView(
                    icon: "globe",
                    title: "Нет пользовательских правил сайтов",
                    message: "Добавьте домен в поле выше, чтобы направить его в туннель, напрямую или заблокировать."
                )
            } else if filteredDomains.isEmpty {
                VGEmptyStateView(
                    icon: "magnifyingglass",
                    title: "Домены не найдены",
                    message: "Попробуйте изменить фильтр или строку поиска."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(filteredDomains) { rule in
                            DomainRuleRow(
                                rule: binding(for: rule),
                                onChanged: { vm.hasUnappliedChanges = true },
                                onDelete: { vm.removeDomain(id: rule.id) }
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
    }

    private var presetsBlock: some View {
        VGCard(padding: VGComponentTokens.Card.paddingCompact) {
            VStack(alignment: .leading, spacing: VGTokens.Spacing.inlineGap) {
                Text("Системные пресеты маршрутизации")
                    .font(VGTokens.Typography.captionEmphasis)
                    .foregroundStyle(VGTokens.Colors.textSecondary)

                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 220), spacing: VGTokens.Spacing.gridGap)],
                    alignment: .leading,
                    spacing: VGTokens.Spacing.inlineGap
                ) {
                    presetToggle(
                        title: "AI-сервисы через туннель",
                        subtitle: "OpenAI, Anthropic, Cursor, GitHub",
                        isOn: $vm.rules.presets.aiServicesProxy
                    )

                    presetToggle(
                        title: "Сервисы РФ напрямую",
                        subtitle: ".ru, .рф, Госуслуги, Банки",
                        isOn: $vm.rules.presets.ruDirect
                    )

                    presetToggle(
                        title: "Блокировка QUIC",
                        subtitle: "UDP:443 (запрет HTTP/3 обхода)",
                        isOn: $vm.rules.presets.blockQuic
                    )
                }
            }
        }
    }

    private func presetToggle(title: String, subtitle: String, isOn: Binding<Bool>) -> some View {
        HStack(spacing: VGTokens.Spacing.inlineGap) {
            VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
                Text(title)
                    .font(VGTokens.Typography.bodyEmphasis)
                    .foregroundStyle(VGTokens.Colors.textPrimary)
                    .lineLimit(1)
                Text(subtitle)
                    .font(VGTokens.Typography.caption)
                    .foregroundStyle(VGTokens.Colors.textSecondary)
                    .lineLimit(1)
            }

            Spacer(minLength: VGPrimitives.Space.s6)

            Toggle("", isOn: isOn)
                .toggleStyle(.switch)
                .controlSize(.small)
                .labelsHidden()
                .onChange(of: isOn.wrappedValue) { _, _ in
                    vm.hasUnappliedChanges = true
                }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func addDomainAction() {
        let clean = vm.sanitizeDomain(newDomainText)
        guard !clean.isEmpty else { return }
        vm.addDomain(input: clean, action: newDomainAction)
        newDomainText = ""
    }
}

private struct DomainRuleRow: View {
    @Binding var rule: DomainRule
    let onChanged: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous)
                        .fill(actionColor.opacity(0.14))
                        .frame(width: 28, height: 28)
                    Image(systemName: actionIcon)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(actionColor)
                }

                Text(rule.domain)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .opacity(rule.enabled ? 1.0 : 0.45)

            Spacer(minLength: 12)

            Picker("", selection: $rule.action) {
                ForEach(RuleAction.allCases) { action in
                    Text(action.displayName).tag(action)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 220)
            .fixedSize()
            .opacity(rule.enabled ? 1.0 : 0.45)
            .onChange(of: rule.action) { _, _ in
                onChanged()
            }

            Toggle("", isOn: $rule.enabled)
                .toggleStyle(.switch)
                .controlSize(.small)
                .labelsHidden()
                .onChange(of: rule.enabled) { _, _ in
                    onChanged()
                }
                .help(rule.enabled ? "Отключить правило" : "Включить правило")

            Button(action: onDelete) {
                Image(systemName: "trash")
                    .font(VGTokens.Typography.body)
            }
            .buttonStyle(VGIconButtonStyle(isDestructive: true))
            .help("Удалить правило")
            .accessibilityLabel("Удалить правило для \(rule.domain)")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .vgHoverRow(cornerRadius: VGTheme.radiusControl)
    }

    private var actionColor: Color {
        switch rule.action {
        case .proxy: return VGTheme.accentPrimary
        case .direct: return VGTheme.statusProtected
        case .block: return VGTheme.statusDanger
        }
    }

    private var actionIcon: String {
        switch rule.action {
        case .proxy: return "shield.fill"
        case .direct: return "globe"
        case .block: return "xmark.octagon.fill"
        }
    }
}
