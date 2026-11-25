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
    
    private var filteredDomains: [Binding<DomainRule>] {
        $vm.rules.domains.filter { binding in
            let rule = binding.wrappedValue
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
    
    public var body: some View {
        VStack(spacing: 0) {
            // Top: Quick Add Domain & Presets
            VStack(spacing: 14) {
                // Presets Block
                presetsBlock
                
                // Quick Add Domain Row
                HStack(spacing: 10) {
                    HStack {
                        Image(systemName: "globe")
                            .foregroundColor(.secondary)
                        TextField("Введите сайт или домен (например, 2ip.io или https://ai.com)...", text: $newDomainText)
                            .textFieldStyle(.plain)
                            .onSubmit {
                                addDomainAction()
                            }
                        
                        if !newDomainText.isEmpty {
                            Button {
                                newDomainText = ""
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.secondary)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(8)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
                    
                    Picker("Действие", selection: $newDomainAction) {
                        ForEach(RuleAction.allCases) { action in
                            Text(action.displayName).tag(action)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 220)
                    
                    Button {
                        addDomainAction()
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "plus")
                            Text("Добавить")
                        }
                        .font(.system(size: 12, weight: .semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 7)
                        .background(Color.blue.gradient, in: RoundedRectangle(cornerRadius: 8))
                        .foregroundColor(.white)
                    }
                    .buttonStyle(.plain)
                    .disabled(newDomainText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                
                // Filters and Search Bar
                HStack {
                    Picker("Фильтр", selection: $selectedFilter) {
                        ForEach(DomainFilter.allCases) { filter in
                            Text(filter.rawValue).tag(filter)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 320)
                    
                    Spacer()
                    
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.secondary)
                        TextField("Поиск по доменам...", text: $searchDomain)
                            .textFieldStyle(.plain)
                    }
                    .padding(6)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 6))
                    .frame(maxWidth: 240)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .background(.regularMaterial)
            
            Divider()
            
            // Domain List
            if vm.rules.domains.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "globe.badge.chevron.backward")
                        .font(.system(size: 40))
                        .foregroundColor(.secondary)
                    Text("Нет пользовательских правил сайтов")
                        .font(.headline)
                    Text("Добавьте домен в поле выше, чтобы явно перенаправить его в туннель, напрямую или заблокировать.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(filteredDomains) { $rule in
                        HStack(spacing: 12) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(ruleColor(rule.action).opacity(0.12))
                                    .frame(width: 28, height: 28)
                                Image(systemName: rule.action.iconName)
                                    .font(.system(size: 13))
                                    .foregroundColor(ruleColor(rule.action))
                            }
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text(rule.domain)
                                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                            }
                            
                            Spacer()
                            
                            // Segmented Action Picker
                            Picker("Действие", selection: $rule.action) {
                                ForEach(RuleAction.allCases) { action in
                                    Text(action.displayName).tag(action)
                                }
                            }
                            .pickerStyle(.segmented)
                            .frame(width: 220)
                            .onChange(of: rule.action) { _, _ in
                                vm.hasUnappliedChanges = true
                            }
                            
                            // Enable toggle
                            Toggle("", isOn: $rule.enabled)
                                .toggleStyle(.switch)
                                .labelsHidden()
                                .onChange(of: rule.enabled) { _, _ in
                                    vm.hasUnappliedChanges = true
                                }
                            
                            // Delete button
                            Button {
                                vm.removeDomain(id: rule.id)
                            } label: {
                                Image(systemName: "trash")
                                    .foregroundColor(.secondary)
                                    .font(.system(size: 13))
                            }
                            .buttonStyle(.plain)
                            .help("Удалить правило")
                        }
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
            
            // Bottom Save Bar
            if vm.hasUnappliedChanges {
                Divider()
                HStack {
                    HStack(spacing: 8) {
                        Circle()
                            .fill(Color.orange)
                            .frame(width: 8, height: 8)
                        Text("Есть несохраненные изменения правил")
                            .font(.system(size: 12, weight: .medium))
                    }
                    
                    Spacer()
                    
                    Button("Сбросить") {
                        vm.discardChanges()
                    }
                    .buttonStyle(.bordered)
                    
                    Button {
                        Task {
                            await vm.applyChanges()
                        }
                    } label: {
                        HStack(spacing: 6) {
                            if vm.isApplyingRules {
                                ProgressView()
                                    .scaleEffect(0.6)
                            }
                            Text("Применить изменения")
                        }
                        .font(.system(size: 12, weight: .semibold))
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(vm.isApplyingRules)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(Color.orange.opacity(0.08))
            }
        }
    }
    
    // MARK: - Presets Block
    private var presetsBlock: some View {
        GlassCard(padding: 12) {
            VStack(alignment: .leading, spacing: 10) {
                Text("СИСТЕМНЫЕ ПРЕСЕТЫ МАРШРУТИЗАЦИИ")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.secondary)
                
                HStack(spacing: 16) {
                    Toggle(isOn: $vm.rules.presets.aiServicesProxy) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("AI-сервисы через туннель")
                                .font(.system(size: 12, weight: .semibold))
                            Text("OpenAI, Anthropic, Claude, Cursor, GitHub")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                    }
                    .toggleStyle(.checkbox)
                    .onChange(of: vm.rules.presets.aiServicesProxy) { _, _ in
                        vm.hasUnappliedChanges = true
                    }
                    
                    Spacer()
                    
                    Toggle(isOn: $vm.rules.presets.ruDirect) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Сервисы РФ напрямую")
                                .font(.system(size: 12, weight: .semibold))
                            Text(".ru, .рф, Госуслуги, Банки, Маркетплейсы")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                    }
                    .toggleStyle(.checkbox)
                    .onChange(of: vm.rules.presets.ruDirect) { _, _ in
                        vm.hasUnappliedChanges = true
                    }
                    
                    Spacer()
                    
                    Toggle(isOn: $vm.rules.presets.blockQuic) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Блокировка QUIC")
                                .font(.system(size: 12, weight: .semibold))
                            Text("UDP:443 (запрет обхода через HTTP/3)")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                    }
                    .toggleStyle(.checkbox)
                    .onChange(of: vm.rules.presets.blockQuic) { _, _ in
                        vm.hasUnappliedChanges = true
                    }
                }
            }
        }
    }
    
    private func addDomainAction() {
        let clean = vm.sanitizeDomain(newDomainText)
        guard !clean.isEmpty else { return }
        vm.addDomain(input: clean, action: newDomainAction)
        newDomainText = ""
    }
    
    private func ruleColor(_ action: RuleAction) -> Color {
        switch action {
        case .proxy: return .blue
        case .direct: return .green
        case .block: return .red
        }
    }
}
