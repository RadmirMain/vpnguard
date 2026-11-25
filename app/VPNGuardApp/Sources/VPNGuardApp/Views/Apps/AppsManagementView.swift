import SwiftUI
import AppKit

public struct AppsManagementView: View {
    @ObservedObject var vm: VPNGuardViewModel
    @State private var showingPickerSheet: Bool = false
    @State private var filterQuery: String = ""
    
    private var filteredApps: [Binding<AppRule>] {
        $vm.rules.apps.filter { binding in
            if filterQuery.isEmpty { return true }
            return binding.wrappedValue.name.localizedCaseInsensitiveContains(filterQuery) ||
                   binding.wrappedValue.bundlePath.localizedCaseInsensitiveContains(filterQuery)
        }
    }
    
    public var body: some View {
        VStack(spacing: 0) {
            // Top Toolbar
            HStack(spacing: 12) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.secondary)
                    TextField("Фильтр добавленных приложений...", text: $filterQuery)
                        .textFieldStyle(.plain)
                    if !filterQuery.isEmpty {
                        Button {
                            filterQuery = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(8)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
                
                Spacer()
                
                Button {
                    showingPickerSheet = true
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "plus")
                        Text("Добавить приложение")
                    }
                    .font(.system(size: 12, weight: .semibold))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color.blue.gradient, in: RoundedRectangle(cornerRadius: 8))
                    .foregroundColor(.white)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .background(.regularMaterial)
            
            Divider()
            
            // Apps Table/List
            if vm.rules.apps.isEmpty {
                VStack(spacing: 16) {
                    Spacer()
                    Image(systemName: "app.badge.checkmark")
                        .font(.system(size: 40))
                        .foregroundColor(.secondary)
                    Text("Нет добавленных приложений")
                        .font(.headline)
                    Text("Нажмите «+ Добавить приложение», чтобы направить трафик нужных программ через туннель или напрямую.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                    Button("Добавить приложение") {
                        showingPickerSheet = true
                    }
                    .buttonStyle(.borderedProminent)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(filteredApps) { $app in
                        HStack(spacing: 14) {
                            // Real app icon
                            Image(nsImage: NSWorkspace.shared.icon(forFile: app.bundlePath))
                                .resizable()
                                .frame(width: 32, height: 32)
                            
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 8) {
                                    Text(app.name)
                                        .font(.system(size: 13, weight: .semibold))
                                    
                                    if !FileManager.default.fileExists(atPath: app.bundlePath) {
                                        Text("Не найдено")
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(.red)
                                            .padding(.horizontal, 4)
                                            .padding(.vertical, 1)
                                            .background(Color.red.opacity(0.1), in: Capsule())
                                    }
                                }
                                
                                Text(app.bundlePath)
                                    .font(.system(size: 11))
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            
                            Spacer()
                            
                            // Segmented Action Picker
                            Picker("Режим", selection: $app.action) {
                                ForEach(RuleAction.allCases) { action in
                                    Text(action.displayName).tag(action)
                                }
                            }
                            .pickerStyle(.segmented)
                            .frame(width: 220)
                            .onChange(of: app.action) { _, _ in
                                vm.hasUnappliedChanges = true
                            }
                            
                            // Enable / Disable switch
                            Toggle("", isOn: $app.enabled)
                                .toggleStyle(.switch)
                                .labelsHidden()
                                .onChange(of: app.enabled) { _, _ in
                                    vm.hasUnappliedChanges = true
                                }
                            
                            // Delete button
                            Button {
                                vm.removeApp(id: app.id)
                            } label: {
                                Image(systemName: "trash")
                                    .foregroundColor(.secondary)
                                    .font(.system(size: 13))
                            }
                            .buttonStyle(.plain)
                            .help("Удалить правило")
                        }
                        .padding(.vertical, 6)
                    }
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
            
            // Bottom Save Bar (Visible when hasUnappliedChanges)
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
        .sheet(isPresented: $showingPickerSheet) {
            AppPickerSheet(vm: vm)
        }
    }
}
