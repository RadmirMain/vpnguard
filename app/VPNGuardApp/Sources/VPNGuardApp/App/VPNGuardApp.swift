import SwiftUI
import AppKit

@main
public struct VPNGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var vm = VPNGuardViewModel()
    @Environment(\.openWindow) private var openWindow
    
    public init() {}
    
    public var body: some Scene {
        // Menu Bar Extra Item
        MenuBarExtra {
            MenuBarExtraView(vm: vm) {
                openControlCenter()
            }
        } label: {
            HStack(spacing: 4) {
                if let pauseEnd = vm.pauseEndDate, vm.isPauseActive {
                    TimelineView(.periodic(from: .now, by: 1.0)) { context in
                        HStack(spacing: VGPrimitives.Space.s4) {
                            Image(systemName: "clock.arrow.circlepath")
                                .foregroundStyle(VGTokens.Colors.statusWarning)
                            if let countdown = VGFormatters.formatCountdown(until: pauseEnd, now: context.date) {
                                Text(countdown)
                                    .font(VGTokens.Typography.monoCaption.weight(.semibold))
                                    .monospacedDigit()
                                    .foregroundStyle(VGTokens.Colors.statusWarning)
                            }
                        }
                    }
                } else {
                    Image(systemName: vm.isProtectionActive ? "shield.fill" : (vm.isTunnelRecovering ? "exclamationmark.shield.fill" : "shield.slash.fill"))
                        .foregroundStyle(vm.isProtectionActive ? VGTokens.Colors.statusProtected : (vm.isTunnelRecovering ? VGTokens.Colors.statusWarning : VGTokens.Colors.textSecondary))
                }
            }
        }
        .menuBarExtraStyle(.window)
        
        // Main Control Center Window
        Window("VPNGuard Control Center", id: "control-center") {
            MainContainerView(vm: vm)
        }
        .defaultSize(width: 860, height: 580)
        .commands {
            CommandGroup(replacing: .textEditing) {
                Button("Вырезать") { NSApp.sendAction(#selector(NSText.cut(_:)), to: nil, from: nil) }
                    .keyboardShortcut("x", modifiers: .command)
                Button("Скопировать") { NSApp.sendAction(#selector(NSText.copy(_:)), to: nil, from: nil) }
                    .keyboardShortcut("c", modifiers: .command)
                Button("Вставить") { NSApp.sendAction(#selector(NSText.paste(_:)), to: nil, from: nil) }
                    .keyboardShortcut("v", modifiers: .command)
                Button("Выбрать все") { NSApp.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil) }
                    .keyboardShortcut("a", modifiers: .command)
            }
        }
    }
    
    private func openControlCenter() {
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "control-center")
    }
}
