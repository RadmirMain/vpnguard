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
                        HStack(spacing: 4) {
                            Image(systemName: "clock.arrow.circlepath")
                                .foregroundColor(.orange)
                            if let countdown = VGFormatters.formatCountdown(until: pauseEnd, now: context.date) {
                                Text(countdown)
                                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                    .monospacedDigit()
                                    .foregroundColor(.orange)
                            }
                        }
                    }
                } else {
                    Image(systemName: vm.isProtectionActive ? "shield.fill" : (vm.isTunnelRecovering ? "exclamationmark.shield.fill" : "shield.slash.fill"))
                        .foregroundColor(vm.isProtectionActive ? .green : (vm.isTunnelRecovering ? .orange : .secondary))
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
