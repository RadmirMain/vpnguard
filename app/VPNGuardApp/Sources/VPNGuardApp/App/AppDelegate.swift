import AppKit
import Darwin

public final class AppDelegate: NSObject, NSApplicationDelegate {
    public func applicationDidFinishLaunching(_ notification: Notification) {
        // Ignore SIGPIPE so writing stdin to an early-exiting child process never terminates the app
        signal(SIGPIPE, SIG_IGN)
        // Allow app to continue running in background as MenuBarExtra even if window is closed
        NSApp.setActivationPolicy(.regular)
    }

    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Do NOT terminate when main window is closed, keep running in menu bar
        return false
    }
}
