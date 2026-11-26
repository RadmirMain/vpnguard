import Foundation
import SystemConfiguration
import IOKit
import IOKit.pwr_mgt

private final class NetWatchDaemon {
    static let shared = NetWatchDaemon()

    private let desiredStatePath = "/var/db/vpnguard/desired_state"
    private let pauseTokenPath = "/var/run/vpnguard/pause_token"
    private let pauseUntilPath = "/var/run/vpnguard/pause_until"
    private let vpnguardCLIPath = "/usr/local/bin/vpnguard"

    private let syncQueue = DispatchQueue(label: "com.vpnguard.netwatch.sync", qos: .utility)
    private var debounceWorkItem: DispatchWorkItem?
    private var lastSyncCompletedAt: Date?

    private var dynamicStore: SCDynamicStore?
    private var rootPowerPort: io_connect_t = 0
    private var powerNotifyPort: IONotificationPortRef?
    private var powerNotifier: io_object_t = 0

    func start() {
        setupDynamicStore()
        setupPowerNotifications()
        log("vpnguard-netwatch started (SCDynamicStore + IORegisterForSystemPower)")
        CFRunLoopRun()
    }

    private func log(_ message: String) {
        let ts = ISO8601DateFormatter().string(from: Date())
        print("[\(ts)] \(message)")
        fflush(stdout)
    }

    // MARK: - SCDynamicStore (Network Roaming / DNS / IPv4 Changes)
    private func setupDynamicStore() {
        var context = SCDynamicStoreContext(
            version: 0,
            info: UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque()),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        let callback: SCDynamicStoreCallBack = { _, changedKeys, info in
            guard let info else { return }
            let daemon = Unmanaged<NetWatchDaemon>.fromOpaque(info).takeUnretainedValue()
            let keys = (changedKeys as NSArray?) as? [String] ?? []
            daemon.handleDynamicStoreChange(keys: keys)
        }

        guard let store = SCDynamicStoreCreate(nil, "com.vpnguard.netwatch" as CFString, callback, &context) else {
            log("Error: failed to create SCDynamicStore")
            return
        }

        let watchedKeys = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/DNS"
        ] as CFArray

        if !SCDynamicStoreSetNotificationKeys(store, watchedKeys, nil) {
            log("Error: failed to set SCDynamicStore notification keys")
            return
        }

        guard let runLoopSource = SCDynamicStoreCreateRunLoopSource(nil, store, 0) else {
            log("Error: failed to create SCDynamicStore run loop source")
            return
        }

        CFRunLoopAddSource(CFRunLoopGetMain(), runLoopSource, .commonModes)
        self.dynamicStore = store
    }

    private func handleDynamicStoreChange(keys: [String]) {
        let dnsOnly = !keys.isEmpty && keys.allSatisfy { $0 == "State:/Network/Global/DNS" }
        if dnsOnly, let lastSync = lastSyncCompletedAt, Date().timeIntervalSince(lastSync) < 5.0 {
            // Cooldown: ignore DNS change notifications caused by our own dns-sync
            return
        }
        scheduleSync(delay: 2.5, reason: "network-change(\(keys.joined(separator: ",")))")
    }

    // MARK: - IOKit System Power (Sleep / Wake)
    private func setupPowerNotifications() {
        let callback: IOServiceInterestCallback = { refcon, _, messageType, messageArgument in
            guard let refcon else { return }
            let daemon = Unmanaged<NetWatchDaemon>.fromOpaque(refcon).takeUnretainedValue()
            daemon.handlePowerMessage(messageType: messageType, messageArgument: messageArgument)
        }

        var notifyPort: IONotificationPortRef?
        let refcon = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
        rootPowerPort = IORegisterForSystemPower(refcon, &notifyPort, callback, &powerNotifier)
        guard rootPowerPort != 0, let notifyPort else {
            log("Error: IORegisterForSystemPower failed")
            return
        }

        self.powerNotifyPort = notifyPort
        CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(notifyPort).takeUnretainedValue(), .commonModes)
    }

    private func handlePowerMessage(messageType: natural_t, messageArgument: UnsafeMutableRawPointer?) {
        // IOKit power messages (IOMessage.h)
        let kIOMsgCanSystemSleep: natural_t = 0xe0000270
        let kIOMsgSystemWillSleep: natural_t = 0xe0000280
        let kIOMsgSystemHasPoweredOn: natural_t = 0xe0000300

        switch messageType {
        case kIOMsgCanSystemSleep, kIOMsgSystemWillSleep:
            if rootPowerPort != 0, let arg = messageArgument {
                IOAllowPowerChange(rootPowerPort, Int(bitPattern: arg))
            }
        case kIOMsgSystemHasPoweredOn:
            scheduleSync(delay: 2.5, reason: "wake")
        default:
            break
        }
    }

    // MARK: - Guarded Sync Execution
    private func scheduleSync(delay: TimeInterval, reason: String) {
        syncQueue.async { [weak self] in
            guard let self else { return }
            self.debounceWorkItem?.cancel()
            let work = DispatchWorkItem { [weak self] in
                self?.performSyncIfEligible(reason: reason)
            }
            self.debounceWorkItem = work
            self.syncQueue.asyncAfter(deadline: .now() + delay, execute: work)
        }
    }

    private func isDesiredStateOn() -> Bool {
        guard let raw = try? String(contentsOfFile: desiredStatePath, encoding: .utf8) else {
            return false
        }
        return raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "on"
    }

    private func isCaptivePauseActive() -> Bool {
        let fm = FileManager.default
        if fm.fileExists(atPath: pauseTokenPath) {
            return true
        }
        if let raw = try? String(contentsOfFile: pauseUntilPath, encoding: .utf8),
           let ts = TimeInterval(raw.trimmingCharacters(in: .whitespacesAndNewlines)),
           ts > Date().timeIntervalSince1970 {
            return true
        }
        return false
    }

    private func performSyncIfEligible(reason: String) {
        guard isDesiredStateOn() else { return }
        guard !isCaptivePauseActive() else {
            log("Skipping sync (\(reason)): Captive Portal pause is active")
            return
        }
        guard FileManager.default.isExecutableFile(atPath: vpnguardCLIPath) else { return }

        log("Running headless sync (\(reason))...")
        _ = runCLI(["dns-sync"], timeout: 15)
        _ = runCLI(["server", "sync-pf"], timeout: 15)
        lastSyncCompletedAt = Date()
    }

    private func runCLI(_ args: [String], timeout: TimeInterval) -> Int32 {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: vpnguardCLIPath)
        proc.arguments = args
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice

        let sem = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in
            sem.signal()
        }

        do {
            try proc.run()
        } catch {
            log("Failed to launch \(args.joined(separator: " ")): \(error.localizedDescription)")
            return -1
        }

        if sem.wait(timeout: .now() + timeout) == .timedOut {
            proc.terminate()
            _ = sem.wait(timeout: .now() + 1.0)
            log("Timed out running \(args.joined(separator: " "))")
            return -1
        }
        return proc.terminationStatus
    }
}

NetWatchDaemon.shared.start()
