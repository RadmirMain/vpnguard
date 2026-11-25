import Foundation

public struct CLIResult {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public var isSuccess: Bool {
        return exitCode == 0
    }
}

public final class CLIExecutor: @unchecked Sendable {
    public static let shared = CLIExecutor()

    private let sudoPath = "/usr/bin/sudo"
    private let vpnguardPath = "/usr/local/bin/vpnguard"

    private init() {
        signal(SIGPIPE, SIG_IGN)
    }

    public func execute(
        arguments: [String],
        stdinData: Data? = nil,
        timeout: TimeInterval = 25.0
    ) async -> CLIResult {
        let sPath = self.sudoPath
        let vPath = self.vpnguardPath
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: sPath)
                process.arguments = ["-n", vPath] + arguments

                let outPipe = Pipe()
                let errPipe = Pipe()
                process.standardOutput = outPipe
                process.standardError = errPipe

                var inPipe: Pipe? = nil
                if stdinData != nil {
                    let pipe = Pipe()
                    process.standardInput = pipe
                    inPipe = pipe
                }

                let lock = NSLock()
                var finished = false
                var timedOut = false
                var outData = Data()
                var errData = Data()

                let finishOnce: (Int32, String, String) -> Void = { code, outStr, errStr in
                    lock.lock()
                    defer { lock.unlock() }
                    guard !finished else { return }
                    finished = true
                    continuation.resume(returning: CLIResult(exitCode: code, stdout: outStr, stderr: errStr))
                }

                let timeoutWork = DispatchWorkItem {
                    lock.lock()
                    let alreadyDone = finished
                    if !alreadyDone {
                        timedOut = true
                    }
                    lock.unlock()
                    if !alreadyDone && process.isRunning {
                        process.terminate()
                    }
                }
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout, execute: timeoutWork)

                do {
                    try process.run()
                } catch {
                    timeoutWork.cancel()
                    finishOnce(-1, "", error.localizedDescription)
                    return
                }

                let ioGroup = DispatchGroup()

                if let dataToWrite = stdinData, let pipe = inPipe {
                    ioGroup.enter()
                    DispatchQueue.global(qos: .userInitiated).async {
                        let handle = pipe.fileHandleForWriting
                        try? handle.write(contentsOf: dataToWrite)
                        try? handle.close()
                        ioGroup.leave()
                    }
                }

                ioGroup.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    let d = outPipe.fileHandleForReading.readDataToEndOfFile()
                    lock.lock()
                    outData = d
                    lock.unlock()
                    ioGroup.leave()
                }

                ioGroup.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    let d = errPipe.fileHandleForReading.readDataToEndOfFile()
                    lock.lock()
                    errData = d
                    lock.unlock()
                    ioGroup.leave()
                }

                process.waitUntilExit()
                ioGroup.wait()
                timeoutWork.cancel()

                let outStr = String(data: outData, encoding: .utf8) ?? ""
                let errStr = String(data: errData, encoding: .utf8) ?? ""

                lock.lock()
                let didTimeout = timedOut
                lock.unlock()

                if didTimeout {
                    let msg = errStr.isEmpty ? "Команда превысила таймаут (\(Int(timeout))с)" : errStr
                    finishOnce(-2, outStr, msg)
                } else {
                    finishOnce(process.terminationStatus, outStr, errStr)
                }
            }
        }
    }
}
