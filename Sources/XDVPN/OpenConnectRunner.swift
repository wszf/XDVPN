import Foundation
import XDVPNCore

private final class LockedDataBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func set(_ value: Data) {
        lock.lock()
        data = value
        lock.unlock()
    }

    func get() -> Data {
        lock.lock()
        let snapshot = data
        lock.unlock()
        return snapshot
    }
}

private final class PendingConnectionProcess: @unchecked Sendable {
    private let lock = NSLock()
    private var pid: pid_t?

    func register(_ pid: pid_t) {
        lock.lock()
        self.pid = pid
        lock.unlock()
    }

    func clear(_ pid: pid_t) {
        lock.lock()
        if self.pid == pid { self.pid = nil }
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        let pid = self.pid
        lock.unlock()
        if let pid { kill(pid, SIGTERM) }
    }
}

enum VPNError: LocalizedError {
    case openconnectNotFound
    case invalidProtocol
    case connectFailed(String)
    case sudoNotConfigured
    case cleanupFailed(String)

    var errorDescription: String? {
        switch self {
        case .openconnectNotFound: return "安装包缺少内置 openconnect，请重新下载 XDVPN"
        case .invalidProtocol: return "不支持的协议"
        case .connectFailed(let s): return "连接失败：\(s)"
        case .sudoNotConfigured: return "sudo 免密未配置或规则不完整，请重新点击\"一键配置\""
        case .cleanupFailed(let s): return "清理失败：\(s)"
        }
    }
}

/// 封装 openconnect 进程的生命周期。
/// v0.3 相比 v0.2 的关键变化：
/// 1) 用 `--script=xdvpn-route-script` 替代默认 vpnc-script
///    → 路由改用 def1 技巧，系统原有 default route 永远不被碰
/// 2) 不再 save/restore 原网关；cleanup 只删我们自己加过的东西
/// 3) disconnect == cleanup，完全同一段代码（跑 xdvpn-cleanup helper）
///    → 没有"修复路由"的概念，也没有分叉路径
enum OpenConnectRunner {
    /// Homebrew 构建的 GnuTLS 会写死构建机上的 CA 路径；运行时显式使用 macOS 系统 CA。
    static let caFilePath = "/etc/ssl/cert.pem"
    /// openconnect 写的 pid 文件（/tmp，reboot 持久但 3 天无访问会被 periodic 清）
    static let pidPath = "/tmp/xdvpn.pid"
    /// 纯代理模式独立 pid 文件（无 sudo，user-owned）
    static let proxyModePidPath = "/tmp/xdvpn-proxy.pid"
    private static let pendingConnection = PendingConnectionProcess()
    private static let rootTunnelOperationGate = ExclusiveOperationGate()
    private static let connectionTimeout: TimeInterval = 30
    /// 专用阻塞队列，避免把长时间的 Process 等待与 NSLock 压到有限的 Swift Cooperative Thread Pool。
    private static let blockingQueue = DispatchQueue(
        label: "com.kafeifei.xdvpn.runner.blocking",
        qos: .userInitiated,
        attributes: .concurrent
    )

    static let protocols = ["anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array"]

    /// 在专用阻塞队列执行同步子进程 / 锁操作，不占用 Swift 并发协作线程池。
    static func runBlocking<T: Sendable>(
        _ operation: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            blockingQueue.async {
                do {
                    continuation.resume(returning: try operation())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    static func runBlocking<T: Sendable>(
        _ operation: @escaping @Sendable () -> T
    ) async -> T {
        await withCheckedContinuation { continuation in
            blockingQueue.async {
                continuation.resume(returning: operation())
            }
        }
    }

    // MARK: - Connect

    /// 清掉旧隧道后启动 openconnect。--background 让它在建好隧道、跑完 route-script 之后再 fork。
    /// 所以本函数返回 = 连接已建立 + session.state 已写好。
    /// 调用线程：**不要**在 MainActor 上跑（会阻塞 UI）。
    static func connect(
        protocolName: String,
        server: String,
        user: String,
        password: String
    ) throws {
        try replaceConnection(
            protocolName: protocolName,
            server: server,
            user: user,
            password: password
        ) {
            // Callers without split/domain configuration still get the same atomic
            // cleanup -> connect transaction and cannot bypass the operation gate.
        }
    }

    /// Atomically replaces a privileged tunnel. `prepare` writes the split/domain files
    /// after stale state is gone and before openconnect's route script reads them.
    static func replaceConnection(
        protocolName: String,
        server: String,
        user: String,
        password: String,
        prepare: () throws -> Void
    ) throws {
        try rootTunnelOperationGate.perform {
            try cleanupUnlocked()
            try prepare()
            try connectUnlocked(
                protocolName: protocolName,
                server: server,
                user: user,
                password: password
            )
        }
    }

    private static func connectUnlocked(
        protocolName: String,
        server: String,
        user: String,
        password: String
    ) throws {
        guard protocols.contains(protocolName) else { throw VPNError.invalidProtocol }
        // 清掉可能残留的旧 pid 文件（openconnect 会创建新的，但防御一下）
        try? FileManager.default.removeItem(atPath: pidPath)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        // 所有参数由 arguments 传入，不经 shell，密码不会被日志捕获。
        // sudoers 只放行 xdvpn-openconnect wrapper，wrapper 固定 openconnect 参数。
        proc.arguments = [
            "-n", // 非交互；sudoers 没配会立刻失败
            SudoersInstaller.openconnectWrapperPath,
            "--protocol", protocolName,
            "--user", user,
            "--server",
            server,
        ]

        let stdin = Pipe()
        let stderr = Pipe()
        proc.standardInput = stdin
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = stderr
        // 不接 stdout —— openconnect 自己写 syslog，我们不需要另一份 log 文件

        let exitSemaphore = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in
            exitSemaphore.signal()
        }

        do {
            try proc.run()
        } catch {
            throw VPNError.connectFailed(error.localizedDescription)
        }
        pendingConnection.register(proc.processIdentifier)
        defer { pendingConnection.clear(proc.processIdentifier) }

        let stderrDrain = startDraining(pipe: stderr)
        stdin.fileHandleForWriting.write(Data((password + "\n").utf8))
        try? stdin.fileHandleForWriting.close()

        let failure = try waitForConnectionProcess(
            proc,
            exitSemaphore: exitSemaphore,
            stderrDrain: stderrDrain
        )
        if failure.contains("a password is required")
            || failure.contains("sudo:")
            || failure.contains("no tty present")
        {
            throw VPNError.sudoNotConfigured
        }
        if !failure.isEmpty { throw VPNError.connectFailed(failure) }
    }

    // MARK: - Cleanup（== Disconnect）

    /// 调 xdvpn-cleanup：停我们的 openconnect、清我们 session 里记下的一切。
    /// 幂等、安全、可在任何时机反复调（启动时 / 用户点断开 / 合盖前）。
    /// 调用线程：不要在 MainActor（阻塞最多 ~12s 等 vpnc-script 回收）。
    static func cleanup() throws {
        try rootTunnelOperationGate.perform {
            try cleanupUnlocked()
        }
    }

    private static func cleanupUnlocked() throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        proc.arguments = ["-n", SudoersInstaller.cleanupPath]
        let errPipe = Pipe()
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = errPipe
        let exitSemaphore = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in
            exitSemaphore.signal()
        }
        do {
            try proc.run()
        } catch {
            throw VPNError.cleanupFailed(error.localizedDescription)
        }
        let errDrain = startDraining(pipe: errPipe)
        exitSemaphore.wait()
        let errData = errDrain.finish()
        if proc.terminationStatus != 0 {
            let msg =
                String(data: errData, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                ?? "exit \(proc.terminationStatus)"
            throw VPNError.cleanupFailed(msg.isEmpty ? "exit \(proc.terminationStatus)" : msg)
        }
    }

    /// disconnect 和 cleanup 是完全同义的。提供别名让调用方代码更易读。
    static func disconnect() throws { try cleanup() }

    // MARK: - 纯代理模式 (userspace, no sudo)
    //
    // openconnect --script-tun --script "ocproxy -D <port>" ...
    //   - 不创建 utun → 不需要 sudo
    //   - openconnect 把 IP 包通过 pipe 喂给 ocproxy
    //   - ocproxy 用 lwIP 在用户态实现 TCP/IP 栈，暴露 SOCKS5
    //   - 完全不动 macOS 路由表 / DNS resolver / 任何系统状态

    /// 在 app bundle 里找 ocproxy，或回退到 brew 安装
    static func locateOcproxy() -> String? {
        if let resourcePath = Bundle.main.resourcePath {
            let bundled = resourcePath + "/openconnect/bin/ocproxy"
            if FileManager.default.isExecutableFile(atPath: bundled) {
                return bundled
            }
        }
        for path in ["/opt/homebrew/bin/ocproxy", "/usr/local/bin/ocproxy"] {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }

    /// 在 app bundle 里找 openconnect
    static func locateBundledOpenconnect() -> String? {
        guard let resourcePath = Bundle.main.resourcePath else { return nil }
        let path = resourcePath + "/openconnect/bin/openconnect"
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }

    /// 启动纯代理模式：openconnect + ocproxy，user 身份，无 sudo。
    /// 调用线程：**不要** MainActor（同步阻塞等到 connect 完成）
    static func connectProxyMode(
        protocolName: String,
        server: String,
        user: String,
        password: String,
        socksPort: UInt16
    ) throws {
        guard protocols.contains(protocolName) else { throw VPNError.invalidProtocol }

        guard let openconnectBin = locateBundledOpenconnect() else {
            throw VPNError.connectFailed("找不到 bundled openconnect")
        }
        guard FileManager.default.isReadableFile(atPath: caFilePath) else {
            throw VPNError.connectFailed("系统 CA 证书不可读：\(caFilePath)")
        }
        guard let ocproxyBin = locateOcproxy() else {
            throw VPNError.connectFailed("找不到 ocproxy。请 brew install ocproxy，或重新打包 app")
        }

        // 清掉旧 pid 文件（防御性）
        try? FileManager.default.removeItem(atPath: proxyModePidPath)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: openconnectBin)
        proc.arguments = [
            "--background",
            "--cafile=" + caFilePath,
            // 客户端每 5s 主动 DPD 探死链：服务端 idle 踢会话 / DTLS 假死后秒级被发现，
            // openconnect 自愈失败即退出，pollTick 的进程探活随即接管重连。零 sudo 代价（user 态）。
            "--force-dpd=5",
            "--pid-file=" + proxyModePidPath,
            "--script-tun",
            // openconnect 通过 sh -c 执行 script string，所以 ocproxy 路径要 quote
            "--script", "'\(ocproxyBin)' -D \(socksPort)",
            "--protocol", protocolName,
            "--user", user,
            server,
        ]

        let stdin = Pipe()
        let stderr = Pipe()
        proc.standardInput = stdin
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = stderr

        let exitSemaphore = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in
            exitSemaphore.signal()
        }

        do {
            try proc.run()
        } catch {
            throw VPNError.connectFailed(error.localizedDescription)
        }
        pendingConnection.register(proc.processIdentifier)
        defer { pendingConnection.clear(proc.processIdentifier) }

        let stderrDrain = startDraining(pipe: stderr)
        stdin.fileHandleForWriting.write(Data((password + "\n").utf8))
        try? stdin.fileHandleForWriting.close()

        let failure = try waitForConnectionProcess(
            proc,
            exitSemaphore: exitSemaphore,
            stderrDrain: stderrDrain
        )
        if !failure.isEmpty { throw VPNError.connectFailed(failure) }
    }

    static func cancelPendingConnection() {
        pendingConnection.cancel()
    }

    private struct PipeDrain {
        let group: DispatchGroup
        let buffer: LockedDataBuffer
        let handle: FileHandle

        func finish(timeout: TimeInterval = 1.0) -> Data {
            _ = group.wait(timeout: .now() + timeout)
            return buffer.get()
        }

        func abort() {
            try? handle.close()
            _ = group.wait(timeout: .now() + 0.5)
        }
    }

    private static func startDraining(pipe: Pipe) -> PipeDrain {
        let group = DispatchGroup()
        let buffer = LockedDataBuffer()
        let readHandle = pipe.fileHandleForReading
        group.enter()
        blockingQueue.async {
            buffer.set(readHandle.readDataToEndOfFile())
            group.leave()
        }
        return PipeDrain(group: group, buffer: buffer, handle: readHandle)
    }

    /// `--background` returns only after authentication and tunnel setup. Bound
    /// that foreground phase so a stale HTTPS socket cannot keep the UI busy forever.
    private static func waitForConnectionProcess(
        _ proc: Process,
        exitSemaphore: DispatchSemaphore,
        stderrDrain: PipeDrain,
        timeout: TimeInterval = connectionTimeout
    ) throws -> String {
        if exitSemaphore.wait(timeout: .now() + timeout) == .timedOut {
            killAndWait(proc.processIdentifier)
            _ = exitSemaphore.wait(timeout: .now() + 2)
            stderrDrain.abort()
            throw VPNError.connectFailed("连接服务器超时（\(Int(timeout)) 秒）")
        }

        let errData = stderrDrain.finish()
        guard proc.terminationStatus != 0 else { return "" }
        let message = String(data: errData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return message.isEmpty ? "exit \(proc.terminationStatus)" : message
    }

    /// 断开纯代理模式：kill openconnect + ocproxy
    /// 现实里 openconnect 死了 ocproxy 不一定跟着死（pipe 闭了 ocproxy 也可能继续 listen），
    /// 所以两个都得显式清掉
    static func disconnectProxyMode() {
        // 1) 拿 openconnect 的 pid 从 pid-file 中
        let ocPid: pid_t? = {
            guard let s = try? String(contentsOfFile: proxyModePidPath, encoding: .utf8) else { return nil }
            return pid_t(s.trimmingCharacters(in: .whitespacesAndNewlines))
        }()
        if let pid = ocPid {
            killAndWait(pid)
        }

        // 2) 兜底：找孤儿 ocproxy 和 openconnect。**只匹配 bundle 里的绝对路径**，
        //    避免误杀用户在别处装的 ocproxy / openconnect。
        //    Bundle 路径形如 `XDVPN.app/Contents/Resources/openconnect/bin/<bin>`，
        //    用 pgrep 的全路径匹配既能精确锁定我们启的进程，又能跨多份 .app 安装（如 dev + 生产）。
        if let resourcePath = Bundle.main.resourcePath {
            let ocproxyPath = resourcePath + "/openconnect/bin/ocproxy"
            let openconnectPath = resourcePath + "/openconnect/bin/openconnect"
            for pid in pidsMatching(command: ocproxyPath) { killAndWait(pid) }
            for pid in pidsMatching(command: openconnectPath) { killAndWait(pid) }
        }

        try? FileManager.default.removeItem(atPath: proxyModePidPath)
    }

    private static func killAndWait(_ pid: pid_t) {
        kill(pid, SIGTERM)
        let deadline = Date().addingTimeInterval(2.0)
        var stepUsec: useconds_t = 20_000
        while Date() < deadline {
            if kill(pid, 0) != 0 { return }
            usleep(stepUsec)
            stepUsec = min(stepUsec + 15_000, 100_000)
        }
        if kill(pid, 0) == 0 { kill(pid, SIGKILL) }
    }

    /// 用 `pgrep -f <pattern>` 找匹配命令行的 pid
    private static func pidsMatching(command: String) -> [pid_t] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        proc.arguments = ["-f", command]
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = FileHandle.nullDevice
        let exitSemaphore = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in
            exitSemaphore.signal()
        }
        do {
            try proc.run()
        } catch { return [] }

        let outDrain = startDraining(pipe: out)
        if exitSemaphore.wait(timeout: .now() + 3) == .timedOut {
            proc.terminate()
            outDrain.abort()
            return []
        }

        let data = outDrain.finish()
        return (String(data: data, encoding: .utf8) ?? "")
            .split(separator: "\n")
            .compactMap { pid_t($0.trimmingCharacters(in: .whitespaces)) }
            .filter { $0 != ProcessInfo.processInfo.processIdentifier }  // 不杀自己
    }

    static var proxyModePid: pid_t? {
        guard let s = try? String(contentsOfFile: proxyModePidPath, encoding: .utf8) else { return nil }
        return pid_t(s.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    static var isProxyModeRunning: Bool {
        guard let pid = proxyModePid else { return false }
        return isAlive(pid)
    }

    // MARK: - Status query

    static func currentPid() -> pid_t? {
        guard let s = try? String(contentsOfFile: pidPath, encoding: .utf8) else { return nil }
        return pid_t(s.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    static func isAlive(_ pid: pid_t) -> Bool {
        // kill 0 不发信号，只校验是否有权（EPERM 也算活着，只是非本用户）
        return kill(pid, 0) == 0 || errno == EPERM
    }

    static var isRunning: Bool {
        guard let pid = currentPid() else { return false }
        return isAlive(pid)
    }
}
