import AppKit
import Darwin.POSIX.net
import Foundation
import SwiftUI

/// 总控。v0.3 相比 v0.2 大幅瘦身：
/// - 删掉 HealthChecker（1Hz 轮询路由表的复杂逻辑不再需要 —— def1 路由天然可恢复）
/// - 删掉 LifecycleWatcher（sleep 处理直接塞 init，没必要单起一个 class）
/// - 删掉 AutoReconnector（自动重连是独立 feature，v0.3 先不做；用户手动重连也是 2 秒的事）
/// - 删掉 needsRepair / intent / StatusDot / statusLockedUntil 等过度设计
///
/// 现在就是一个普通的 ObservableObject：
/// - init 时跑一次 cleanup（self-heal）
/// - connect 前再跑一次 cleanup（确保干净起点）
/// - 2s Timer 轮询 pid，发现异常死亡 → 自动 cleanup
/// - willSleep → 同步 cleanup
@MainActor
final class VPNController: ObservableObject {
    // MARK: - 表单

    @Published var protocolName: String = "anyconnect"
    @Published var server: String = ""
    @Published var user: String = ""
    @Published var password: String = ""
    @Published var rememberPassword: Bool = true
    /// 启动时自动连接 —— 远程维护机器场景：开机/重启后无需人工操作即可上线
    @Published var autoConnectOnLaunch: Bool = false {
        didSet { UserDefaults.standard.set(autoConnectOnLaunch, forKey: "xdvpn.autoConnectOnLaunch") }
    }

    // MARK: - 分流（Split Tunnel）—— 仅在 runningMode == .split 时生效
    @Published var splitPreset10: Bool = true      // 10.0.0.0/8
    @Published var splitPreset172: Bool = true     // 172.16.0.0/12
    @Published var splitPreset192: Bool = false    // 192.168.0.0/16（通常是本地 LAN）
    /// 自定义 CIDR，多行/逗号分隔
    @Published var splitCustom: String = ""
    /// 域名分流后缀列表，一行一个（如 xindong.com），匹配该域名及所有子域名
    @Published var splitDomains: String = ""

    // MARK: - 状态

    @Published private(set) var isConnected: Bool = false {
        didSet {
            // 任何路径让 VPN 断开（手动 / 休眠 / 异常死亡 / 唤醒重连前清理）
            // 都把 SOCKS5 server 同步关掉 —— 它绑的 utun 接口已经无效
            if !isConnected, oldValue {
                socks5.stop()
                socks5Active = false
            }
        }
    }
    @Published private(set) var isBusy: Bool = false
    @Published private(set) var statusText: String = "未连接"
    @Published private(set) var sudoConfigured: Bool = SudoersInstaller.isInstalled

    // MARK: - 诊断信息

    @Published private(set) var connectedAt: Date?
    @Published private(set) var tunnelInterface: String?
    @Published private(set) var tunnelIP: String?
    @Published private(set) var vpnGateway: String?
    @Published private(set) var activeRoutes: [String] = []
    @Published private(set) var dnsProxyActive: Bool = false
    @Published private(set) var trafficIn: UInt64 = 0
    @Published private(set) var trafficOut: UInt64 = 0
    /// 实时速率（字节/秒）—— 从两次 poll 之间的差值估算
    @Published private(set) var trafficInRate: UInt64 = 0
    @Published private(set) var trafficOutRate: UInt64 = 0
    /// 菜单栏标题里是否外显实时速度
    @Published var showSpeedInMenuBar: Bool = false {
        didSet { UserDefaults.standard.set(showSpeedInMenuBar, forKey: "xdvpn.showSpeedInMenuBar") }
    }

    // MARK: - 运行模式（三选一）
    /// 三种模式语义：
    ///   - .proxy   纯代理：openconnect --script-tun + ocproxy 用户态，不动系统状态
    ///   - .split   VPN 分流：标准模式，仅指定 CIDR 走 VPN，其它走本地默认
    ///   - .full    VPN 全局：标准模式，所有流量走 VPN（def1）
    enum RunningMode: String, CaseIterable, Identifiable {
        case proxy, split, full
        var id: String { rawValue }

        var label: String {
            switch self {
            case .proxy: return "纯代理模式"
            case .split: return "VPN 分流模式"
            case .full:  return "VPN 全局模式"
            }
        }

        var summary: String {
            switch self {
            case .proxy: return "不动系统路由 / DNS，只暴露 SOCKS5"
            case .split: return "标准 VPN，仅指定网段走隧道"
            case .full:  return "标准 VPN，所有外网流量走隧道"
            }
        }
    }

    @Published var runningMode: RunningMode = .split {
        didSet { UserDefaults.standard.set(runningMode.rawValue, forKey: "xdvpn.runningMode") }
    }

    /// 兼容旧调用方：内部代码大量用 useProxyMode/splitEnabled 这两个 bool，
    /// 通过 computed property 派生，保留单一数据源（runningMode）
    var useProxyMode: Bool { runningMode == .proxy }
    var splitEnabled: Bool {
        get { runningMode == .split }
        set {
            // 兼容旧 UI：拖 split toggle 时只在 kernel 两种模式间切，不动 proxy
            if useProxyMode { return }
            runningMode = newValue ? .split : .full
        }
    }

    // MARK: - SOCKS5 代理（给 Surge / Clash 这类客户端用）
    @Published var socks5Enabled: Bool = true {
        didSet {
            UserDefaults.standard.set(socks5Enabled, forKey: "xdvpn.socks5.enabled")
            applySocks5State()
        }
    }
    @Published var socks5Port: Int = 5180 {
        didSet {
            UserDefaults.standard.set(socks5Port, forKey: "xdvpn.socks5.port")
            applySocks5State()
        }
    }
    @Published private(set) var socks5Active: Bool = false
    @Published private(set) var socks5Error: String?

    private let socks5 = Socks5Proxy()

    // MARK: - 私有

    private var lastTrafficSample: (inBytes: UInt64, outBytes: UInt64, at: Date)?
    private var pollTimer: Timer?
    /// 自动重连：连接突然死掉时跑的 backoff 重试。
    /// 每次成功连上后清零，每次失败递增；超过 maxAttempts 就放弃
    private var autoReconnectAttempt: Int = 0
    private var autoReconnectTimer: Timer?
    private let autoReconnectMaxAttempts = 5
    private var sleepObserver: NSObjectProtocol?
    private var wakeObserver: NSObjectProtocol?
    /// 睡前是否连着 → 醒来自动重连
    private var shouldReconnectAfterWake = false

    init() {
        loadPrefs()
        // Self-heal：启动时清两种模式可能残留的进程
        //   - 标准模式：/tmp/xdvpn.pid 指的 openconnect + helper 启的 dns-proxy
        //   - 纯代理模式：/tmp/xdvpn-proxy.pid 指的 openconnect (用户身份) + 它的 ocproxy 子进程
        // 这两套必须分开清，否则上一次 GUI 被 kill 后留下的孤儿 VPN 会让新 GUI 显示"未连接"
        // 但底层 SOCKS5 仍能用的诡异状态
        Task.detached {
            // 用户态的（无需 sudo），永远跑
            OpenConnectRunner.disconnectProxyMode()
        }
        // root 那套需要 sudoers 已配 —— 首次启动时 cleanup helper 还不存在，跳过
        if sudoConfigured {
            runCleanupDetached(reason: "启动清理上次残余")
        }
        startPolling()
        registerSleepHook()
    }

    deinit {
        pollTimer?.invalidate()
        let nc = NSWorkspace.shared.notificationCenter
        if let obs = sleepObserver { nc.removeObserver(obs) }
        if let obs = wakeObserver { nc.removeObserver(obs) }
    }

    // MARK: - Preferences / Keychain

    private var keychainAccount: String { "\(user)@\(server)" }

    func savePrefs() {
        let d = UserDefaults.standard
        d.set(protocolName, forKey: "xdvpn.protocol")
        d.set(server, forKey: "xdvpn.server")
        d.set(user, forKey: "xdvpn.user")
        d.set(rememberPassword, forKey: "xdvpn.remember")
        d.set(autoConnectOnLaunch, forKey: "xdvpn.autoConnectOnLaunch")
        d.set(runningMode.rawValue, forKey: "xdvpn.runningMode")
        d.set(splitPreset10, forKey: "xdvpn.split.preset10")
        d.set(splitPreset172, forKey: "xdvpn.split.preset172")
        d.set(splitPreset192, forKey: "xdvpn.split.preset192")
        d.set(splitCustom, forKey: "xdvpn.split.custom")
        d.set(splitDomains, forKey: "xdvpn.split.domains")
    }

    private func loadPrefs() {
        let d = UserDefaults.standard
        protocolName = d.string(forKey: "xdvpn.protocol") ?? "anyconnect"
        server = d.string(forKey: "xdvpn.server") ?? ""
        user = d.string(forKey: "xdvpn.user") ?? ""
        rememberPassword = d.object(forKey: "xdvpn.remember") as? Bool ?? true
        autoConnectOnLaunch = d.bool(forKey: "xdvpn.autoConnectOnLaunch")

        // 三态模式 —— 优先读新 key；如果没有，从旧 useProxyMode/splitEnabled 迁移
        if let raw = d.string(forKey: "xdvpn.runningMode"),
           let mode = RunningMode(rawValue: raw) {
            runningMode = mode
        } else {
            let oldProxy = d.bool(forKey: "xdvpn.useProxyMode")
            let oldSplit = (d.object(forKey: "xdvpn.split.enabled") as? Bool) ?? true
            runningMode = oldProxy ? .proxy : (oldSplit ? .split : .full)
        }

        splitPreset10 = d.object(forKey: "xdvpn.split.preset10") as? Bool ?? true
        splitPreset172 = d.object(forKey: "xdvpn.split.preset172") as? Bool ?? true
        splitPreset192 = d.object(forKey: "xdvpn.split.preset192") as? Bool ?? false
        splitCustom = d.string(forKey: "xdvpn.split.custom") ?? ""
        splitDomains = d.string(forKey: "xdvpn.split.domains") ?? ""
        showSpeedInMenuBar = d.bool(forKey: "xdvpn.showSpeedInMenuBar")
        // SOCKS5: 默认开启 + 5180 端口
        socks5Enabled = (d.object(forKey: "xdvpn.socks5.enabled") as? Bool) ?? true
        let savedPort = d.integer(forKey: "xdvpn.socks5.port")
        socks5Port = (savedPort >= 1024 && savedPort <= 65535) ? savedPort : 5180
        if rememberPassword, !user.isEmpty, !server.isEmpty {
            password = KeychainStore.load(account: keychainAccount) ?? ""
        }
    }

    // MARK: - 分流

    nonisolated static let splitConfPath = "/tmp/xdvpn-split.conf"
    nonisolated static let domainConfPath = "/tmp/xdvpn-split-domains.conf"

    /// 按当前 UI 状态收集并校验 CIDR。非法的静默丢弃。
    func collectSplitCIDRs() -> [String] {
        var out: [String] = []
        if splitPreset10 { out.append("10.0.0.0/8") }
        if splitPreset172 { out.append("172.16.0.0/12") }
        if splitPreset192 { out.append("192.168.0.0/16") }

        let extras = splitCustom
            .components(separatedBy: CharacterSet(charactersIn: ",\n"))
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .filter(Self.isValidCIDR)
        out.append(contentsOf: extras)

        // 去重，保持顺序
        var seen = Set<String>()
        return out.filter { seen.insert($0).inserted }
    }

    func collectDomainSuffixes() -> [String] {
        var seen = Set<String>()
        return splitDomains
            .components(separatedBy: CharacterSet(charactersIn: ",\n"))
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .map { $0.hasPrefix("*.") ? String($0.dropFirst(2)) : $0 }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") && Self.isValidDomainSuffix($0) }
            .filter { seen.insert($0).inserted }
    }

    private static func isValidDomainSuffix(_ s: String) -> Bool {
        let labels = s.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        return labels.allSatisfy { label in
            !label.isEmpty && label.count <= 63
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
                && !label.hasPrefix("-") && !label.hasSuffix("-")
        }
    }

    /// 基础 CIDR 语法校验：X.X.X.X/N，N∈[0,32]，四段 0–255。
    private static func isValidCIDR(_ s: String) -> Bool {
        let parts = s.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let maskLen = Int(parts[1]),
              (0...32).contains(maskLen) else { return false }
        let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return false }
        return octets.allSatisfy { seg in
            if let n = Int(seg), (0...255).contains(n) { return true }
            return false
        }
    }

    /// 供 detached task 调用（非 MainActor）。enabled=false 或 cidrs 为空 → 删除旧文件。
    nonisolated static func writeSplitConfFile(enabled: Bool, cidrs: [String]) {
        let path = splitConfPath
        if enabled, !cidrs.isEmpty {
            let content = cidrs.joined(separator: "\n") + "\n"
            try? content.write(toFile: path, atomically: true, encoding: .utf8)
        } else {
            try? FileManager.default.removeItem(atPath: path)
        }
    }

    // MARK: - SOCKS5 调度
    //
    // 历史遗留：早期标准模式下也跑过 Swift 写的 Socks5Proxy，
    // 但这是设计错误 —— 让用户以为三种模式可叠加，实际它们应该互斥：
    //   - 代理模式：SOCKS5 由 ocproxy 提供（openconnect 的 child）
    //   - 分流/全局模式：kernel 自动路由，不需要 SOCKS5
    // 现在这个函数永远只是 stop（防御性），不再启动 Swift Socks5Proxy。
    func applySocks5State() {
        socks5.stop()
        socks5Active = false
        socks5Error = nil
    }

    nonisolated static func writeDomainConfFile(enabled: Bool, domains: [String]) {
        let path = domainConfPath
        if enabled, !domains.isEmpty {
            let content = domains.joined(separator: "\n") + "\n"
            try? content.write(toFile: path, atomically: true, encoding: .utf8)
        } else {
            try? FileManager.default.removeItem(atPath: path)
        }
    }

    var canConnect: Bool {
        // 纯代理模式不需要 sudo（openconnect 以用户身份跑，不创建 utun）
        let sudoOK = useProxyMode || sudoConfigured
        return sudoOK && !server.isEmpty && !user.isEmpty && !password.isEmpty
            && !isBusy && !isConnected
    }

    // MARK: - 用户动作

    /// 启动后调用：如果用户开了"启动时自动连接"且凭据齐全，就发起一次连接。
    /// 给 init 里的 self-heal cleanup 一点时间跑完，再走正常 connect 流程
    /// （connect 内部会再做一次 cleanup，所以即便 cleanup 还没跑完也安全）。
    func autoConnectIfNeeded() {
        guard autoConnectOnLaunch else { return }
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 500_000_000)
            guard let self else { return }
            // canConnect 已经覆盖了：sudo 状态、凭据齐全、未在连接中
            if self.canConnect { self.connect() }
        }
    }

    func connect() {
        guard canConnect else { return }
        isBusy = true
        statusText = "正在连接…"

        let p = protocolName, s = server, u = user, pw = password
        let remember = rememberPassword
        let account = keychainAccount
        let proxyMode = useProxyMode
        let socksPort = UInt16(socks5Port)
        let splitOn = splitEnabled
        let splitCIDRs = collectSplitCIDRs()
        let domainSuffixes = collectDomainSuffixes()

        Task.detached { [weak self] in
            // 先清两种模式的所有残留 —— 用户可能从对方模式切过来，旧进程还在
            OpenConnectRunner.disconnectProxyMode()
            try? OpenConnectRunner.cleanup()  // 即使 proxyMode，前一次标准模式的 root 进程也得清

            if !proxyMode {
                Self.writeSplitConfFile(enabled: splitOn, cidrs: splitCIDRs)
                Self.writeDomainConfFile(enabled: splitOn, domains: domainSuffixes)
            }

            // 连接
            let result: Result<Void, Error>
            do {
                try await BiometricGate.ensure()
                if proxyMode {
                    try OpenConnectRunner.connectProxyMode(
                        protocolName: p, server: s, user: u, password: pw, socksPort: socksPort
                    )
                } else {
                    try OpenConnectRunner.connect(
                        protocolName: p, server: s, user: u, password: pw
                    )
                }
                result = .success(())
            } catch {
                result = .failure(error)
            }

            await MainActor.run { [weak self] in
                guard let self else { return }
                self.isBusy = false
                switch result {
                case .success:
                    if remember {
                        KeychainStore.save(password: pw, account: account)
                    } else {
                        KeychainStore.delete(account: account)
                    }
                    self.savePrefs()
                    BiometricGate.markActivity()
                    // 成功连上 → 重置自动重连计数（之后再断只算"新一轮"）
                    self.autoReconnectAttempt = 0
                    self.isConnected = true
                    self.connectedAt = Date()
                    if proxyMode {
                        // 纯代理模式：ocproxy 已在 socksPort 暴露 SOCKS5
                        self.statusText = "已连接（纯代理 · SOCKS5 127.0.0.1:\(socksPort)）"
                        self.socks5Active = true
                    } else {
                        // 分流 / 全局模式：kernel 路由自动接管，不再启 Swift Socks5Proxy
                        self.parseSessionFile()
                        self.updateTrafficStats()
                        self.statusText = "已连接"
                    }
                case .failure(let err):
                    if case VPNError.sudoNotConfigured = err {
                        self.sudoConfigured = false
                    }
                    self.isConnected = false
                    self.statusText = err.localizedDescription
                }
            }
        }
    }

    func disconnect() {
        guard isConnected || isBusy == false else { return }
        // 用户主动断开 → 取消任何待执行的自动重连
        cancelAutoReconnect()
        isBusy = true
        statusText = "正在断开…"

        let proxyMode = useProxyMode

        Task.detached { [weak self] in
            let errMsg: String?
            if proxyMode {
                OpenConnectRunner.disconnectProxyMode()
                errMsg = nil
            } else {
                do { try OpenConnectRunner.cleanup(); errMsg = nil }
                catch { errMsg = error.localizedDescription }
            }
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.isBusy = false
                self.isConnected = false
                self.clearDiagnostics()
                self.statusText = errMsg ?? "未连接"
            }
        }
    }

    // MARK: - Sudo helpers

    func installSudoers(thenConnect: Bool = false) {
        isBusy = true
        statusText = "正在安装组件…"
        Task.detached { [weak self] in
            let errMsg: String? = {
                do {
                    try SudoersInstaller.install()
                    // 装完之后同步跑一次 cleanup，顺手把 v0.2 残余（如果有）也清了。
                    // 完成后才允许自动连接，避免后台 cleanup 删掉新连接的 split/domain conf。
                    try? OpenConnectRunner.cleanup()
                    return nil
                }
                catch { return error.localizedDescription }
            }()
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.isBusy = false
                self.sudoConfigured = SudoersInstaller.isInstalled
                if let errMsg { self.statusText = errMsg }
                else if !self.isConnected { self.statusText = "未连接" }
                // 配置成功 + 凭据齐全 → 自动连接
                if thenConnect, self.canConnect {
                    self.connect()
                }
            }
        }
    }

    func uninstallSudoers() {
        isBusy = true
        Task.detached { [weak self] in
            try? SudoersInstaller.uninstall()
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.isBusy = false
                self.sudoConfigured = SudoersInstaller.isInstalled
            }
        }
    }

    // MARK: - Polling

    private func startPolling() {
        pollTimer?.invalidate()
        // 1s 心跳：实时速率（菜单栏外显）需要每秒刷新一次才有"动"的感觉
        let timer = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.pollTick()
            }
        }
        // .common 模式 → 菜单展开/拖窗等期间也继续 fire
        RunLoop.main.add(timer, forMode: .common)
        pollTimer = timer
    }

    private func pollTick() {
        // 按当前模式检查对应的 openconnect 进程是否还活着
        let running = useProxyMode ? OpenConnectRunner.isProxyModeRunning : OpenConnectRunner.isRunning
        if isConnected, running, !useProxyMode {
            // 标准模式才采流量/解析 session；纯代理模式拿不到这些数据
            if tunnelInterface == nil { parseSessionFile() }
            updateTrafficStats()
        }
        // 声明"连着"但进程没了 = 意外死亡 → 自动清理 + 重连
        if isConnected, !running, !isBusy {
            isBusy = true
            statusText = "连接已丢失，正在清理…"
            if useProxyMode {
                Task.detached { [weak self] in
                    OpenConnectRunner.disconnectProxyMode()
                    await MainActor.run { [weak self] in
                        guard let self else { return }
                        self.isConnected = false
                        self.isBusy = false
                        self.scheduleAutoReconnect()
                    }
                }
            } else {
                runCleanupDetached(reason: "意外断开自动清理") { [weak self] in
                    guard let self else { return }
                    self.isConnected = false
                    self.isBusy = false
                    self.scheduleAutoReconnect()
                }
            }
        }
    }

    // MARK: - 自动重连（意外掉线场景）
    //
    // 触发：pollTick 检测到 isConnected=true 但 openconnect/ocproxy 进程没了。
    // 策略：指数退避 1/2/4/8/16s，5 次都不行就放弃，状态栏给提示。
    // 重置：每次手动 disconnect、休眠 willSleep、和成功连上后都清零计数。

    private func scheduleAutoReconnect() {
        autoReconnectTimer?.invalidate()
        autoReconnectTimer = nil

        // 没凭据 → 不可能重连，直接放弃
        guard !server.isEmpty, !user.isEmpty, !password.isEmpty else {
            statusText = "未连接（凭据不全，请手动连接）"
            return
        }

        autoReconnectAttempt += 1
        if autoReconnectAttempt > autoReconnectMaxAttempts {
            statusText = "自动重连失败 \(autoReconnectMaxAttempts) 次，请手动重连"
            autoReconnectAttempt = 0
            return
        }

        // 1, 2, 4, 8, 16 秒
        let delay = pow(2.0, Double(autoReconnectAttempt - 1))
        statusText = "连接已丢失，\(Int(delay))s 后自动重连（第 \(autoReconnectAttempt)/\(autoReconnectMaxAttempts) 次）"

        autoReconnectTimer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.autoReconnectTimer = nil
                if !self.isConnected, self.canConnect {
                    self.connect()
                }
            }
        }
    }

    private func cancelAutoReconnect() {
        autoReconnectTimer?.invalidate()
        autoReconnectTimer = nil
        autoReconnectAttempt = 0
    }

    // MARK: - Sleep hook

    private func registerSleepHook() {
        let nc = NSWorkspace.shared.notificationCenter
        sleepObserver = nc.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.handleWillSleep()
            }
        }
        wakeObserver = nc.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.handleDidWake()
            }
        }
    }

    private func handleWillSleep() {
        // willSleep 通知给应用 ~20s 窗口。cleanup 最多 12s，够用。
        // 睡眠场景由 shouldReconnectAfterWake 走另一条 reconnect 路径，
        // 取消掉这里 pollTick 触发的自动重连，避免两套机制打架
        cancelAutoReconnect()
        shouldReconnectAfterWake = isConnected
        if useProxyMode {
            guard isConnected || OpenConnectRunner.isProxyModeRunning else { return }
            OpenConnectRunner.disconnectProxyMode()
        } else {
            // 只在 sudo 已配 的情况下清；其他情况 noop 就行
            guard sudoConfigured, isConnected || OpenConnectRunner.isRunning else { return }
            try? OpenConnectRunner.cleanup()
        }
        isConnected = false
        clearDiagnostics()
        statusText = "未连接"
    }

    private func handleDidWake() {
        // 唤醒后 openconnect 进程可能还活着，但 VPN 服务端 session 已超时、
        // TLS/DTLS 连接已断，隧道实际是黑洞。进程活着 ≠ 隧道通。
        let shouldReconnect = shouldReconnectAfterWake
        shouldReconnectAfterWake = false

        if useProxyMode {
            if isConnected || OpenConnectRunner.isProxyModeRunning {
                isBusy = true
                statusText = "休眠唤醒，正在清理…"
                Task.detached { [weak self] in
                    OpenConnectRunner.disconnectProxyMode()
                    await MainActor.run { [weak self] in
                        guard let self else { return }
                        self.isConnected = false
                        self.isBusy = false
                        self.statusText = "未连接"
                        if shouldReconnect { self.reconnectAfterWake() }
                    }
                }
            } else if shouldReconnect {
                reconnectAfterWake()
            }
            return
        }

        // 标准模式：走 sudo cleanup
        guard sudoConfigured else { return }
        if isConnected || OpenConnectRunner.isRunning {
            isBusy = true
            statusText = "休眠唤醒，正在清理…"
            runCleanupDetached(reason: "唤醒后清理残留隧道") { [weak self] in
                guard let self else { return }
                self.isConnected = false
                self.isBusy = false
                self.statusText = "未连接"
                if shouldReconnect { self.reconnectAfterWake() }
            }
        } else if shouldReconnect {
            reconnectAfterWake()
        }
    }

    /// 唤醒后自动重连。需要凭据齐全才尝试，否则静默跳过（用户手动点连接就行）。
    private func reconnectAfterWake() {
        guard !server.isEmpty, !user.isEmpty, !password.isEmpty else {
            statusText = "未连接（缺少凭据，请手动连接）"
            return
        }
        statusText = "正在自动重连…"
        connect()
    }

    // MARK: - 诊断数据采集

    private func parseSessionFile() {
        guard let content = try? String(contentsOfFile: "/tmp/xdvpn.session", encoding: .utf8) else { return }
        var routes: [String] = []
        var hasDnsProxy = false
        for line in content.components(separatedBy: .newlines) {
            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            switch String(parts[0]) {
            case "TUNDEV": tunnelInterface = String(parts[1])
            case "VPNGATEWAY": vpnGateway = String(parts[1])
            case "ROUTE_NET": routes.append(String(parts[1]))
            case "DNS_PROXY_PID": hasDnsProxy = true
            default: break
            }
        }
        activeRoutes = routes
        dnsProxyActive = hasDnsProxy
    }

    private func updateTrafficStats() {
        guard let iface = tunnelInterface else { return }
        let info = Self.queryTunnel(iface)
        tunnelIP = info.ip

        // 估算实时速率：当前样本 vs 上次样本
        let now = Date()
        if let last = lastTrafficSample {
            let dt = now.timeIntervalSince(last.at)
            if dt > 0.1 {
                let dIn = info.bytesIn >= last.inBytes ? info.bytesIn - last.inBytes : 0
                let dOut = info.bytesOut >= last.outBytes ? info.bytesOut - last.outBytes : 0
                trafficInRate = UInt64(Double(dIn) / dt)
                trafficOutRate = UInt64(Double(dOut) / dt)
            }
        }
        lastTrafficSample = (info.bytesIn, info.bytesOut, now)

        trafficIn = info.bytesIn
        trafficOut = info.bytesOut
    }

    private func clearDiagnostics() {
        connectedAt = nil
        tunnelInterface = nil
        tunnelIP = nil
        vpnGateway = nil
        activeRoutes = []
        dnsProxyActive = false
        trafficIn = 0
        trafficOut = 0
        trafficInRate = 0
        trafficOutRate = 0
        lastTrafficSample = nil
        // VPN 没了 socks 也必须停（出站绑的接口已无效）
        socks5.stop()
        socks5Active = false
        socks5Error = nil
    }

    struct TunnelInfo {
        var ip: String?
        var bytesIn: UInt64 = 0
        var bytesOut: UInt64 = 0
    }

    nonisolated static func queryTunnel(_ name: String) -> TunnelInfo {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return TunnelInfo() }
        defer { freeifaddrs(first) }

        var info = TunnelInfo()
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cur {
            defer { cur = ifa.pointee.ifa_next }
            guard String(cString: ifa.pointee.ifa_name) == name,
                  let addr = ifa.pointee.ifa_addr else { continue }

            let family = Int32(addr.pointee.sa_family)
            if family == AF_INET {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                getnameinfo(addr, socklen_t(addr.pointee.sa_len),
                            &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST)
                info.ip = String(cString: buf)
            }
            if family == AF_LINK, let data = ifa.pointee.ifa_data {
                let d = data.assumingMemoryBound(to: if_data.self).pointee
                info.bytesIn = UInt64(d.ifi_ibytes)
                info.bytesOut = UInt64(d.ifi_obytes)
            }
        }
        return info
    }

    var diagnosticsSummary: String {
        var lines: [String] = []
        lines.append("XDVPN 连接诊断")
        lines.append("协议\t\(protocolName)")
        lines.append("服务器\t\(server)")
        if let gw = vpnGateway { lines.append("网关\t\(gw)") }
        if let iface = tunnelInterface { lines.append("接口\t\(iface)") }
        if let ip = tunnelIP { lines.append("地址\t\(ip)") }
        if let t = connectedAt {
            let dur = Int(Date().timeIntervalSince(t))
            lines.append("时长\t\(Self.formatDuration(dur))")
        }
        lines.append("流量\t↑ \(Self.formatBytes(trafficOut))  ↓ \(Self.formatBytes(trafficIn))")
        if !activeRoutes.isEmpty { lines.append("路由\t\(activeRoutes.joined(separator: ", "))") }
        lines.append("分流\t\(splitEnabled ? "启用" : "关闭")")
        if dnsProxyActive { lines.append("DNS 代理\t活跃") }
        return lines.joined(separator: "\n")
    }

    nonisolated static func formatDuration(_ seconds: Int) -> String {
        let h = seconds / 3600
        let m = (seconds % 3600) / 60
        let s = seconds % 60
        return String(format: "%02d:%02d:%02d", h, m, s)
    }

    nonisolated static func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var idx = 0
        while value >= 1024 && idx < units.count - 1 { value /= 1024; idx += 1 }
        return idx == 0 ? "\(bytes) B" : String(format: "%.1f %@", value, units[idx])
    }

    /// 固定 8 字符宽的速率格式（菜单栏标题用）—— 永远不抖
    /// KB 为最小单位：
    ///   "  0 KB/s"  < 1 KB
    ///   " 12 KB/s"  / "999 KB/s"
    ///   "1.5 MB/s"  / "9.9 MB/s"  (< 10 MB，一位小数)
    ///   " 12 MB/s"  / "999 MB/s"  (≥ 10 MB，整数)
    ///   "1.5 GB/s"  / "9.9 GB/s"
    nonisolated static func formatRate(_ bps: UInt64) -> String {
        let kb = Double(bps) / 1024.0

        if kb < 1024 {
            return String(format: "%3d KB/s", Int(kb))
        }
        let mb = kb / 1024.0
        if mb < 1024 {
            if mb < 10 { return String(format: "%.1f MB/s", mb) }
            return String(format: "%3d MB/s", Int(mb))
        }
        let gb = mb / 1024.0
        if gb < 10 { return String(format: "%.1f GB/s", gb) }
        return String(format: "%3d GB/s", Int(gb))
    }

    // MARK: - Internal helpers

    /// 在后台跑 cleanup，成功/失败都更新一下 isConnected / statusText。
    private func runCleanupDetached(
        reason: String,
        completion: (@MainActor () -> Void)? = nil
    ) {
        Task.detached { [weak self] in
            try? OpenConnectRunner.cleanup()
            // 兜底：cleanup helper 里也删了，这里再来一次无害
            try? FileManager.default.removeItem(atPath: Self.splitConfPath)
            try? FileManager.default.removeItem(atPath: Self.domainConfPath)
            await MainActor.run { [weak self] in
                guard let self else { return }
                // 不改 isBusy —— 启动期间的 cleanup 是静默的，不应该锁 UI
                if let completion { completion() }
                else {
                    // 没 completion → 静默 cleanup，不改 statusText
                    // 只在真的已经不跑了的情况下确认 isConnected
                    if !OpenConnectRunner.isRunning, self.isConnected {
                        self.isConnected = false
                        self.statusText = "未连接"
                    }
                }
                _ = reason  // 目前不输出日志，保留参数便于后续加 os_log
            }
        }
    }
}
