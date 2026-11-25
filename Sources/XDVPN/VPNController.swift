import AppKit
import Darwin.POSIX.net
import Foundation
import SwiftUI
import XDVPNCore

/// 高频流量采样独立于 VPNController，避免每秒采样触发整个主窗口的
/// `VPNController.objectWillChange`。SwiftUI 中只有诊断区域需要观察它；
/// 状态栏也直接订阅这一份合并后的快照。
struct TrafficSnapshot: Equatable, Sendable {
    var bytesIn: UInt64 = 0
    var bytesOut: UInt64 = 0
    var bytesInRate: UInt64 = 0
    var bytesOutRate: UInt64 = 0
}

@MainActor
final class TrafficMonitor: ObservableObject {
    @Published private(set) var snapshot = TrafficSnapshot()

    func update(_ next: TrafficSnapshot) {
        guard snapshot != next else { return }
        snapshot = next
    }

    func reset() {
        update(TrafficSnapshot())
    }

    func resetRates() {
        var next = snapshot
        next.bytesInRate = 0
        next.bytesOutRate = 0
        update(next)
    }
}

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
    /// 认证组，可选。服务器登录页有「组」下拉框时才需要填。
    @Published var authGroup: String = ""
    @Published var user: String = ""
    @Published var password: String = ""
    @Published var rememberPassword: Bool = true
    /// 启动时自动连接 —— 远程维护机器场景：开机/重启后无需人工操作即可上线
    @Published var autoConnectOnLaunch: Bool = false {
        didSet {
            guard !isLoadingPrefs else { return }
            UserDefaults.standard.set(autoConnectOnLaunch, forKey: "xdvpn.autoConnectOnLaunch")
        }
    }

    // MARK: - Wi-Fi 按需连接

    @Published var wifiOnDemandEnabled: Bool = false {
        didSet {
            guard !isLoadingPrefs else { return }
            UserDefaults.standard.set(wifiOnDemandEnabled, forKey: "xdvpn.wifiOnDemand.enabled")
            if wifiOnDemandEnabled {
                suppressedAutoConnectSSID = nil
                _ = refreshCurrentWiFiSSID()
                _ = applyWiFiOnDemandPolicy(trigger: "启用 Wi-Fi 按需连接", respectManualSuppression: false)
            } else {
                pausedByWiFiPolicy = false
                pendingWiFiPolicyReevaluation = false
                suppressedAutoConnectSSID = nil
                wifiOnDemandStatusText = "未启用"
            }
        }
    }
    @Published var wifiOnDemandRules: [WiFiOnDemandRule] = [] {
        didSet {
            guard !isLoadingPrefs else { return }
            saveWiFiOnDemandRules()
        }
    }
    @Published private(set) var currentWiFiSSID: String?
    @Published private(set) var wifiOnDemandStatusText: String = "未启用"
    @Published private(set) var pausedByWiFiPolicy: Bool = false
    @Published private(set) var wifiSSIDLocationPermissionRequired: Bool = false

    // MARK: - 分流（Split Tunnel）—— 仅在 runningMode == .split 时生效
    @Published var splitPreset10: Bool = true {      // 10.0.0.0/8
        didSet { guard !isLoadingPrefs else { return }; updateSplitRuleSummaryIfNeeded() }
    }
    @Published var splitPreset172: Bool = true {     // 172.16.0.0/12
        didSet { guard !isLoadingPrefs else { return }; updateSplitRuleSummaryIfNeeded() }
    }
    @Published var splitPreset192: Bool = false {    // 192.168.0.0/16（通常是本地 LAN）
        didSet { guard !isLoadingPrefs else { return }; updateSplitRuleSummaryIfNeeded() }
    }
    /// 自定义 CIDR，多行/逗号分隔
    @Published var splitCustom: String = "" {
        didSet { guard !isLoadingPrefs else { return }; updateSplitRuleSummaryIfNeeded() }
    }
    /// 域名分流后缀列表，一行一个（如 xindong.com），匹配该域名及所有子域名
    @Published var splitDomains: String = "" {
        didSet { guard !isLoadingPrefs else { return }; updateSplitRuleSummaryIfNeeded() }
    }
    /// 缓存的分流摘要，避免主窗口其他字段变化时重复解析 CIDR/域名列表。
    private(set) var splitRuleSummary: String = "2 个网段 走 VPN"

    // MARK: - 状态

    @Published private(set) var isConnected: Bool = false {
        didSet {
            if isConnected {
                startPolling()
            } else {
                stopPolling()
                if oldValue {
                    socks5Active = false
                }
            }
        }
    }
    @Published private(set) var isBusy: Bool = false {
        didSet {
            if oldValue, !isBusy, pendingWiFiPolicyReevaluation {
                pendingWiFiPolicyReevaluation = false
                Task { @MainActor [weak self] in
                    self?.flushPendingWiFiPolicyIfNeeded()
                }
            }
        }
    }
    @Published private(set) var isConnecting: Bool = false
    @Published private(set) var statusText: String = "未连接"
    @Published private(set) var sudoConfigured: Bool = SudoersInstaller.isInstalled

    // MARK: - 诊断信息

    @Published private(set) var connectedAt: Date?
    @Published private(set) var tunnelInterface: String?
    @Published private(set) var tunnelIP: String?
    @Published private(set) var vpnGateway: String?
    @Published private(set) var activeRoutes: [String] = []
    @Published private(set) var dnsProxyActive: Bool = false
    let trafficMonitor = TrafficMonitor()
    var trafficIn: UInt64 { trafficMonitor.snapshot.bytesIn }
    var trafficOut: UInt64 { trafficMonitor.snapshot.bytesOut }
    /// 实时速率（字节/秒）—— 从两次 poll 之间的差值估算。
    /// 这些 computed property 不再触发 VPNController.objectWillChange。
    var trafficInRate: UInt64 { trafficMonitor.snapshot.bytesInRate }
    var trafficOutRate: UInt64 { trafficMonitor.snapshot.bytesOutRate }
    /// 菜单栏标题里是否外显实时速度
    @Published var showSpeedInMenuBar: Bool = false {
        didSet {
            guard !isLoadingPrefs else { return }
            UserDefaults.standard.set(showSpeedInMenuBar, forKey: "xdvpn.showSpeedInMenuBar")
            if showSpeedInMenuBar, isConnected {
                pollTick(forceTrafficSample: true)
            }
        }
    }

    // MARK: - 运行模式（三选一）
    /// 三种模式语义：
    ///   - .proxy   纯代理：openconnect --script-tun + ocproxy 用户态，不动系统状态
    ///   - .split   VPN 分流：标准模式，仅指定 CIDR 走 VPN，其它走本地默认
    ///   - .full    VPN 全局：标准模式，所有流量走 VPN（def1）
    enum RunningMode: String, CaseIterable, Identifiable, Sendable {
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
        didSet {
            guard !isLoadingPrefs else { return }
            UserDefaults.standard.set(runningMode.rawValue, forKey: "xdvpn.runningMode")
        }
    }

    /// 当前底层进程真实采用的模式。`runningMode` 是用户选择/下次连接模式；
    /// 已连接时清理必须按 activeMode 走，避免切换 UI 后杀错进程族。
    private var activeMode: RunningMode?

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
            guard !isLoadingPrefs else { return }
            UserDefaults.standard.set(socks5Enabled, forKey: "xdvpn.socks5.enabled")
            applySocks5State()
        }
    }
    @Published var socks5Port: Int = 5180 {
        didSet {
            guard !isLoadingPrefs else { return }
            UserDefaults.standard.set(socks5Port, forKey: "xdvpn.socks5.port")
            applySocks5State()
        }
    }
    @Published private(set) var socks5Active: Bool = false
    @Published private(set) var socks5Error: String?

    /// 主窗口当前是否可见（含遮挡/最小化检测）：不可见且未在状态栏外显速度时，降低非 full 模式的流量采集频率。
    var isMainWindowVisible: Bool = false {
        didSet {
            if isMainWindowVisible, !oldValue, isConnected {
                pollTick(forceTrafficSample: true)
            }
        }
    }

    // MARK: - 私有

    private struct SessionFileStamp: Equatable, Sendable {
        let mtimeSec: Int
        let mtimeNsec: Int
        let size: off_t
        let inode: UInt64
    }

    private struct PollSample: Sendable {
        let processAlive: Bool
        let resolvedPid: pid_t?
        let session: RouteScriptSession?
        let sessionStamp: SessionFileStamp?
        let tunnelInfo: TunnelInfo?
    }

    /// 使用单调时钟（systemUptime）计算速率与黑洞超时，免疫系统 NTP 墙钟跳变。
    private var lastTrafficSample: (inBytes: UInt64, outBytes: UInt64, uptime: TimeInterval)?
    private var connectedAtUptime: TimeInterval?
    private var pollTimer: Timer?
    private let pollQueue = DispatchQueue(label: "com.kafeifei.xdvpn.poll", qos: .utility)
    private var pollInFlight = false
    private var pollTickCount: UInt64 = 0
    private var cachedProcessPid: pid_t?
    private var cachedSessionStamp: SessionFileStamp?
    private var connectionTask: Task<Void, Never>?
    private var connectionAttemptID: UUID?
    private var startupCleanupTask: Task<String?, Never>?

    // 自动重连：纯决策逻辑在 XDVPNCore.ReconnectPolicy（已单测），
    // 这里只持有它 + 退避计时器 + 「是否处于自动重连流程」标志。
    private var policy = ReconnectPolicy()
    private var autoReconnectTimer: Timer?
    /// 区分本次 connect 是自动重连发起（失败要推进退避）还是用户手动（失败就停）
    private var isAutoReconnecting = false

    // 网络可达性：NWPathMonitor + CoreWLAN 驱动，供「等网就绪再重连」门控与换网/Wi-Fi 检测
    private let pathMonitor = NetworkPathMonitor()
    private var networkSatisfied = true
    private var networkUsesWiFi = true
    private var networkUsesWiredEthernet = false
    private var hasPathSnapshot = false
    private var changeDetector = NetworkChangeDetector()
    private let wifiSSIDReader = WiFiSSIDReader()
    private var wifiAssociated = false
    private var lastObservedSSID: String?
    private var hasObservedSSID = false
    private var wifiSSIDFallbackInFlight = false
    private var wifiSSIDFallbackTask: Task<Void, Never>?
    private var lastWiFiSSIDFallbackStartedUptime: TimeInterval?
    /// 单调递增观测版本号：确保异步 system_profiler 的过期结果绝不覆盖更新的 CoreWLAN 观测值。
    private var wifiObservationGeneration: UInt64 = 0
    /// 唤醒后或 Wi-Fi 规则触发的等待网络就绪任务，防止重复并发拉起。
    private var wifiWakeEvaluationTask: Task<Void, Never>?
    /// 当 Wi-Fi 规则触发时恰逢 isBusy（例如正在断开/切换），标记延后到 isBusy 结束后补评估。
    private var pendingWiFiPolicyReevaluation = false
    /// 用户在该 SSID 下手动点过「断开」：离开该 SSID 或手动连接前，不再被同一 SSID 的自动连接规则拉回。
    private var suppressedAutoConnectSSID: String?

    // 黑洞检测（full 模式）：跟踪入站字节是否长期停滞（单调时钟）
    private var lastInboundBytes: UInt64 = 0
    private var lastInboundChangeUptime: TimeInterval?
    private var hadInboundEverSinceConnect = false

    private var sleepObserver: NSObjectProtocol?
    private var wakeObserver: NSObjectProtocol?
    /// 睡前是否连着 → 醒来自动重连
    private var shouldReconnectAfterWake = false
    private var isLoadingPrefs = false

    /// 当前模式映射到纯核心的 RunMode
    private var coreMode: RunMode {
        switch activeMode ?? runningMode {
        case .proxy: return .proxy
        case .split: return .split
        case .full:  return .full
        }
    }

    /// 凭据是否齐全（自动重连前置）
    private var hasCredentials: Bool {
        !server.isEmpty && !user.isEmpty && !password.isEmpty
    }

    init() {
        loadPrefs()
        updateSplitRuleSummaryIfNeeded()
        wifiSSIDReader.onAuthorizationChanged = { [weak self] in
            guard let self else { return }
            self.updateWiFiSSIDLocationPermissionState()
            let changed = self.refreshCurrentWiFiSSID()
            if changed || self.wifiOnDemandEnabled {
                _ = self.applyWiFiOnDemandPolicy(trigger: "Wi-Fi 权限变更")
            }
        }
        wifiSSIDReader.onWiFiChanged = { [weak self] in
            guard let self else { return }
            let changed = self.refreshCurrentWiFiSSID(fallbackMinInterval: 4)
            if changed {
                self.handleNetworkChanged()
            } else if self.wifiOnDemandEnabled {
                _ = self.applyWiFiOnDemandPolicy(trigger: "Wi-Fi 状态变化")
            }
        }
        updateWiFiSSIDLocationPermissionState()
        _ = refreshCurrentWiFiSSID()
        // 日志脱敏兜底：把当前内存密码注入 LogStore，万一某条 message 混入密码也被抹掉。
        // @MainActor 闭包；weak 捕获避免 LogStore.shared 长期持有 controller。
        LogStore.shared.secretsProvider = { [weak self] in
            self.map { [$0.password] } ?? []
        }
        // Self-heal：启动时清两种模式可能残留的进程
        //   - 标准模式：/tmp/xdvpn.pid 指的 openconnect + helper 启的 dns-proxy
        //   - 纯代理模式：/tmp/xdvpn-proxy.pid 指的 openconnect (用户身份) + 它的 ocproxy 子进程
        // 这两套必须分开清，否则上一次 GUI 被 kill 后留下的孤儿 VPN 会让新 GUI 显示"未连接"
        // 但底层 SOCKS5 仍能用的诡异状态
        Task {
            // 用户态的（无需 sudo），放到专用阻塞队列避免占用协作线程池
            await OpenConnectRunner.runBlocking {
                OpenConnectRunner.disconnectProxyMode()
            }
        }
        // root 那套需要 sudoers 已配 —— 首次启动时 cleanup helper 还不存在，跳过
        if sudoConfigured {
            let task = runCleanupDetached(reason: "启动清理上次残余")
            startupCleanupTask = task
            Task { [weak self] in
                _ = await task.value
                self?.startupCleanupTask = nil
            }
        }
        registerSleepHook()
        startPathMonitor()
    }

    deinit {
        pollTimer?.invalidate()
        autoReconnectTimer?.invalidate()
        wifiSSIDFallbackTask?.cancel()
        wifiWakeEvaluationTask?.cancel()
        pathMonitor.cancel()
        let nc = NSWorkspace.shared.notificationCenter
        if let obs = sleepObserver { nc.removeObserver(obs) }
        if let obs = wakeObserver { nc.removeObserver(obs) }
    }

    // MARK: - 网络路径监听（换网 / 等网就绪）

    private func startPathMonitor() {
        pathMonitor.onUpdate = { [weak self] snapshot in
            // 回调在后台 queue，切回 MainActor 再读写状态
            Task { @MainActor [weak self] in
                guard let self else { return }
                let previousSatisfied = self.networkSatisfied
                let previousUsesWired = self.networkUsesWiredEthernet
                let hadSnapshot = self.hasPathSnapshot
                self.hasPathSnapshot = true
                self.networkSatisfied = snapshot.isSatisfied
                self.networkUsesWiFi = snapshot.usesWiFi
                self.networkUsesWiredEthernet = snapshot.usesWiredEthernet

                let changed = self.changeDetector.observe(
                    fingerprint: physicalInterfaceFingerprint(snapshot.interfaceNames))
                let wiredTransportChanged = hadSnapshot && (previousUsesWired != snapshot.usesWiredEthernet)
                let becameSatisfied = hadSnapshot && !previousSatisfied && snapshot.isSatisfied
                let ssidChanged = self.refreshCurrentWiFiSSID(
                    fallbackMinInterval: (changed || wiredTransportChanged || becameSatisfied) ? 8 : 30
                )
                if changed || ssidChanged || wiredTransportChanged {
                    self.handleNetworkChanged()
                } else if becameSatisfied, self.wifiOnDemandEnabled {
                    _ = self.applyWiFiOnDemandPolicy(trigger: "网络就绪")
                }
            }
        }
        pathMonitor.start()
    }

    /// 物理出口变了（换网 / 漫游到不同接口 / 插拔网线）。
    /// 旧隧道基本作废 → 干净重建（走统一的自动重连路径，含等网门控）。
    private func handleNetworkChanged() {
        if applyWiFiOnDemandPolicy(trigger: "网络切换") { return }
        if isConnecting {
            appLog(.warn, "连接过程中网络切换，取消旧连接")
            cancelPendingConnection(
                status: "网络已切换，准备重新连接…",
                resetReconnect: false,
                reconnectAfterCleanup: true
            )
            return
        }
        guard isConnected, !isBusy else { return }
        statusText = "网络已切换，正在重建连接…"
        appLog(.warn, "网络已切换，重建连接")
        isBusy = true
        let mode = activeMode ?? runningMode
        if mode == .proxy {
            Task { [weak self] in
                await OpenConnectRunner.runBlocking {
                    OpenConnectRunner.disconnectProxyMode()
                }
                guard let self else { return }
                self.isConnected = false
                self.activeMode = nil
                self.isBusy = false
                self.onTunnelLost()
            }
        } else {
            runCleanupDetached(reason: "换网清理旧隧道") { [weak self] in
                guard let self else { return }
                self.isConnected = false
                self.activeMode = nil
                self.isBusy = false
                self.onTunnelLost()
            }
        }
    }

    // MARK: - Preferences / Keychain

    private var keychainAccount: String { "\(user)@\(server)" }

    func savePrefs() {
        let d = UserDefaults.standard
        d.set(protocolName, forKey: "xdvpn.protocol")
        d.set(server, forKey: "xdvpn.server")
        d.set(authGroup, forKey: "xdvpn.authGroup")
        d.set(user, forKey: "xdvpn.user")
        d.set(rememberPassword, forKey: "xdvpn.remember")
        d.set(autoConnectOnLaunch, forKey: "xdvpn.autoConnectOnLaunch")
        d.set(wifiOnDemandEnabled, forKey: "xdvpn.wifiOnDemand.enabled")
        d.set(runningMode.rawValue, forKey: "xdvpn.runningMode")
        d.set(splitPreset10, forKey: "xdvpn.split.preset10")
        d.set(splitPreset172, forKey: "xdvpn.split.preset172")
        d.set(splitPreset192, forKey: "xdvpn.split.preset192")
        d.set(splitCustom, forKey: "xdvpn.split.custom")
        d.set(splitDomains, forKey: "xdvpn.split.domains")
        saveWiFiOnDemandRules()
    }

    private func loadPrefs() {
        isLoadingPrefs = true
        defer { isLoadingPrefs = false }

        let d = UserDefaults.standard
        protocolName = d.string(forKey: "xdvpn.protocol") ?? "anyconnect"
        server = d.string(forKey: "xdvpn.server") ?? ""
        authGroup = d.string(forKey: "xdvpn.authGroup") ?? ""
        user = d.string(forKey: "xdvpn.user") ?? ""
        rememberPassword = d.object(forKey: "xdvpn.remember") as? Bool ?? true
        autoConnectOnLaunch = d.bool(forKey: "xdvpn.autoConnectOnLaunch")
        wifiOnDemandEnabled = d.bool(forKey: "xdvpn.wifiOnDemand.enabled")
        wifiOnDemandRules = Self.loadWiFiOnDemandRules(from: d)

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

    private static func loadWiFiOnDemandRules(from defaults: UserDefaults) -> [WiFiOnDemandRule] {
        guard let data = defaults.data(forKey: "xdvpn.wifiOnDemand.rules"),
              let decoded = try? JSONDecoder().decode([WiFiOnDemandRule].self, from: data) else {
            return []
        }
        return decoded.filter { !WiFiOnDemandRule.normalizedSSID($0.ssid).isEmpty }
    }

    private func saveWiFiOnDemandRules() {
        if let data = try? JSONEncoder().encode(wifiOnDemandRules) {
            UserDefaults.standard.set(data, forKey: "xdvpn.wifiOnDemand.rules")
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
        DomainRules.parseSuffixList(splitDomains)
    }

    private func updateSplitRuleSummaryIfNeeded() {
        let c = collectSplitCIDRs().count
        let d = collectDomainSuffixes().count
        let next: String
        if c == 0 && d == 0 {
            next = "尚未选择任何规则"
        } else {
            var parts: [String] = []
            if c > 0 { parts.append("\(c) 个网段") }
            if d > 0 { parts.append("\(d) 个域名") }
            next = parts.joined(separator: " · ") + " 走 VPN"
        }
        if splitRuleSummary != next {
            splitRuleSummary = next
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

    // MARK: - SOCKS5 状态重置
    //
    // 纯代理模式的 SOCKS5 由 ocproxy 提供；分流/全局模式不需要 SOCKS5。
    func applySocks5State() {
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

    // MARK: - Wi-Fi 按需连接

    func refreshWiFiSSID(requestPermissionIfNeeded: Bool = false) {
        updateWiFiSSIDLocationPermissionState()
        let changed = refreshCurrentWiFiSSID(fallbackMinInterval: requestPermissionIfNeeded ? 0 : 5)
        if requestPermissionIfNeeded, currentWiFiSSID == nil {
            wifiSSIDReader.requestLocationPermissionIfNeeded()
            updateWiFiSSIDLocationPermissionState()
            if !wifiAssociated {
                wifiOnDemandStatusText = "当前未连接 Wi-Fi"
            } else if wifiSSIDLocationPermissionRequired {
                wifiOnDemandStatusText = missingWiFiSSIDStatusText()
            } else {
                wifiOnDemandStatusText = "正在读取当前 Wi-Fi…"
                scheduleWiFiSSIDFallback(trigger: "手动刷新 Wi-Fi", minInterval: 0)
            }
        }
        if changed, wifiOnDemandEnabled {
            _ = applyWiFiOnDemandPolicy(trigger: "刷新 Wi-Fi")
        }
    }

    func openWiFiLocationSettings() {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
        ) else {
            return
        }
        NSWorkspace.shared.open(url)
    }

    func evaluateWiFiOnDemandNow() {
        suppressedAutoConnectSSID = nil
        _ = refreshCurrentWiFiSSID()
        _ = applyWiFiOnDemandPolicy(trigger: "手动检查 Wi-Fi 规则", respectManualSuppression: false)
    }

    func addCurrentWiFiRule(action: WiFiOnDemandAction) {
        guard let ssid = currentWiFiSSID else {
            wifiSSIDReader.requestLocationPermissionIfNeeded()
            updateWiFiSSIDLocationPermissionState()
            if wifiAssociated && !wifiSSIDLocationPermissionRequired {
                scheduleWiFiSSIDFallback(trigger: "添加当前 Wi-Fi", minInterval: 0)
                wifiOnDemandStatusText = "正在读取当前 Wi-Fi…"
                statusText = "正在读取当前 Wi-Fi，请稍后再添加"
            } else {
                wifiOnDemandStatusText = missingWiFiSSIDStatusText()
                statusText = wifiOnDemandStatusText
            }
            return
        }
        addWiFiRule(ssid: ssid, action: action)
    }

    func addWiFiRule(ssid: String, action: WiFiOnDemandAction) {
        let normalized = WiFiOnDemandRule.normalizedSSID(ssid)
        guard !normalized.isEmpty else { return }
        if suppressedAutoConnectSSID == normalized {
            suppressedAutoConnectSSID = nil
        }
        wifiOnDemandRules = WiFiOnDemandPolicy.replacingOrAppending(
            wifiOnDemandRules,
            ssid: normalized,
            action: action
        )
        wifiOnDemandStatusText = "已保存 Wi-Fi 规则：\(normalized)"
        if wifiOnDemandEnabled {
            _ = applyWiFiOnDemandPolicy(trigger: "保存 Wi-Fi 规则", respectManualSuppression: false)
        }
    }

    func updateWiFiRule(id: UUID, action: WiFiOnDemandAction) {
        guard let idx = wifiOnDemandRules.firstIndex(where: { $0.id == id }) else { return }
        if suppressedAutoConnectSSID == wifiOnDemandRules[idx].ssid {
            suppressedAutoConnectSSID = nil
        }
        wifiOnDemandRules[idx].action = action
        if wifiOnDemandEnabled {
            _ = applyWiFiOnDemandPolicy(trigger: "更新 Wi-Fi 规则", respectManualSuppression: false)
        }
    }

    func removeWiFiRule(id: UUID) {
        wifiOnDemandRules.removeAll { $0.id == id }
        if wifiOnDemandEnabled {
            _ = applyWiFiOnDemandPolicy(trigger: "删除 Wi-Fi 规则", respectManualSuppression: false)
        }
    }

    private var currentWiFiAssociationState: WiFiAssociationState {
        WiFiAssociationState.resolve(
            wifiAssociated: wifiAssociated,
            currentSSID: currentWiFiSSID,
            hasPathSnapshot: hasPathSnapshot,
            networkSatisfied: networkSatisfied,
            usesWiFi: networkUsesWiFi,
            usesWiredEthernet: networkUsesWiredEthernet
        )
    }

    @discardableResult
    private func refreshCurrentWiFiSSID(fallbackMinInterval: TimeInterval = 8) -> Bool {
        updateWiFiSSIDLocationPermissionState()
        let snapshot = wifiSSIDReader.currentInterfaceSnapshot()
        wifiAssociated = snapshot.isAssociatedToWiFi

        if let ssid = snapshot.ssid {
            invalidatePendingWiFiFallback()
            return setObservedWiFiSSID(ssid)
        }

        // 未关联 Wi-Fi（关闭 Wi-Fi / 仅插网线）：明确清空，不拉起昂贵的 system_profiler。
        guard snapshot.isAssociatedToWiFi else {
            invalidatePendingWiFiFallback()
            return setObservedWiFiSSID(nil)
        }

        // macOS 14+ 缺少定位权限时，system_profiler 同样只会返回 <redacted>，直接跳过。
        if wifiSSIDLocationPermissionRequired {
            invalidatePendingWiFiFallback()
            return setObservedWiFiSSID(nil)
        }

        // 已关联 Wi-Fi 且有定位权限，但 CoreWLAN 暂未返回 SSID：
        // 不要立刻把已缓存的 SSID 抹成 nil（避免短暂抖动触发误拆隧道），改由异步 fallback 核实后再更新。
        scheduleWiFiSSIDFallback(trigger: "读取 Wi-Fi", minInterval: fallbackMinInterval)
        return false
    }

    private func invalidatePendingWiFiFallback() {
        wifiObservationGeneration &+= 1
        wifiSSIDFallbackTask?.cancel()
        wifiSSIDFallbackTask = nil
        wifiSSIDFallbackInFlight = false
    }

    @discardableResult
    private func setObservedWiFiSSID(_ ssid: String?) -> Bool {
        let normalized = ObservedWiFiSSID.normalized(ssid)
        if currentWiFiSSID != normalized {
            currentWiFiSSID = normalized
        }
        if let suppressed = suppressedAutoConnectSSID, suppressed != normalized {
            suppressedAutoConnectSSID = nil
        }
        let previous = lastObservedSSID
        lastObservedSSID = normalized
        if !hasObservedSSID {
            hasObservedSSID = true
            return normalized != nil
        }
        return previous != normalized
    }

    private func scheduleWiFiSSIDFallback(trigger: String, minInterval: TimeInterval) {
        guard !wifiSSIDFallbackInFlight else { return }
        guard wifiAssociated, !wifiSSIDLocationPermissionRequired else { return }
        let nowUptime = ProcessInfo.processInfo.systemUptime
        if let last = lastWiFiSSIDFallbackStartedUptime,
           nowUptime - last < minInterval {
            return
        }

        wifiSSIDFallbackInFlight = true
        lastWiFiSSIDFallbackStartedUptime = nowUptime
        let expectedGeneration = wifiObservationGeneration

        let task = Task { @MainActor [weak self] in
            let ssid = await OpenConnectRunner.runBlocking {
                WiFiSSIDReader.currentSSIDFromSystemProfiler()
            }
            guard let self, !Task.isCancelled else { return }
            self.wifiSSIDFallbackInFlight = false
            self.wifiSSIDFallbackTask = nil
            // 如果在 system_profiler 运行期间 CoreWLAN 已经拿到更新的观测结果，丢弃过期结果。
            guard self.wifiObservationGeneration == expectedGeneration else { return }

            let changed = self.setObservedWiFiSSID(ssid)

            if self.wifiOnDemandEnabled {
                if ssid != nil {
                    if changed || self.pausedByWiFiPolicy || !self.isConnected {
                        _ = self.applyWiFiOnDemandPolicy(trigger: "\(trigger)（系统信息）")
                    }
                } else {
                    self.wifiOnDemandStatusText = self.missingWiFiSSIDStatusText()
                }
            } else if ssid != nil {
                self.wifiOnDemandStatusText = "已读取当前 Wi-Fi"
            } else {
                self.wifiOnDemandStatusText = self.missingWiFiSSIDStatusText()
            }
        }
        wifiSSIDFallbackTask = task
    }

    private func awaitPendingWiFiFallback(timeout: TimeInterval) async {
        guard let fallbackTask = wifiSSIDFallbackTask else { return }
        let deadline = Date().addingTimeInterval(timeout)
        while wifiSSIDFallbackInFlight, Date() < deadline {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        _ = fallbackTask
    }

    private func updateWiFiSSIDLocationPermissionState() {
        let required = wifiSSIDReader.isLocationPermissionRequired
        if wifiSSIDLocationPermissionRequired != required {
            wifiSSIDLocationPermissionRequired = required
        }
    }

    private func missingWiFiSSIDStatusText(
        pendingText: String = "未读取到当前 Wi-Fi"
    ) -> String {
        if !wifiAssociated {
            return "当前未连接 Wi-Fi"
        }
        if !wifiSSIDReader.isLocationServicesEnabled {
            return "请在系统设置中开启定位服务"
        }
        if wifiSSIDLocationPermissionRequired {
            return "请在系统设置中允许 XDVPN 使用定位服务"
        }
        return pendingText
    }

    private var currentWiFiPolicy: WiFiOnDemandPolicy {
        WiFiOnDemandPolicy(isEnabled: wifiOnDemandEnabled, rules: wifiOnDemandRules)
    }

    private func flushPendingWiFiPolicyIfNeeded() {
        guard wifiOnDemandEnabled, !isBusy else { return }
        _ = refreshCurrentWiFiSSID(fallbackMinInterval: 8)
        _ = applyWiFiOnDemandPolicy(trigger: "忙状态结束补查 Wi-Fi 规则")
    }

    @discardableResult
    private func applyWiFiOnDemandPolicy(
        trigger: String,
        respectManualSuppression: Bool = true
    ) -> Bool {
        guard wifiOnDemandEnabled else {
            pausedByWiFiPolicy = false
            pendingWiFiPolicyReevaluation = false
            wifiOnDemandStatusText = "未启用"
            return false
        }

        let state = currentWiFiAssociationState
        let outcome = currentWiFiPolicy.evaluate(state: state, wasPaused: pausedByWiFiPolicy)
        let wasPaused = pausedByWiFiPolicy

        switch outcome.decision {
        case .disconnect:
            let ssid = currentWiFiSSID ?? "未知 Wi-Fi"
            pausedByWiFiPolicy = outcome.shouldPause
            shouldReconnectAfterWake = false
            cancelAutoReconnect()
            wifiOnDemandStatusText = "当前 Wi-Fi「\(ssid)」规则：断开 VPN"
            appLog(.info, "\(trigger)：SSID \(ssid) 命中断开规则")

            if isConnecting {
                cancelPendingConnection(
                    status: "当前 Wi-Fi「\(ssid)」配置为断开 VPN",
                    resetReconnect: true,
                    reconnectAfterCleanup: false
                )
                return true
            }
            guard !isBusy else {
                pendingWiFiPolicyReevaluation = true
                return true
            }
            if isConnected {
                disconnectDueToWiFiPolicy(ssid: ssid)
            } else {
                statusText = "当前 Wi-Fi「\(ssid)」配置为断开 VPN"
            }
            return true

        case .connect:
            let ssid = currentWiFiSSID ?? "未知 Wi-Fi"
            pausedByWiFiPolicy = outcome.shouldPause
            wifiOnDemandStatusText = "当前 Wi-Fi「\(ssid)」规则：连接 VPN"

            if respectManualSuppression, suppressedAutoConnectSSID == ssid {
                return false
            }
            // 已连接或正在连接中：返回 false，允许 handleNetworkChanged() 正常取消/重建旧网络上的隧道。
            guard !isConnected, !isConnecting else { return false }
            guard !isBusy else {
                pendingWiFiPolicyReevaluation = true
                return true
            }
            guard hasCredentials else {
                statusText = "当前 Wi-Fi「\(ssid)」需要连接 VPN，但凭据不完整"
                appLog(.warn, "\(trigger)：SSID \(ssid) 命中连接规则，但凭据不完整")
                return true
            }
            guard runningMode == .proxy || sudoConfigured else {
                statusText = "当前 Wi-Fi「\(ssid)」需要连接 VPN，请先完成首次配置"
                appLog(.warn, "\(trigger)：SSID \(ssid) 命中连接规则，但 sudo 组件未配置")
                return true
            }

            connectDueToWiFiPolicy(ssid: ssid, trigger: trigger)
            return true

        case .noMatch:
            pausedByWiFiPolicy = outcome.shouldPause
            if outcome.blocksAutomaticConnect {
                wifiOnDemandStatusText = "无法读取当前 Wi-Fi，保持 VPN 暂停"
                statusText = "无法读取当前 Wi-Fi，VPN 自动连接已暂停"
                return true
            }

            if wasPaused {
                switch state {
                case .notOnWiFi:
                    wifiOnDemandStatusText = "当前未经由 Wi-Fi，已解除暂停"
                    appLog(.info, "\(trigger)：已离开 Wi-Fi（或切至有线），解除暂停")
                case .associated(let ssid):
                    wifiOnDemandStatusText = "当前 Wi-Fi「\(ssid)」未配置规则"
                    appLog(.info, "\(trigger)：已离开断开规则 Wi-Fi，解除暂停")
                case .associatedUnknownSSID:
                    wifiOnDemandStatusText = missingWiFiSSIDStatusText()
                }
                return false
            }

            switch state {
            case .associated(let ssid):
                wifiOnDemandStatusText = "当前 Wi-Fi「\(ssid)」未配置规则"
            case .notOnWiFi:
                wifiOnDemandStatusText = wifiAssociated ? "当前主网络非 Wi-Fi" : "当前未连接 Wi-Fi"
            case .associatedUnknownSSID:
                wifiOnDemandStatusText = missingWiFiSSIDStatusText()
            }
            return false
        }
    }

    /// 命中 Wi-Fi「连接 VPN」规则：走带网络就绪门控与退避重试的自动连接链路，
    /// 避免 Wi-Fi 刚关联但 DHCP/DNS 尚未就绪时首连失败一次就彻底放弃。
    private func connectDueToWiFiPolicy(ssid: String, trigger: String) {
        if isAutoReconnecting {
            // 已经在自动重连队列/等网中，无需重复触发。
            return
        }
        appLog(.info, "\(trigger)：SSID \(ssid) 命中连接规则")
        policy.reset()
        isAutoReconnecting = true
        if !networkSatisfied {
            statusText = "当前 Wi-Fi「\(ssid)」规则：等待网络就绪…"
            Task { @MainActor [weak self] in
                await self?.fireAutoReconnect()
            }
        } else if canConnect {
            connect(silent: true)
        } else {
            isAutoReconnecting = false
        }
    }

    private func disconnectDueToWiFiPolicy(ssid: String) {
        isBusy = true
        statusText = "当前 Wi-Fi「\(ssid)」配置为断开，正在断开 VPN…"

        let disconnectMode = activeMode ?? runningMode
        Task { [weak self] in
            let errMsg: String? = await OpenConnectRunner.runBlocking {
                do {
                    try Self.cleanup(mode: disconnectMode)
                    return nil
                } catch {
                    return error.localizedDescription
                }
            }
            guard let self else { return }
            self.isConnected = false
            self.activeMode = nil
            self.clearDiagnostics()
            if let errMsg {
                self.statusText = "Wi-Fi 规则断开失败：\(errMsg)"
                appLog(.error, "Wi-Fi 规则断开失败：\(errMsg)")
            } else {
                self.statusText = "已因 Wi-Fi「\(ssid)」断开 VPN"
                appLog(.info, "已因 Wi-Fi「\(ssid)」断开 VPN")
            }
            self.isBusy = false
        }
    }

    private func isWiFiPolicyBlockingAutomaticConnect(trigger: String) -> Bool {
        guard wifiOnDemandEnabled else { return false }
        _ = refreshCurrentWiFiSSID()

        let state = currentWiFiAssociationState
        let outcome = currentWiFiPolicy.evaluate(state: state, wasPaused: pausedByWiFiPolicy)
        pausedByWiFiPolicy = outcome.shouldPause

        guard outcome.blocksAutomaticConnect else { return false }

        switch outcome.decision {
        case .disconnect:
            let ssid = currentWiFiSSID ?? "未知 Wi-Fi"
            cancelAutoReconnect()
            wifiOnDemandStatusText = "当前 Wi-Fi「\(ssid)」规则：断开 VPN"
            statusText = "当前 Wi-Fi「\(ssid)」配置为断开 VPN"
            appLog(.info, "\(trigger)：SSID \(ssid) 命中断开规则，停止自动连接")
            return true
        case .noMatch:
            wifiOnDemandStatusText = "无法读取当前 Wi-Fi，保持 VPN 暂停"
            statusText = "无法读取当前 Wi-Fi，VPN 自动连接已暂停"
            appLog(.warn, "\(trigger)：无法读取 SSID，保持 Wi-Fi 策略暂停")
            return true
        case .connect:
            return false
        }
    }

    // MARK: - 用户动作

    func selectMode(_ mode: RunningMode, presentingWindow: NSWindow? = nil) {
        guard mode != runningMode, !isBusy else { return }
        guard isConnected else {
            runningMode = mode
            savePrefs()
            return
        }
        confirmModeSwitch(to: mode, presentingWindow: presentingWindow)
    }

    private func confirmModeSwitch(to targetMode: RunningMode, presentingWindow: NSWindow?) {
        let currentMode = activeMode ?? runningMode
        guard targetMode != currentMode else { return }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "切换到\(targetMode.label)？"
        alert.informativeText = "这会先断开当前的\(currentMode.label)，然后用\(targetMode.label)重新连接。"
        alert.addButton(withTitle: "切换并重连")
        alert.addButton(withTitle: "取消")

        if let window = sheetParentWindow(preferred: presentingWindow) {
            alert.beginSheetModal(for: window) { [weak self] response in
                guard response == .alertFirstButtonReturn else { return }
                Task { @MainActor [weak self] in
                    self?.switchModeAndReconnect(to: targetMode)
                }
            }
        } else {
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            switchModeAndReconnect(to: targetMode)
        }
    }

    private func sheetParentWindow(preferred: NSWindow?) -> NSWindow? {
        let candidates = [preferred, NSApp.keyWindow, NSApp.mainWindow] + NSApp.windows
        return candidates.compactMap { $0 }.first {
            $0.isVisible && !$0.isSheet && $0.canBecomeKey
        }
    }

    private func switchModeAndReconnect(to targetMode: RunningMode) {
        guard !isBusy else { return }
        let currentMode = activeMode ?? runningMode
        guard targetMode != currentMode else { return }

        guard isConnected else {
            switchToModeAndConnectIfPossible(targetMode)
            return
        }

        cancelAutoReconnect()
        isBusy = true
        statusText = "正在切换到\(targetMode.label)…"
        appLog(.info, "切换运行模式：\(currentMode.label) → \(targetMode.label)")

        Task { [weak self] in
            let errMsg: String? = await OpenConnectRunner.runBlocking {
                do {
                    try Self.cleanup(mode: currentMode)
                    return nil
                } catch {
                    return error.localizedDescription
                }
            }

            guard let self else { return }
            if let errMsg {
                self.statusText = "切换失败：\(errMsg)"
                appLog(.error, "切换模式清理失败：\(errMsg)")
                self.isBusy = false
                return
            }

            self.isConnected = false
            self.activeMode = nil
            self.clearDiagnostics()
            self.isBusy = false
            self.switchToModeAndConnectIfPossible(targetMode)
        }
    }

    private func switchToModeAndConnectIfPossible(_ targetMode: RunningMode) {
        runningMode = targetMode
        savePrefs()

        if targetMode != .proxy && !sudoConfigured {
            installSudoers(thenConnect: true)
        } else if canConnect {
            connect()
        } else {
            statusText = "已切换到\(targetMode.label)，请补全配置后连接"
        }
    }

    /// 启动后调用：如果用户开了"启动时自动连接"且凭据齐全，就发起一次连接。
    /// 给 init 里的 self-heal cleanup 一点时间跑完，再走正常 connect 流程
    /// （connect 内部会再做一次 cleanup，所以即便 cleanup 还没跑完也安全）。
    func autoConnectIfNeeded() {
        guard autoConnectOnLaunch || wifiOnDemandEnabled else { return }
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 500_000_000)
            guard let self else { return }
            if self.wifiOnDemandEnabled {
                await self.awaitPendingWiFiFallback(timeout: 2.5)
            }
            // Wi-Fi 规则和传统“启动时自动连接”是两套独立开关。即使后者关闭，
            // 启动时也必须执行已启用的当前 SSID 规则。
            if self.wifiOnDemandEnabled,
               self.applyWiFiOnDemandPolicy(trigger: "启动 Wi-Fi 按需连接") {
                return
            }
            guard self.autoConnectOnLaunch else { return }
            // canConnect 已经覆盖了：sudo 状态、凭据齐全、未在连接中
            // 启动自动连接是无人值守场景（远程维护机）→ 静默，不卡 Touch ID
            if self.isWiFiPolicyBlockingAutomaticConnect(trigger: "启动自动连接") { return }
            if self.canConnect { self.connect(silent: true) }
        }
    }

    /// silent=true 为自动重连：跳过 BiometricGate（无人值守/远程无 Touch ID 不卡），
    /// 只复用内存里的密码；失败会沿退避链推进。silent=false 为用户手动连接。
    func connect(silent: Bool = false) {
        if !silent {
            suppressedAutoConnectSSID = nil
        }
        if silent, isWiFiPolicyBlockingAutomaticConnect(trigger: "自动连接") { return }
        guard canConnect else { return }
        isBusy = true
        isConnecting = true
        statusText = silent ? "正在自动重连…" : "正在连接…"
        let mode = runningMode
        appLog(.info, silent ? "开始自动重连（\(mode.label)）" : "用户发起连接（\(mode.label)）")

        let p = protocolName, s = server, g = authGroup, u = user, pw = password
        let remember = rememberPassword
        let account = keychainAccount
        let proxyMode = mode == .proxy
        let socksPort = UInt16(socks5Port)
        let splitOn = mode == .split
        let splitCIDRs = collectSplitCIDRs()
        let domainSuffixes = collectDomainSuffixes()
        let attemptID = UUID()
        connectionAttemptID = attemptID

        let rootCleanupRequired = !proxyMode || sudoConfigured
        let startupCleanupTask = self.startupCleanupTask
        let task = Task { [weak self] in
            // 先清两种模式的所有残留 —— 用户可能从对方模式切过来，旧进程还在
            await OpenConnectRunner.runBlocking {
                OpenConnectRunner.disconnectProxyMode()
            }

            // 连接
            let result: Result<Void, Error>
            do {
                // init 的 self-heal 是唯一会在没有状态机 completion 的情况下先行 cleanup
                // 的路径。显式等待它，不能依赖 NSLock 的非 FIFO 唤醒顺序。
                if let startupCleanupTask,
                   let cleanupErrorMessage = await startupCleanupTask.value {
                    throw VPNError.cleanupFailed(cleanupErrorMessage)
                }
                if !silent { try await BiometricGate.ensure() }
                guard !Task.isCancelled else { return }
                final class CancellationFlag: @unchecked Sendable {
                    private let lock = NSLock()
                    private var cancelled = false
                    func markCancelled() { lock.lock(); cancelled = true; lock.unlock() }
                    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
                }
                let cancelFlag = CancellationFlag()
                if proxyMode {
                    if rootCleanupRequired {
                        try await OpenConnectRunner.runBlocking {
                            try OpenConnectRunner.cleanup()
                        }
                    }
                    guard !Task.isCancelled else { return }
                    try await OpenConnectRunner.runBlocking {
                        try OpenConnectRunner.connectProxyMode(
                            protocolName: p,
                            server: s,
                            authGroup: g,
                            user: u,
                            password: pw,
                            socksPort: socksPort
                        )
                    }
                } else {
                    try await withTaskCancellationHandler {
                        try await OpenConnectRunner.runBlocking {
                            try OpenConnectRunner.replaceConnection(
                                protocolName: p,
                                server: s,
                                authGroup: g,
                                user: u,
                                password: pw
                            ) {
                                guard !cancelFlag.isCancelled else { throw CancellationError() }
                                Self.writeSplitConfFile(enabled: splitOn, cidrs: splitCIDRs)
                                Self.writeDomainConfFile(enabled: splitOn, domains: domainSuffixes)
                            }
                        }
                    } onCancel: {
                        cancelFlag.markCancelled()
                        OpenConnectRunner.cancelPendingConnection()
                    }
                }
                result = .success(())
            } catch {
                result = .failure(error)
            }

            await MainActor.run { [weak self] in
                guard let self, self.connectionAttemptID == attemptID else { return }
                self.connectionAttemptID = nil
                self.connectionTask = nil
                self.isConnecting = false
                self.isBusy = false
                switch result {
                case .success:
                    if remember {
                        KeychainStore.save(password: pw, account: account)
                    } else {
                        KeychainStore.delete(account: account)
                    }
                    self.savePrefs()
                    if !silent { BiometricGate.markActivity() }
                    // 重连成功：手动 → 整体清零；自动 → 不清零，由「稳定存活 60s」才清（修抖动无限重连）
                    let now = Date()
                    if silent {
                        self.policy.onConnectSucceeded(now: now)
                    } else {
                        self.policy.reset()
                    }
                    self.isAutoReconnecting = false
                    self.resetBlackholeTracking()
                    self.activeMode = mode
                    self.cachedProcessPid = nil
                    self.connectedAtUptime = ProcessInfo.processInfo.systemUptime
                    self.connectedAt = now
                    self.isConnected = true
                    if proxyMode {
                        // 纯代理模式：ocproxy 已在 socksPort 暴露 SOCKS5
                        self.statusText = "已连接（纯代理 · SOCKS5 127.0.0.1:\(socksPort)）"
                        self.socks5Active = true
                        appLog(.info, "已连接（纯代理 · SOCKS5 127.0.0.1:\(socksPort)）")
                    } else {
                        // 分流 / 全局模式：kernel 路由自动接管，不再启 Swift Socks5Proxy
                        self.parseSessionFile()
                        self.updateTrafficStats()
                        self.statusText = "已连接"
                        appLog(.info, "已连接（\(mode.label)）")
                    }
                case .failure(let err):
                    if case VPNError.sudoNotConfigured = err {
                        self.sudoConfigured = false
                    }
                    self.isConnected = false
                    self.activeMode = nil
                    if case VPNError.cleanupFailed = err {
                        self.cancelAutoReconnect()
                        self.statusText = "网络清理失败，已停止重连：\(err.localizedDescription)"
                        appLog(.error, self.statusText)
                    } else if silent, self.isAutoReconnecting {
                        // 自动重连这次失败 → 沿退避链推进，而不是停在未连接（修硬失败单次放弃）
                        appLog(.error, "自动重连尝试失败：\(err.localizedDescription)")
                        self.applyReconnectCommand(self.policy.onReconnectAttemptFailed(now: Date()))
                    } else {
                        self.statusText = err.localizedDescription
                        appLog(.error, "连接失败：\(err.localizedDescription)")
                    }
                }
            }
        }
        connectionTask = task
    }

    func disconnect() {
        if isConnecting {
            cancelConnection()
            return
        }
        guard isConnected, !isBusy else { return }
        // 用户主动断开 → 取消任何待执行的自动重连，并在当前 SSID 会话内抑制「自动连接」规则立刻拉回
        if wifiOnDemandEnabled, let ssid = currentWiFiSSID {
            suppressedAutoConnectSSID = ssid
        }
        cancelAutoReconnect()
        isBusy = true
        statusText = "正在断开…"
        appLog(.info, "用户手动断开")

        let disconnectMode = activeMode ?? runningMode

        Task { [weak self] in
            let errMsg: String? = await OpenConnectRunner.runBlocking {
                do {
                    try Self.cleanup(mode: disconnectMode)
                    return nil
                } catch {
                    return error.localizedDescription
                }
            }
            guard let self else { return }
            self.isConnected = false
            self.activeMode = nil
            self.clearDiagnostics()
            self.statusText = errMsg ?? "未连接"
            self.isBusy = false
        }
    }

    func cancelConnection() {
        guard isConnecting else { return }
        if wifiOnDemandEnabled, let ssid = currentWiFiSSID {
            suppressedAutoConnectSSID = ssid
        }
        appLog(.info, "用户取消连接")
        cancelPendingConnection(
            status: "已取消连接",
            resetReconnect: true,
            reconnectAfterCleanup: false
        )
    }

    private func cancelPendingConnection(
        status: String,
        resetReconnect: Bool,
        reconnectAfterCleanup: Bool
    ) {
        let mode = runningMode
        connectionAttemptID = nil
        connectionTask?.cancel()
        connectionTask = nil
        isConnecting = false
        isBusy = true
        isConnected = false
        activeMode = nil
        statusText = "正在取消连接…"
        if resetReconnect { cancelAutoReconnect() }

        Task { [weak self] in
            let (cleanupSucceeded, cleanupErrorMessage): (Bool, String?) = await OpenConnectRunner.runBlocking {
                OpenConnectRunner.cancelPendingConnection()
                if mode == .proxy {
                    OpenConnectRunner.disconnectProxyMode()
                    return (true, nil)
                }
                do {
                    try OpenConnectRunner.cleanup()
                    return (true, nil)
                } catch {
                    return (false, error.localizedDescription)
                }
            }
            guard let self, self.connectionAttemptID == nil else { return }
            self.isBusy = false
            guard cleanupSucceeded else {
                self.cancelAutoReconnect()
                self.statusText = "网络清理失败，已停止重连：\(cleanupErrorMessage ?? "未知错误")"
                appLog(.error, "取消连接：\(self.statusText)")
                return
            }
            self.statusText = status
            if reconnectAfterCleanup { self.onTunnelLost() }
        }
    }

    // MARK: - Sudo helpers

    func installSudoers(thenConnect: Bool = false) {
        isBusy = true
        statusText = "正在安装组件…"
        Task { [weak self] in
            let (errMsg, installed): (String?, Bool) = await OpenConnectRunner.runBlocking {
                let err: String?
                do {
                    try SudoersInstaller.install()
                    // 装完之后同步跑一次 cleanup，顺手把 v0.2 残余（如果有）也清了。
                    // 完成后才允许自动连接，避免后台 cleanup 删掉新连接的 split/domain conf。
                    try OpenConnectRunner.cleanup()
                    err = nil
                } catch {
                    err = error.localizedDescription
                }
                return (err, SudoersInstaller.isInstalled)
            }
            guard let self else { return }
            self.sudoConfigured = installed
            if let errMsg {
                self.statusText = errMsg
                appLog(.error, "组件安装失败：\(errMsg)")
            } else if !installed {
                self.statusText = "组件校验未通过，请重新安装"
                appLog(.error, "组件安装后校验未通过（isInstalled=false）")
            } else if !self.isConnected {
                self.statusText = "未连接"
                appLog(.info, "免密组件安装完成")
            }
            self.isBusy = false
            // 配置成功 + 凭据齐全 → 自动连接
            if errMsg == nil, thenConnect, self.canConnect {
                self.connect()
            }
        }
    }

    func uninstallSudoers() {
        isBusy = true
        Task { [weak self] in
            let installed = await OpenConnectRunner.runBlocking {
                try? SudoersInstaller.uninstall()
                return SudoersInstaller.isInstalled
            }
            guard let self else { return }
            self.isBusy = false
            self.sudoConfigured = installed
        }
    }

    // MARK: - Polling

    private func startPolling() {
        guard pollTimer == nil else { return }
        pollTickCount = 0
        // 仅在连接态启动心跳；设 tolerance 允许系统合并定时器唤醒，降低空闲耗电。
        let timer = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.pollTick()
            }
        }
        timer.tolerance = 0.2
        // .common 模式 → 菜单展开/拖窗等期间也继续 fire
        RunLoop.main.add(timer, forMode: .common)
        pollTimer = timer
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
        pollInFlight = false
        pollTickCount = 0
        cachedProcessPid = nil
    }

    private func pollTick(forceTrafficSample: Bool = false) {
        guard isConnected, !pollInFlight else { return }
        pollInFlight = true
        pollTickCount &+= 1

        let mode = activeMode ?? runningMode
        let previousPid = cachedProcessPid
        let previousStamp = cachedSessionStamp
        let currentIface = tunnelInterface
        // 仅在需要实时速率展示（菜单栏外显/主窗口可见）或 full 模式黑洞检测时每秒采流量；
        // 后台静默 split 模式每 5 秒采一次接口统计，但每秒仍检查进程存活。
        let needsHighFreqTraffic = forceTrafficSample || showSpeedInMenuBar || isMainWindowVisible || mode == .full
        let shouldSampleTraffic = mode != .proxy && (needsHighFreqTraffic || pollTickCount % 5 == 0)
        let shouldCheckSession = mode != .proxy && (currentIface == nil || pollTickCount % 3 == 1)

        pollQueue.async { [weak self] in
            // PID 缓存快路径：同一连接期间 openconnect PID 稳定，直接 kill(pid, 0) 免去每秒读盘。
            // 仅当无缓存或缓存 PID 已退出时才重新读取 pid 文件复核。
            let resolvedPid: pid_t?
            let running: Bool
            if let pid = previousPid, OpenConnectRunner.isAlive(pid) {
                resolvedPid = pid
                running = true
            } else {
                let freshPid = mode == .proxy ? OpenConnectRunner.proxyModePid : OpenConnectRunner.currentPid()
                if let freshPid, OpenConnectRunner.isAlive(freshPid) {
                    resolvedPid = freshPid
                    running = true
                } else {
                    resolvedPid = nil
                    running = false
                }
            }

            var parsedSession: RouteScriptSession?
            var nextStamp = previousStamp
            var effectiveIface = currentIface

            if running, shouldCheckSession {
                let (session, stamp) = Self.readSessionFileIfChanged(previousStamp: previousStamp)
                parsedSession = session
                nextStamp = stamp
                if let session {
                    effectiveIface = session.tunnelInterface
                }
            }

            let info: TunnelInfo?
            if running, shouldSampleTraffic, let iface = effectiveIface {
                info = Self.queryTunnel(iface)
            } else {
                info = nil
            }

            let sample = PollSample(
                processAlive: running,
                resolvedPid: resolvedPid,
                session: parsedSession,
                sessionStamp: nextStamp,
                tunnelInfo: info
            )
            Task { @MainActor [weak self] in
                self?.applyPollSample(sample, mode: mode)
            }
        }
    }

    private func applyPollSample(_ sample: PollSample, mode: RunningMode) {
        pollInFlight = false
        guard isConnected else { return }

        cachedProcessPid = sample.resolvedPid
        if sample.processAlive, mode != .proxy {
            cachedSessionStamp = sample.sessionStamp
            if let session = sample.session {
                applySession(session)
            }
            if let info = sample.tunnelInfo {
                applyTunnelTraffic(info)
                trackInbound()
            }
        }
        guard !isBusy else { return }

        let nowUptime = ProcessInfo.processInfo.systemUptime
        let secsSinceConnect = connectedAtUptime.map { max(0, nowUptime - $0) } ?? 9999

        // 健康判定（纯逻辑、已单测）：进程死 / 黑洞 → 重连；健康 → 喂稳定窗口
        let facts = TunnelFacts(
            declaredConnected: isConnected,
            processAlive: sample.processAlive,
            mode: coreMode,
            secsSinceConnect: secsSinceConnect,
            graceSeconds: 15,
            defaultRouteOnUtun: nil,        // 路由主动探测留作后续，先不在主线程跑 route
            inboundStalledSeconds: inboundStalledSeconds(),
            stallThreshold: 30,
            hadInboundEverSinceConnect: hadInboundEverSinceConnect,
            outboundActive: trafficOutRate > 0,
            socksReachable: nil             // proxy 主动探测留作后续
        )
        switch diagnoseTunnel(facts) {
        case .healthy:
            policy.onHealthyTick(now: Date())
        case .notConnected:
            break
        case .processDead:
            appLog(.warn, "检测到掉线（进程已退）")
            beginAutoCleanupAndReconnect()
        case .blackholeSuspect:
            appLog(.warn, "检测到掉线（疑似黑洞，无回流）")
            beginAutoCleanupAndReconnect()
        }
    }

    /// 意外掉线 → 先清理（按模式），完成后交给 policy 排重连。
    private func beginAutoCleanupAndReconnect() {
        isBusy = true
        statusText = "连接已丢失，正在清理…"
        let mode = activeMode ?? runningMode
        if mode == .proxy {
            Task { [weak self] in
                await OpenConnectRunner.runBlocking {
                    OpenConnectRunner.disconnectProxyMode()
                }
                guard let self else { return }
                self.isConnected = false
                self.activeMode = nil
                self.isBusy = false
                self.onTunnelLost()
            }
        } else {
            runCleanupDetached(reason: "意外断开自动清理") { [weak self] in
                guard let self else { return }
                self.isConnected = false
                self.activeMode = nil
                self.isBusy = false
                self.onTunnelLost()
            }
        }
    }

    // MARK: - 黑洞检测：入站字节停滞跟踪

    private func trackInbound() {
        if trafficIn != lastInboundBytes {
            lastInboundBytes = trafficIn
            lastInboundChangeUptime = ProcessInfo.processInfo.systemUptime
            if trafficIn > 0 { hadInboundEverSinceConnect = true }
        }
    }

    private func inboundStalledSeconds() -> TimeInterval {
        let nowUptime = ProcessInfo.processInfo.systemUptime
        let ref = lastInboundChangeUptime ?? connectedAtUptime ?? nowUptime
        return max(0, nowUptime - ref)
    }

    private func resetBlackholeTracking() {
        lastInboundBytes = 0
        lastInboundChangeUptime = nil
        hadInboundEverSinceConnect = false
    }

    // MARK: - 自动重连（策略驱动，纯逻辑在 XDVPNCore.ReconnectPolicy，已单测）
    //
    // 触发来源统一三处：pollTick 健康判定掉线、换网、休眠唤醒。
    // 退避节奏 / 计数清零 / 放弃由 ReconnectPolicy 决定；这里只负责计时器、等网门控与副作用。

    /// 检测到非用户意图掉线 → 交给 policy 决定退避并落地命令。
    private func onTunnelLost() {
        if isWiFiPolicyBlockingAutomaticConnect(trigger: "掉线自动重连") { return }
        guard hasCredentials else {
            statusText = "未连接（凭据不全，请手动连接）"
            appLog(.warn, "掉线但凭据不全，不自动重连")
            return
        }
        applyReconnectCommand(policy.onTunnelLost(now: Date()))
    }

    /// 把 policy 的命令落地为「计时器 + 状态文案」。
    private func applyReconnectCommand(_ cmd: ReconnectCommand) {
        autoReconnectTimer?.invalidate()
        autoReconnectTimer = nil
        switch cmd {
        case .giveUp:
            isAutoReconnecting = false
            statusText = "自动重连失败 \(policy.maxAttempts) 次，请手动重连"
            appLog(.error, "自动重连放弃（已失败 \(policy.maxAttempts) 次）")
        case .scheduleReconnect(let delay, let attempt):
            isAutoReconnecting = true
            statusText = "连接已丢失，\(Int(delay))s 后自动重连（第 \(attempt)/\(policy.maxAttempts) 次）"
            appLog(.info, "第 \(attempt)/\(policy.maxAttempts) 次自动重连，\(Int(delay))s 后")
            autoReconnectTimer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.autoReconnectTimer = nil
                    await self.fireAutoReconnect()
                }
            }
        }
    }

    /// 计时器到点：先等网络真就绪（修唤醒/重连抢在 WiFi 握手前必失败），再静默重连。
    /// 全程用 isAutoReconnecting 守卫：用户在等网期间手动断开 → cancelAutoReconnect 置 false → 此处提前退出，
    /// 不会出现「断开后又被重连拉起」。
    private func fireAutoReconnect() async {
        guard isAutoReconnecting, !isConnected, !isBusy else { return }
        if !networkSatisfied { appLog(.info, "等待网络就绪…") }
        await awaitNetworkReady(timeout: 8)
        guard isAutoReconnecting, !isConnected, !isBusy else { return }
        if wifiOnDemandEnabled {
            _ = refreshCurrentWiFiSSID(fallbackMinInterval: 4)
            await awaitPendingWiFiFallback(timeout: 2.0)
        }
        guard isAutoReconnecting, !isConnected, !isBusy else { return }
        if isWiFiPolicyBlockingAutomaticConnect(trigger: "自动重连") { return }
        guard hasCredentials else {
            statusText = "未连接（缺少凭据，请手动连接）"
            appLog(.warn, "缺少凭据，停止自动重连")
            isAutoReconnecting = false
            return
        }
        connect(silent: true)
    }

    /// 等到 networkSatisfied 或超时。有界等待，绝不无限阻塞。
    private func awaitNetworkReady(timeout: TimeInterval) async {
        let deadline = Date().addingTimeInterval(timeout)
        while !networkSatisfied, Date() < deadline {
            try? await Task.sleep(nanoseconds: 300_000_000)
        }
    }

    /// 用户主动连/断、或休眠前 → 取消待执行重连并清零计数。
    private func cancelAutoReconnect() {
        autoReconnectTimer?.invalidate()
        autoReconnectTimer = nil
        isAutoReconnecting = false
        policy.reset()
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
        // willSleep 通知给应用 ~20s 窗口。cleanup 本身最多 12s，但它要先拿 root 串行门；
        // 若此刻有连接事务在跑（cleanup 12s + connect 超时 30s），这里会在主线程上多等一轮。
        // 所以先掐掉在途连接：pending 进程一死，事务立刻解开，门随即释放。
        // 睡眠场景由 shouldReconnectAfterWake 走另一条 reconnect 路径，
        // 取消掉这里 pollTick 触发的自动重连，避免两套机制打架
        cancelAutoReconnect()
        wifiWakeEvaluationTask?.cancel()
        wifiWakeEvaluationTask = nil
        // 休眠前先终止在途连接任务，防止随后异步回调污染状态或重新排重连。
        if isConnecting || connectionTask != nil {
            connectionAttemptID = nil
            connectionTask?.cancel()
            connectionTask = nil
            isConnecting = false
            isBusy = false
        }
        shouldReconnectAfterWake = isConnected
        if isConnected { appLog(.warn, "休眠，断开连接") }
        let mode = activeMode ?? runningMode
        if mode == .proxy {
            guard isConnected || OpenConnectRunner.isProxyModeRunning else { return }
            OpenConnectRunner.disconnectProxyMode()
        } else {
            // 只在 sudo 已配 的情况下清；其他情况 noop 就行
            guard sudoConfigured, isConnected || OpenConnectRunner.isRunning else { return }
            OpenConnectRunner.cancelPendingConnection()
            do {
                try OpenConnectRunner.cleanup()
            } catch {
                shouldReconnectAfterWake = false
                cancelAutoReconnect()
                isConnected = false
                activeMode = nil
                clearDiagnostics()
                statusText = "网络清理失败，唤醒后不会重连：\(error.localizedDescription)"
                appLog(.error, statusText)
                return
            }
        }
        isConnected = false
        activeMode = nil
        clearDiagnostics()
        statusText = "未连接"
    }

    private func handleDidWake() {
        // 唤醒后 openconnect 进程可能还活着，但 VPN 服务端 session 已超时、
        // TLS/DTLS 连接已断，隧道实际是黑洞。进程活着 ≠ 隧道通。
        let shouldReconnect = shouldReconnectAfterWake
        shouldReconnectAfterWake = false

        let mode = activeMode ?? runningMode
        if mode == .proxy {
            if isConnected || OpenConnectRunner.isProxyModeRunning {
                isBusy = true
                statusText = "休眠唤醒，正在清理…"
                Task { [weak self] in
                    await OpenConnectRunner.runBlocking {
                        OpenConnectRunner.disconnectProxyMode()
                    }
                    guard let self else { return }
                    self.isConnected = false
                    self.activeMode = nil
                    self.isBusy = false
                    self.statusText = "未连接"
                    if shouldReconnect {
                        self.reconnectAfterWake()
                    } else if self.wifiOnDemandEnabled {
                        self.evaluateWiFiPolicyAfterWake()
                    }
                }
            } else if shouldReconnect {
                reconnectAfterWake()
            } else if wifiOnDemandEnabled {
                evaluateWiFiPolicyAfterWake()
            }
            return
        }

        // 标准模式：走 sudo cleanup
        guard sudoConfigured else {
            if wifiOnDemandEnabled { evaluateWiFiPolicyAfterWake() }
            return
        }
        if isConnected || OpenConnectRunner.isRunning {
            isBusy = true
            statusText = "休眠唤醒，正在清理…"
            runCleanupDetached(reason: "唤醒后清理残留隧道") { [weak self] in
                guard let self else { return }
                self.isConnected = false
                self.activeMode = nil
                self.isBusy = false
                self.statusText = "未连接"
                if shouldReconnect {
                    self.reconnectAfterWake()
                } else if self.wifiOnDemandEnabled {
                    self.evaluateWiFiPolicyAfterWake()
                }
            }
        } else if shouldReconnect {
            reconnectAfterWake()
        } else if wifiOnDemandEnabled {
            evaluateWiFiPolicyAfterWake()
        }
    }

    /// 休眠前未连接 VPN，但开启了 Wi-Fi 按需连接：
    /// 唤醒后等网络就绪再读取新 Wi-Fi 并执行规则（例如公司断开合盖 → 回家开盖自动连）。
    private func evaluateWiFiPolicyAfterWake() {
        wifiWakeEvaluationTask?.cancel()
        wifiWakeEvaluationTask = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.awaitNetworkReady(timeout: 8)
            guard !Task.isCancelled, self.wifiOnDemandEnabled else { return }
            _ = self.refreshCurrentWiFiSSID(fallbackMinInterval: 4)
            await self.awaitPendingWiFiFallback(timeout: 2.0)
            guard !Task.isCancelled, self.wifiOnDemandEnabled else { return }
            _ = self.applyWiFiOnDemandPolicy(trigger: "休眠唤醒")
        }
    }

    /// 唤醒后自动重连。不再立即 connect() 或在网卡未关联前就误判 Wi-Fi 规则；
    /// 改为等网络就绪后再读取当前 Wi-Fi 并执行规则校验。凭据不全则静默跳过。
    private func reconnectAfterWake() {
        guard hasCredentials else {
            statusText = "未连接（缺少凭据，请手动连接）"
            appLog(.warn, "唤醒后缺少凭据，不自动重连")
            return
        }
        statusText = "正在自动重连（等待网络就绪…）"
        appLog(.info, "唤醒，准备重连")
        isAutoReconnecting = true
        Task { @MainActor [weak self] in
            await self?.fireAutoReconnect()
        }
    }

    // MARK: - 诊断数据采集

    nonisolated private static func sessionFileStamp() -> SessionFileStamp? {
        var st = stat()
        guard stat("/tmp/xdvpn.session", &st) == 0 else { return nil }
        return SessionFileStamp(
            mtimeSec: st.st_mtimespec.tv_sec,
            mtimeNsec: st.st_mtimespec.tv_nsec,
            size: st.st_size,
            inode: st.st_ino
        )
    }

    nonisolated private static func readSessionFileIfChanged(
        previousStamp: SessionFileStamp?
    ) -> (RouteScriptSession?, SessionFileStamp?) {
        guard let stamp = sessionFileStamp() else { return (nil, nil) }
        if stamp == previousStamp {
            return (nil, stamp)
        }
        guard let content = try? String(contentsOfFile: "/tmp/xdvpn.session", encoding: .utf8),
              let session = RouteScriptSession.parse(content) else {
            return (nil, previousStamp)
        }
        return (session, stamp)
    }

    private func parseSessionFile() {
        let (session, stamp) = Self.readSessionFileIfChanged(previousStamp: cachedSessionStamp)
        cachedSessionStamp = stamp
        if let session {
            applySession(session)
        }
    }

    private func applySession(_ session: RouteScriptSession) {
        if let oldInterface = tunnelInterface, oldInterface != session.tunnelInterface {
            appLog(.info, "检测到隧道接口切换：\(oldInterface) -> \(session.tunnelInterface)")
            resetTrafficBaselines()
        }

        if tunnelInterface != session.tunnelInterface {
            tunnelInterface = session.tunnelInterface
        }
        if vpnGateway != session.vpnGateway {
            vpnGateway = session.vpnGateway
        }
        if activeRoutes != session.routes {
            activeRoutes = session.routes
        }
        if dnsProxyActive != session.dnsProxyActive {
            dnsProxyActive = session.dnsProxyActive
        }
    }

    private func updateTrafficStats() {
        guard let iface = tunnelInterface else { return }
        applyTunnelTraffic(Self.queryTunnel(iface))
    }

    private func applyTunnelTraffic(_ info: TunnelInfo) {
        if tunnelIP != info.ip {
            tunnelIP = info.ip
        }

        var next = trafficMonitor.snapshot

        // 估算实时速率：使用单调时钟，避免系统 NTP 校时导致速率跳变
        let nowUptime = ProcessInfo.processInfo.systemUptime
        if let last = lastTrafficSample {
            let dt = nowUptime - last.uptime
            if dt > 0.1 {
                let dIn = info.bytesIn >= last.inBytes ? info.bytesIn - last.inBytes : 0
                let dOut = info.bytesOut >= last.outBytes ? info.bytesOut - last.outBytes : 0
                let newInRate = UInt64(Double(dIn) / dt)
                let newOutRate = UInt64(Double(dOut) / dt)
                next.bytesInRate = newInRate
                next.bytesOutRate = newOutRate
            }
        }
        lastTrafficSample = (info.bytesIn, info.bytesOut, nowUptime)
        next.bytesIn = info.bytesIn
        next.bytesOut = info.bytesOut
        trafficMonitor.update(next)
    }

    private func clearDiagnostics() {
        connectedAt = nil
        connectedAtUptime = nil
        tunnelInterface = nil
        tunnelIP = nil
        vpnGateway = nil
        activeRoutes = []
        dnsProxyActive = false
        cachedProcessPid = nil
        cachedSessionStamp = nil
        trafficMonitor.reset()
        lastTrafficSample = nil
        socks5Active = false
        socks5Error = nil
    }

    private func resetTrafficBaselines() {
        trafficMonitor.resetRates()
        lastTrafficSample = nil
        resetBlackholeTracking()
    }

    struct TunnelInfo: Sendable {
        var ip: String?
        var bytesIn: UInt64 = 0
        var bytesOut: UInt64 = 0
    }

    nonisolated static func queryTunnel(_ name: String) -> TunnelInfo {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return TunnelInfo() }
        defer { freeifaddrs(first) }

        return name.withCString { targetName in
            var info = TunnelInfo()
            var foundIP = false
            var foundLink = false
            var cur: UnsafeMutablePointer<ifaddrs>? = first
            while let ifa = cur {
                defer { cur = ifa.pointee.ifa_next }
                guard strcmp(ifa.pointee.ifa_name, targetName) == 0,
                      let addr = ifa.pointee.ifa_addr else { continue }

                let family = Int32(addr.pointee.sa_family)
                if family == AF_INET {
                    var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(addr, socklen_t(addr.pointee.sa_len),
                                &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST)
                    info.ip = String(cString: buf)
                    foundIP = true
                } else if family == AF_LINK, let data = ifa.pointee.ifa_data {
                    let d = data.assumingMemoryBound(to: if_data.self).pointee
                    info.bytesIn = UInt64(d.ifi_ibytes)
                    info.bytesOut = UInt64(d.ifi_obytes)
                    foundLink = true
                }
                if foundIP && foundLink {
                    break
                }
            }
            return info
        }
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

    nonisolated private static func cleanup(mode: RunningMode) throws {
        switch mode {
        case .proxy:
            OpenConnectRunner.disconnectProxyMode()
        case .split, .full:
            try OpenConnectRunner.cleanup()
        }
    }

    /// 在后台跑 cleanup。只有成功才执行 completion；失败会停止自动重连并显式报错。
    @discardableResult
    private func runCleanupDetached(
        reason: String,
        completion: (@MainActor () -> Void)? = nil
    ) -> Task<String?, Never> {
        Task { [weak self] in
            let cleanupErrorMessage: String? = await OpenConnectRunner.runBlocking {
                do {
                    try OpenConnectRunner.cleanup()
                    return nil
                } catch {
                    return error.localizedDescription
                }
            }
            // split/domain 配置由 cleanup helper 在 root operation gate 内删除。
            // 这里不能再删：新的 replaceConnection 可能已写入下一次连接的配置。
            await MainActor.run { [weak self] in
                guard let self else { return }
                let cleanupSucceeded = cleanupErrorMessage == nil
                guard cleanupSucceeded else {
                    self.cancelAutoReconnect()
                    self.isConnected = false
                    self.activeMode = nil
                    self.isBusy = false
                    self.statusText = "网络清理失败，已停止重连：\(cleanupErrorMessage ?? "未知错误")"
                    appLog(.error, "\(reason)：\(self.statusText)")
                    return
                }
                // 不改 isBusy —— 启动期间的 cleanup 是静默的，不应该锁 UI
                if let completion { completion() }
                else {
                    // 没 completion → 静默 cleanup，不改 statusText
                    // 只在真的已经不跑了的情况下确认 isConnected
                    if !OpenConnectRunner.isRunning, self.isConnected {
                        self.isConnected = false
                        self.activeMode = nil
                        self.statusText = "未连接"
                    }
                }
                _ = reason  // 目前不输出日志，保留参数便于后续加 os_log
            }
            return cleanupErrorMessage
        }
    }
}

#if DEBUG
// 调试注入：让 DebugServer 能 curl 驱动重连状态机、读内部量（仅 DEBUG 编进去）。
// 放在同文件内才能访问 private 成员。
extension VPNController {
    var debugReconnectState: [String: Any] {
        [
            "isConnected": isConnected,
            "isBusy": isBusy,
            "isAutoReconnecting": isAutoReconnecting,
            "policyAttempt": policy.attempt,
            "policyMaxAttempts": policy.maxAttempts,
            "networkSatisfied": networkSatisfied,
            "runningMode": runningMode.rawValue,
            "statusText": statusText,
            "shouldReconnectAfterWake": shouldReconnectAfterWake,
            "hadInboundEver": hadInboundEverSinceConnect,
            "inboundStalledSec": Int(inboundStalledSeconds()),
        ]
    }

    func debugSimulateWillSleep() { handleWillSleep() }
    func debugSimulateDidWake() { handleDidWake() }
    func debugSimulateTunnelLost() { beginAutoCleanupAndReconnect() }
    func debugSimulateNetworkChange() { handleNetworkChanged() }
    func debugSetNetworkSatisfied(_ v: Bool) { networkSatisfied = v }
}
#endif
