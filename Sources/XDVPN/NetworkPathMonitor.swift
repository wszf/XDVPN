import Foundation
import Network

struct NetworkPathSnapshot: Sendable, Equatable {
    let isSatisfied: Bool
    let interfaceNames: [String]
    let usesWiFi: Bool
    let usesWiredEthernet: Bool
}

/// NWPathMonitor 的薄封装：报告「网络是否可达」+「当前接口名列表」+「当前路径是否使用 Wi-Fi / 有线」。
/// 纯外壳，无决策逻辑——决策在 XDVPNCore（networkSatisfied 门控 / NetworkChangeDetector）。
/// 回调在后台 queue 触发，调用方需自行切回 MainActor。
final class NetworkPathMonitor {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "xdvpn.pathmonitor")
    private var started = false

    /// 必须在 start() 之前设置。
    var onUpdate: (@Sendable (NetworkPathSnapshot) -> Void)?

    func start() {
        guard !started else { return }
        started = true
        let handler = onUpdate   // 本地捕获，避免 @Sendable 闭包捕获非 Sendable 的 self
        monitor.pathUpdateHandler = { path in
            let snapshot = NetworkPathSnapshot(
                isSatisfied: path.status == .satisfied,
                interfaceNames: path.availableInterfaces.map { $0.name },
                usesWiFi: path.usesInterfaceType(.wifi),
                usesWiredEthernet: path.usesInterfaceType(.wiredEthernet)
            )
            handler?(snapshot)
        }
        monitor.start(queue: queue)
    }

    func cancel() {
        monitor.cancel()
    }
}
