import CoreLocation
@preconcurrency import CoreWLAN
import Foundation
import XDVPNCore

struct WiFiInterfaceSnapshot: Sendable, Equatable {
    let ssid: String?
    let isAssociatedToWiFi: Bool
}

@MainActor
final class WiFiSSIDReader: NSObject, CLLocationManagerDelegate, CWEventDelegate {
    var onAuthorizationChanged: (() -> Void)?
    var onWiFiChanged: (() -> Void)?

    private let locationManager = CLLocationManager()
    private let wifiClient = CWWiFiClient.shared()
    private nonisolated static let profilerTimeout: TimeInterval = 6

    override init() {
        super.init()
        locationManager.delegate = self
        startMonitoringWiFiEvents()
    }

    func stopMonitoringWiFiEvents() {
        try? wifiClient.stopMonitoringAllEvents()
        if wifiClient.delegate === self {
            wifiClient.delegate = nil
        }
    }

    private func startMonitoringWiFiEvents() {
        wifiClient.delegate = self
        try? wifiClient.startMonitoringEvent(with: .ssidDidChange)
        try? wifiClient.startMonitoringEvent(with: .linkDidChange)
        try? wifiClient.startMonitoringEvent(with: .powerDidChange)
    }

    var isLocationServicesEnabled: Bool {
        CLLocationManager.locationServicesEnabled()
    }

    var isLocationPermissionRequired: Bool {
        guard isLocationServicesEnabled else { return true }
        switch locationManager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            return false
        default:
            return true
        }
    }

    func currentSSID() -> String? {
        currentInterfaceSnapshot().ssid
    }

    func currentInterfaceSnapshot() -> WiFiInterfaceSnapshot {
        guard let iface = wifiClient.interface() else {
            return WiFiInterfaceSnapshot(ssid: nil, isAssociatedToWiFi: false)
        }
        let ssid = ObservedWiFiSSID.normalized(iface.ssid())
        // 没有定位权限时 macOS 会脱敏 ssid()/bssid() 为 nil，但 powerOn() 与
        // wlanChannel()/interfaceMode() 仍能准确反映是否关联了 Wi-Fi。
        // 注意：不能用 serviceActive()，它在 Wi-Fi 开启但未连任何热点时仍可能为 true。
        let associated = ssid != nil || (
            iface.powerOn() && (
                iface.wlanChannel() != nil
                || iface.interfaceMode() == .station
            )
        )
        return WiFiInterfaceSnapshot(ssid: ssid, isAssociatedToWiFi: associated)
    }

    nonisolated static func currentSSIDFromSystemProfiler() -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
        process.arguments = ["SPAirPortDataType", "-json"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        let exitSemaphore = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in
            exitSemaphore.signal()
        }

        do {
            try process.run()
        } catch {
            return nil
        }

        // 先并发读尽 stdout，避免周围 AP 较多导致输出超过 64KB Pipe 缓冲区时死锁。
        final class OutputBox: @unchecked Sendable {
            private let lock = NSLock()
            private var value = Data()
            func set(_ data: Data) { lock.lock(); value = data; lock.unlock() }
            func get() -> Data { lock.lock(); defer { lock.unlock() }; return value }
        }
        let readGroup = DispatchGroup()
        let outputBox = OutputBox()
        let readHandle = pipe.fileHandleForReading
        readGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            outputBox.set(readHandle.readDataToEndOfFile())
            readGroup.leave()
        }

        if exitSemaphore.wait(timeout: .now() + profilerTimeout) == .timedOut {
            process.terminate()
            _ = exitSemaphore.wait(timeout: .now() + 1)
            try? readHandle.close()
            _ = readGroup.wait(timeout: .now() + 1)
            return nil
        }

        _ = readGroup.wait(timeout: .now() + 1)
        guard process.terminationStatus == 0 else { return nil }

        let data = outputBox.get()

        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let groups = root["SPAirPortDataType"] as? [[String: Any]] else {
            return nil
        }

        for group in groups {
            guard let interfaces = group["spairport_airport_interfaces"] as? [[String: Any]] else {
                continue
            }
            for iface in interfaces {
                guard let current = iface["spairport_current_network_information"] as? [String: Any],
                      let ssid = current["_name"] as? String else {
                    continue
                }
                if let normalized = ObservedWiFiSSID.normalized(ssid) {
                    return normalized
                }
            }
        }
        return nil
    }

    func requestLocationPermissionIfNeeded() {
        guard isLocationServicesEnabled else { return }
        if locationManager.authorizationStatus == .notDetermined {
            locationManager.requestWhenInUseAuthorization()
        }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor [weak self] in
            self?.onAuthorizationChanged?()
        }
    }

    nonisolated func ssidDidChangeForWiFiInterface(withName interfaceName: String) {
        notifyWiFiChanged()
    }

    nonisolated func linkDidChangeForWiFiInterface(withName interfaceName: String) {
        notifyWiFiChanged()
    }

    nonisolated func powerStateDidChangeForWiFiInterface(withName interfaceName: String) {
        notifyWiFiChanged()
    }

    private nonisolated func notifyWiFiChanged() {
        Task { @MainActor [weak self] in
            self?.onWiFiChanged?()
        }
    }
}
