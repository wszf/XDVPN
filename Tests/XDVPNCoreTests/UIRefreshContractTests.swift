import Foundation
import XCTest

final class UIRefreshContractTests: XCTestCase {
    func test_highFrequencyTrafficDoesNotPublishThroughVPNController() throws {
        let controller = try source("Sources/XDVPN/VPNController.swift")
        let content = try source("Sources/XDVPN/ContentView.swift")

        XCTAssertTrue(controller.contains("let trafficMonitor = TrafficMonitor()"))
        XCTAssertFalse(controller.contains("@Published private(set) var trafficIn:"))
        XCTAssertFalse(controller.contains("@Published private(set) var trafficOut:"))
        XCTAssertFalse(controller.contains("@Published private(set) var trafficInRate:"))
        XCTAssertFalse(controller.contains("@Published private(set) var trafficOutRate:"))
        XCTAssertTrue(content.contains("@ObservedObject var traffic: TrafficMonitor"))
    }

    func test_closedMainWindowReleasesHostingTreeAndStopsPreferredSizeFeedback() throws {
        let app = try source("Sources/XDVPN/XDVPNApp.swift")

        XCTAssertTrue(app.contains("hosting.sizingOptions = []"))
        XCTAssertFalse(app.contains("hosting.sizingOptions = .preferredContentSize"))
        XCTAssertTrue(app.contains("window.isReleasedWhenClosed = false"))
        XCTAssertTrue(app.contains("window.contentViewController = nil"))
        XCTAssertTrue(app.contains("mainWindow = nil"))
    }

    func test_statusItemRefreshUsesOneDeduplicatedTrafficSnapshot() throws {
        let app = try source("Sources/XDVPN/XDVPNApp.swift")

        XCTAssertTrue(app.contains("controller.trafficMonitor.$snapshot"))
        XCTAssertTrue(app.contains(".removeDuplicates()"))
        XCTAssertFalse(app.contains("Publishers.CombineLatest(controller.$trafficInRate"))
        XCTAssertTrue(app.contains("guard presentation != lastStatusItemPresentation else { return }"))
    }

    func test_launchEvaluatesWiFiRulesWithoutLegacyAutoConnect() throws {
        let controller = try source("Sources/XDVPN/VPNController.swift")

        XCTAssertTrue(controller.contains("guard autoConnectOnLaunch || wifiOnDemandEnabled else { return }"))
        XCTAssertTrue(controller.contains("applyWiFiOnDemandPolicy(trigger: \"启动 Wi-Fi 按需连接\")"))
        XCTAssertTrue(controller.contains("guard self.autoConnectOnLaunch else { return }"))
    }

    func test_wifiSettingsRequestsLocationPermissionBeforeReadingSSID() throws {
        let content = try source("Sources/XDVPN/ContentView.swift")

        XCTAssertTrue(content.contains("refreshWiFiSSID(requestPermissionIfNeeded: true)"))
        XCTAssertFalse(content.contains("refreshWiFiSSID(requestPermissionIfNeeded: false)"))
    }

    func test_releaseNotesRemainAvailableAfterUpdate() throws {
        let app = try source("Sources/XDVPN/XDVPNApp.swift")
        let content = try source("Sources/XDVPN/ContentView.swift")
        let build = try source("build.sh")

        XCTAssertTrue(app.contains("updater.showCurrentReleaseNotesIfNeeded()"))
        XCTAssertTrue(app.contains("menuShowReleaseNotes"))
        XCTAssertTrue(content.contains("Button(\"更新日志\")"))
        XCTAssertTrue(build.contains("RELEASE_NOTES.md"))
    }

    func test_detachedCleanupCannotDeleteNewConnectionConfiguration() throws {
        let controller = try source("Sources/XDVPN/VPNController.swift")

        XCTAssertFalse(controller.contains("removeItem(atPath: Self.splitConfPath)"))
        XCTAssertFalse(controller.contains("removeItem(atPath: Self.domainConfPath)"))
    }

    func test_connectionWaitsForStartupCleanup() throws {
        let controller = try source("Sources/XDVPN/VPNController.swift")

        XCTAssertTrue(controller.contains("startupCleanupTask = task"))
        XCTAssertTrue(controller.contains("let startupCleanupTask = self.startupCleanupTask"))
        XCTAssertTrue(controller.contains("await startupCleanupTask.value"))
    }

    func test_wifiReaderSubscribesToCoreWLANEventsAndDrainsPipeWithoutDeadlock() throws {
        let reader = try source("Sources/XDVPN/WiFiSSIDReader.swift")

        XCTAssertTrue(reader.contains("CWEventDelegate"))
        XCTAssertTrue(reader.contains("startMonitoringEvent(with: .ssidDidChange)"))
        XCTAssertTrue(reader.contains("process.standardError = FileHandle.nullDevice"))
        XCTAssertFalse(reader.contains("process.waitUntilExit()"))
        XCTAssertFalse(reader.contains("iface.serviceActive()"))
    }

    func test_processStdinWriteIsProtectedAgainstSigpipeAndProxySeparatesServerArg() throws {
        let main = try source("Sources/XDVPN/main.swift")
        let runner = try source("Sources/XDVPN/OpenConnectRunner.swift")
        let installer = try source("Sources/XDVPN/SudoersInstaller.swift")

        XCTAssertTrue(main.contains("signal(SIGPIPE, SIG_IGN)"))
        XCTAssertTrue(runner.contains("try? stdin.fileHandleForWriting.write(contentsOf:"))
        XCTAssertFalse(runner.contains("stdin.fileHandleForWriting.write(Data("))
        XCTAssertTrue(runner.contains("\"--\",\n            server,"))
        XCTAssertTrue(installer.contains("let expected = Data(signature.utf8)"))
        XCTAssertTrue(installer.contains("handle.read(upToCount: expected.count)"))
    }

    func test_uiBackgroundAndOcclusionAvoidIdleGpuAndTimerWork() throws {
        let content = try source("Sources/XDVPN/ContentView.swift")
        let app = try source("Sources/XDVPN/XDVPNApp.swift")

        XCTAssertTrue(content.contains("v.state = .followsWindowActiveState"))
        XCTAssertFalse(content.contains("v.state = .active"))
        XCTAssertTrue(content.contains("didChangeOcclusionStateNotification"))
        XCTAssertTrue(app.contains("func windowDidChangeOcclusionState("))
        XCTAssertTrue(app.contains("CGImageSourceCreateThumbnailAtIndex"))
    }

    func test_pollingRunsOnlyWhileConnectedAndUpdaterInvalidatesSession() throws {
        let controller = try source("Sources/XDVPN/VPNController.swift")
        let updater = try source("Sources/XDVPN/UpdateChecker.swift")

        XCTAssertTrue(controller.contains("stopPolling()"))
        XCTAssertTrue(controller.contains("timer.tolerance ="))
        XCTAssertTrue(updater.contains("session.finishTasksAndInvalidate()"))
        XCTAssertTrue(updater.contains("window.contentViewController = nil"))
        XCTAssertTrue(updater.contains("If-None-Match"))
    }

    private func source(_ relativePath: String) throws -> String {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }
}
