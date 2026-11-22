import XCTest
@testable import XDVPNCore

final class WiFiOnDemandPolicyTests: XCTestCase {
    func test_disabledPolicyDoesNotMatch() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: false,
            rules: [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        )

        XCTAssertEqual(policy.decision(for: "Office"), .noMatch)
    }

    func test_connectRuleMatchesExactSSID() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: true,
            rules: [WiFiOnDemandRule(ssid: "Home", action: .connectVPN)]
        )

        XCTAssertEqual(policy.decision(for: "Home"), .connect)
    }

    func test_disconnectRuleMatchesExactSSID() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: true,
            rules: [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        )

        XCTAssertEqual(policy.decision(for: "Office"), .disconnect)
    }

    func test_unknownOrEmptySSIDDoesNotMatch() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: true,
            rules: [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        )

        XCTAssertEqual(policy.decision(for: "Cafe"), .noMatch)
        XCTAssertEqual(policy.decision(for: nil), .noMatch)
        XCTAssertEqual(policy.decision(for: "  "), .noMatch)
    }

    func test_ssidMatchingIsCaseSensitive() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: true,
            rules: [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        )

        XCTAssertEqual(policy.decision(for: "office"), .noMatch)
    }

    func test_observedSSIDRejectsPrivacyPlaceholder() {
        XCTAssertNil(ObservedWiFiSSID.normalized("<redacted>"))
        XCTAssertNil(ObservedWiFiSSID.normalized("  <REDACTED>  "))
    }

    func test_observedSSIDTrimsRealNetworkName() {
        XCTAssertEqual(ObservedWiFiSSID.normalized("  Office Wi-Fi  "), "Office Wi-Fi")
        XCTAssertNil(ObservedWiFiSSID.normalized("  "))
        XCTAssertNil(ObservedWiFiSSID.normalized(nil))
    }

    func test_replacingOrAppendingUpdatesExistingRule() {
        let original = [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        let updated = WiFiOnDemandPolicy.replacingOrAppending(
            original,
            ssid: "Office",
            action: .connectVPN
        )

        XCTAssertEqual(updated.count, 1)
        XCTAssertEqual(updated[0].ssid, "Office")
        XCTAssertEqual(updated[0].action, .connectVPN)
    }

    func test_replacingOrAppendingTrimsAndAppendsSSID() {
        let updated = WiFiOnDemandPolicy.replacingOrAppending(
            [],
            ssid: "  Office  ",
            action: .disconnectVPN
        )

        XCTAssertEqual(updated.count, 1)
        XCTAssertEqual(updated[0].ssid, "Office")
        XCTAssertEqual(updated[0].action, .disconnectVPN)
    }

    func test_evaluateLeavingWiFiForEthernetClearsPausedState() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: true,
            rules: [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        )

        let outcome = policy.evaluate(state: .notOnWiFi, wasPaused: true)
        XCTAssertEqual(outcome.decision, .noMatch)
        XCTAssertFalse(outcome.shouldPause)
        XCTAssertFalse(outcome.blocksAutomaticConnect)
    }

    func test_evaluateUnknownSSIDKeepsPauseOnlyWhenPreviouslyPaused() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: true,
            rules: [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        )

        let stillPaused = policy.evaluate(state: .associatedUnknownSSID, wasPaused: true)
        XCTAssertEqual(stillPaused.decision, .noMatch)
        XCTAssertTrue(stillPaused.shouldPause)
        XCTAssertTrue(stillPaused.blocksAutomaticConnect)

        let notPaused = policy.evaluate(state: .associatedUnknownSSID, wasPaused: false)
        XCTAssertEqual(notPaused.decision, .noMatch)
        XCTAssertFalse(notPaused.shouldPause)
        XCTAssertFalse(notPaused.blocksAutomaticConnect)
    }

    func test_evaluateSwitchingFromDisconnectWiFiToOtherWiFiOrConnectRuleResumes() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: true,
            rules: [
                WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN),
                WiFiOnDemandRule(ssid: "Home", action: .connectVPN),
            ]
        )

        let paused = policy.evaluate(state: .associated(ssid: "Office"), wasPaused: false)
        XCTAssertEqual(paused.decision, .disconnect)
        XCTAssertTrue(paused.shouldPause)
        XCTAssertTrue(paused.blocksAutomaticConnect)

        let unmatched = policy.evaluate(state: .associated(ssid: "Cafe"), wasPaused: true)
        XCTAssertEqual(unmatched.decision, .noMatch)
        XCTAssertFalse(unmatched.shouldPause)
        XCTAssertFalse(unmatched.blocksAutomaticConnect)

        let connect = policy.evaluate(state: .associated(ssid: "Home"), wasPaused: true)
        XCTAssertEqual(connect.decision, .connect)
        XCTAssertFalse(connect.shouldPause)
        XCTAssertFalse(connect.blocksAutomaticConnect)
    }

    func test_evaluateDisabledPolicyAlwaysClearsPause() {
        let policy = WiFiOnDemandPolicy(
            isEnabled: false,
            rules: [WiFiOnDemandRule(ssid: "Office", action: .disconnectVPN)]
        )

        let outcome = policy.evaluate(state: .associated(ssid: "Office"), wasPaused: true)
        XCTAssertEqual(outcome.decision, .noMatch)
        XCTAssertFalse(outcome.shouldPause)
        XCTAssertFalse(outcome.blocksAutomaticConnect)
    }
}
