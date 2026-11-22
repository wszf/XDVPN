import Foundation

public enum WiFiOnDemandAction: String, CaseIterable, Codable, Equatable, Identifiable, Sendable {
    case connectVPN
    case disconnectVPN

    public var id: String { rawValue }
}

public struct WiFiOnDemandRule: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var ssid: String
    public var action: WiFiOnDemandAction

    public init(id: UUID = UUID(), ssid: String, action: WiFiOnDemandAction) {
        self.id = id
        self.ssid = Self.normalizedSSID(ssid)
        self.action = action
    }

    public static func normalizedSSID(_ ssid: String) -> String {
        ssid.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// 规范化系统观察到的 Wi-Fi 名称。
///
/// macOS 在应用没有定位权限时，`system_profiler` 可能返回字面量
/// `<redacted>`。它不是 SSID，不能进入规则匹配或展示为当前网络。
public enum ObservedWiFiSSID {
    public static func normalized(_ ssid: String?) -> String? {
        guard let ssid else { return nil }
        let normalized = ssid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty,
              normalized.caseInsensitiveCompare("<redacted>") != .orderedSame else {
            return nil
        }
        return normalized
    }
}

public enum WiFiOnDemandDecision: Equatable, Sendable {
    case noMatch
    case connect
    case disconnect
}

/// 当前 Wi-Fi 关联观测状态，严格区分「未在 Wi-Fi 上」与「连着 Wi-Fi 但拿不到 SSID」。
public enum WiFiAssociationState: Equatable, Sendable {
    /// 未连 Wi-Fi（Wi-Fi 关闭/未关联）或当前主出口为非 Wi-Fi（如网线/USB 热点）。
    case notOnWiFi
    /// 已关联 Wi-Fi 且读到了真实 SSID。
    case associated(ssid: String)
    /// 已关联 Wi-Fi，但因为缺少定位权限或系统暂未返回而拿不到 SSID。
    case associatedUnknownSSID
}

/// 结合历史暂停态得出的完整策略结果。
public struct WiFiPolicyOutcome: Equatable, Sendable {
    public let decision: WiFiOnDemandDecision
    public let shouldPause: Bool
    public let blocksAutomaticConnect: Bool

    public init(
        decision: WiFiOnDemandDecision,
        shouldPause: Bool,
        blocksAutomaticConnect: Bool
    ) {
        self.decision = decision
        self.shouldPause = shouldPause
        self.blocksAutomaticConnect = blocksAutomaticConnect
    }
}

public struct WiFiOnDemandPolicy: Equatable, Sendable {
    public var isEnabled: Bool
    public var rules: [WiFiOnDemandRule]

    public init(isEnabled: Bool, rules: [WiFiOnDemandRule]) {
        self.isEnabled = isEnabled
        self.rules = rules
    }

    public func decision(for ssid: String?) -> WiFiOnDemandDecision {
        guard isEnabled,
              let ssid,
              !WiFiOnDemandRule.normalizedSSID(ssid).isEmpty else {
            return .noMatch
        }

        let normalized = WiFiOnDemandRule.normalizedSSID(ssid)
        guard let rule = rules.first(where: { $0.ssid == normalized }) else {
            return .noMatch
        }

        switch rule.action {
        case .connectVPN:
            return .connect
        case .disconnectVPN:
            return .disconnect
        }
    }

    /// 完整评估当前 Wi-Fi 状态与历史暂停态：
    /// - 未启用 → 不匹配且解除暂停
    /// - 离开 Wi-Fi（如切有线/关 Wi-Fi）→ 解除暂停、不阻塞自动连接
    /// - 已知 SSID → 按规则决定；非断开规则均解除暂停
    /// - 已连 Wi-Fi 但未知 SSID → 仅当此前已被断开规则暂停时保守维持暂停
    public func evaluate(
        state: WiFiAssociationState,
        wasPaused: Bool
    ) -> WiFiPolicyOutcome {
        guard isEnabled else {
            return WiFiPolicyOutcome(
                decision: .noMatch,
                shouldPause: false,
                blocksAutomaticConnect: false
            )
        }

        switch state {
        case .notOnWiFi:
            return WiFiPolicyOutcome(
                decision: .noMatch,
                shouldPause: false,
                blocksAutomaticConnect: false
            )

        case .associated(let ssid):
            let matched = decision(for: ssid)
            switch matched {
            case .disconnect:
                return WiFiPolicyOutcome(
                    decision: .disconnect,
                    shouldPause: true,
                    blocksAutomaticConnect: true
                )
            case .connect:
                return WiFiPolicyOutcome(
                    decision: .connect,
                    shouldPause: false,
                    blocksAutomaticConnect: false
                )
            case .noMatch:
                return WiFiPolicyOutcome(
                    decision: .noMatch,
                    shouldPause: false,
                    blocksAutomaticConnect: false
                )
            }

        case .associatedUnknownSSID:
            return WiFiPolicyOutcome(
                decision: .noMatch,
                shouldPause: wasPaused,
                blocksAutomaticConnect: wasPaused
            )
        }
    }

    public static func replacingOrAppending(
        _ rules: [WiFiOnDemandRule],
        ssid: String,
        action: WiFiOnDemandAction
    ) -> [WiFiOnDemandRule] {
        let normalized = WiFiOnDemandRule.normalizedSSID(ssid)
        guard !normalized.isEmpty else { return rules }

        var updated = rules
        if let idx = updated.firstIndex(where: { $0.ssid == normalized }) {
            updated[idx].action = action
        } else {
            updated.append(WiFiOnDemandRule(ssid: normalized, action: action))
        }
        return updated
    }
}
