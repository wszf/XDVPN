import AppKit
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpn: VPNController
    @EnvironmentObject var updater: UpdateChecker
    @State private var showAdvanced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 4) {
                Image(systemName: "shield.fill")
                    .font(.system(size: 16))
                    .foregroundStyle(vpn.isConnected ? .green : .secondary)
                Text("XDVPN")
                    .font(.headline)
                Spacer()
                Button {
                    if updater.hasUpdate {
                        updater.showUpdateWindow()
                    } else {
                        NSWorkspace.shared.open(URL(string: "https://github.com/kafeifei/XDVPN")!)
                    }
                } label: {
                    HStack(spacing: 2) {
                        Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")
                            .font(.subheadline)
                        if updater.hasUpdate {
                            Circle()
                                .fill(.orange)
                                .frame(width: 6, height: 6)
                                .offset(y: -4)
                        }
                    }
                    .foregroundStyle(updater.hasUpdate ? AnyShapeStyle(.orange) : AnyShapeStyle(.tertiary))
                }
                .buttonStyle(.plain)
                .onHover { hovering in
                    if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
                }
                Button {
                    NSWorkspace.shared.open(URL(string: "https://github.com/kafeifei/XDVPN")!)
                } label: {
                    Image(nsImage: .githubMark)
                        .foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .onHover { hovering in
                    if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
                }
            }

            VStack(spacing: 6) {
                TextField("服务器地址", text: $vpn.server)
                    .textFieldStyle(.roundedBorder)
                    .disabled(vpn.isConnected || vpn.isBusy)
                TextField("用户名", text: $vpn.user)
                    .textFieldStyle(.roundedBorder)
                    .disabled(vpn.isConnected || vpn.isBusy)
                SecureField("密码", text: $vpn.password)
                    .textFieldStyle(.roundedBorder)
                    .disabled(vpn.isConnected || vpn.isBusy)
            }

            Toggle("记住密码", isOn: $vpn.rememberPassword)
                .font(.caption)
                .disabled(vpn.isConnected || vpn.isBusy)

            Divider()

            // 状态行
            HStack(spacing: 6) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 8, height: 8)
                Text(vpn.statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer()
            }

            // 按钮行
            HStack(spacing: 8) {
                if vpn.isConnected {
                    Button { vpn.disconnect() } label: {
                        Label("断开", systemImage: "power")
                            .labelStyle(.titleAndIcon)
                    }
                    .buttonStyle(SubtleDisconnectButtonStyle())
                        .disabled(vpn.isBusy)

                    TimelineView(.periodic(from: .now, by: 1)) { _ in
                        if let t = vpn.connectedAt {
                            Text(VPNController.formatDuration(Int(Date().timeIntervalSince(t))))
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                } else if !vpn.sudoConfigured {
                    Button("一键配置") { vpn.installSudoers(thenConnect: true) }
                        .keyboardShortcut(.defaultAction)
                        .controlSize(.small)
                        .disabled(vpn.isBusy)
                } else {
                    Button("连接") { vpn.connect() }
                        .keyboardShortcut(.defaultAction)
                        .controlSize(.small)
                        .disabled(!vpn.canConnect)
                }

                Spacer()

                // 高级设置齿轮
                Button {
                    showAdvanced.toggle()
                } label: {
                    Image(systemName: "gearshape")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .popover(isPresented: $showAdvanced, arrowEdge: .leading) {
                    AdvancedSettingsPopover(vpn: vpn)
                        .disabled(vpn.isConnected || vpn.isBusy)
                }

                // 更多菜单
                Menu {
                    if vpn.sudoConfigured {
                        Button("卸载免密 sudo 配置") { vpn.uninstallSudoers() }
                    }
                    Divider()
                    Button("退出 XDVPN") { NSApp.terminate(nil) }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .frame(width: 30)
            }

            // 连接详情（连接后直接显示）
            if vpn.isConnected {
                VStack(alignment: .leading, spacing: 0) {
                    DiagRow("协议", vpn.protocolName)
                    DiagRow("服务器", vpn.server)
                    if let gw = vpn.vpnGateway { DiagRow("网关", gw) }
                    if let iface = vpn.tunnelInterface { DiagRow("接口", iface) }
                    if let ip = vpn.tunnelIP { DiagRow("地址", ip) }

                    DiagRow("流量",
                            "↑ \(VPNController.formatBytes(vpn.trafficOut))  ↓ \(VPNController.formatBytes(vpn.trafficIn))")

                    if !vpn.activeRoutes.isEmpty {
                        DiagRow("路由", vpn.activeRoutes.joined(separator: ", "))
                    }
                    DiagRow("分流", vpn.splitEnabled ? "启用" : "关闭")
                    if vpn.dnsProxyActive { DiagRow("DNS 代理", "活跃") }
                }
            }
        }
        .padding(12)
        .frame(width: 260)
    }

    private var dotColor: Color {
        if vpn.isConnected { return .green }
        if vpn.isBusy { return .orange }
        return .secondary
    }
}

private struct SubtleDisconnectButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(.caption, weight: .medium))
            .symbolVariant(.circle)
            .foregroundStyle(foregroundColor(pressed: configuration.isPressed))
            .padding(.horizontal, 9)
            .frame(height: 24)
            .background {
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .fill(backgroundColor(pressed: configuration.isPressed))
            }
            .overlay {
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .stroke(borderColor, lineWidth: 1)
            }
            .opacity(isEnabled ? 1 : 0.55)
    }

    private func backgroundColor(pressed: Bool) -> Color {
        if !isEnabled { return Color.secondary.opacity(0.05) }
        return Color.secondary.opacity(pressed ? 0.12 : 0.06)
    }

    private func foregroundColor(pressed: Bool) -> Color {
        if !isEnabled { return Color.secondary }
        return pressed ? Color.red.opacity(0.9) : Color.primary.opacity(0.78)
    }

    private var borderColor: Color {
        isEnabled ? Color.secondary.opacity(0.22) : Color.secondary.opacity(0.14)
    }
}

// MARK: - 高级设置 Popover

private struct AdvancedSettingsPopover: View {
    @ObservedObject var vpn: VPNController

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("高级设置").font(.headline)

            Picker("协议", selection: $vpn.protocolName) {
                ForEach(OpenConnectRunner.protocols, id: \.self) { p in
                    Text(p).tag(p)
                }
            }
            .pickerStyle(.menu)

            Divider()

            Toggle("分流模式（仅指定子网走 VPN）", isOn: $vpn.splitEnabled)

            if vpn.splitEnabled {
                VStack(alignment: .leading, spacing: 4) {
                    Text("常见内网段").font(.caption).foregroundStyle(.secondary)
                    Toggle("10.0.0.0/8", isOn: $vpn.splitPreset10)
                    Toggle("172.16.0.0/12", isOn: $vpn.splitPreset172)
                    Toggle("192.168.0.0/16（可能覆盖本地网络）", isOn: $vpn.splitPreset192)

                    Text("自定义 CIDR（逗号或换行分隔）")
                        .font(.caption).foregroundStyle(.secondary)
                        .padding(.top, 2)
                    TextEditor(text: $vpn.splitCustom)
                        .font(.system(.caption, design: .monospaced))
                        .frame(height: 48)
                        .overlay(
                            RoundedRectangle(cornerRadius: 4)
                                .stroke(Color.secondary.opacity(0.3), lineWidth: 1)
                        )

                    Text("域名分流（一行一个域名后缀）")
                        .font(.caption).foregroundStyle(.secondary)
                        .padding(.top, 2)
                    TextEditor(text: $vpn.splitDomains)
                        .font(.system(.caption, design: .monospaced))
                        .frame(height: 48)
                        .overlay(
                            RoundedRectangle(cornerRadius: 4)
                                .stroke(Color.secondary.opacity(0.3), lineWidth: 1)
                        )
                }
                .font(.caption)
            }
        }
        .padding(14)
        .frame(width: 280)
    }
}

// MARK: - Diagnostics Row

private struct DiagRow: View {
    let label: String
    let value: String

    init(_ label: String, _ value: String) {
        self.label = label
        self.value = value
    }

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 56, alignment: .trailing)
            Text("  ")
            Text(value)
        }
        .font(.system(.caption, design: .monospaced))
        .textSelection(.enabled)
        .padding(.vertical, 1)
    }
}

extension NSImage {
    static let githubMark: NSImage = {
        let svg = """
        <svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">\
        <path fill="black" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 \
        7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69\
        -.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 \
        1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64\
        -.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 \
        .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 \
        2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 \
        3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 \
        2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>\
        </svg>
        """
        let img = NSImage(data: Data(svg.utf8)) ?? NSImage()
        img.isTemplate = true
        return img
    }()
}
