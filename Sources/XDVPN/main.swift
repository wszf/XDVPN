import AppKit

// 防双开：在 AppDelegate / VPNController 初始化之前检测
let me = NSRunningApplication.current
let others = NSRunningApplication.runningApplications(
    withBundleIdentifier: me.bundleIdentifier ?? ""
).filter { $0 != me }

if !others.isEmpty {
    _ = NSApplication.shared
    let alert = NSAlert()
    alert.messageText = "XDVPN 已在运行"
    alert.informativeText = "请在菜单栏找到 XDVPN 图标。"
    alert.alertStyle = .informational
    alert.addButton(withTitle: "确认")
    alert.runModal()
    exit(0)
}

// 正常启动：纯 AppKit，不走 SwiftUI App 协议。
// 故意不用 SwiftUI 的 App.main() —— 它在只有 Settings scene 的 LSUIElement App 里
// 被 `open` 命令拉起时会偶发蹦出一个空 Settings 窗口（从 1.4.0 更新到 1.5.x
// 的复现路径就是这条）。改成手动装配 NSApplication，杜绝任何 SwiftUI scene 被
// 自动展示的可能。
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
