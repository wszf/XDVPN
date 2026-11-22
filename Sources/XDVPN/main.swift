import AppKit
import Darwin

// 忽略 SIGPIPE：防止向已提前退出的子进程 stdin pipe 或断开的 socket 写入时终止进程。
signal(SIGPIPE, SIG_IGN)

let openMainWindowNotification = Notification.Name("com.kafeifei.xdvpn.openMainWindow")

// 防双开：在 AppDelegate / VPNController 初始化之前检测
let me = NSRunningApplication.current
let bundleIdentifier = me.bundleIdentifier ?? Bundle.main.bundleIdentifier
let others = NSWorkspace.shared.runningApplications.filter { app in
    guard app.processIdentifier != me.processIdentifier else { return false }
    return (bundleIdentifier != nil && app.bundleIdentifier == bundleIdentifier)
        || (me.executableURL != nil && app.executableURL == me.executableURL)
}

if let existing = others.first {
    DistributedNotificationCenter.default().post(
        name: openMainWindowNotification,
        object: String(existing.processIdentifier),
        userInfo: nil
    )
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
