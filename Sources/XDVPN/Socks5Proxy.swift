import Darwin
import Foundation

/// 轻量 SOCKS5 server：监听 127.0.0.1:<port>，把进来的 TCP 连接转出去时用
/// `setsockopt(IP_BOUND_IF, utunIfIndex)` 强制走 VPN 接口。
///
/// 这样 Surge（或任何 SOCKS5 客户端）就能把指定流量明确"经由 XDVPN"出公司出口，
/// 不依赖 host route 是否覆盖目标 IP。
///
/// 协议范围：
///   - 仅支持 NO_AUTH（method 0x00）
///   - 仅支持 CMD = CONNECT (0x01)
///   - ATYP: IPv4 / Domain / IPv6（IPv6 转发，但只在 V4 socket 上 setsockopt；
///     如果目标确实是 IPv6 内网会失败，留给将来再扩展）
///   - 不支持 BIND / UDP ASSOCIATE
///
/// 线程模型：accept loop 一个线程，每个连接独立线程跑 SOCKS5 协商 + 中继，
/// 中继再 spawn 一个反向 thread。VPN 同时活跃几十条连接的场景这点开销可以忽略。
final class Socks5Proxy {
    enum Socks5Error: LocalizedError {
        case invalidInterface(String)
        case socketFailed(String)
        case bindFailed(port: Int, reason: String)
        case listenFailed(String)

        var errorDescription: String? {
            switch self {
            case .invalidInterface(let n): return "网络接口 \(n) 不存在或未就绪"
            case .socketFailed(let s): return "socket() 失败: \(s)"
            case .bindFailed(let p, let r): return "端口 \(p) 绑定失败: \(r)"
            case .listenFailed(let s): return "listen() 失败: \(s)"
            }
        }
    }

    private var listenerFd: Int32 = -1
    private var utunIndex: UInt32 = 0
    private var acceptThread: Thread?

    /// 活跃连接 fd 集合，stop() 时统一 shutdown
    private var liveFds: Set<Int32> = []
    private let liveLock = NSLock()

    private(set) var isRunning: Bool = false
    private(set) var listeningPort: UInt16 = 0
    private(set) var boundInterface: String = ""

    // MARK: - Public

    /// 启动 server。已在运行时先 stop 再启。
    func start(port: UInt16, utunInterface: String) throws {
        stop()

        let idx = if_nametoindex(utunInterface)
        guard idx > 0 else { throw Socks5Error.invalidInterface(utunInterface) }

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw Socks5Error.socketFailed(String(cString: strerror(errno)))
        }

        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")  // 只绑回环，外部网络无法连入

        let bindResult = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            let err = String(cString: strerror(errno))
            close(fd)
            throw Socks5Error.bindFailed(port: Int(port), reason: err)
        }

        guard listen(fd, 32) == 0 else {
            let err = String(cString: strerror(errno))
            close(fd)
            throw Socks5Error.listenFailed(err)
        }

        listenerFd = fd
        utunIndex = idx
        listeningPort = port
        boundInterface = utunInterface
        isRunning = true

        let thread = Thread { [weak self] in self?.acceptLoop() }
        thread.name = "com.kafeifei.xdvpn.socks5.accept"
        thread.qualityOfService = .userInitiated
        thread.start()
        acceptThread = thread
    }

    func stop() {
        isRunning = false

        if listenerFd >= 0 {
            // 关 listener，让阻塞中的 accept() 返回错误退出循环
            shutdown(listenerFd, SHUT_RDWR)
            close(listenerFd)
            listenerFd = -1
        }
        acceptThread = nil

        // 把所有还活跃的连接 fd 强行 shutdown，relay 线程会因 read 返回 0/-1 而退出
        liveLock.lock()
        for fd in liveFds {
            shutdown(fd, SHUT_RDWR)
        }
        liveFds.removeAll()
        liveLock.unlock()

        listeningPort = 0
        boundInterface = ""
        utunIndex = 0
    }

    // MARK: - Accept loop

    private func acceptLoop() {
        let listener = listenerFd
        while listener == listenerFd && isRunning {
            var ca = sockaddr_in()
            var clen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let cfd = withUnsafeMutablePointer(to: &ca) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(listener, $0, &clen)
                }
            }
            if cfd < 0 {
                if !isRunning { return }
                // accept 偶发错误（EINTR 等）忽略继续
                if errno == EINTR { continue }
                return
            }

            let utunIdx = utunIndex
            track(cfd)
            Thread.detachNewThread { [weak self] in
                Self.handleClient(fd: cfd, utunIndex: utunIdx, onClose: { self?.untrack(cfd) })
            }
        }
    }

    private func track(_ fd: Int32) {
        liveLock.lock(); liveFds.insert(fd); liveLock.unlock()
    }
    private func untrack(_ fd: Int32) {
        liveLock.lock(); liveFds.remove(fd); liveLock.unlock()
    }

    // MARK: - Per-connection

    private static func handleClient(fd clientFd: Int32, utunIndex: UInt32, onClose: @escaping () -> Void) {
        var outFd: Int32 = -1
        defer {
            close(clientFd)
            if outFd >= 0 { close(outFd) }
            onClose()
        }

        // SOCKS5 greeting: [VER, NMETHODS, METHODS...]
        guard let greet = readExact(clientFd, count: 2), greet[0] == 0x05 else { return }
        let nmethods = Int(greet[1])
        if nmethods > 0, readExact(clientFd, count: nmethods) == nil { return }
        guard writeAll(clientFd, [0x05, 0x00]) else { return }  // NO_AUTH

        // SOCKS5 request: [VER=5, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
        guard let hdr = readExact(clientFd, count: 4), hdr[0] == 0x05 else { return }
        if hdr[1] != 0x01 {  // 仅 CONNECT
            _ = writeAll(clientFd, [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            return
        }

        var host = ""
        let atyp = hdr[3]
        switch atyp {
        case 0x01:  // IPv4
            guard let ip = readExact(clientFd, count: 4) else { return }
            host = "\(ip[0]).\(ip[1]).\(ip[2]).\(ip[3])"
        case 0x03:  // Domain
            guard let lb = readExact(clientFd, count: 1) else { return }
            let n = Int(lb[0])
            guard n > 0, let nb = readExact(clientFd, count: n),
                  let s = String(bytes: nb, encoding: .utf8), !s.isEmpty
            else { return }
            host = s
        case 0x04:  // IPv6
            guard let ip = readExact(clientFd, count: 16) else { return }
            // 简单格式化，留给 getaddrinfo 解析
            host = ip.withUnsafeBufferPointer { buf -> String in
                var s = sockaddr_in6()
                s.sin6_family = sa_family_t(AF_INET6)
                memcpy(&s.sin6_addr, buf.baseAddress, 16)
                var str = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                _ = withUnsafePointer(to: &s.sin6_addr) {
                    inet_ntop(AF_INET6, $0, &str, socklen_t(INET6_ADDRSTRLEN))
                }
                return String(cString: str)
            }
        default:
            _ = writeAll(clientFd, [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            return
        }
        guard let pb = readExact(clientFd, count: 2) else { return }
        let port = (UInt16(pb[0]) << 8) | UInt16(pb[1])

        // 解析 + 连接：getaddrinfo 会走系统 resolver（即 /etc/resolver/<domain> → 我们的 dns-proxy）
        var hints = addrinfo()
        hints.ai_family = AF_INET  // 优先 IPv4（IP_BOUND_IF 是 IPv4 选项）
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP

        var ai: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &ai) == 0, let r = ai else {
            _ = writeAll(clientFd, [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])  // host unreachable
            return
        }
        defer { freeaddrinfo(ai) }

        outFd = socket(AF_INET, SOCK_STREAM, 0)
        guard outFd >= 0 else {
            _ = writeAll(clientFd, [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            return
        }

        // 关键：把出站 socket 绑到 utun 接口 —— 包强制走 VPN
        var idx = utunIndex
        guard setsockopt(outFd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            _ = writeAll(clientFd, [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            return
        }

        guard connect(outFd, r.pointee.ai_addr, r.pointee.ai_addrlen) == 0 else {
            let rep: UInt8 = (errno == ECONNREFUSED) ? 0x05
                : (errno == ENETUNREACH || errno == EHOSTUNREACH) ? 0x03
                : 0x01
            _ = writeAll(clientFd, [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            return
        }

        // 成功响应
        guard writeAll(clientFd, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) else { return }

        // 双向中继：另起一个线程做 client→out，本线程做 out→client
        let cfd = clientFd, ofd = outFd
        let group = DispatchGroup()
        group.enter()
        Thread.detachNewThread {
            Self.relay(from: cfd, to: ofd)
            shutdown(ofd, SHUT_WR)
            group.leave()
        }
        Self.relay(from: ofd, to: cfd)
        shutdown(cfd, SHUT_WR)
        group.wait()
    }

    // MARK: - Low-level helpers

    private static func readExact(_ fd: Int32, count: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = buf.withUnsafeMutableBufferPointer { ptr -> Int in
                read(fd, ptr.baseAddress!.advanced(by: got), count - got)
            }
            if n <= 0 { return nil }
            got += n
        }
        return buf
    }

    private static func writeAll(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
        var sent = 0
        while sent < bytes.count {
            let n = bytes.withUnsafeBufferPointer { ptr -> Int in
                write(fd, ptr.baseAddress!.advanced(by: sent), bytes.count - sent)
            }
            if n <= 0 { return false }
            sent += n
        }
        return true
    }

    private static func relay(from src: Int32, to dst: Int32) {
        var buf = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = buf.withUnsafeMutableBufferPointer { ptr -> Int in
                read(src, ptr.baseAddress!, ptr.count)
            }
            if n <= 0 { return }
            var sent = 0
            while sent < n {
                let w = buf.withUnsafeBufferPointer { ptr -> Int in
                    write(dst, ptr.baseAddress!.advanced(by: sent), n - sent)
                }
                if w <= 0 { return }
                sent += w
            }
        }
    }
}
