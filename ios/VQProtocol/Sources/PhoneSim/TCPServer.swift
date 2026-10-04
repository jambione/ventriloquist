import Foundation
import VQPhoneCore
import VQProtocol

/// The phone side of the TCP dev transport (README §2.1): a TCP **server**
/// carrying `length (u16 BE) ‖ frame` records, `mtu` 512.
///
/// Plain non-blocking POSIX sockets driven by `poll(2)` from PhoneSim's
/// single-threaded main loop, so the engine is only ever touched from one
/// thread. Implements `PhoneTransport`: the engine calls `send`/`disconnect`;
/// the server reports connects, frames and disconnects through `delegate`.
final class TCPServer: PhoneTransport {
    /// Called for transport events. Never called from inside `send` or
    /// `disconnect`, so the engine is never re-entered.
    struct Delegate {
        var connected: (PeerID) -> Void
        var received: ([UInt8], PeerID) -> Void
        var disconnected: (PeerID, String) -> Void
        /// The engine closed `peer` itself (informational only).
        var closedByEngine: (PeerID) -> Void
    }

    private final class Client {
        let fd: Int32
        let peer: PeerID
        var decoder = TCPFrameCodec.Decoder()
        var out: [UInt8] = []
        /// Frames held back while TX is paused (never reach the socket).
        var held: [UInt8] = []
        init(fd: Int32, peer: PeerID) {
            self.fd = fd
            self.peer = peer
        }
    }

    let port: UInt16
    var delegate: Delegate?
    /// While paused, frames from the engine are held in memory, not written.
    private(set) var txPaused = false
    /// While paused, nothing is read from the sockets (so acks are not seen).
    private(set) var rxPaused = false

    private let listenFD: Int32
    private var clients: [PeerID: Client] = [:]
    private var order: [PeerID] = []
    private var counter = 0

    var connectionCount: Int { clients.count }
    var peers: [PeerID] { order }

    /// Listen on `host:port` (`port` 0 picks a free port).
    init(host: String, port: UInt16) throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SimError("socket: \(String(cString: strerror(errno)))") }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else {
            close(fd)
            throw SimError("invalid IPv4 address \(host)")
        }
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            let msg = String(cString: strerror(errno))
            close(fd)
            throw SimError("bind \(host):\(port): \(msg)")
        }
        guard listen(fd, 16) == 0 else {
            close(fd)
            throw SimError("listen: \(String(cString: strerror(errno)))")
        }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        var actual = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        listenFD = fd
        self.port = UInt16(bigEndian: actual.sin_port)
    }

    // MARK: PhoneTransport

    func send(frame: [UInt8], to peer: PeerID) {
        guard let c = clients[peer], let record = TCPFrameCodec.encode(frame) else { return }
        if txPaused {
            c.held += record
        } else {
            c.out += record
            flush(c)
        }
    }

    func disconnect(_ peer: PeerID) {
        guard let c = clients[peer] else { return }
        flush(c)  // best effort: e.g. an `error` queued just before the close
        remove(c)
        delegate?.closedByEngine(peer)
    }

    func mtu(for peer: PeerID) -> Int { TCPFrameCodec.mtu }

    // MARK: Test controls

    func setTxPaused(_ paused: Bool) {
        txPaused = paused
        guard !paused else { return }
        for c in clients.values where !c.held.isEmpty {
            c.out += c.held
            c.held = []
            flush(c)
        }
    }

    func setRxPaused(_ paused: Bool) { rxPaused = paused }

    /// Close every connection (frames held by a TX pause are discarded) and
    /// report each as disconnected. Clears both pauses, so the next
    /// connection starts normally.
    func dropAll(reason: String) {
        let all = order.compactMap { clients[$0] }
        for c in all {
            c.held = []
            remove(c)
            delegate?.disconnected(c.peer, reason)
        }
        txPaused = false
        rxPaused = false
    }

    /// Write raw frame bytes to every connection, bypassing the engine
    /// (adversarial injection).
    func injectFrames(_ frames: [[UInt8]]) -> Int {
        for c in clients.values {
            for f in frames {
                if let record = TCPFrameCodec.encode(f) { c.out += record }
            }
            flush(c)
        }
        return clients.count
    }

    func shutdown() {
        for c in clients.values { close(c.fd) }
        clients = [:]
        order = []
        close(listenFD)
    }

    // MARK: Event loop

    /// Wait up to `timeoutMs` for socket activity and handle it.
    func pollOnce(timeoutMs: Int32, extraFD: Int32?) -> Bool {
        var fds: [pollfd] = [pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)]
        let list = order.compactMap { clients[$0] }
        for c in list {
            var ev: Int16 = 0
            if !rxPaused { ev |= Int16(POLLIN) }
            if !c.out.isEmpty { ev |= Int16(POLLOUT) }
            fds.append(pollfd(fd: c.fd, events: ev, revents: 0))
        }
        if let extraFD { fds.append(pollfd(fd: extraFD, events: Int16(POLLIN), revents: 0)) }
        let n = poll(&fds, nfds_t(fds.count), timeoutMs)
        guard n > 0 else { return false }
        if fds[0].revents & Int16(POLLIN) != 0 { acceptAll() }
        for (i, c) in list.enumerated() {
            let re = fds[i + 1].revents
            guard re != 0, clients[c.peer] === c else { continue }
            if re & Int16(POLLOUT) != 0 { flush(c) }
            if !rxPaused && re & Int16(POLLIN | POLLHUP | POLLERR) != 0 { readFrom(c) }
        }
        if let extraFD, let last = fds.last, last.fd == extraFD {
            return last.revents != 0
        }
        return false
    }

    private func acceptAll() {
        while true {
            let fd = accept(listenFD, nil, nil)
            if fd < 0 { return }
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(fd, Int32(IPPROTO_TCP), TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
            counter += 1
            let c = Client(fd: fd, peer: PeerID("tcp#\(counter)"))
            clients[c.peer] = c
            order.append(c.peer)
            delegate?.connected(c.peer)
        }
    }

    private func readFrom(_ c: Client) {
        var buf = [UInt8](repeating: 0, count: 65_536)
        while clients[c.peer] === c {
            let n = buf.withUnsafeMutableBytes { read(c.fd, $0.baseAddress, $0.count) }
            if n > 0 {
                for frame in c.decoder.push(buf[0..<n]) {
                    guard clients[c.peer] === c else { return }
                    delegate?.received(frame, c.peer)
                }
                continue
            }
            if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { return }
            if n < 0 && errno == EINTR { continue }
            let reason = n == 0 ? "eof" : "read: \(String(cString: strerror(errno)))"
            remove(c)
            delegate?.disconnected(c.peer, reason)
            return
        }
    }

    private func flush(_ c: Client) {
        while !c.out.isEmpty {
            let n = c.out.withUnsafeBytes { write(c.fd, $0.baseAddress, $0.count) }
            if n > 0 {
                c.out.removeFirst(n)
                continue
            }
            if n < 0 && errno == EINTR { continue }
            return  // EAGAIN: POLLOUT will resume; errors surface on read
        }
    }

    private func remove(_ c: Client) {
        guard clients[c.peer] === c else { return }
        clients[c.peer] = nil
        order.removeAll { $0 == c.peer }
        close(c.fd)
    }
}

struct SimError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}
