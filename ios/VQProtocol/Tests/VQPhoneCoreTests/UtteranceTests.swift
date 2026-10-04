import Foundation
import Testing
import VQPhoneCore
import VQProtocol

/// A harness with one paired desktop that is active and Secure.
private func connected(partials: Bool = true, autoAck: Bool = true) -> (Harness, FakeDesktop, PeerID) {
    let h = Harness(partials: partials)
    let d = h.pairedDesktop("Mac")
    d.autoAck = autoAck
    h.engine.selectHost(d.deviceId)
    let peer = h.net.connect(d)
    return (h, d, peer)
}

@Suite("utterance pipeline (SPEC §4.6, README §5.11)")
struct UtteranceTests {
    @Test func partialsThenFinalWithIncreasingRevs() {
        let (h, d, _) = connected()
        let id = h.engine.beginUtterance()
        h.engine.updatePartial("kube")
        h.advance(0.3)
        h.engine.updatePartial("kubectl get")
        h.advance(0.3)
        let f = h.engine.finishUtterance("kubectl get pods")
        h.net.pump()
        #expect(f?.id == id)
        #expect(d.utts.map(\.state) == [.partial, .partial, .final])
        #expect(d.utts.map(\.rev) == [0, 1, 2])
        #expect(d.utts.allSatisfy { $0.id == id })
        #expect(d.finals.first?.text == "kubectl get pods")
        let ts = d.utts[0].ts
        #expect(d.utts.allSatisfy { $0.ts == ts })
        #expect(ts == 1_759_500_000_000)
        #expect(h.engine.deliveryStatus(of: id) == .acked)
        #expect(h.statusEvents(id) == [.pending, .acked])
    }

    @Test func partialThrottleAtMostFivePerSecondLatestWins() {
        let (h, d, _) = connected()
        h.engine.beginUtterance()
        var sentTimes: [Double] = []
        var last = ""
        // The recognizer updates every 10 ms for 3 s.
        for i in 0..<300 {
            last = "word \(i)"
            let before = d.partials.count
            h.engine.updatePartial(last)
            h.net.pump()
            h.clock.advance(0.01)
            if i % 10 == 0 { h.engine.tick() }
            h.net.pump()
            if d.partials.count > before { sentTimes.append(h.clock.now) }
        }
        h.advance(0.3)
        #expect(d.partials.count >= 10)
        // No half-open 1 s window holds more than 5.
        for t in sentTimes {
            #expect(sentTimes.filter { $0 >= t && $0 < t + 1.0 - 1e-9 }.count <= 5)
        }
        // Latest text wins: after the throttle window, the newest text went out.
        #expect(d.partials.last?.text == last)
        // The final is immediate, without waiting for a tick.
        h.engine.finishUtterance("done")
        h.net.pump()
        #expect(d.finals.map(\.text) == ["done"])
    }

    @Test func identicalPartialsAreNotRepeated() {
        let (h, d, _) = connected()
        h.engine.beginUtterance()
        h.engine.updatePartial("same")
        h.advance(0.3)
        h.engine.updatePartial("same")
        h.advance(0.3)
        #expect(d.partials.count == 1)
    }

    @Test func partialStreamingOffSendsOnlyFinal() {
        let (h, d, _) = connected(partials: false)
        h.engine.beginUtterance()
        h.engine.updatePartial("one")
        h.advance(0.5)
        h.engine.updatePartial("one two")
        h.advance(0.5)
        h.engine.finishUtterance("one two three")
        h.net.pump()
        #expect(d.utts.map(\.state) == [.final])
        #expect(d.utts.first?.rev == 0)
    }

    @Test func emptyUtteranceWithNothingSentIsDropped() {
        let (h, d, _) = connected()
        h.engine.beginUtterance()
        #expect(h.engine.finishUtterance("") == nil)
        h.net.pump()
        #expect(d.utts.isEmpty)
    }

    @Test func editHasHigherRevAndReplaces() {
        let (h, d, _) = connected()
        h.engine.beginUtterance()
        h.engine.updatePartial("helo")
        h.advance(0.3)
        let f = h.engine.finishUtterance("helo world")!
        h.net.pump()
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
        let sent = h.engine.sendEdit(id: f.id, text: "hello world")
        h.net.pump()
        #expect(sent == "hello world")
        #expect(d.edits.count == 1)
        #expect(d.edits[0].id == f.id)
        #expect(d.edits[0].rev > d.finals[0].rev)
        #expect(d.edits[0].ts == d.finals[0].ts)
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
        #expect(h.statusEvents(f.id) == [.pending, .acked, .pending, .acked])
        // A second correction goes higher again.
        h.engine.sendEdit(id: f.id, text: "hello, world")
        h.net.pump()
        #expect(d.edits.map(\.rev) == [2, 3])
    }

    @Test func editOfUnknownIdIsRefused() {
        let (h, d, _) = connected()
        #expect(h.engine.sendEdit(id: UUID(), text: "x") == nil)
        h.net.pump()
        #expect(d.utts.isEmpty)
    }

    @Test func editSupersedesUnackedFinal() {
        let (h, d, _) = connected(autoAck: false)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("first")!
        h.engine.sendEdit(id: f.id, text: "second")
        h.net.pump()
        #expect(h.engine.pendingDeliveryCount == 1)
        // An ack for the older final does not clear the pending edit.
        d.sendSealed(.ack(Ack(id: f.id, rev: 0)))
        h.net.pump()
        #expect(h.engine.deliveryStatus(of: f.id) == .pending)
        d.sendSealed(.ack(Ack(id: f.id, rev: 1)))
        h.net.pump()
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
        // Only the edit is retried afterwards — nothing is pending now.
        h.advance(3)
        #expect(d.utts.count == 2)
    }

    @Test func resendCreatesNewIdSingleFinal() {
        let (h, d, _) = connected()
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("git status")!
        let r = h.engine.resend(text: "git status")
        h.net.pump()
        #expect(r.id != f.id)
        let forR = d.utts.filter { $0.id == r.id }
        #expect(forR.count == 1)
        #expect(forR[0].state == .final)
        #expect(forR[0].rev == 0)
        #expect(h.engine.deliveryStatus(of: r.id) == .acked)
    }

    @Test func retriesEvery2sFiveTimesThenFailed() {
        let (h, d, _) = connected(autoAck: false)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("ls -la")!
        h.net.pump()
        #expect(d.finals.count == 1)
        h.advance(1.9)
        #expect(d.finals.count == 1)
        h.advance(0.2)
        #expect(d.finals.count == 2)
        h.advance(8.1)
        #expect(d.finals.count == 6)  // initial + 5 retries
        #expect(h.engine.deliveryStatus(of: f.id) == .pending)
        h.advance(2.1)
        #expect(d.finals.count == 6)
        #expect(h.engine.deliveryStatus(of: f.id) == .failed)
        h.advance(10)
        #expect(d.finals.count == 6)
        #expect(Set(d.finals.map(\.rev)) == [0])
    }

    @Test func failedDeliveryIsResentOnReconnect() {
        let (h, d, peer) = connected(autoAck: false)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("make test")!
        h.advance(13)
        #expect(h.engine.deliveryStatus(of: f.id) == .failed)
        h.net.drop(peer)
        d.autoAck = true
        h.net.connect(d)
        #expect(d.finals.last?.id == f.id)
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
        #expect(h.statusEvents(f.id) == [.pending, .failed, .pending, .acked])
    }

    @Test func pendingIsResentOnReconnect() {
        let (h, d, peer) = connected(autoAck: false)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("cargo build")!
        h.net.pump()
        h.net.drop(peer)
        #expect(h.engine.indicator == .connecting)
        h.advance(5)
        #expect(d.finals.count == 1)
        d.autoAck = true
        h.net.connect(d)
        #expect(d.finals.count == 2)
        #expect(d.finals.map(\.rev) == [0, 0])
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
    }

    @Test func queuedWhileNoActiveHostThenFlushedOnPairing() {
        let h = Harness()
        h.engine.beginUtterance()
        h.engine.updatePartial("queued")
        let f = h.engine.finishUtterance("queued text")!
        let r = h.engine.resend(text: "another")
        #expect(h.engine.deliveryStatus(of: f.id) == .pending)
        #expect(h.engine.pendingDeliveryCount == 2)
        let d = h.desktop("Mac")
        h.net.connect(d)
        #expect(d.utts.isEmpty)  // not active, not paired
        h.pair(d)
        #expect(d.finals.map(\.id) == [f.id, r.id])
        #expect(d.partials.isEmpty)
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
        #expect(h.engine.deliveryStatus(of: r.id) == .acked)
    }

    @Test func queuedUntilRememberedHostConnects() {
        let seed = Harness()
        let d = seed.pairedDesktop("Mac")
        let h = Harness(hosts: seed.hostStore.hosts, lastHostId: d.deviceId, identity: seed.identity)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("waiting")!
        h.advance(1)
        h.net.connect(d)
        #expect(d.finals.map(\.id) == [f.id])
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
    }

    @Test func onlyActiveDesktopReceivesUtterances() {
        let h = Harness()
        let a = h.pairedDesktop("Alpha")
        let b = h.pairedDesktop("Beta")
        h.engine.selectHost(a.deviceId)
        h.net.connect(a)
        h.net.connect(b)
        h.engine.beginUtterance()
        h.engine.updatePartial("to alpha")
        h.advance(0.3)
        h.engine.finishUtterance("to alpha!")
        h.net.pump()
        #expect(a.utts.count == 2)
        #expect(b.utts.isEmpty)

        h.engine.selectHost(b.deviceId)
        #expect(h.settings.lastHostId == b.deviceId)
        h.engine.beginUtterance()
        h.engine.finishUtterance("to beta")
        h.net.pump()
        #expect(a.utts.count == 2)
        #expect(b.finals.map(\.text) == ["to beta"])
    }

    @Test func pendingFollowsTheActiveHost() {
        let h = Harness()
        let a = h.pairedDesktop("Alpha")
        let b = h.pairedDesktop("Beta")
        a.autoAck = false
        h.engine.selectHost(a.deviceId)
        h.net.connect(a)
        h.net.connect(b)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("important")!
        h.net.pump()
        h.engine.selectHost(b.deviceId)
        h.net.pump()
        #expect(b.finals.map(\.id) == [f.id])
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
    }

    @Test func textLimitEndsUtteranceWithLongestPrefix() {
        let (h, d, _) = connected()
        let id = h.engine.beginUtterance()
        h.engine.updatePartial("short")
        h.advance(0.3)
        let long = String(repeating: "a", count: 31_999) + "é"  // 32,001 bytes
        h.engine.updatePartial(long)
        h.net.pump()
        let expected = String(repeating: "a", count: 31_999)
        #expect(d.finals.count == 1)
        #expect(d.finals[0].id == id)
        #expect(d.finals[0].text == expected)
        #expect(h.events.contains(.utteranceLimitReached(id: id, text: expected)))
        #expect(!h.engine.isUtteranceOpen)
        // Later recognizer output and the stop are ignored for this utterance.
        h.engine.updatePartial(long + "more")
        #expect(h.engine.finishUtterance(long + "more") == nil)
        h.advance(0.5)
        #expect(d.utts.filter { $0.id == id }.count == 2)
        #expect(h.engine.deliveryStatus(of: id) == .acked)
    }

    @Test func escapedSizeLimitAlsoEndsUtterance() {
        let (h, d, _) = connected()
        h.engine.beginUtterance()
        // 11,000 U+0001: 11,000 bytes raw, but 66,000 escaped.
        let text = String(repeating: "\u{1}", count: 11_000)
        h.engine.updatePartial(text)
        h.net.pump()
        #expect(d.finals.count == 1)
        let sent = d.finals[0].text
        #expect(uttTextFits(sent))
        #expect(sent.unicodeScalars.count == (65_511 - 126) / 6)
    }

    @Test func finalAndEditAreTruncatedToFit() {
        let (h, d, _) = connected()
        h.engine.beginUtterance()
        let big = String(repeating: "b", count: 40_000)
        let f = h.engine.finishUtterance(big)!
        #expect(f.truncated)
        #expect(f.text.utf8.count == 32_000)
        let e = h.engine.sendEdit(id: f.id, text: big + "c")
        h.net.pump()
        #expect(e?.utf8.count == 32_000)
        #expect(d.utts.allSatisfy { $0.text.utf8.count <= 32_000 })
        let r = h.engine.resend(text: big)
        #expect(r.truncated)
    }

    @Test func forgetDeliveryStopsRetries() {
        let (h, d, _) = connected(autoAck: false)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("x")!
        h.net.pump()
        h.engine.forgetDelivery(f.id)
        h.advance(5)
        #expect(d.finals.count == 1)
        #expect(h.engine.deliveryStatus(of: f.id) == nil)
    }

    @Test func partialsWaitForTheHostThenOnlyLatestIsSent() {
        let seed = Harness()
        let d = seed.pairedDesktop("Mac")
        let h = Harness(hosts: seed.hostStore.hosts, lastHostId: d.deviceId, identity: seed.identity)
        h.engine.beginUtterance()
        h.engine.updatePartial("one")
        h.engine.updatePartial("one two")
        h.advance(0.5)
        h.net.connect(d)
        #expect(d.partials.map(\.text) == ["one two"])
    }

    @Test func ackFromUnknownIdIsIgnored() {
        let (h, d, peer) = connected()
        d.sendSealed(.ack(Ack(id: UUID(), rev: 9)))
        h.net.pump()
        #expect(h.net.isConnected(peer))
        #expect(h.engine.pendingDeliveryCount == 0)
    }
}
