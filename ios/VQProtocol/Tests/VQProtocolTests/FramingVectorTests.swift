import Testing
@testable import VQProtocol

@Suite("framing.json vectors")
struct FramingVectorTests {
    let file = "framing.json"

    @Test func split() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "split") {
            let name = c["name"].str
            var sp = FrameSplitter(seq: UInt16(c["seq"].u64))
            let msg = bytes(c["message"])
            let frames = try sp.split(msg, mtu: c["mtu"].int)
            #expect(frames == c["frames"].array.map(bytes), "\(name)")
            #expect(UInt64(sp.nextSeq) == c["next_seq"].u64, "\(name)")
            var r = Reassembler()
            var out: [UInt8]?
            for f in frames { out = try r.push(f) }
            #expect(out == msg, "\(name)")
        }
    }

    @Test func splitLarge() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "split_large") {
            let name = c["name"].str
            let msg = bytes(c["message"])
            var sp = FrameSplitter(seq: UInt16(c["seq"].u64))
            let frames = try sp.split(msg, mtu: c["mtu"].int)
            #expect(frames.count == c["frame_count"].int, "\(name)")
            #expect(hexString(frames[0].prefix(3)) == c["first_frame_header"].str, "\(name)")
            #expect(hexString(frames.last!.prefix(3)) == c["last_frame_header"].str, "\(name)")
            #expect(frames.last!.count == c["last_frame_len"].int, "\(name)")
            var r = Reassembler()
            var out: [UInt8]?
            for f in frames { out = try r.push(f) }
            #expect(out == msg, "\(name)")
        }
    }

    @Test func splitErrors() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "split_errors") {
            var sp = FrameSplitter()
            let r = result { () throws(VQError) in try sp.split(bytes(c["message"]), mtu: c["mtu"].int) }
            #expect(r.errorCode == c["error"].str, "\(c["name"].str)")
            #expect(sp.nextSeq == 0, "\(c["name"].str)")
        }
    }

    @Test func reassembly() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "reassembly") {
            let name = c["name"].str
            var r = Reassembler()
            for (i, st) in c["steps"].array.enumerated() {
                let got = result { () throws(VQError) in try r.push(bytes(st["frame"])) }
                switch (st["result"].str, got) {
                case ("pending", .success(nil)): break
                case ("message", .success(let m?)): #expect(m == bytes(st["message"]), "\(name) step \(i)")
                case ("error", .failure(let e)): #expect(e.code == st["error"].str, "\(name) step \(i)")
                case (let want, let got): Issue.record("\(name) step \(i): want \(want), got \(got)")
                }
            }
        }
    }
}
