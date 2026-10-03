import Testing
@testable import VQProtocol

@Suite("replay.json vectors")
struct ReplayVectorTests {
    let file = "replay.json"

    @Test func sequences() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "sequences") {
            let name = c["name"].str
            let rx = SessionCipher(rawKeyForTests: bytes(c["key"]), role: role(c["receiver_role"]))
            for (i, st) in c["steps"].array.enumerated() {
                let got = result { () throws(VQError) in try rx.open(bytes(st["envelope"])) }
                switch (st["result"].str, got) {
                case ("ok", .success(let pt)): #expect(pt == bytes(st["plaintext"]), "\(name) step \(i)")
                case ("error", .failure(let e)): #expect(e.code == st["error"].str, "\(name) step \(i)")
                case (let want, let got): Issue.record("\(name) step \(i): want \(want), got \(got)")
                }
                #expect(rx.lastReceivedCounter == optU64s(st["last_accepted_after"]), "\(name) step \(i)")
            }
        }
    }

    @Test func sendSequences() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "send_sequences") {
            let name = c["name"].str
            let tx = SessionCipher(rawKeyForTests: bytes(c["key"]), role: role(c["sender_role"]))
            tx.advanceSendCounterForTests(to: c["start_counter"].u64s)
            for (i, st) in c["sends"].array.enumerated() {
                let got = result { () throws(VQError) in try tx.seal(bytes(st["plaintext"])) }
                switch (st["result"].str, got) {
                case ("ok", .success(let env)): #expect(env == bytes(st["envelope"]), "\(name) step \(i)")
                case ("error", .failure(let e)): #expect(e.code == st["error"].str, "\(name) step \(i)")
                case (let want, let got): Issue.record("\(name) step \(i): want \(want), got \(got)")
                }
            }
        }
    }
}
