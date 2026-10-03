/// Framing over the BLE byte pipe (README §3).
///
///     byte 0     : flags  (bit0 = FIRST, bit1 = LAST, bits 2-7 reserved = 0)
///     bytes 1..2 : msg_seq (u16 BE; per logical message, per direction, wraps)
///     bytes 3..  : chunk
public enum FrameFlags {
    public static let first: UInt8 = 0x01
    public static let last: UInt8 = 0x02
    public static let reservedMask: UInt8 = 0xFC
}

/// Splits logical messages (envelopes) into frames. One per direction per connection.
public struct FrameSplitter: Sendable {
    /// `msg_seq` the next message will use.
    public private(set) var nextSeq: UInt16

    /// A splitter whose first message uses `msg_seq = 0`.
    public init() { nextSeq = 0 }

    /// A splitter whose first message uses `msg_seq = seq` (tests / vectors).
    public init(seq: UInt16) { nextSeq = seq }

    /// Split `message` into frames of at most `mtu` bytes.
    ///
    /// Every frame but the last is exactly `mtu` bytes. An empty message
    /// yields one `FIRST|LAST` frame with no chunk. On success `nextSeq`
    /// advances by one (wrapping); on error it is unchanged.
    public mutating func split(_ message: [UInt8], mtu: Int) throws(VQError) -> [[UInt8]] {
        guard mtu >= VQ.minMTU else { throw .mtuTooSmall(mtu) }
        guard message.count <= VQ.maxMessageBytes else { throw .messageTooLarge(message.count) }
        let seq = nextSeq
        let chunkSize = mtu - VQ.frameHeaderBytes
        var frames: [[UInt8]] = []
        if message.isEmpty {
            frames.append(makeFrame(FrameFlags.first | FrameFlags.last, seq, []))
        } else {
            var start = 0
            while start < message.count {
                let end = min(start + chunkSize, message.count)
                var flags: UInt8 = 0
                if start == 0 { flags |= FrameFlags.first }
                if end == message.count { flags |= FrameFlags.last }
                frames.append(makeFrame(flags, seq, message[start..<end]))
                start = end
            }
        }
        nextSeq = seq &+ 1
        return frames
    }

    private func makeFrame(_ flags: UInt8, _ seq: UInt16, _ chunk: ArraySlice<UInt8>) -> [UInt8] {
        var f: [UInt8] = []
        f.reserveCapacity(VQ.frameHeaderBytes + chunk.count)
        f.append(flags)
        f.append(UInt8(seq >> 8))
        f.append(UInt8(seq & 0xFF))
        f.append(contentsOf: chunk)
        return f
    }
}

/// Reassembles frames from one direction of one connection (README §3.2).
public struct Reassembler: Sendable {
    private var partialSeq: UInt16 = 0
    private var buffer: [UInt8]?

    public init() {}

    /// Whether a partially reassembled message is buffered.
    public var hasPartial: Bool { buffer != nil }

    /// Discard any partial message (e.g. on disconnect).
    public mutating func reset() { buffer = nil }

    /// Feed one frame.
    ///
    /// Returns the message when one completes and `nil` when more frames are
    /// needed. Throws when the frame was dropped; errors are non-fatal and the
    /// reassembler stays usable. Rules, in order:
    ///
    /// 1. shorter than 3 bytes → `frame_too_short`, partial discarded;
    /// 2. reserved flag bits → `reserved_flags`, partial discarded;
    /// 3. FIRST → discard any partial and start a new one (even with the same seq);
    /// 4. continuation with no partial → `orphan_frame`;
    /// 5. continuation with another seq → `seq_mismatch`, partial and frame discarded;
    /// 6. append; 7. over 65,536 bytes → `message_too_large`, partial discarded;
    /// 8. LAST → the message is complete.
    public mutating func push(_ frame: [UInt8]) throws(VQError) -> [UInt8]? {
        guard frame.count >= VQ.frameHeaderBytes else {
            buffer = nil
            throw .frameTooShort
        }
        let flags = frame[0]
        guard flags & FrameFlags.reservedMask == 0 else {
            buffer = nil
            throw .reservedFlags(flags)
        }
        let seq = UInt16(frame[1]) << 8 | UInt16(frame[2])
        let chunk = frame[VQ.frameHeaderBytes...]

        if flags & FrameFlags.first != 0 {
            partialSeq = seq
            buffer = []
        } else {
            guard buffer != nil else { throw .orphanFrame }
            guard partialSeq == seq else {
                let expected = partialSeq
                buffer = nil
                throw .seqMismatch(expected: expected, got: seq)
            }
        }

        let total = buffer!.count + chunk.count
        guard total <= VQ.maxMessageBytes else {
            buffer = nil
            throw .messageTooLarge(total)
        }
        buffer!.append(contentsOf: chunk)

        if flags & FrameFlags.last != 0 {
            let done = buffer
            buffer = nil
            return done
        }
        return nil
    }
}
