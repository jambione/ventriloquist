//! Framing over the BLE byte pipe (SPEC §4.2).
//!
//! ```text
//! byte 0     : flags  (bit0 = FIRST, bit1 = LAST, bits 2-7 reserved = 0)
//! bytes 1..2 : msg_seq (u16 big-endian; per logical message, per direction, wraps)
//! bytes 3..  : chunk
//! ```

use crate::error::{Error, Result};
use crate::{FRAME_HEADER_BYTES, MAX_MESSAGE_BYTES, MIN_MTU};

/// FIRST flag (bit 0).
pub const FLAG_FIRST: u8 = 0x01;
/// LAST flag (bit 1).
pub const FLAG_LAST: u8 = 0x02;
/// Mask of reserved flag bits (bits 2-7), which must be zero.
pub const FLAG_RESERVED_MASK: u8 = 0xFC;

/// Splits logical messages (envelopes) into frames. One per direction per connection.
#[derive(Debug, Clone, Default)]
pub struct FrameSplitter {
    next_seq: u16,
}

impl FrameSplitter {
    /// New splitter whose first message uses `msg_seq = 0`.
    pub fn new() -> Self {
        Self::default()
    }

    /// New splitter whose first message uses `msg_seq = seq` (tests / vectors).
    pub fn with_seq(seq: u16) -> Self {
        Self { next_seq: seq }
    }

    /// `msg_seq` the next message will use.
    pub fn next_seq(&self) -> u16 {
        self.next_seq
    }

    /// Split `message` into frames of at most `mtu` bytes each.
    ///
    /// `mtu` is the usable ATT payload size (≥ 20). Every frame but the last is
    /// exactly `mtu` bytes. An empty message yields one frame with flags
    /// `FIRST|LAST` and no chunk. On success the sequence number advances by
    /// one (wrapping); on error it is unchanged.
    pub fn split(&mut self, message: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>> {
        if mtu < MIN_MTU {
            return Err(Error::MtuTooSmall(mtu));
        }
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge(message.len()));
        }
        let seq = self.next_seq;
        let chunk_size = mtu - FRAME_HEADER_BYTES;
        let mut frames = Vec::with_capacity(message.len() / chunk_size + 1);
        let mut chunks = message.chunks(chunk_size).peekable();
        if chunks.peek().is_none() {
            frames.push(make_frame(FLAG_FIRST | FLAG_LAST, seq, &[]));
        }
        let mut first = true;
        while let Some(chunk) = chunks.next() {
            let mut flags = 0;
            if first {
                flags |= FLAG_FIRST;
            }
            if chunks.peek().is_none() {
                flags |= FLAG_LAST;
            }
            frames.push(make_frame(flags, seq, chunk));
            first = false;
        }
        self.next_seq = seq.wrapping_add(1);
        Ok(frames)
    }
}

fn make_frame(flags: u8, seq: u16, chunk: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAME_HEADER_BYTES + chunk.len());
    f.push(flags);
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(chunk);
    f
}

/// Reassembles frames from one direction of one connection.
#[derive(Debug, Clone, Default)]
pub struct Reassembler {
    partial: Option<(u16, Vec<u8>)>,
}

impl Reassembler {
    /// New, empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a partially reassembled message is buffered.
    pub fn has_partial(&self) -> bool {
        self.partial.is_some()
    }

    /// Discard any partial message (e.g. on disconnect).
    pub fn reset(&mut self) {
        self.partial = None;
    }

    /// Feed one frame.
    ///
    /// Returns `Ok(Some(bytes))` when a message completes, `Ok(None)` when more
    /// frames are needed, and `Err` when the frame was dropped. Errors are
    /// non-fatal: the reassembler stays usable. Rules, in order:
    ///
    /// 1. Frame shorter than 3 bytes → `frame_too_short`; the partial buffer is discarded.
    /// 2. Any reserved flag bit set → `reserved_flags`; the partial buffer is discarded.
    /// 3. FIRST set → any partial buffer is silently discarded and a new buffer
    ///    is started with this frame's `msg_seq` and chunk.
    /// 4. FIRST clear, no partial buffer → `orphan_frame` (frame dropped).
    /// 5. FIRST clear, `msg_seq` differs from the buffer's → `seq_mismatch`;
    ///    the buffer and the frame are discarded.
    /// 6. Otherwise the chunk is appended.
    /// 7. If the buffer now exceeds 65,536 bytes → `message_too_large`; the buffer is discarded.
    /// 8. If LAST is set, the buffer is returned as a complete message.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        if frame.len() < FRAME_HEADER_BYTES {
            self.partial = None;
            return Err(Error::FrameTooShort);
        }
        let flags = frame[0];
        if flags & FLAG_RESERVED_MASK != 0 {
            self.partial = None;
            return Err(Error::ReservedFlags(flags));
        }
        let seq = u16::from_be_bytes([frame[1], frame[2]]);
        let chunk = &frame[FRAME_HEADER_BYTES..];

        if flags & FLAG_FIRST != 0 {
            self.partial = Some((seq, Vec::with_capacity(chunk.len())));
        } else {
            match &self.partial {
                None => return Err(Error::OrphanFrame),
                Some((expected, _)) if *expected != seq => {
                    let expected = *expected;
                    self.partial = None;
                    return Err(Error::SeqMismatch { expected, got: seq });
                }
                Some(_) => {}
            }
        }

        let Some((_, buf)) = self.partial.as_mut() else {
            unreachable!("partial buffer was just ensured");
        };
        if buf.len() + chunk.len() > MAX_MESSAGE_BYTES {
            let total = buf.len() + chunk.len();
            self.partial = None;
            return Err(Error::MessageTooLarge(total));
        }
        buf.extend_from_slice(chunk);

        if flags & FLAG_LAST != 0 {
            Ok(self.partial.take().map(|(_, b)| b))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble_all(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut r = Reassembler::new();
        let mut out = None;
        for (i, f) in frames.iter().enumerate() {
            let res = r.push(f).unwrap();
            if i + 1 == frames.len() {
                out = res;
            } else {
                assert!(res.is_none());
            }
        }
        out.unwrap()
    }

    #[test]
    fn split_basic_layout() {
        let mut s = FrameSplitter::new();
        let msg: Vec<u8> = (0..40u8).collect();
        let frames = s.split(&msg, 20).unwrap();
        assert_eq!(frames.len(), 3); // 17 + 17 + 6
        assert_eq!(&frames[0][..3], &[0x01, 0, 0]);
        assert_eq!(&frames[1][..3], &[0x00, 0, 0]);
        assert_eq!(&frames[2][..3], &[0x02, 0, 0]);
        assert_eq!(frames[0].len(), 20);
        assert_eq!(frames[2].len(), 3 + 6);
        assert_eq!(s.next_seq(), 1);
        assert_eq!(reassemble_all(&frames), msg);
    }

    #[test]
    fn split_sizes_roundtrip() {
        for mtu in [20, 21, 23, 64, 185, 244, 512, 70_000] {
            for len in [0usize, 1, 16, 17, 18, 34, 35, 1000, 65_536] {
                let msg: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
                let frames = FrameSplitter::new().split(&msg, mtu).unwrap();
                let cs = mtu - 3;
                assert_eq!(frames.len(), len.div_ceil(cs).max(1), "mtu {mtu} len {len}");
                assert!(frames.iter().all(|f| f.len() <= mtu));
                assert_eq!(reassemble_all(&frames), msg);
            }
        }
    }

    #[test]
    fn single_frame_and_empty() {
        let f = FrameSplitter::new().split(b"abc", 20).unwrap();
        assert_eq!(f, vec![vec![0x03, 0, 0, b'a', b'b', b'c']]);
        let f = FrameSplitter::new().split(b"", 20).unwrap();
        assert_eq!(f, vec![vec![0x03, 0, 0]]);
        assert_eq!(Reassembler::new().push(&f[0]).unwrap(), Some(vec![]));
    }

    #[test]
    fn split_errors_do_not_advance_seq() {
        let mut s = FrameSplitter::with_seq(5);
        assert_eq!(s.split(b"x", 19).unwrap_err(), Error::MtuTooSmall(19));
        assert_eq!(
            s.split(&vec![0; 65_537], 20).unwrap_err(),
            Error::MessageTooLarge(65_537)
        );
        assert_eq!(s.next_seq(), 5);
    }

    #[test]
    fn seq_wraps() {
        let mut s = FrameSplitter::with_seq(0xFFFF);
        let a = s.split(b"a", 20).unwrap();
        let b = s.split(b"b", 20).unwrap();
        assert_eq!(&a[0][1..3], &[0xFF, 0xFF]);
        assert_eq!(&b[0][1..3], &[0x00, 0x00]);
    }

    #[test]
    fn first_resets_partial() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(&[0x01, 0, 1, b'x']).unwrap(), None);
        assert_eq!(r.push(&[0x01, 0, 2, b'y']).unwrap(), None);
        assert_eq!(r.push(&[0x02, 0, 2, b'z']).unwrap(), Some(b"yz".to_vec()));
        // FIRST with same seq also resets
        assert_eq!(r.push(&[0x01, 0, 3, b'a']).unwrap(), None);
        assert_eq!(r.push(&[0x03, 0, 3, b'b']).unwrap(), Some(b"b".to_vec()));
    }

    #[test]
    fn seq_mismatch_discards() {
        let mut r = Reassembler::new();
        r.push(&[0x01, 0, 1, b'x']).unwrap();
        assert_eq!(
            r.push(&[0x00, 0, 2, b'y']).unwrap_err(),
            Error::SeqMismatch {
                expected: 1,
                got: 2
            }
        );
        assert!(!r.has_partial());
        // the rest of the old message is now an orphan
        assert_eq!(r.push(&[0x02, 0, 1, b'z']).unwrap_err(), Error::OrphanFrame);
    }

    #[test]
    fn malformed_frames() {
        let mut r = Reassembler::new();
        r.push(&[0x01, 0, 1, b'x']).unwrap();
        assert_eq!(r.push(&[0x02, 0]).unwrap_err(), Error::FrameTooShort);
        assert!(!r.has_partial());
        r.push(&[0x01, 0, 1, b'x']).unwrap();
        assert_eq!(
            r.push(&[0x06, 0, 1]).unwrap_err(),
            Error::ReservedFlags(0x06)
        );
        assert!(!r.has_partial());
        assert_eq!(
            r.push(&[0x80 | 0x03, 0, 1]).unwrap_err().code(),
            "reserved_flags"
        );
        assert_eq!(r.push(&[]).unwrap_err(), Error::FrameTooShort);
        // still usable
        assert_eq!(r.push(&[0x03, 0, 9, 1, 2]).unwrap(), Some(vec![1, 2]));
    }

    #[test]
    fn oversize_reassembly() {
        let mut r = Reassembler::new();
        let chunk = vec![0xAA; 1000];
        let mut f = vec![0x01, 0, 7];
        f.extend_from_slice(&chunk);
        r.push(&f).unwrap();
        f[0] = 0x00;
        for _ in 0..64 {
            r.push(&f).unwrap();
        }
        // 65000 buffered; 536 more is exactly the limit
        let mut exact = vec![0x02, 0, 7];
        exact.extend_from_slice(&vec![0xAA; 536]);
        assert_eq!(r.push(&exact).unwrap().unwrap().len(), 65_536);

        let mut r = Reassembler::new();
        f[0] = 0x01;
        r.push(&f).unwrap();
        f[0] = 0x00;
        for _ in 0..64 {
            r.push(&f).unwrap();
        }
        let mut over = vec![0x00, 0, 7];
        over.extend_from_slice(&vec![0xAA; 537]);
        assert_eq!(r.push(&over).unwrap_err(), Error::MessageTooLarge(65_537));
        assert!(!r.has_partial());
        assert_eq!(r.push(&[0x02, 0, 7, 1]).unwrap_err(), Error::OrphanFrame);
    }

    #[test]
    fn orphan_continuations() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(&[0x00, 0, 0, 1]).unwrap_err(), Error::OrphanFrame);
        assert_eq!(r.push(&[0x02, 0, 0, 1]).unwrap_err(), Error::OrphanFrame);
        r.push(&[0x01, 0, 0, 1]).unwrap();
        r.reset();
        assert_eq!(r.push(&[0x02, 0, 0, 1]).unwrap_err(), Error::OrphanFrame);
    }
}
