//! Test helpers: a fake phone built only from the production `vq-protocol`
//! API, and a harness that drives `Core` with a manual clock.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::DateTime;
use uuid::Uuid;
use vq_host_core::transport::{TransportCommand, TransportEvent};
use vq_host_core::{Core, CoreOptions, CoreOutput, HostCommand, HostEvent, ManualClock};
use vq_protocol::{
    decode_inbound, encode_plaintext, FrameSplitter, Hello, IdentityKeyPair, Inbound, Message,
    PairChallenge, PairKey, PairRequest, PairResult, PairingCode, Reassembler, Role, SessionCipher,
    SessionNonce, Utt, UttState,
};

// ---------------------------------------------------------------- fake phone

/// One connection's protocol state on the phone side.
pub struct PhoneConn {
    pub mtu: usize,
    splitter: FrameSplitter,
    reassembler: Reassembler,
    own_nonce: Option<SessionNonce>,
    pub desktop_hello: Option<Hello>,
    pub cipher: Option<SessionCipher>,
    request: Option<PairRequest>,
    challenge: Option<PairChallenge>,
    key: Option<PairKey>,
}

/// A scripted phone.
pub struct FakePhone {
    pub identity: IdentityKeyPair,
    pub device_id: Uuid,
    pub name: String,
    /// Stored pairing: desktop device id + public key.
    pub desktop: Option<(Uuid, [u8; 32])>,
    pub conn: Option<PhoneConn>,
}

impl FakePhone {
    pub fn new(name: &str) -> Self {
        Self {
            identity: IdentityKeyPair::generate(),
            device_id: Uuid::new_v4(),
            name: name.to_owned(),
            desktop: None,
            conn: None,
        }
    }

    pub fn connect(&mut self, mtu: usize) {
        self.conn = Some(PhoneConn {
            mtu,
            splitter: FrameSplitter::new(),
            reassembler: Reassembler::new(),
            own_nonce: None,
            desktop_hello: None,
            cipher: None,
            request: None,
            challenge: None,
            key: None,
        });
    }

    fn c(&mut self) -> &mut PhoneConn {
        self.conn.as_mut().expect("phone not connected")
    }

    pub fn is_secure(&self) -> bool {
        self.conn.as_ref().is_some_and(|c| c.cipher.is_some())
    }

    /// Feed frames from the desktop; returns decoded messages. Records the
    /// desktop hello and pair_challenge as a side effect.
    pub fn receive(&mut self, frames: &[Vec<u8>]) -> Vec<Inbound> {
        let mut out = Vec::new();
        for f in frames {
            let c = self.c();
            if let Some(env) = c.reassembler.push(f).expect("desktop frames are valid") {
                let inb =
                    decode_inbound(&env, c.cipher.as_mut()).expect("desktop envelope decodes");
                match inb.message() {
                    Message::Hello(h) => c.desktop_hello = Some(h.clone()),
                    Message::PairChallenge(ch) => c.challenge = Some(ch.clone()),
                    _ => {}
                }
                out.push(inb);
            }
        }
        out
    }

    /// Whether we know the desktop that sent its hello on this connection.
    pub fn knows_desktop(&self) -> bool {
        let h = self.conn.as_ref().and_then(|c| c.desktop_hello.as_ref());
        match (h, self.desktop) {
            (Some(h), Some((id, pk))) => h.device_id == id && h.public_key == pk,
            _ => false,
        }
    }

    fn split(&mut self, envelope: &[u8]) -> Vec<Vec<u8>> {
        let c = self.c();
        let mtu = c.mtu;
        c.splitter.split(envelope, mtu).expect("split")
    }

    pub fn plain(&mut self, msg: &Message) -> Vec<Vec<u8>> {
        let env = encode_plaintext(msg).expect("encode");
        self.split(&env)
    }

    /// A raw plaintext envelope (bypasses the encoder's checks).
    pub fn raw_plain(&mut self, json: &[u8]) -> Vec<Vec<u8>> {
        let mut env = vec![0u8];
        env.extend_from_slice(json);
        self.split(&env)
    }

    pub fn sealed(&mut self, msg: &Message) -> Vec<Vec<u8>> {
        let env = self
            .c()
            .cipher
            .as_mut()
            .expect("secure")
            .seal_message(msg)
            .expect("seal");
        self.split(&env)
    }

    /// Encrypt arbitrary JSON bytes (bypasses the encoder's checks).
    pub fn raw_sealed(&mut self, json: &[u8]) -> Vec<Vec<u8>> {
        let env = self
            .c()
            .cipher
            .as_mut()
            .expect("secure")
            .seal(json)
            .expect("seal");
        self.split(&env)
    }

    /// Our hello. `paired` defaults to whether we know the desktop.
    pub fn hello(&mut self, paired: Option<bool>) -> Vec<Vec<u8>> {
        let paired = paired.unwrap_or_else(|| self.knows_desktop());
        let (hello, nonce) = Hello::new(
            self.device_id,
            self.name.clone(),
            self.identity.public_bytes(),
            paired,
        );
        self.c().own_nonce = Some(nonce);
        self.plain(&Message::Hello(hello))
    }

    /// Phone side of README §7.2: Secure iff it knows the desktop.
    pub fn establish(&mut self) {
        let c = self.conn.as_mut().expect("connected");
        let h = c.desktop_hello.clone().expect("desktop hello");
        let nonce = c.own_nonce.take().expect("own hello sent");
        c.cipher = Some(
            SessionCipher::establish(
                &self.identity,
                Role::Phone,
                &h.public_key,
                nonce,
                &h.session_nonce,
            )
            .expect("establish"),
        );
    }

    pub fn pair_request(&mut self) -> Vec<Vec<u8>> {
        let r = PairRequest::generate();
        self.c().request = Some(r.clone());
        self.plain(&Message::PairRequest(r))
    }

    /// pair_confirm for `code` (needs the challenge received).
    pub fn pair_confirm(&mut self, code: &str) -> Vec<Vec<u8>> {
        let code: PairingCode = code.parse().expect("6 digits");
        let c = self.conn.as_mut().expect("connected");
        let h = c.desktop_hello.as_ref().expect("desktop hello");
        let key = PairKey::derive(
            &self.identity,
            Role::Phone,
            &h.public_key,
            c.request.as_ref().expect("request"),
            c.challenge.as_ref().expect("challenge"),
            &code,
        )
        .expect("derive");
        let msg = Message::PairConfirm(key.confirm_message());
        c.key = Some(key);
        self.plain(&msg)
    }

    /// Handle pair_result: on a verified success, store the desktop and
    /// become Secure. Returns whether pairing succeeded.
    pub fn on_pair_result(&mut self, r: &PairResult) -> bool {
        if !r.ok {
            return false;
        }
        let c = self.conn.as_mut().expect("connected");
        let key = c.key.as_ref().expect("key");
        key.verify_desktop_mac(r.mac.as_ref().expect("mac"))
            .expect("desktop mac verifies");
        let h = c.desktop_hello.as_ref().expect("hello");
        self.desktop = Some((h.device_id, h.public_key));
        self.establish();
        true
    }

    pub fn utt(&mut self, id: Uuid, rev: u32, state: UttState, text: &str) -> Vec<Vec<u8>> {
        self.sealed(&Message::Utt(Utt {
            id,
            rev,
            state,
            text: text.to_owned(),
            ts: 1_759_500_000_000,
        }))
    }
}

// ---------------------------------------------------------------- harness

pub fn start_time() -> chrono::DateTime<chrono::FixedOffset> {
    DateTime::parse_from_rfc3339("2026-10-03T14:03:22+02:00").unwrap()
}

/// Drives a `Core` directly (no tokio, no sockets).
pub struct Harness {
    pub core: Core,
    pub clock: Arc<ManualClock>,
    pub dir: tempfile::TempDir,
    pub events: Vec<HostEvent>,
    pub outbox: HashMap<String, Vec<Vec<u8>>>,
    pub disconnects: Vec<(String, Option<Duration>)>,
}

impl Harness {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(start_time()));
        let core = open_core(&dir, clock.clone());
        Self {
            core,
            clock,
            dir,
            events: Vec::new(),
            outbox: HashMap::new(),
            disconnects: Vec::new(),
        }
    }

    pub fn config_dir(&self) -> PathBuf {
        self.dir.path().join("config")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.dir.path().join("logs")
    }

    /// Simulate an app restart: a fresh Core on the same directories.
    pub fn restart(&mut self) {
        self.core = open_core(&self.dir, self.clock.clone());
        self.events.clear();
        self.outbox.clear();
        self.disconnects.clear();
    }

    pub fn absorb(&mut self, outs: Vec<CoreOutput>) {
        for o in outs {
            match o {
                CoreOutput::Event(e) => self.events.push(e),
                CoreOutput::Transport(TransportCommand::Send { peer, frames }) => {
                    self.outbox.entry(peer).or_default().extend(frames)
                }
                CoreOutput::Transport(TransportCommand::Disconnect {
                    peer,
                    reconnect_after,
                }) => self.disconnects.push((peer, reconnect_after)),
                CoreOutput::Transport(TransportCommand::Shutdown) => {}
            }
        }
    }

    pub fn connect(&mut self, peer: &str, mtu: usize) {
        let o = self.core.handle_transport(TransportEvent::Connected {
            peer: peer.to_owned(),
            mtu,
        });
        self.absorb(o);
    }

    pub fn frames(&mut self, peer: &str, frames: Vec<Vec<u8>>) {
        for frame in frames {
            let o = self.core.handle_transport(TransportEvent::Frame {
                peer: peer.to_owned(),
                frame,
            });
            self.absorb(o);
        }
    }

    pub fn disconnected(&mut self, peer: &str) {
        let o = self.core.handle_transport(TransportEvent::Disconnected {
            peer: peer.to_owned(),
            reason: "test".into(),
        });
        self.absorb(o);
    }

    pub fn command(&mut self, cmd: HostCommand) {
        let o = self.core.handle_command(cmd);
        self.absorb(o);
    }

    pub fn advance(&mut self, d: Duration) {
        self.clock.advance(d);
        let o = self.core.tick();
        self.absorb(o);
    }

    /// Frames queued for `peer` since the last call.
    pub fn take(&mut self, peer: &str) -> Vec<Vec<u8>> {
        self.outbox.remove(peer).unwrap_or_default()
    }

    /// Deliver queued desktop frames to the phone.
    pub fn deliver_to_phone(&mut self, peer: &str, phone: &mut FakePhone) -> Vec<Inbound> {
        let f = self.take(peer);
        phone.receive(&f)
    }

    pub fn take_events(&mut self) -> Vec<HostEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn last_code(&self) -> Option<String> {
        self.events.iter().rev().find_map(|e| match e {
            HostEvent::PairingCodeShown { code, .. } => Some(code.clone()),
            _ => None,
        })
    }

    pub fn log_text(&self) -> String {
        std::fs::read_to_string(self.log_dir().join("2026-10-03.md")).unwrap_or_default()
    }

    /// Connect `phone` on `peer` and exchange hellos (phone's `paired`
    /// follows its store unless overridden).
    pub fn handshake(&mut self, peer: &str, phone: &mut FakePhone, paired: Option<bool>) {
        self.connect(peer, 185);
        phone.connect(185);
        let hello = self.deliver_to_phone(peer, phone);
        assert!(
            matches!(hello.as_slice(), [Inbound::Plaintext(Message::Hello(_))]),
            "{hello:?}"
        );
        let f = phone.hello(paired);
        if phone.knows_desktop() && paired.unwrap_or(true) {
            phone.establish();
        }
        self.frames(peer, f);
    }

    /// Full first-time pairing on `peer`. Returns the code.
    pub fn pair(&mut self, peer: &str, phone: &mut FakePhone) -> String {
        self.handshake(peer, phone, None);
        let f = phone.pair_request();
        self.frames(peer, f);
        let r = self.deliver_to_phone(peer, phone);
        assert!(
            matches!(
                r.as_slice(),
                [Inbound::Plaintext(Message::PairChallenge(_))]
            ),
            "{r:?}"
        );
        let code = self.last_code().expect("code shown");
        let f = phone.pair_confirm(&code);
        self.frames(peer, f);
        let r = self.deliver_to_phone(peer, phone);
        match r.as_slice() {
            [Inbound::Plaintext(Message::PairResult(res))] => assert!(phone.on_pair_result(res)),
            other => panic!("expected pair_result, got {other:?}"),
        }
        code
    }

    /// Entry-upsert events so far.
    pub fn upserts(&self) -> Vec<vq_host_core::transcript::Entry> {
        self.events
            .iter()
            .filter_map(|e| match e {
                HostEvent::EntryUpserted { entry } => Some(entry.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn rejected_codes(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                HostEvent::MessageRejected { code, .. } => Some(code.clone()),
                _ => None,
            })
            .collect()
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

fn open_core(dir: &tempfile::TempDir, clock: Arc<ManualClock>) -> Core {
    Core::open(CoreOptions {
        config_dir: dir.path().join("config"),
        log_dir_override: Some(dir.path().join("logs")),
        name_override: Some("Test Desktop".into()),
        clock,
    })
    .expect("core opens")
}

/// The acks among decoded messages, as (id, rev).
pub fn acks(msgs: &[Inbound]) -> Vec<(Uuid, u32)> {
    msgs.iter()
        .filter_map(|m| match m {
            Inbound::Encrypted(Message::Ack(a)) => Some((a.id, a.rev)),
            _ => None,
        })
        .collect()
}

/// A wrong 6-digit code, different from `code`.
pub fn wrong_code(code: &str) -> String {
    let n: u32 = code.parse().unwrap();
    format!("{:06}", (n + 1) % 1_000_000)
}
