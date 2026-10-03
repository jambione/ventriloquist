//! Per-peer connection state machine (README §7), sans I/O.
//!
//! ```text
//! Connected ──hello──▶ HelloExchanged ──pair_request──▶ Pairing ──pair_confirm ok──▶ Secure
//!     │                     │  (known + paired:true) ─────────────────────────────▶ Secure
//!     └──────────── any ────┴──────────── error / protocol violation / drop ─────▶ Closed
//! ```
//!
//! The [`SessionManager`] owns framing, crypto and the protocol rules for
//! every connected peer. It is driven by transport events and a clock and
//! returns [`SessionOutput`]s (frames to send, disconnects, events, and
//! authenticated utterances to deliver). It never sleeps and never does I/O,
//! except persisting a successful pairing through [`PairingStore`].

use std::collections::HashMap;
use std::time::Duration;

use uuid::Uuid;
use vq_protocol::{
    check_in_session, decode_inbound, encode_plaintext, Ack, Error as ProtoError, ErrorMsg,
    FrameSplitter, Hello, Inbound, Message, PairChallenge, PairKey, PairRequest, PairResult,
    PairingCode, Reassembler, Role, SessionCipher, SessionNonce, Utt, UttState, MIN_MTU,
    PAIR_CODE_TTL_SECS, PAIR_MAX_FAILURES, PING_INTERVAL_SECS, PING_MAX_MISSED,
};

use crate::clock::Clock;
use crate::events::{CodeEndReason, HostEvent, PeerId, PeerState};
use crate::pairing_store::{Identity, PairedPeer, PairingStore};
use crate::transport::policy::{
    idle_drop_due, IDLE_RECONNECT_HOLDOFF, UNKNOWN_PEER_RECONNECT_HOLDOFF,
};

/// Pairing code lifetime (120 s).
pub const PAIR_CODE_TTL: Duration = Duration::from_secs(PAIR_CODE_TTL_SECS);
/// Keepalive interval (15 s).
pub const PING_INTERVAL: Duration = Duration::from_secs(PING_INTERVAL_SECS);

/// What the session layer wants done.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionOutput {
    /// Send these frames to `peer`.
    Send {
        /// Connection id.
        peer: PeerId,
        /// Frames, in order.
        frames: Vec<Vec<u8>>,
    },
    /// Close the connection (after the frames already queued).
    Disconnect {
        /// Connection id.
        peer: PeerId,
        /// Minimum delay before the transport reconnects to this phone.
        reconnect_after: Option<Duration>,
    },
    /// Emit an event.
    Event(HostEvent),
    /// An authenticated utterance from a Secure peer. The `ack` (for
    /// `final`/`edit`) has already been queued.
    Deliver {
        /// Connection id.
        peer: PeerId,
        /// Sending phone's `device_id`.
        device_id: Uuid,
        /// Sending phone's name.
        device_name: String,
        /// The utterance.
        utt: Utt,
    },
}

/// README §7.2: what the desktop does once both hellos are exchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloDecision {
    /// Known peer and `paired:true`: derive `K_sess`.
    Secure,
    /// Wait for `pair_request`.
    AwaitPairing,
    /// `paired:true` from a phone we do not know: `error{unknown_peer}`.
    UnknownPeer,
}

/// The README §7.2 table.
pub fn decide_after_hello(desktop_knows_phone: bool, phone_says_paired: bool) -> HelloDecision {
    match (desktop_knows_phone, phone_says_paired) {
        (true, true) => HelloDecision::Secure,
        (false, true) => HelloDecision::UnknownPeer,
        (_, false) => HelloDecision::AwaitPairing,
    }
}

struct PairingAttempt {
    request: PairRequest,
    challenge: PairChallenge,
    code: PairingCode,
    created_at: Duration,
    failures: u32,
}

impl PairingAttempt {
    fn expired(&self, now: Duration) -> bool {
        now.saturating_sub(self.created_at) >= PAIR_CODE_TTL
    }
}

struct PeerSession {
    mtu: usize,
    splitter: FrameSplitter,
    reassembler: Reassembler,
    state: PeerState,
    own_nonce: Option<SessionNonce>,
    peer_hello: Option<Hello>,
    cipher: Option<SessionCipher>,
    pairing: Option<PairingAttempt>,
    last_pairing_activity: Duration,
    next_ping_at: Duration,
    unanswered_pings: u32,
    closing: bool,
    close_reason: Option<String>,
}

/// All live sessions.
pub struct SessionManager {
    identity: Identity,
    name: String,
    sessions: HashMap<PeerId, PeerSession>,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("device_id", &self.identity.device_id)
            .field("name", &self.name)
            .field("peers", &self.sessions.keys().collect::<Vec<_>>())
            .finish()
    }
}

type Out = Vec<SessionOutput>;

impl SessionManager {
    /// A manager for this desktop's identity and display name.
    pub fn new(identity: Identity, name: String) -> Self {
        Self {
            identity,
            name,
            sessions: HashMap::new(),
        }
    }

    /// This desktop's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The display name used in future `hello`s.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Change the display name (affects connections made from now on).
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// State of `peer`, if connected.
    pub fn peer_state(&self, peer: &str) -> Option<PeerState> {
        self.sessions.get(peer).map(|s| s.state)
    }

    /// Connected peer ids.
    pub fn peers(&self) -> Vec<PeerId> {
        self.sessions.keys().cloned().collect()
    }

    /// A transport connected (and subscribed): send our `hello`.
    pub fn on_connected(&mut self, peer: PeerId, mtu: usize, clock: &dyn Clock) -> Out {
        let now = clock.mono();
        let mut out = Vec::new();
        let (hello, nonce) = Hello::new(
            self.identity.device_id,
            self.name.clone(),
            self.identity.keypair.public_bytes(),
            // README §7.1: the desktop does not know yet which phone this
            // is, so it sends paired:false (informational).
            false,
        );
        let mut s = PeerSession {
            mtu: mtu.max(MIN_MTU),
            splitter: FrameSplitter::new(),
            reassembler: Reassembler::new(),
            state: PeerState::Connected,
            own_nonce: Some(nonce),
            peer_hello: None,
            cipher: None,
            pairing: None,
            last_pairing_activity: now,
            next_ping_at: now + PING_INTERVAL,
            unanswered_pings: 0,
            closing: false,
            close_reason: None,
        };
        out.push(status_event(&peer, &s, None));
        s.send_plain(&peer, &Message::Hello(hello), &mut out);
        self.sessions.insert(peer, s);
        out
    }

    /// The transport reports the connection gone.
    pub fn on_disconnected(&mut self, peer: &str, reason: &str, store: &PairingStore) -> Out {
        let mut out = Vec::new();
        if let Some(mut s) = self.sessions.remove(peer) {
            if s.pairing.take().is_some() {
                out.push(SessionOutput::Event(HostEvent::PairingCodeEnded {
                    peer: peer.to_owned(),
                    reason: CodeEndReason::Disconnected,
                }));
            }
            s.state = PeerState::Closed;
            let reason = s.close_reason.clone().unwrap_or_else(|| reason.to_owned());
            out.push(status_event(peer, &s, Some(store)));
            if let SessionOutput::Event(HostEvent::ConnectionStatus { reason: r, .. }) =
                out.last_mut().expect("just pushed")
            {
                *r = Some(reason);
            }
        }
        out
    }

    /// One frame arrived from `peer`.
    pub fn on_frame(
        &mut self,
        peer: &str,
        frame: &[u8],
        clock: &dyn Clock,
        store: &mut PairingStore,
    ) -> Out {
        let mut out = Vec::new();
        let Some(s) = self.sessions.get_mut(peer) else {
            return out;
        };
        if s.closing {
            return out;
        }
        match s.reassembler.push(frame) {
            Err(e) => {
                log::warn!("{peer}: frame dropped: {e}");
                out.push(rejected(peer, &e));
            }
            Ok(None) => {}
            Ok(Some(envelope)) => {
                let ctx = Ctx {
                    identity: &self.identity,
                    own_name: &self.name,
                    store,
                    clock,
                };
                handle_envelope(peer, s, &envelope, ctx, &mut out);
            }
        }
        out
    }

    /// Timers: pairing-code expiry, idle drop of unpaired peers, keepalive.
    pub fn tick(&mut self, clock: &dyn Clock, store: &PairingStore) -> Out {
        let now = clock.mono();
        let mut out = Vec::new();
        for (peer, s) in &mut self.sessions {
            if s.closing {
                continue;
            }
            if s.state == PeerState::Secure {
                if now >= s.next_ping_at {
                    if s.unanswered_pings >= PING_MAX_MISSED {
                        s.close(peer, None, "keepalive_timeout", &mut out);
                    } else {
                        s.unanswered_pings += 1;
                        s.next_ping_at = now + PING_INTERVAL;
                        s.send_sealed(peer, &Message::Ping, &mut out);
                    }
                }
                continue;
            }
            if s.pairing.as_ref().is_some_and(|a| a.expired(now)) {
                s.end_pairing(peer, CodeEndReason::Expired, store, &mut out);
            }
            if idle_drop_due(false, s.last_pairing_activity, now) {
                s.close(
                    peer,
                    Some(IDLE_RECONNECT_HOLDOFF),
                    "idle_unpaired",
                    &mut out,
                );
            }
        }
        out
    }

    /// The user cancelled the pairing modal for `peer`.
    pub fn cancel_pairing(&mut self, peer: &str, store: &PairingStore) -> Out {
        let mut out = Vec::new();
        if let Some(s) = self.sessions.get_mut(peer) {
            if s.pairing.is_some() {
                s.end_pairing(peer, CodeEndReason::Cancelled, store, &mut out);
            }
        }
        out
    }

    /// Close every connection to `device_id` (after it was forgotten).
    pub fn disconnect_device(&mut self, device_id: &Uuid) -> Out {
        let mut out = Vec::new();
        for (peer, s) in &mut self.sessions {
            if s.peer_hello
                .as_ref()
                .is_some_and(|h| &h.device_id == device_id)
            {
                s.close(peer, None, "forgotten", &mut out);
            }
        }
        out
    }
}

struct Ctx<'a> {
    identity: &'a Identity,
    own_name: &'a str,
    store: &'a mut PairingStore,
    clock: &'a dyn Clock,
}

fn rejected(peer: &str, e: &ProtoError) -> SessionOutput {
    SessionOutput::Event(HostEvent::MessageRejected {
        peer: peer.to_owned(),
        code: e.code().to_owned(),
    })
}

fn status_event(peer: &str, s: &PeerSession, store: Option<&PairingStore>) -> SessionOutput {
    let h = s.peer_hello.as_ref();
    SessionOutput::Event(HostEvent::ConnectionStatus {
        peer: peer.to_owned(),
        state: s.state,
        device_id: h.map(|h| h.device_id),
        name: h.map(|h| h.name.clone()),
        paired: match (h, store) {
            (Some(h), Some(st)) => st.knows(&h.device_id, &h.public_key),
            _ => false,
        },
        reason: s.close_reason.clone(),
    })
}

impl PeerSession {
    fn frames(&mut self, envelope: &[u8]) -> Result<Vec<Vec<u8>>, ProtoError> {
        self.splitter.split(envelope, self.mtu)
    }

    fn send_plain(&mut self, peer: &str, msg: &Message, out: &mut Out) {
        match encode_plaintext(msg).and_then(|env| self.frames(&env)) {
            Ok(frames) => out.push(SessionOutput::Send {
                peer: peer.to_owned(),
                frames,
            }),
            Err(e) => log::error!("{peer}: cannot send {}: {e}", msg.type_name()),
        }
    }

    fn send_sealed(&mut self, peer: &str, msg: &Message, out: &mut Out) {
        let Some(cipher) = self.cipher.as_mut() else {
            log::error!("{peer}: no session for {}", msg.type_name());
            return;
        };
        match cipher.seal_message(msg).and_then(|env| self.frames(&env)) {
            Ok(frames) => out.push(SessionOutput::Send {
                peer: peer.to_owned(),
                frames,
            }),
            Err(e) => {
                // counter_exhausted or similar: the session cannot continue.
                log::error!("{peer}: cannot seal {}: {e}", msg.type_name());
                self.close(peer, None, e.code(), out);
            }
        }
    }

    fn send_error(&mut self, peer: &str, code: &str, msg: &str, out: &mut Out) {
        self.send_plain(peer, &Message::Error(ErrorMsg::new(code, msg)), out);
    }

    fn close(
        &mut self,
        peer: &str,
        reconnect_after: Option<Duration>,
        reason: &str,
        out: &mut Out,
    ) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.close_reason = Some(reason.to_owned());
        out.push(SessionOutput::Disconnect {
            peer: peer.to_owned(),
            reconnect_after,
        });
    }

    fn set_state(&mut self, peer: &str, state: PeerState, store: &PairingStore, out: &mut Out) {
        if self.state != state {
            self.state = state;
            out.push(status_event(peer, self, Some(store)));
        }
    }

    fn end_pairing(
        &mut self,
        peer: &str,
        reason: CodeEndReason,
        store: &PairingStore,
        out: &mut Out,
    ) {
        if self.pairing.take().is_some() {
            out.push(SessionOutput::Event(HostEvent::PairingCodeEnded {
                peer: peer.to_owned(),
                reason,
            }));
        }
        if self.state == PeerState::Pairing {
            self.set_state(peer, PeerState::HelloExchanged, store, out);
        }
    }

    fn protocol_violation(&mut self, peer: &str, why: &str, out: &mut Out) {
        log::warn!("{peer}: protocol violation: {why}");
        self.send_error(peer, ErrorMsg::PROTOCOL, "Protocol violation", out);
        self.close(peer, None, "protocol", out);
    }
}

fn handle_envelope(peer: &str, s: &mut PeerSession, envelope: &[u8], ctx: Ctx<'_>, out: &mut Out) {
    let inbound = match decode_inbound(envelope, s.cipher.as_mut()) {
        Ok(i) => i,
        Err(e @ ProtoError::Replay { .. }) => {
            // README §7.4: a replayed envelope is silently dropped.
            log::debug!("{peer}: {e}");
            return;
        }
        Err(e @ ProtoError::DecryptFailed) => {
            log::warn!("{peer}: {e}");
            out.push(rejected(peer, &e));
            // README §7.4: MAY answer with error{decrypt_failed} and disconnect.
            s.send_error(peer, ErrorMsg::DECRYPT_FAILED, "Decryption failed", out);
            s.close(peer, None, "decrypt_failed", out);
            return;
        }
        Err(e) => {
            // plaintext_not_allowed, no_session, invalid_json, text_too_long,
            // message_too_large, …: log and drop, never fatal.
            log::warn!("{peer}: message dropped: {e}");
            out.push(rejected(peer, &e));
            return;
        }
    };
    if s.state == PeerState::Secure {
        handle_secure(peer, s, inbound, ctx, out);
    } else {
        handle_unsecured(peer, s, inbound, ctx, out);
    }
}

fn handle_peer_error(
    peer: &str,
    s: &mut PeerSession,
    em: &ErrorMsg,
    authenticated: bool,
    own_name: &str,
    out: &mut Out,
) {
    // README §5.7/§7.4: show it and disconnect. Never touch the pairing
    // store because of it (whatever its provenance).
    out.push(SessionOutput::Event(HostEvent::PeerError {
        peer: peer.to_owned(),
        code: em.code.clone(),
        message: em.msg.clone(),
        authenticated,
    }));
    if em.code == ErrorMsg::VERSION {
        out.push(SessionOutput::Event(HostEvent::VersionMismatch {
            peer: peer.to_owned(),
            device: own_name.to_owned(),
        }));
    }
    s.close(peer, None, &format!("peer_error:{}", short(&em.code)), out);
}

fn short(code: &str) -> String {
    code.chars().filter(|c| !c.is_control()).take(32).collect()
}

fn handle_secure(peer: &str, s: &mut PeerSession, inbound: Inbound, ctx: Ctx<'_>, out: &mut Out) {
    if let Err(e) = check_in_session(&inbound) {
        out.push(rejected(peer, &e));
        match inbound.message() {
            Message::Hello(_) | Message::HelloUnsupported(_) => {
                // README §7.1: a second hello is a protocol error.
                s.protocol_violation(peer, "second hello", out);
            }
            // Pairing messages are dropped.
            _ => log::debug!("{peer}: {e}"),
        }
        return;
    }
    let authenticated = inbound.is_authenticated();
    match inbound.into_message() {
        Message::Utt(utt) if authenticated => {
            let h = s.peer_hello.as_ref().expect("Secure implies a peer hello");
            let (device_id, device_name) = (h.device_id, h.name.clone());
            let needs_ack = utt.state != UttState::Partial;
            let ack = Message::Ack(Ack {
                id: utt.id,
                rev: utt.rev,
            });
            out.push(SessionOutput::Deliver {
                peer: peer.to_owned(),
                device_id,
                device_name,
                utt,
            });
            // README §5.11: ack every final/edit, duplicates included.
            if needs_ack {
                s.send_sealed(peer, &ack, out);
            }
        }
        Message::Ping if authenticated => s.send_sealed(peer, &Message::Pong, out),
        Message::Pong if authenticated => s.unanswered_pings = 0,
        Message::Error(em) => handle_peer_error(peer, s, &em, authenticated, ctx.own_name, out),
        Message::Ack(_) => log::debug!("{peer}: unexpected ack from phone, ignored"),
        Message::Unknown { t } => {
            log::info!("{peer}: unknown message type {:?} dropped", short(&t))
        }
        other => log::warn!("{peer}: unexpected {} dropped", other.type_name()),
    }
}

fn handle_unsecured(
    peer: &str,
    s: &mut PeerSession,
    inbound: Inbound,
    ctx: Ctx<'_>,
    out: &mut Out,
) {
    let authenticated = inbound.is_authenticated();
    let now = ctx.clock.mono();
    match inbound.into_message() {
        Message::Hello(h) => {
            if s.peer_hello.is_some() {
                return s.protocol_violation(peer, "second hello", out);
            }
            s.last_pairing_activity = now;
            on_hello(peer, s, h, ctx, out);
        }
        Message::HelloUnsupported(hu) => {
            if s.peer_hello.is_some() {
                return s.protocol_violation(peer, "second hello", out);
            }
            out.push(SessionOutput::Event(HostEvent::VersionMismatch {
                peer: peer.to_owned(),
                device: hu.name.clone().unwrap_or_else(|| "the phone".to_owned()),
            }));
            s.send_error(peer, ErrorMsg::VERSION, "Update Ventriloquist", out);
            s.close(peer, None, "version", out);
        }
        Message::PairRequest(req) => {
            s.last_pairing_activity = now;
            let Some(h) = s.peer_hello.as_ref() else {
                log::warn!("{peer}: pair_request before hello dropped");
                return;
            };
            let (device_id, phone_name) = (h.device_id, h.name.clone());
            // README §7.3: always a new code and nonce_d, failures reset.
            let attempt = PairingAttempt {
                request: req,
                challenge: PairChallenge::generate(),
                code: PairingCode::generate(),
                created_at: now,
                failures: 0,
            };
            let challenge = attempt.challenge.clone();
            let code = attempt.code.to_string();
            s.pairing = Some(attempt);
            s.set_state(peer, PeerState::Pairing, ctx.store, out);
            s.send_plain(peer, &Message::PairChallenge(challenge), out);
            out.push(SessionOutput::Event(HostEvent::PairingCodeShown {
                peer: peer.to_owned(),
                device_id,
                phone_name,
                code,
                expires_in_secs: PAIR_CODE_TTL_SECS,
            }));
        }
        Message::PairConfirm(confirm) => {
            s.last_pairing_activity = now;
            on_pair_confirm(peer, s, &confirm.mac, ctx, out);
        }
        Message::PairChallenge(_) | Message::PairResult(_) => {
            // README §7.3: pairing messages in the wrong direction are ignored.
            log::debug!("{peer}: wrong-direction pairing message ignored");
        }
        Message::Error(em) => handle_peer_error(peer, s, &em, authenticated, ctx.own_name, out),
        Message::Unknown { t } => {
            log::info!("{peer}: unknown message type {:?} dropped", short(&t))
        }
        // utt/ack/ping/pong cannot decode without a session (plaintext is
        // rejected, encrypted is no_session).
        other => log::warn!("{peer}: unexpected {} dropped", other.type_name()),
    }
}

fn on_hello(peer: &str, s: &mut PeerSession, h: Hello, ctx: Ctx<'_>, out: &mut Out) {
    if ctx.identity.keypair.shared_secret(&h.public_key).is_err() {
        // Low-order public key: neither pairing nor a session is possible.
        s.peer_hello = Some(h);
        return s.protocol_violation(peer, "non-contributory public key", out);
    }
    let known = ctx.store.knows(&h.device_id, &h.public_key);
    let decision = decide_after_hello(known, h.paired);
    s.peer_hello = Some(h);
    match decision {
        HelloDecision::Secure => establish(peer, s, ctx.identity, ctx.store, out),
        HelloDecision::UnknownPeer => {
            s.send_error(
                peer,
                ErrorMsg::UNKNOWN_PEER,
                "This desktop does not know this phone. Forget it on the phone and pair again.",
                out,
            );
            s.close(
                peer,
                Some(UNKNOWN_PEER_RECONNECT_HOLDOFF),
                "unknown_peer",
                out,
            );
        }
        HelloDecision::AwaitPairing => s.set_state(peer, PeerState::HelloExchanged, ctx.store, out),
    }
}

fn establish(
    peer: &str,
    s: &mut PeerSession,
    identity: &Identity,
    store: &PairingStore,
    out: &mut Out,
) {
    let h = s.peer_hello.as_ref().expect("hello before establish");
    let Some(nonce) = s.own_nonce.take() else {
        return s.protocol_violation(peer, "session nonce already used", out);
    };
    match SessionCipher::establish(
        &identity.keypair,
        Role::Desktop,
        &h.public_key,
        nonce,
        &h.session_nonce,
    ) {
        Ok(cipher) => {
            s.cipher = Some(cipher);
            s.unanswered_pings = 0;
            s.set_state(peer, PeerState::Secure, store, out);
        }
        Err(e) => s.protocol_violation(peer, &e.to_string(), out),
    }
}

fn on_pair_confirm(peer: &str, s: &mut PeerSession, mac: &[u8; 32], ctx: Ctx<'_>, out: &mut Out) {
    let now = ctx.clock.mono();
    let hello = s.peer_hello.clone();
    let result_event = |ok: bool, remaining: u32| {
        SessionOutput::Event(HostEvent::PairingResult {
            peer: peer.to_owned(),
            device_id: hello.as_ref().map(|h| h.device_id),
            phone_name: hello.as_ref().map(|h| h.name.clone()),
            ok,
            attempts_remaining: remaining,
        })
    };
    // Expired codes are invalidated here too, not only by tick().
    if s.pairing.as_ref().is_some_and(|a| a.expired(now)) {
        s.end_pairing(peer, CodeEndReason::Expired, ctx.store, out);
    }
    let (Some(h), Some(attempt)) = (hello.as_ref(), s.pairing.as_mut()) else {
        // No active code (never generated, expired, invalidated, cancelled):
        // README §7.3 — still answer, with ok:false.
        s.send_plain(peer, &Message::PairResult(PairResult::failure()), out);
        out.push(result_event(false, 0));
        return;
    };
    let verified = PairKey::derive(
        &ctx.identity.keypair,
        Role::Desktop,
        &h.public_key,
        &attempt.request,
        &attempt.challenge,
        &attempt.code,
    )
    .and_then(|key| key.verify_phone_mac(mac).map(|()| key));
    if verified.is_err() {
        attempt.failures += 1;
    }
    let failures = attempt.failures;
    match verified {
        Ok(key) => {
            let record = PairedPeer {
                device_id: h.device_id,
                name: h.name.clone(),
                public_key: h.public_key,
                paired_at_ms: u64::try_from(ctx.clock.local_now().timestamp_millis()).unwrap_or(0),
            };
            if let Err(e) = ctx.store.upsert(record) {
                // Without a stored record the phone would be rejected on the
                // next connection, so do not report success.
                out.push(SessionOutput::Event(HostEvent::StorageWarning {
                    message: format!("Could not save the pairing: {e}"),
                }));
                s.send_plain(peer, &Message::PairResult(PairResult::failure()), out);
                out.push(result_event(
                    false,
                    PAIR_MAX_FAILURES.saturating_sub(failures),
                ));
                return;
            }
            s.pairing = None;
            s.send_plain(peer, &Message::PairResult(key.success_message()), out);
            out.push(result_event(true, 0));
            out.push(SessionOutput::Event(HostEvent::PairedPeersChanged {
                peers: ctx.store.peers().to_vec(),
            }));
            establish(peer, s, ctx.identity, ctx.store, out);
        }
        Err(e) => {
            let remaining = PAIR_MAX_FAILURES.saturating_sub(failures);
            log::info!("{peer}: pair_confirm failed ({e}); {remaining} attempts left");
            s.send_plain(peer, &Message::PairResult(PairResult::failure()), out);
            out.push(result_event(false, remaining));
            if remaining == 0 {
                s.end_pairing(peer, CodeEndReason::TooManyFailures, ctx.store, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_decision_table() {
        assert_eq!(decide_after_hello(true, true), HelloDecision::Secure);
        assert_eq!(decide_after_hello(true, false), HelloDecision::AwaitPairing);
        assert_eq!(decide_after_hello(false, true), HelloDecision::UnknownPeer);
        assert_eq!(
            decide_after_hello(false, false),
            HelloDecision::AwaitPairing
        );
    }
}
