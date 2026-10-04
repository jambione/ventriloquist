//! Pure data model for bindings (SPEC_V2 §3, §4).

use serde::{Deserialize, Serialize};

/// Slot number, always 1..=9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct SlotId(u8);

impl SlotId {
    pub const MIN: u8 = 1;
    pub const MAX: u8 = 9;

    pub fn new(n: u8) -> Option<Self> {
        (Self::MIN..=Self::MAX).contains(&n).then_some(Self(n))
    }

    pub fn get(self) -> u8 {
        self.0
    }

    /// All slots, 1 to 9 in order.
    pub fn all() -> impl Iterator<Item = SlotId> {
        (Self::MIN..=Self::MAX).map(SlotId)
    }
}

impl TryFrom<u8> for SlotId {
    type Error = String;
    fn try_from(n: u8) -> Result<Self, String> {
        SlotId::new(n).ok_or_else(|| format!("slot {n} out of range 1-9"))
    }
}

impl From<SlotId> for u8 {
    fn from(s: SlotId) -> u8 {
        s.0
    }
}

impl std::fmt::Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The active slot: Off (display only) or one of 1..=9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ActiveSlot {
    #[default]
    Off,
    Slot(SlotId),
}

impl ActiveSlot {
    /// 0 is Off, 1..=9 a slot; anything else is `None`.
    pub fn from_digit(n: u8) -> Option<Self> {
        if n == 0 {
            Some(ActiveSlot::Off)
        } else {
            SlotId::new(n).map(ActiveSlot::Slot)
        }
    }

    pub fn digit(self) -> u8 {
        match self {
            ActiveSlot::Off => 0,
            ActiveSlot::Slot(s) => s.get(),
        }
    }

    pub fn slot(self) -> Option<SlotId> {
        match self {
            ActiveSlot::Off => None,
            ActiveSlot::Slot(s) => Some(s),
        }
    }
}

/// What a slot is bound to (§4.1 step 3). The live AX references are not part
/// of this: the injector keeps them for the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingTarget {
    /// App identity: the bundle id on macOS, the process executable name
    /// (e.g. `ms-teams.exe`) on Windows. Old files used `bundle_id`.
    #[serde(alias = "bundle_id")]
    pub app_id: String,
    pub app_name: String,
    pub window_title: String,
    pub element_role: String,
    #[serde(default)]
    pub element_subrole: String,
    pub ax_insertable: bool,
}

/// Per-slot settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SlotSettings {
    /// Press Return after the text (default off, §5).
    #[serde(default)]
    pub auto_submit: bool,
}

/// How a delivery reached the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMethod {
    /// `AXSelectedText` set through Accessibility.
    AxInsert,
    /// Unicode keyboard events.
    Type,
    /// Clipboard paste, line by line.
    Paste,
}

/// Outcome of one delivery (§4.3 step 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum DeliveryResult {
    Sent { method: DeliveryMethod },
    Missing,
    Blocked { reason: String },
    Failed { reason: String },
}

impl DeliveryResult {
    pub fn blocked(reason: impl Into<String>) -> Self {
        DeliveryResult::Blocked { reason: reason.into() }
    }
    pub fn failed(reason: impl Into<String>) -> Self {
        DeliveryResult::Failed { reason: reason.into() }
    }
    pub fn is_sent(&self) -> bool {
        matches!(self, DeliveryResult::Sent { .. })
    }
}

/// Feedback sounds (§4.2). Names are `NSSound` named sounds on macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sound {
    /// Slot selected or bound: Tink.
    Selected,
    /// Slot empty: Basso.
    Empty,
    /// Off: Pop.
    Off,
    /// Error / refusal: Basso.
    Error,
}

impl Sound {
    pub fn mac_name(self) -> &'static str {
        match self {
            Sound::Selected => "Tink",
            Sound::Empty | Sound::Error => "Basso",
            Sound::Off => "Pop",
        }
    }
}

/// A window of a running app, as seen by the injector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowInfo {
    /// Same meaning as `BindingTarget::app_id`.
    pub app_id: String,
    pub pid: i32,
    pub title: String,
    /// True for a standard document-style window (`AXStandardWindow`).
    pub standard: bool,
    /// Opaque, injector-assigned handle (e.g. the index in the AX window list).
    pub id: u64,
}
