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
///
/// Deserialising accepts the legacy `bundle_id` key; when both `app_id` and
/// `bundle_id` are present `app_id` wins (no duplicate-field error).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawBindingTarget")]
pub struct BindingTarget {
    /// App identity: the bundle id on macOS, the process executable name
    /// (e.g. `ms-teams.exe`) on Windows. Old files used `bundle_id`.
    pub app_id: String,
    pub app_name: String,
    pub window_title: String,
    pub element_role: String,
    #[serde(default)]
    pub element_subrole: String,
    pub ax_insertable: bool,
}

#[derive(Deserialize)]
struct RawBindingTarget {
    app_id: Option<String>,
    bundle_id: Option<String>,
    app_name: String,
    window_title: String,
    element_role: String,
    #[serde(default)]
    element_subrole: String,
    ax_insertable: bool,
}

impl TryFrom<RawBindingTarget> for BindingTarget {
    type Error = String;
    fn try_from(r: RawBindingTarget) -> Result<Self, String> {
        let app_id = r.app_id.or(r.bundle_id).ok_or("missing field `app_id`")?;
        Ok(BindingTarget {
            app_id,
            app_name: r.app_name,
            window_title: r.window_title,
            element_role: r.element_role,
            element_subrole: r.element_subrole,
            ax_insertable: r.ax_insertable,
        })
    }
}

/// Extra window identity used by the re-match fallback (SPEC_V2 §4.6, R7):
/// the window class and, when the app is packaged, its AppUserModelID. Empty
/// strings mean "unknown" (macOS, old files).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WindowIdentity {
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub aumid: String,
}

/// How line breaks are delivered (SPEC_V2 §2, §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NewlineMode {
    /// Shift+Return (soft newline).
    #[default]
    ShiftEnter,
    /// Flatten to one line: each line break becomes a single space.
    Spaces,
}

/// Per-slot settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SlotSettings {
    /// Press Return after the text (default off, §5).
    #[serde(default)]
    pub auto_submit: bool,
    /// Line-break handling. The default for a new binding depends on the app
    /// (see [`SlotSettings::for_app`]).
    #[serde(default)]
    pub newline_mode: NewlineMode,
}

impl SlotSettings {
    /// Defaults for a freshly bound app: terminals get `Spaces` (Shift+Enter
    /// can arrive as Enter and submit), everything else `ShiftEnter`.
    pub fn for_app(app_id: &str) -> Self {
        Self::for_app_class(app_id, "")
    }

    /// Like [`SlotSettings::for_app`], also using the window class (a console
    /// window of an unknown exe is still a terminal).
    pub fn for_app_class(app_id: &str, window_class: &str) -> Self {
        let newline_mode = match crate::planner::category_for(app_id, window_class) {
            crate::planner::AppCategory::Terminal => NewlineMode::Spaces,
            _ => NewlineMode::ShiftEnter,
        };
        SlotSettings { auto_submit: false, newline_mode }
    }
}

/// Default of a slot's `follow_title_changes` (SPEC_V2 §4.5): true for
/// terminals (whose titles change with every command), false otherwise.
pub fn default_follow_title(app_id: &str, window_class: &str) -> bool {
    crate::planner::category_for(app_id, window_class) == crate::planner::AppCategory::Terminal
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

    /// Windows system sound alias for `PlaySoundW` (SPEC_V2 §4.8).
    pub fn windows_alias(self) -> &'static str {
        match self {
            Sound::Selected => "SystemAsterisk",
            Sound::Empty | Sound::Error => "SystemHand",
            Sound::Off => "SystemExclamation",
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

/// A window plus what the re-match fallback needs beyond [`WindowInfo`] (R6, R7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowDetail {
    pub info: WindowInfo,
    pub identity: WindowIdentity,
    /// The window is on another virtual desktop (Windows): it counts for
    /// ambiguity and uniqueness but is never picked by the fallback.
    pub other_desktop: bool,
}

impl From<WindowInfo> for WindowDetail {
    fn from(info: WindowInfo) -> Self {
        WindowDetail { info, identity: WindowIdentity::default(), other_desktop: false }
    }
}
