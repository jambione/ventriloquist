//! The only module with `unsafe` on Windows: Win32 and UI Automation calls.
//! Everything it exports is a safe API over plain data (`isize` window
//! handles, `u32` pids, `String`s) plus the opaque [`UiaElement`].
//!
//! Safety notes shared by the wrappers:
//! - Window handles are passed around as `isize`. A stale handle only makes
//!   the Win32 call fail (or act on a reused handle, which callers guard with
//!   a pid check), it never causes memory unsafety.
//! - Out-pointers and buffers are valid, initialised locals that outlive the
//!   call. Buffers are sized from the API's own length report.
//! - Kernel handles are closed by [`OwnedHandle`]. The clipboard is closed by
//!   [`ClipboardGuard`], and `GlobalLock`/`GlobalUnlock` are always paired.
//! - UIA (`IUIAutomation*`) objects are free-threaded when COM is initialised
//!   as MTA, which [`ensure_com`] does once per thread. [`UiaElement`] is
//!   therefore `Send + Sync`.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Duration;

use windows::core::{w, BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GlobalFree, HANDLE, HGLOBAL, HWND, LPARAM};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::Media::Audio::{PlaySoundW, SND_ALIAS, SND_ASYNC};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, SAFEARRAY,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetClipboardData,
    GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayDestroy, SafeArrayGetLBound, SafeArrayGetUBound,
    SafeArrayUnaccessData,
};
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentProcess, GetCurrentThreadId, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationTextPattern,
    IUIAutomationValuePattern, TreeScope_Descendants, UIA_ControlTypePropertyId, UIA_TextPatternId,
    UIA_ValuePatternId,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE, VIRTUAL_KEY, VK_CONTROL, VK_RETURN, VK_SHIFT, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, CreateWindowExW, EnumWindows, GetForegroundWindow, GetWindow,
    GetWindowLongW, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindow,
    IsWindowVisible, SetForegroundWindow, ShowWindow, GWL_EXSTYLE, GW_OWNER, HWND_MESSAGE,
    SW_RESTORE, WINDOW_EX_STYLE, WINDOW_STYLE, WS_EX_TOOLWINDOW,
};

// ---------------------------------------------------------------- basics

fn hw(h: isize) -> HWND {
    HWND(h as *mut c_void)
}

fn hv(h: HWND) -> isize {
    h.0 as isize
}

/// Kernel handle closed on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Initialise COM (MTA) on the calling thread, once. Never uninitialised: the
/// injector's threads live as long as the process.
pub fn ensure_com() {
    thread_local! {
        static INIT: () = {
            // SAFETY: plain COM init; S_FALSE / RPC_E_CHANGED_MODE are fine to ignore
            // (the thread then already has a usable apartment).
            unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            }
        };
    }
    INIT.with(|_| {});
}

pub fn own_pid() -> u32 {
    std::process::id()
}

// --------------------------------------------------------------- windows

pub fn foreground() -> Option<isize> {
    // SAFETY: no arguments.
    let h = unsafe { GetForegroundWindow() };
    (!h.0.is_null()).then(|| hv(h))
}

pub fn is_window(h: isize) -> bool {
    // SAFETY: any handle value is accepted by IsWindow.
    unsafe { IsWindow(Some(hw(h))).as_bool() }
}

pub fn window_pid(h: isize) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid out-pointer.
    let tid = unsafe { GetWindowThreadProcessId(hw(h), Some(&mut pid)) };
    (tid != 0 && pid != 0).then_some(pid)
}

pub fn window_title(h: isize) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: the slice is valid for its length.
    let n = unsafe { GetWindowTextW(hw(h), &mut buf) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

/// Executable file name (e.g. `notepad.exe`) of a process.
pub fn exe_name(pid: u32) -> Option<String> {
    // SAFETY: handle is closed by OwnedHandle; the buffer/length pair is valid.
    unsafe {
        let p = OwnedHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        QueryFullProcessImageNameW(p.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).ok()?;
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        Some(super::file_name_of(&path))
    }
}

/// Integrity level RID of a process token (e.g. 0x2000 medium, 0x3000 high).
fn integrity_level(process: HANDLE) -> Option<u32> {
    // SAFETY: token handle closed by OwnedHandle; the buffer is 8-aligned
    // (Vec<u64>) and sized by the first GetTokenInformation call, and the SID
    // pointer inside it is only read while `buf` is alive.
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut tok).ok()?;
        let tok = OwnedHandle(tok);
        let mut len = 0u32;
        let _ = GetTokenInformation(tok.0, TokenIntegrityLevel, None, 0, &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        GetTokenInformation(tok.0, TokenIntegrityLevel, Some(buf.as_mut_ptr() as *mut c_void), len, &mut len)
            .ok()?;
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        let n = *GetSidSubAuthorityCount(sid);
        if n == 0 {
            return None;
        }
        Some(*GetSidSubAuthority(sid, u32::from(n) - 1))
    }
}

/// Medium integrity, assumed for ourselves if our own token can't be read.
const MEDIUM_RID: u32 = 0x2000;

/// True when the target's integrity level is higher than ours, or its token
/// can't be opened (SPEC_V2 §4.8). Messages to such a window are dropped by UIPI.
pub fn target_is_elevated(pid: u32) -> bool {
    // SAFETY: handle closed by OwnedHandle; GetCurrentProcess is a pseudo handle.
    let target = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let Ok(target) = target else { return true };
    let target = OwnedHandle(target);
    let Some(theirs) = integrity_level(target.0) else { return true };
    // SAFETY: pseudo handle, never closed.
    let ours = integrity_level(unsafe { GetCurrentProcess() }).unwrap_or(MEDIUM_RID);
    theirs > ours
}

/// One visible, top-level, titled window.
pub struct WinEntry {
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    /// No owner and not a tool window: a document-style window.
    pub standard: bool,
}

unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: lparam is the `&mut Vec<WinEntry>` passed by `enum_windows`,
    // valid for the duration of EnumWindows.
    let out = unsafe { &mut *(lparam.0 as *mut Vec<WinEntry>) };
    // SAFETY: plain queries on the handle EnumWindows gave us.
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() {
            return BOOL(1);
        }
        let mut cloaked = 0u32;
        if DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &mut cloaked as *mut u32 as *mut c_void, 4).is_ok()
            && cloaked != 0
        {
            return BOOL(1);
        }
    }
    let h = hv(hwnd);
    let title = window_title(h);
    if title.is_empty() {
        return BOOL(1);
    }
    let Some(pid) = window_pid(h) else { return BOOL(1) };
    // SAFETY: plain queries.
    let standard = unsafe {
        let ex = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
        GetWindow(hwnd, GW_OWNER).map(|o| o.0.is_null()).unwrap_or(true) && ex & WS_EX_TOOLWINDOW.0 == 0
    };
    out.push(WinEntry { hwnd: h, pid, title, standard });
    BOOL(1)
}

/// Visible, top-level, titled windows (uncloaked).
pub fn enum_windows() -> Vec<WinEntry> {
    let mut out: Vec<WinEntry> = Vec::new();
    // SAFETY: the callback only dereferences the pointer we pass, which stays
    // valid until EnumWindows returns.
    unsafe {
        let _ = EnumWindows(Some(enum_cb), LPARAM(&mut out as *mut Vec<WinEntry> as isize));
    }
    out
}

/// Bring `target` to the foreground (SPEC_V2 §4.8 activation, steps 1-2):
/// restore if minimised, then the AttachThreadInput technique so the
/// foreground-lock rules allow SetForegroundWindow.
pub fn activate(target: isize) {
    let t = hw(target);
    // SAFETY: plain window calls; the thread attach is always detached again.
    unsafe {
        if IsIconic(t).as_bool() {
            let _ = ShowWindow(t, SW_RESTORE);
        }
        let cur = GetCurrentThreadId();
        let fg = GetForegroundWindow();
        let fg_thread = if fg.0.is_null() { 0 } else { GetWindowThreadProcessId(fg, None) };
        let attached = fg_thread != 0 && fg_thread != cur && AttachThreadInput(cur, fg_thread, true).as_bool();
        let _ = BringWindowToTop(t);
        let _ = SetForegroundWindow(t);
        if attached {
            let _ = AttachThreadInput(cur, fg_thread, false);
        }
    }
}

/// Poll until `target` is the foreground window.
pub fn wait_foreground(target: isize, timeout: Duration) -> bool {
    let end = std::time::Instant::now() + timeout;
    loop {
        if foreground() == Some(target) {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ----------------------------------------------------------------- input

fn key(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn send(inputs: &[INPUT]) -> bool {
    if inputs.is_empty() {
        return true;
    }
    // SAFETY: `inputs` is a valid slice of fully initialised INPUT structs.
    let n = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    n as usize == inputs.len()
}

/// Type text as Unicode key events (one down/up pair per UTF-16 unit, sent in
/// batches). `\t` is sent as a real Tab key.
pub fn send_unicode(text: &str) -> bool {
    let mut batch: Vec<INPUT> = Vec::new();
    for unit in text.encode_utf16() {
        if unit == 0x09 {
            batch.push(key(VK_TAB, 0, KEYBD_EVENT_FLAGS(0)));
            batch.push(key(VK_TAB, 0, KEYEVENTF_KEYUP));
        } else {
            batch.push(key(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE));
            batch.push(key(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
        }
        if batch.len() >= 40 {
            if !send(&batch) {
                return false;
            }
            batch.clear();
        }
    }
    send(&batch)
}

pub fn send_shift_return() -> bool {
    send(&[
        key(VK_SHIFT, 0, KEYBD_EVENT_FLAGS(0)),
        key(VK_RETURN, 0, KEYBD_EVENT_FLAGS(0)),
        key(VK_RETURN, 0, KEYEVENTF_KEYUP),
        key(VK_SHIFT, 0, KEYEVENTF_KEYUP),
    ])
}

pub fn send_return() -> bool {
    send(&[key(VK_RETURN, 0, KEYBD_EVENT_FLAGS(0)), key(VK_RETURN, 0, KEYEVENTF_KEYUP)])
}

pub fn send_ctrl_v() -> bool {
    const VK_V: VIRTUAL_KEY = VIRTUAL_KEY(0x56);
    send(&[
        key(VK_CONTROL, 0, KEYBD_EVENT_FLAGS(0)),
        key(VK_V, 0, KEYBD_EVENT_FLAGS(0)),
        key(VK_V, 0, KEYEVENTF_KEYUP),
        key(VK_CONTROL, 0, KEYEVENTF_KEYUP),
    ])
}

// ---------------------------------------------------------------- sounds

pub fn play_alias(alias: &str) {
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; SND_ALIAS with
    // SND_ASYNC copies the alias before returning.
    unsafe {
        let _ = PlaySoundW(PCWSTR(wide.as_ptr()), None, SND_ALIAS | SND_ASYNC);
    }
}

// ------------------------------------------------------------- clipboard

pub const CF_UNICODETEXT: u32 = 13;

/// Hidden message-only window that owns the clipboard while we write to it
/// (`SetClipboardData` fails after `EmptyClipboard` with a NULL owner).
fn clipboard_owner() -> Option<HWND> {
    static OWNER: OnceLock<isize> = OnceLock::new();
    let h = *OWNER.get_or_init(|| {
        // SAFETY: the predefined STATIC class needs no registration; the
        // window lives for the rest of the process.
        unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("vq-inject clipboard owner"),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                None,
                None,
            )
            .map(hv)
            .unwrap_or(0)
        }
    });
    (h != 0).then(|| hw(h))
}

/// An open clipboard; closed on drop.
struct ClipboardGuard;

impl ClipboardGuard {
    fn open() -> Option<Self> {
        let owner = clipboard_owner()?;
        for _ in 0..20 {
            // SAFETY: owner is a live window handle.
            if unsafe { OpenClipboard(Some(owner)) }.is_ok() {
                return Some(ClipboardGuard);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        // SAFETY: we opened the clipboard in `open`.
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

fn formats_on_open_clipboard() -> Vec<u32> {
    let mut v = Vec::new();
    let mut f = 0u32;
    loop {
        // SAFETY: the clipboard is open (callers hold a ClipboardGuard).
        f = unsafe { EnumClipboardFormats(f) };
        if f == 0 {
            break;
        }
        v.push(f);
    }
    v
}

/// Formats currently on the clipboard; `None` if it can't be opened.
pub fn clipboard_formats() -> Option<Vec<u32>> {
    let _g = ClipboardGuard::open()?;
    Some(formats_on_open_clipboard())
}

/// A copy of every HGLOBAL format on the clipboard.
pub struct ClipboardSnapshot {
    items: Vec<(u32, Vec<u8>)>,
}

/// Copy the clipboard. `None` if it can't be opened, a format's data can't be
/// read as an HGLOBAL, or it is unreasonably large (caller must not paste).
pub fn clipboard_snapshot() -> Option<ClipboardSnapshot> {
    const MAX_BYTES: usize = 64 << 20;
    let _g = ClipboardGuard::open()?;
    let formats = formats_on_open_clipboard();
    if !super::formats_restorable(&formats) {
        return None;
    }
    let skip_synth = super::has_dib(&formats);
    let mut items = Vec::new();
    let mut total = 0usize;
    for f in formats {
        if skip_synth && super::is_synthesizable_from_dib(f) {
            continue;
        }
        // SAFETY: clipboard open; the handle stays owned by the clipboard. We
        // lock it only while copying and unlock before moving on.
        unsafe {
            let h = GetClipboardData(f).ok()?;
            let g = HGLOBAL(h.0);
            let size = GlobalSize(g);
            total += size;
            if total > MAX_BYTES {
                return None;
            }
            let p = GlobalLock(g);
            if p.is_null() {
                return None;
            }
            let bytes = std::slice::from_raw_parts(p as *const u8, size).to_vec();
            let _ = GlobalUnlock(g);
            items.push((f, bytes));
        }
    }
    Some(ClipboardSnapshot { items })
}

/// Allocate a moveable global block holding `bytes`.
///
/// # Safety
/// The caller must hand the block to the clipboard or free it.
unsafe fn alloc_global(bytes: &[u8]) -> Option<HGLOBAL> {
    // SAFETY: size > 0; the lock/copy/unlock stays within the allocation.
    unsafe {
        let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)).ok()?;
        let p = GlobalLock(h);
        if p.is_null() {
            let _ = GlobalFree(Some(h));
            return None;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len());
        let _ = GlobalUnlock(h);
        Some(h)
    }
}

/// `SetClipboardData` on the open clipboard; frees the block if refused.
fn put(format: u32, bytes: &[u8]) -> bool {
    // SAFETY: clipboard open and emptied by us; on success the clipboard owns
    // the block, on failure we free it.
    unsafe {
        let Some(h) = alloc_global(bytes) else { return false };
        if SetClipboardData(format, Some(HANDLE(h.0))).is_ok() {
            true
        } else {
            let _ = GlobalFree(Some(h));
            false
        }
    }
}

fn utf16_nul_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect()
}

/// Replace the clipboard with `text`, marked so clipboard history / cloud
/// sync skip it. Returns the clipboard sequence number right after the set.
pub fn clipboard_set_text(text: &str) -> Option<u32> {
    {
        let _g = ClipboardGuard::open()?;
        // SAFETY: clipboard open.
        unsafe { EmptyClipboard().ok()? };
        if !put(CF_UNICODETEXT, &utf16_nul_bytes(text)) {
            return None;
        }
        // Best effort privacy markers (Windows 10+ clipboard history/cloud).
        // SAFETY: registering formats has no preconditions.
        let (exclude, hist, cloud) = unsafe {
            (
                RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing")),
                RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory")),
                RegisterClipboardFormatW(w!("CanUploadToCloudClipboard")),
            )
        };
        for f in [exclude, hist, cloud] {
            if f != 0 {
                put(f, &0u32.to_le_bytes());
            }
        }
    }
    Some(clipboard_sequence())
}

/// Current `CF_UNICODETEXT` content, if any. For integration tests.
pub fn clipboard_get_text() -> Option<String> {
    let _g = ClipboardGuard::open()?;
    // SAFETY: clipboard open; the block is locked only while we copy it out.
    unsafe {
        let h = GetClipboardData(CF_UNICODETEXT).ok()?;
        let g = HGLOBAL(h.0);
        let p = GlobalLock(g) as *const u16;
        if p.is_null() {
            return None;
        }
        let max = GlobalSize(g) / 2;
        let units = std::slice::from_raw_parts(p, max);
        let end = units.iter().position(|u| *u == 0).unwrap_or(max);
        let text = String::from_utf16_lossy(&units[..end]);
        let _ = GlobalUnlock(g);
        Some(text)
    }
}

pub fn clipboard_sequence() -> u32 {
    // SAFETY: no arguments.
    unsafe { GetClipboardSequenceNumber() }
}

/// Put the snapshot back, but only if the sequence number is still `expected`
/// (nobody else wrote since our set). Returns whether it restored.
pub fn clipboard_restore_if_unchanged(snap: &ClipboardSnapshot, expected: u32) -> bool {
    let Some(_g) = ClipboardGuard::open() else { return false };
    if clipboard_sequence() != expected {
        return false;
    }
    // SAFETY: clipboard open.
    if unsafe { EmptyClipboard() }.is_err() {
        return false;
    }
    for (f, bytes) in &snap.items {
        put(*f, bytes);
    }
    true
}

// ------------------------------------------------------------------- UIA

/// A UIA element plus its RuntimeId at capture time.
#[derive(Clone)]
pub struct UiaElement {
    el: IUIAutomationElement,
    runtime_id: Vec<i32>,
}

// SAFETY: UIA objects are free-threaded under MTA (see module docs).
unsafe impl Send for UiaElement {}
unsafe impl Sync for UiaElement {}

pub struct FocusedInfo {
    pub element: UiaElement,
    pub pid: u32,
    pub control_type: i32,
    pub class_name: String,
    pub is_password: bool,
}

fn automation() -> Option<&'static IUIAutomation> {
    struct Holder(Option<IUIAutomation>);
    // SAFETY: IUIAutomation is free-threaded under MTA.
    unsafe impl Send for Holder {}
    unsafe impl Sync for Holder {}
    static UIA: OnceLock<Holder> = OnceLock::new();
    ensure_com();
    UIA.get_or_init(|| {
        // SAFETY: standard in-proc CoCreateInstance of the UIA client object.
        Holder(unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }.ok())
    })
    .0
    .as_ref()
}

/// Read a SAFEARRAY of i32 (a RuntimeId) and destroy it.
///
/// # Safety
/// `psa` must be a valid 1-D SAFEARRAY of i32 that the caller owns.
unsafe fn take_i32_array(psa: *mut SAFEARRAY) -> Vec<i32> {
    if psa.is_null() {
        return Vec::new();
    }
    // SAFETY: per the contract; access/unaccess are paired, bounds come from the array.
    unsafe {
        let mut out = Vec::new();
        if let (Ok(lo), Ok(hi)) = (SafeArrayGetLBound(psa, 1), SafeArrayGetUBound(psa, 1)) {
            let mut data: *mut c_void = std::ptr::null_mut();
            if hi >= lo && SafeArrayAccessData(psa, &mut data).is_ok() && !data.is_null() {
                let n = (hi - lo + 1) as usize;
                out = std::slice::from_raw_parts(data as *const i32, n).to_vec();
                let _ = SafeArrayUnaccessData(psa);
            }
        }
        let _ = SafeArrayDestroy(psa);
        out
    }
}

fn runtime_id(el: &IUIAutomationElement) -> Option<Vec<i32>> {
    // SAFETY: GetRuntimeId returns an array we own and `take_i32_array` frees.
    unsafe { el.GetRuntimeId().ok().map(|p| take_i32_array(p)) }
}

fn describe(el: IUIAutomationElement) -> Option<FocusedInfo> {
    // SAFETY: plain property reads on a live COM object.
    unsafe {
        let pid = el.CurrentProcessId().ok()? as u32;
        let control_type = el.CurrentControlType().map(|c| c.0).unwrap_or(0);
        let class_name = el.CurrentClassName().map(|b| b.to_string()).unwrap_or_default();
        let is_password = el.CurrentIsPassword().map(|b| b.as_bool()).unwrap_or(false);
        let runtime_id = runtime_id(&el).unwrap_or_default();
        Some(FocusedInfo { element: UiaElement { el, runtime_id }, pid, control_type, class_name, is_password })
    }
}

/// UIA's globally focused element.
pub fn uia_focused() -> Option<FocusedInfo> {
    let a = automation()?;
    // SAFETY: live automation object.
    let el = unsafe { a.GetFocusedElement() }.ok()?;
    describe(el)
}

impl UiaElement {
    /// Still resolves to the same element (its RuntimeId is unchanged)?
    pub fn is_valid(&self) -> bool {
        !self.runtime_id.is_empty() && runtime_id(&self.el).as_deref() == Some(self.runtime_id.as_slice())
    }

    /// Re-focus if it still resolves. Returns whether focus was set.
    pub fn refocus(&self) -> bool {
        // SAFETY: live COM object.
        self.is_valid() && unsafe { self.el.SetFocus() }.is_ok()
    }

    pub fn is_password(&self) -> Option<bool> {
        // SAFETY: live COM object.
        unsafe { self.el.CurrentIsPassword().ok().map(|b| b.as_bool()) }
    }
}

/// Text of the first Edit or Document control under `hwnd`, read through UIA
/// TextPattern (then ValuePattern). For integration tests.
pub fn window_text(hwnd: isize) -> Option<String> {
    let a = automation()?;
    // SAFETY: live automation object; all COM objects are released on drop.
    unsafe {
        let root = a.ElementFromHandle(hw(hwnd)).ok()?;
        for control_type in [50004i32 /* Edit */, 50030 /* Document */] {
            let cond = a.CreatePropertyCondition(UIA_ControlTypePropertyId, &VARIANT::from(control_type)).ok()?;
            let Ok(el) = root.FindFirst(TreeScope_Descendants, &cond) else { continue };
            if let Ok(p) = el.GetCurrentPattern(UIA_TextPatternId) {
                if let Ok(tp) = windows::core::Interface::cast::<IUIAutomationTextPattern>(&p) {
                    if let Ok(t) = tp.DocumentRange().and_then(|r| r.GetText(-1)) {
                        return Some(t.to_string());
                    }
                }
            }
            if let Ok(p) = el.GetCurrentPattern(UIA_ValuePatternId) {
                if let Ok(vp) = windows::core::Interface::cast::<IUIAutomationValuePattern>(&p) {
                    if let Ok(t) = vp.CurrentValue() {
                        return Some(t.to_string());
                    }
                }
            }
        }
        None
    }
}
