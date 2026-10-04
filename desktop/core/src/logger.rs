//! Append-only daily Markdown log (SPEC §6.2).
//!
//! File: `<log_dir>/YYYY-MM-DD.md`, the **local date of the revision's
//! arrival**, created with the header `# Ventriloquist — YYYY-MM-DD`.
//! Each logged `final`/`edit` appends:
//!
//! ```text
//! - **HH:MM:SS** · <device name> · `id=<first 8 hex digits of id>`[ · edited]
//!   <text line 1>
//!   <text line 2>
//! ```
//!
//! * Partials are never logged.
//! * Each entry (header included, for a new file) is written with one
//!   `write_all` and then flushed.
//! * **Dedupe across restarts and midnight.** The Markdown line only
//!   carries an 8-digit id prefix and no revision, so it cannot identify
//!   (`id`, `rev`) by itself. Each day file therefore has a sidecar index
//!   `<log_dir>/.vq-index/YYYY-MM-DD.idx` with one `<uuid> <rev>` line per
//!   logged entry, appended *after* the Markdown entry is written and
//!   `sync_data`'d. Dedupe consults the index of the arrival day **and of
//!   the previous day**, so a `final` re-delivered just after midnight (or
//!   after a restart) is not logged again. A crash between the two appends
//!   can at worst log one entry twice; it never loses one.
//! * **Robust index.** Lines are parsed byte-wise; non-UTF-8, torn or
//!   otherwise unparseable lines are skipped. A torn last line is
//!   terminated before the next record is appended. An index that cannot
//!   be read (other than "not found") is reported through
//!   [`Logger::take_warnings`] and re-read on the next write instead of
//!   being cached as empty. If the index cannot be written, the entry
//!   stays deduplicated in memory for the rest of the run and a warning is
//!   reported; the Markdown entry itself counts as written.
//! * **Inert text.** Every text line is indented two spaces, so no text line
//!   can start at column 0 and mimic an entry or header. LF separates lines
//!   (a CR directly before an LF is dropped). Control characters other than
//!   TAB (C0, DEL, C1, including lone CR and ESC), Unicode bidi controls
//!   and U+2028/U+2029 are written as visible `\u{XX}` escapes, so viewing
//!   the log in a terminal or editor cannot execute escape sequences or
//!   reorder text. Markdown syntax is left as is so the text stays verbatim.
//!   The device name gets the same escaping (and LF is escaped there too).

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, NaiveDate};
use uuid::Uuid;
use vq_protocol::{Utt, UttState};

/// Name of the sidecar dedupe-index directory inside the log directory.
pub const INDEX_DIR: &str = ".vq-index";

/// Result of [`Logger::log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOutcome {
    /// The entry was appended to this file.
    Written(PathBuf),
    /// This (`id`, `rev`) was already logged in today's file.
    Duplicate,
    /// Partials are never logged.
    SkippedPartial,
}

/// A failed log write (surfaced as a warning event, never a panic).
#[derive(Debug, thiserror::Error)]
#[error("cannot write log file {path}: {source}")]
pub struct LogError {
    /// File that could not be written.
    pub path: PathBuf,
    /// Underlying error.
    #[source]
    pub source: io::Error,
}

#[derive(Debug)]
struct DayIndex {
    date: NaiveDate,
    seen: HashSet<(Uuid, u32)>,
    /// The on-disk index was read (or does not exist).
    loaded: bool,
    /// A read failure was already reported for this day.
    warned: bool,
}

impl DayIndex {
    fn new(date: NaiveDate) -> Self {
        Self {
            date,
            seen: HashSet::new(),
            loaded: false,
            warned: false,
        }
    }
}

/// The daily Markdown logger.
#[derive(Debug)]
pub struct Logger {
    dir: PathBuf,
    /// Index of the day last written to, and of the day before it.
    today: Option<DayIndex>,
    prev: Option<DayIndex>,
    warnings: Vec<String>,
    index_write_warned: bool,
}

impl Logger {
    /// A logger writing into `dir` (created on first write).
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            today: None,
            prev: None,
            warnings: Vec::new(),
            index_write_warned: false,
        }
    }

    /// Current log directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Switch to another directory; its dedupe indexes are loaded lazily.
    pub fn set_dir(&mut self, dir: PathBuf) {
        self.dir = dir;
        self.today = None;
        self.prev = None;
        self.index_write_warned = false;
    }

    /// Non-fatal problems (unreadable or unwritable index) since the last
    /// call.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    /// Path of the day file for `date`.
    pub fn day_file(&self, date: NaiveDate) -> PathBuf {
        self.dir.join(format!("{}.md", date.format("%Y-%m-%d")))
    }

    fn index_file(&self, date: NaiveDate) -> PathBuf {
        self.dir
            .join(INDEX_DIR)
            .join(format!("{}.idx", date.format("%Y-%m-%d")))
    }

    fn select_day(&mut self, date: NaiveDate) {
        if self.today.as_ref().is_some_and(|d| d.date == date) {
            return;
        }
        let yesterday = date.pred_opt();
        let old_today = self.today.take();
        let old_prev = self.prev.take();
        self.prev = [old_today, old_prev]
            .into_iter()
            .flatten()
            .find(|d| Some(d.date) == yesterday)
            .or_else(|| yesterday.map(DayIndex::new));
        self.today = Some(DayIndex::new(date));
    }

    fn load_pending(&mut self) {
        for slot in [&mut self.today, &mut self.prev] {
            let Some(day) = slot.as_mut() else { continue };
            if day.loaded {
                continue;
            }
            let path = self
                .dir
                .join(INDEX_DIR)
                .join(format!("{}.idx", day.date.format("%Y-%m-%d")));
            match read_index(&path) {
                Ok(set) => {
                    day.seen.extend(set);
                    day.loaded = true;
                }
                // A missing or blocked directory: the write path reports
                // it; just retry the read next time.
                Err(e) if e.kind() == io::ErrorKind::NotADirectory => {}
                Err(e) => {
                    if !day.warned {
                        day.warned = true;
                        self.warnings.push(format!(
                            "cannot read log index {} (duplicates may be logged): {e}",
                            path.display()
                        ));
                    }
                }
            }
        }
    }

    fn is_duplicate(&self, key: &(Uuid, u32)) -> bool {
        [&self.today, &self.prev]
            .into_iter()
            .flatten()
            .any(|d| d.seen.contains(key))
    }

    /// Log one accepted `final`/`edit` that arrived at `arrived` (local time).
    pub fn log(
        &mut self,
        utt: &Utt,
        device_name: &str,
        arrived: DateTime<FixedOffset>,
    ) -> Result<LogOutcome, LogError> {
        if utt.state == UttState::Partial {
            return Ok(LogOutcome::SkippedPartial);
        }
        let date = arrived.date_naive();
        self.select_day(date);
        self.load_pending();
        let key = (utt.id, utt.rev);
        if self.is_duplicate(&key) {
            return Ok(LogOutcome::Duplicate);
        }
        let path = self.day_file(date);
        let entry = format_entry(
            &arrived.format("%H:%M:%S").to_string(),
            device_name,
            &utt.id,
            utt.state == UttState::Edit,
            &utt.text,
        );
        append_entry(&self.dir, &path, date, &entry).map_err(|source| LogError {
            path: path.clone(),
            source,
        })?;
        if let Some(d) = self.today.as_mut() {
            d.seen.insert(key);
        }
        let idx = self.index_file(date);
        match append_index(&idx, &utt.id, utt.rev) {
            Ok(()) => self.index_write_warned = false,
            Err(e) => {
                if !self.index_write_warned {
                    self.index_write_warned = true;
                    self.warnings.push(format!(
                        "cannot write log index {} (deduplicating in memory only): {e}",
                        idx.display()
                    ));
                }
            }
        }
        Ok(LogOutcome::Written(path))
    }
}

/// Read an index file. A missing file is an empty index; unparseable
/// lines (torn, non-UTF-8, garbage) are skipped.
fn read_index(path: &Path) -> io::Result<HashSet<(Uuid, u32)>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(e),
    };
    Ok(bytes
        .split(|b| *b == b'\n')
        .filter_map(parse_index_line)
        .collect())
}

fn parse_index_line(line: &[u8]) -> Option<(Uuid, u32)> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    let (id, rev) = (parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    Some((Uuid::parse_str(id).ok()?, rev.parse::<u32>().ok()?))
}

/// `# Ventriloquist — YYYY-MM-DD` followed by a blank line.
pub fn format_header(date: NaiveDate) -> String {
    format!("# Ventriloquist — {}\n\n", date.format("%Y-%m-%d"))
}

/// One log entry, exactly as appended (ends with a newline).
pub fn format_entry(time: &str, device_name: &str, id: &Uuid, edited: bool, text: &str) -> String {
    let hex = id.simple().to_string();
    let mut out = format!(
        "- **{time}** · {} · `id={}`{}\n",
        inert(device_name, true),
        &hex[..8],
        if edited { " · edited" } else { "" }
    );
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        out.push_str("  ");
        out.push_str(&inert(line, false));
        out.push('\n');
    }
    out
}

fn needs_escape(c: char) -> bool {
    (c.is_control() && c != '\t')
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{2028}'
                | '\u{2029}'
        )
}

/// Escape characters that could act on a terminal or reorder text.
/// `escape_tab` also escapes TAB (used for the single-line device name).
pub fn inert(s: &str, escape_tab: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if needs_escape(c) || (escape_tab && c == '\t') {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn append_entry(dir: &Path, path: &Path, date: NaiveDate, entry: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;
    let len = f.metadata()?.len();
    let mut buf = String::new();
    if len == 0 {
        buf.push_str(&format_header(date));
    } else {
        // Keep the structure intact if the file was edited by hand and no
        // longer ends with a newline.
        f.seek(SeekFrom::End(-1))?;
        let mut last = [0u8; 1];
        f.read_exact(&mut last)?;
        if last[0] != b'\n' {
            buf.push('\n');
        }
    }
    buf.push_str(entry);
    f.write_all(buf.as_bytes())?;
    f.flush()?;
    // The index line is appended only once the entry is durable, so a
    // power loss cannot leave an index record for a missing entry.
    f.sync_data()?;
    Ok(())
}

fn append_index(idx: &Path, id: &Uuid, rev: u32) -> io::Result<()> {
    if let Some(parent) = idx.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(idx)?;
    let mut line = String::new();
    if f.metadata()?.len() > 0 {
        // A torn last line (crash mid-append) must not swallow this record.
        f.seek(SeekFrom::End(-1))?;
        let mut last = [0u8; 1];
        f.read_exact(&mut last)?;
        if last[0] != b'\n' {
            line.push('\n');
        }
    }
    line.push_str(&format!("{} {}\n", id.hyphenated(), rev));
    f.write_all(line.as_bytes())?;
    f.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(s).unwrap()
    }

    fn utt(id: Uuid, rev: u32, state: UttState, text: &str) -> Utt {
        Utt {
            id,
            rev,
            state,
            text: text.into(),
            ts: 0,
        }
    }

    const ID: &str = "1a2b3c4d-0000-4000-8000-000000000000";

    #[test]
    fn exact_format_final_then_edit() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = Logger::new(dir.path().join("logs"));
        let id = Uuid::parse_str(ID).unwrap();
        let t = at("2026-10-03T14:03:22+02:00");
        assert!(matches!(
            l.log(
                &utt(id, 1, UttState::Final, "kubectl get pods\nsecond line"),
                "Jon's iPhone",
                t
            )
            .unwrap(),
            LogOutcome::Written(_)
        ));
        l.log(
            &utt(id, 2, UttState::Edit, "kubectl get pods -A"),
            "Jon's iPhone",
            at("2026-10-03T14:05:00+02:00"),
        )
        .unwrap();
        let s = fs::read_to_string(dir.path().join("logs/2026-10-03.md")).unwrap();
        assert_eq!(
            s,
            "# Ventriloquist — 2026-10-03\n\n\
             - **14:03:22** · Jon's iPhone · `id=1a2b3c4d`\n  kubectl get pods\n  second line\n\
             - **14:05:00** · Jon's iPhone · `id=1a2b3c4d` · edited\n  kubectl get pods -A\n"
        );
    }

    #[test]
    fn partials_never_logged_and_duplicates_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = Logger::new(dir.path().to_path_buf());
        let id = Uuid::new_v4();
        let t = at("2026-10-03T10:00:00+00:00");
        assert_eq!(
            l.log(&utt(id, 0, UttState::Partial, "x"), "P", t).unwrap(),
            LogOutcome::SkippedPartial
        );
        assert!(!dir.path().join("2026-10-03.md").exists());
        l.log(&utt(id, 1, UttState::Final, "x"), "P", t).unwrap();
        assert_eq!(
            l.log(&utt(id, 1, UttState::Final, "x"), "P", t).unwrap(),
            LogOutcome::Duplicate
        );
        let s = fs::read_to_string(dir.path().join("2026-10-03.md")).unwrap();
        assert_eq!(s.matches("- **").count(), 1);
    }

    #[test]
    fn dedupe_survives_restart_and_midnight() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let t = at("2026-10-03T23:59:00+00:00");
        Logger::new(dir.path().into())
            .log(&utt(id, 1, UttState::Final, "a"), "P", t)
            .unwrap();
        let mut l2 = Logger::new(dir.path().into());
        assert_eq!(
            l2.log(&utt(id, 1, UttState::Final, "a"), "P", t).unwrap(),
            LogOutcome::Duplicate
        );
        // a higher revision is new
        assert!(matches!(
            l2.log(&utt(id, 2, UttState::Edit, "b"), "P", t).unwrap(),
            LogOutcome::Written(_)
        ));
        // next day: the previous day's index still dedupes (A4) …
        let t2 = at("2026-10-04T00:00:01+00:00");
        assert_eq!(
            l2.log(&utt(id, 1, UttState::Final, "a"), "P", t2).unwrap(),
            LogOutcome::Duplicate
        );
        // … also after a restart …
        assert_eq!(
            Logger::new(dir.path().into())
                .log(&utt(id, 2, UttState::Edit, "b"), "P", t2)
                .unwrap(),
            LogOutcome::Duplicate
        );
        // … but not two days later.
        let t3 = at("2026-10-05T00:00:01+00:00");
        let w = l2.log(&utt(id, 1, UttState::Final, "a"), "P", t3).unwrap();
        assert_eq!(w, LogOutcome::Written(dir.path().join("2026-10-05.md")));
        let s = fs::read_to_string(dir.path().join("2026-10-05.md")).unwrap();
        assert!(s.starts_with("# Ventriloquist — 2026-10-05\n\n"));
    }

    #[test]
    fn local_date_of_arrival_picks_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = Logger::new(dir.path().into());
        // 2026-10-03 23:30 at UTC-5 is 2026-10-04 in UTC; local date wins.
        let t = at("2026-10-03T23:30:00-05:00");
        l.log(&utt(Uuid::new_v4(), 0, UttState::Final, "x"), "P", t)
            .unwrap();
        assert!(dir.path().join("2026-10-03.md").exists());
        assert!(!dir.path().join("2026-10-04.md").exists());
    }

    #[test]
    fn text_is_inert_and_indented() {
        let id = Uuid::parse_str(ID).unwrap();
        let e = format_entry(
            "01:02:03",
            "Evil\nName\u{1b}[31m",
            &id,
            false,
            "- **00:00:00** · fake · `id=deadbeef`\r\n\u{1b}]0;title\u{7}\r\nrtl\u{202E}txt\u{2028}\ttab\n\n",
        );
        assert_eq!(
            e,
            "- **01:02:03** · Evil\\u{a}Name\\u{1b}[31m · `id=1a2b3c4d`\n\
             \x20 - **00:00:00** · fake · `id=deadbeef`\n\
             \x20 \\u{1b}]0;title\\u{7}\n\
             \x20 rtl\\u{202e}txt\\u{2028}\ttab\n\
             \x20 \n\
             \x20 \n"
        );
        assert_eq!(inert("a\rb\u{85}\u{7f}", false), "a\\u{d}b\\u{85}\\u{7f}");
        // every line after the first is indented: no line can start at column 0
        assert!(e.lines().skip(1).all(|l| l.starts_with("  ")));
    }

    #[test]
    fn empty_text_still_one_indented_line() {
        let e = format_entry("01:02:03", "P", &Uuid::parse_str(ID).unwrap(), true, "");
        assert_eq!(e, "- **01:02:03** · P · `id=1a2b3c4d` · edited\n  \n");
    }

    #[test]
    fn appends_newline_if_file_was_hand_edited() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("2026-10-03.md"),
            "# Ventriloquist — 2026-10-03\n\nnote",
        )
        .unwrap();
        let mut l = Logger::new(dir.path().into());
        l.log(
            &utt(Uuid::parse_str(ID).unwrap(), 0, UttState::Final, "x"),
            "P",
            at("2026-10-03T01:00:00+00:00"),
        )
        .unwrap();
        let s = fs::read_to_string(dir.path().join("2026-10-03.md")).unwrap();
        assert!(
            s.ends_with("note\n- **01:00:00** · P · `id=1a2b3c4d`\n  x\n"),
            "{s}"
        );
    }

    #[test]
    fn write_failure_is_an_error_not_a_panic_and_a_new_dir_works() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        fs::write(&blocker, b"file").unwrap();
        let mut l = Logger::new(blocker.join("logs"));
        let u = utt(Uuid::new_v4(), 0, UttState::Final, "x");
        let t = at("2026-10-03T01:00:00+00:00");
        assert!(l.log(&u, "P", t).is_err());
        // after fixing the directory, the same (id, rev) is still logged
        l.set_dir(dir.path().join("ok"));
        assert!(matches!(l.log(&u, "P", t).unwrap(), LogOutcome::Written(_)));
    }

    #[test]
    fn unwritable_index_dedupes_in_memory_and_warns_once() {
        let dir = tempfile::tempdir().unwrap();
        // `.vq-index` is a file: the index can be neither read nor written.
        fs::write(dir.path().join(INDEX_DIR), b"").unwrap();
        let mut l = Logger::new(dir.path().into());
        let t = at("2026-10-03T10:00:00+00:00");
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(matches!(
            l.log(&utt(a, 0, UttState::Final, "x"), "P", t).unwrap(),
            LogOutcome::Written(_)
        ));
        l.log(&utt(b, 0, UttState::Final, "y"), "P", t).unwrap();
        let w = l.take_warnings();
        assert_eq!(
            w.iter().filter(|m| m.contains("cannot write")).count(),
            1,
            "{w:?}"
        );
        assert_eq!(
            l.log(&utt(a, 0, UttState::Final, "x"), "P", t).unwrap(),
            LogOutcome::Duplicate
        );
    }

    #[test]
    fn index_parsing_skips_garbage() {
        assert_eq!(parse_index_line(b"\xff\xfe 1"), None);
        assert_eq!(parse_index_line(b"1a2b3c4d-0000-40"), None);
        assert_eq!(parse_index_line(&format!("{ID} 1 extra").into_bytes()), None);
        assert_eq!(
            parse_index_line(&format!("{ID} 7").into_bytes()),
            Some((Uuid::parse_str(ID).unwrap(), 7))
        );
    }
}
