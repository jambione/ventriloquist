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
//! * **Dedupe across restarts.** The Markdown line only carries an 8-digit id
//!   prefix and no revision, so it cannot identify (`id`, `rev`) by itself.
//!   Each day file therefore has a sidecar index
//!   `<log_dir>/.vq-index/YYYY-MM-DD.idx` with one `<uuid> <rev>` line per
//!   logged entry, appended *after* the Markdown entry is flushed. On the
//!   first write of a day (and after a log-dir change) the index is loaded,
//!   so a duplicate (`id`, `rev`) delivered after a restart, on the same day
//!   file, is not logged again. A crash between the two appends can at worst
//!   log one entry twice; it never loses one. Dedupe is per day file, as the
//!   spec scopes it.
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
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
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

/// The daily Markdown logger.
#[derive(Debug)]
pub struct Logger {
    dir: PathBuf,
    /// Day whose index is loaded in `seen`.
    day: Option<NaiveDate>,
    seen: HashSet<(Uuid, u32)>,
}

impl Logger {
    /// A logger writing into `dir` (created on first write).
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            day: None,
            seen: HashSet::new(),
        }
    }

    /// Current log directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Switch to another directory; its dedupe index is loaded lazily.
    pub fn set_dir(&mut self, dir: PathBuf) {
        self.dir = dir;
        self.day = None;
        self.seen.clear();
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

    fn load_day(&mut self, date: NaiveDate) {
        if self.day == Some(date) {
            return;
        }
        self.seen.clear();
        if let Ok(f) = fs::File::open(self.index_file(date)) {
            for line in io::BufReader::new(f).lines().map_while(Result::ok) {
                let mut parts = line.split_whitespace();
                if let (Some(id), Some(rev)) = (parts.next(), parts.next()) {
                    if let (Ok(id), Ok(rev)) = (Uuid::parse_str(id), rev.parse::<u32>()) {
                        self.seen.insert((id, rev));
                    }
                }
            }
        }
        self.day = Some(date);
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
        self.load_day(date);
        if self.seen.contains(&(utt.id, utt.rev)) {
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
        self.seen.insert((utt.id, utt.rev));
        let idx = self.index_file(date);
        append_index(&idx, &utt.id, utt.rev).map_err(|source| LogError { path: idx, source })?;
        Ok(LogOutcome::Written(path))
    }
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
    Ok(())
}

fn append_index(idx: &Path, id: &Uuid, rev: u32) -> io::Result<()> {
    if let Some(parent) = idx.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().append(true).create(true).open(idx)?;
    f.write_all(format!("{} {}\n", id.hyphenated(), rev).as_bytes())?;
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
    fn dedupe_survives_restart_same_day_only() {
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
        // next day file: dedupe is per day file
        let t2 = at("2026-10-04T00:00:01+00:00");
        let w = l2.log(&utt(id, 1, UttState::Final, "a"), "P", t2).unwrap();
        assert_eq!(w, LogOutcome::Written(dir.path().join("2026-10-04.md")));
        let s = fs::read_to_string(dir.path().join("2026-10-04.md")).unwrap();
        assert!(s.starts_with("# Ventriloquist — 2026-10-04\n\n"));
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
    fn write_failure_is_an_error_not_a_panic_and_is_retried() {
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
}
