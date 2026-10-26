//! A local record of what the operator asked for and what came of it.
//!
//! Everything this application tells the frontend is deliberately closed: a refused apply reports
//! `update_already_applied` and nothing else, because the frontend is an untrusted page and raw
//! diagnostics have no business crossing to it. That is right, and it leaves an operator whose
//! update was refused with no way to find out why — the only diagnosis available was reading the
//! workspace by hand, which is not something anyone should have to do to their own machine.
//!
//! So the trusted side keeps its own record, beside the workspace it already owns. The boundary
//! this respects is the one between a web page and the operator's files; a file written by Rust,
//! into the operator's own application directory, naming the operator's own paths, is on the
//! operator's side of it.
//!
//! What is never written: file content, merged bytes, and anything escrow protects. Those are the
//! developer's, and a log is not a place to launder them out of a resource.
//!
//! Failing to write costs a line in a log. It never costs an operation: every entry point here
//! swallows its own errors, because an update that worked must not be reported as failed by the
//! thing whose whole job is to say what happened.
//!
//! Every byte written here is ASCII. The file is UTF-8 and correct either way, but this is a
//! support artifact: it gets opened with whatever the operator has, pasted into a message, read
//! over somebody's shoulder. `type` in a console, an older Notepad, and PowerShell's own default
//! read all show `C2 B7` as `Â·`, so a middle dot that is technically right still arrives
//! looking broken — and a log nobody trusts the rendering of is one they stop reading.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use gkrm_core::GkrmError;

const FILE_NAME: &str = "diagnostics.log";
const PREVIOUS_FILE_NAME: &str = "diagnostics.log.1";
/// Rotate past this, keeping one older file: at most twice this on disk, forever.
const MAX_BYTES: u64 = 1024 * 1024;
/// A cause is one line of a log, not a core dump.
const MAX_CAUSE_CHARS: usize = 300;
/// Marks a cause that was cut. Three dots rather than an ellipsis, for the reason below.
const CUT_MARK: &str = "...";

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

thread_local! {
    /// The last core error mapped on this thread, kept until the operation reports its outcome.
    ///
    /// The closed code the operator is shown is the same for a dozen different causes, so logging
    /// it would say no more than the screen already does. The cause is captured where the mapping
    /// happens, which is the last point it still exists.
    static LAST_CAUSE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Say where the log lives, and mark the run. Called once, at startup.
///
/// The line matters for two reasons. A log of operations alone cannot be read across restarts:
/// which run an entry belongs to is exactly the context somebody debugging needs, and it is gone
/// the moment two sessions run together. And an empty file is otherwise indistinguishable from a
/// log that was never wired up at all — a record nobody can tell is working is not one to rely on.
pub fn init(app_data_root: &Path) {
    let _ = LOG_PATH.set(app_data_root.join(FILE_NAME));
    record("start", Outcome::Ok, "");
}

/// Remember why a core call failed, for the operation that is about to report its outcome.
pub fn note_cause(error: &GkrmError) {
    // Sanitized by the core itself: `GkrmError`'s Debug is its Display, deliberately, so that no
    // path or io detail is ever dumped. What arrives here is the reason and nothing else.
    let mut text = format!("{error:?}");
    if text.chars().count() > MAX_CAUSE_CHARS {
        text = text.chars().take(MAX_CAUSE_CHARS).collect::<String>() + CUT_MARK;
    }
    LAST_CAUSE.with(|cause| *cause.borrow_mut() = Some(text));
}

/// Take whatever cause was noted, clearing it.
fn take_cause() -> Option<String> {
    LAST_CAUSE.with(|cause| cause.borrow_mut().take())
}

/// Record one operation and what came of it.
///
/// `detail` is the operation's own summary — counts, versions, whatever it actually did. A cause
/// noted while it ran is appended, because a line saying only "refused" repeats the screen.
pub fn record(operation: &str, outcome: Outcome, detail: &str) {
    let cause = take_cause();
    let Some(path) = LOG_PATH.get() else {
        return;
    };
    append(
        path,
        compose(&timestamp(), operation, outcome, detail, cause).as_bytes(),
    );
}

/// One line, exactly as it is written.
fn compose(
    at: &str,
    operation: &str,
    outcome: Outcome,
    detail: &str,
    cause: Option<String>,
) -> String {
    let mut line = format!(
        "{at}  {}  {operation:<8} {}",
        env!("CARGO_PKG_VERSION"),
        outcome.as_str(),
    );
    if !detail.is_empty() {
        line.push(' ');
        line.push_str(detail);
    }
    // Only where it explains something the outcome does not. A successful operation that happened
    // to map an error on the way is not a failure, and saying so would read as one.
    if outcome != Outcome::Ok {
        if let Some(cause) = cause {
            line.push_str("\n    cause: ");
            line.push_str(&cause);
        }
    }
    line.push('\n');
    // Enforced where the line is built rather than at each thing that goes into it: every caller
    // then gets the guarantee, including ones written later that never read this module's docs.
    line.chars()
        .map(|character| if character.is_ascii() { character } else { '?' })
        .collect()
}

/// What became of one operation, in the operator's terms rather than the code's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// Nothing was written, and the reason is one the operator can act on.
    Refused,
    /// Nothing this could account for.
    Failed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Refused => "REFUSED",
            Self::Failed => "FAILED",
        }
    }
}

fn append(path: &Path, bytes: &[u8]) {
    rotate_if_large(path);
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = file.write_all(bytes);
}

/// Keep the current file and one older one, so a long-lived installation stays bounded.
fn rotate_if_large(path: &Path) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.len() < MAX_BYTES {
        return;
    }
    let previous = path.with_file_name(PREVIOUS_FILE_NAME);
    // Renaming over the older file is the rotation: what it held is what has already been kept
    // longest, and keeping a third would only move the same decision further out.
    let _ = std::fs::rename(path, previous);
}

/// `YYYY-MM-DD HH:MM:SSZ`, UTC.
///
/// The `Z` is not decoration. An operator reads this against their own clock, and in most of the
/// world a bare timestamp that is silently UTC is read as local and is wrong by hours — which is
/// the kind of misreading a log exists to prevent rather than cause.
///
/// Written out rather than taken from a date library: this is the only calendar arithmetic in the
/// application, and a release-audited dependency graph is not worth widening for one line format.
fn timestamp() -> String {
    let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "unknown-time".to_owned();
    };
    let total = since_epoch.as_secs();
    let (days, seconds) = ((total / 86_400) as i64, total % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60,
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a proleptic Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timestamp_says_which_clock_it_is_on() {
        // A bare timestamp that is silently UTC is read as local time and is wrong by hours for
        // most of the world, including where this is used.
        let now = timestamp();
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(now.len(), "2026-08-29 17:40:04Z".len(), "{now}");
    }

    #[test]
    fn the_epoch_and_a_leap_day_convert_exactly() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2024-02-29 is day 19782, and a leap day is where naive date arithmetic goes wrong.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn a_cause_is_taken_once_and_then_gone() {
        // It belongs to the operation that was running when it happened. Left behind, it would be
        // reported against whatever ran next, which is worse than reporting nothing.
        note_cause(&GkrmError::TrustedCliUpdateRecoveryRequired);
        assert!(take_cause().is_some());
        assert!(take_cause().is_none());
    }

    #[test]
    fn every_byte_written_is_ascii() {
        // The bytes are valid UTF-8 either way. The point is that they survive `type`, an older
        // Notepad, and PowerShell's default read, which show C2 B7 as "Â·" — a line that is
        // technically right and arrives looking broken is one the reader stops trusting.
        let line = compose(
            "2026-08-29 19:05:31Z",
            "apply",
            Outcome::Refused,
            "resource gksphone-ü, 569 replaced · 6 reviewed",
            Some("sebep-üç".to_owned()),
        );
        assert!(line.is_ascii(), "{line}");
        assert!(
            line.contains("gksphone-?, 569 replaced ? 6 reviewed"),
            "{line}"
        );
        assert!(line.contains("cause: sebep-??"), "{line}");
    }

    #[test]
    fn a_cause_is_cut_rather_than_written_without_bound() {
        note_cause(&GkrmError::BaselineUnsafeResourceKey {
            value: "x".repeat(10_000),
        });
        let cause = take_cause().expect("noted");
        assert!(cause.chars().count() <= MAX_CAUSE_CHARS + 1, "{cause}");
    }

    #[test]
    fn a_refusal_carries_the_reason_the_screen_could_not() {
        // The whole point. The operator is shown one closed sentence for a dozen different
        // causes; a log that repeated it would have been no help at all.
        let line = compose(
            "2026-08-28 14:02:11",
            "apply",
            Outcome::Refused,
            "UpdateAlreadyApplied after 98.0s",
            Some("TrustedTransactionalApplyExecutionTransactionExists".to_owned()),
        );
        assert!(
            line.starts_with("2026-08-28 14:02:11  1.0.0  apply    REFUSED"),
            "{line}"
        );
        assert!(
            line.contains("cause: TrustedTransactionalApplyExecutionTransactionExists"),
            "{line}"
        );
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn a_success_carries_no_cause_even_when_one_was_noted() {
        // Core errors are mapped on paths that recover from them. Printing one under an operation
        // that succeeded would report a failure that did not happen.
        let line = compose(
            "2026-08-28 13:58:02",
            "compare",
            Outcome::Ok,
            "715 files, 6 to answer in 10.4s",
            Some("BaselineMissingBlob".to_owned()),
        );
        assert!(!line.contains("cause"), "{line}");
        assert_eq!(line.lines().count(), 1, "{line}");
    }

    #[test]
    fn a_run_marks_itself_so_the_lines_under_it_have_an_owner() {
        // Across restarts, which run an entry belongs to is the context a reader needs, and an
        // empty file would otherwise be indistinguishable from one that was never wired up.
        let line = compose("2026-08-29 20:15:00", "start", Outcome::Ok, "", None);
        assert_eq!(line, "2026-08-29 20:15:00  1.0.0  start    OK\n");
    }

    #[test]
    fn writing_without_a_destination_is_not_a_failure() {
        // `init` runs at startup; a test binary and a headless call have not had one.
        record("compare", Outcome::Ok, "715 files");
    }

    #[test]
    fn a_full_log_is_rotated_rather_than_grown() {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join(FILE_NAME);
        std::fs::write(&path, vec![b'x'; MAX_BYTES as usize + 1]).expect("write");
        append(&path, b"after\n");

        assert!(temp.path().join(PREVIOUS_FILE_NAME).exists());
        assert_eq!(std::fs::read(&path).expect("read"), b"after\n");
    }
}
