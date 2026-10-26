//! What each installation is currently installed from.
//!
//! Telling an operator's own edits from the developer's needs the version they installed, and
//! asking them to have kept a ZIP for it is asking most of them for something they no longer have.
//! An update knows the package it applied, and after it runs that package is exactly what the
//! installation corresponds to — so it is kept, and the next update reaches for it by itself.
//!
//! This holds no content. The package itself lives in the trusted workspace's baseline store,
//! captured and verified there; this is only the note of which one belongs to which installation,
//! and it is authority for nothing. Losing it costs the next update its evidence, which is the
//! state every update was in before any of this existed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "installed-baselines.json";
/// More installations than anyone updates from one machine, and small enough to read whole.
const MAX_ENTRIES: usize = 256;
const MAX_FILE_BYTES: u64 = 512 * 1024;

/// One installation, and what it was last updated from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledBaseline {
    /// The installation root the operator chose, as an absolute path.
    pub installed_root: String,
    /// The resource inside it this belongs to.
    pub resource: String,
    /// The baseline in the workspace store, by the identity it was captured under.
    pub baseline_id: String,
    /// The version that package declared, for saying which one this is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Book {
    #[serde(default)]
    entries: Vec<InstalledBaseline>,
}

fn file_for(app_data_root: &Path) -> PathBuf {
    app_data_root.join(FILE_NAME)
}

/// Read the book, or an empty one.
///
/// A missing, oversized, or unreadable file is an empty book rather than a failure. This is a
/// convenience and never a safety property: an update with no baseline asks the operator about
/// every file they could have edited, which is correct, just longer.
fn read(app_data_root: &Path) -> Book {
    let path = file_for(app_data_root);
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Book::default();
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Book::default();
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return Book::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Every installation this knows what was installed from.
///
/// For deciding what the store still owes anyone: a baseline an installation is on is one a later
/// update will reach for, and throwing it away would cost that update its evidence.
pub fn all(app_data_root: &Path) -> Vec<InstalledBaseline> {
    read(app_data_root).entries
}

/// What this installation is currently installed from, when exactly one entry names it.
///
/// An installation root holding several resources cannot be answered by the root alone, and
/// guessing which of them the operator means is worse than asking them for the package.
pub fn lookup(app_data_root: &Path, installed_root: &Path) -> Option<InstalledBaseline> {
    let wanted = installed_root.to_string_lossy();
    let mut matches = read(app_data_root)
        .entries
        .into_iter()
        .filter(|entry| entry.installed_root == wanted);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

/// Note what this installation is now installed from, replacing what it said before.
///
/// A failure here is not the operator's problem: the update has already run, and the note is a
/// convenience for the next one.
pub fn record(app_data_root: &Path, entry: InstalledBaseline) {
    let mut book = read(app_data_root);
    book.entries
        .retain(|existing| existing.installed_root != entry.installed_root);
    book.entries.push(entry);
    // Oldest first, so the ones dropped are the ones least likely to be updated again.
    if book.entries.len() > MAX_ENTRIES {
        let excess = book.entries.len() - MAX_ENTRIES;
        book.entries.drain(..excess);
    }
    let Ok(bytes) = serde_json::to_vec_pretty(&book) else {
        return;
    };
    let path = file_for(app_data_root);
    if std::fs::create_dir_all(app_data_root).is_err() {
        return;
    }
    // Written beside itself and renamed over, so a reader never sees half a book.
    let temporary = path.with_extension("writing");
    if std::fs::write(&temporary, &bytes).is_err() {
        return;
    }
    let _ = std::fs::rename(&temporary, &path);
}

/// Forget what an installation was installed from.
pub fn forget(app_data_root: &Path, installed_root: &str) {
    let mut book = read(app_data_root);
    let before = book.entries.len();
    book.entries
        .retain(|entry| entry.installed_root != installed_root);
    if book.entries.len() == before {
        return;
    }
    let Ok(bytes) = serde_json::to_vec_pretty(&book) else {
        return;
    };
    let path = file_for(app_data_root);
    let temporary = path.with_extension("writing");
    if std::fs::write(&temporary, &bytes).is_err() {
        return;
    }
    let _ = std::fs::rename(&temporary, &path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(root: &str, id: &str) -> InstalledBaseline {
        InstalledBaseline {
            installed_root: root.into(),
            resource: "gksphone".into(),
            baseline_id: id.into(),
            version: Some("2.7.1".into()),
        }
    }

    #[test]
    fn an_installation_is_remembered_and_then_replaced() {
        let temp = tempfile::tempdir().expect("temp");
        record(temp.path(), entry("C:/one", "aaa"));
        assert_eq!(
            lookup(temp.path(), Path::new("C:/one"))
                .expect("remembered")
                .baseline_id,
            "aaa"
        );

        // A second update of the same installation replaces what it was installed from.
        record(temp.path(), entry("C:/one", "bbb"));
        let remembered = lookup(temp.path(), Path::new("C:/one")).expect("remembered");
        assert_eq!(remembered.baseline_id, "bbb");
        assert_eq!(read(temp.path()).entries.len(), 1);
    }

    #[test]
    fn an_installation_nobody_recorded_is_simply_unknown() {
        let temp = tempfile::tempdir().expect("temp");
        assert!(lookup(temp.path(), Path::new("C:/one")).is_none());
        record(temp.path(), entry("C:/one", "aaa"));
        assert!(lookup(temp.path(), Path::new("C:/two")).is_none());
    }

    #[test]
    fn undoing_an_update_forgets_what_it_installed_from() {
        let temp = tempfile::tempdir().expect("temp");
        record(temp.path(), entry("C:/one", "aaa"));
        forget(temp.path(), "C:/one");
        assert!(lookup(temp.path(), Path::new("C:/one")).is_none());
    }

    #[test]
    fn a_book_that_will_not_read_is_an_empty_one() {
        // It is a convenience, never a safety property. An update with no baseline asks about
        // every file the operator could have edited, which is correct and only longer.
        let temp = tempfile::tempdir().expect("temp");
        std::fs::write(file_for(temp.path()), b"{ not json").expect("write");
        assert!(lookup(temp.path(), Path::new("C:/one")).is_none());
        // And it is replaced rather than fought with.
        record(temp.path(), entry("C:/one", "aaa"));
        assert!(lookup(temp.path(), Path::new("C:/one")).is_some());
    }
}
