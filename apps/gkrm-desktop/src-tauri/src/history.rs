//! A record of the updates this operator has run, so the app can show them without being asked.
//!
//! This is a convenience index and nothing more. It is written beside the trusted workspace, never
//! inside it, and it is authority for nothing: what is actually on record comes from the workspace
//! overview, and recovery still binds to the live installation at the moment it runs. Losing this
//! file costs a list on a screen and no safety property at all.
//!
//! It exists because the alternative was making the operator point at a folder again to be told
//! something the application already knew.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{DesktopFailure, DesktopResult};

/// The most updates the list will remember. Older ones fall off the end.
const MAX_ENTRIES: usize = 200;
/// A resource name longer than this is not one; refuse rather than store it.
const MAX_RESOURCE_CHARS: usize = 128;
/// The whole file, so a corrupt or hostile one cannot be read without bound.
const MAX_FILE_BYTES: u64 = 256 * 1024;

const FILE_NAME: &str = "update-history.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateHistoryEntry {
    /// Names this update, so what it would take to put it back can be filed under it.
    ///
    /// Entries written before undo existed have none, and are simply not undoable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// The resource this update was for, by name.
    pub resource: String,
    /// `committed`, `rolled_back`, or whatever the transaction reported.
    pub outcome: String,
    /// Milliseconds since the epoch, as the machine saw it when the update finished.
    pub applied_at_ms: u64,
    /// Files the operator decided, files taken from the update, and the resource's total.
    pub reviewed: u32,
    pub replaced: u32,
    pub total: u32,
    /// What the manifests declared on each side, when they declared exactly one version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HistoryFile {
    #[serde(default)]
    entries: Vec<UpdateHistoryEntry>,
}

fn path_for(app_data_root: &Path) -> PathBuf {
    app_data_root.join(FILE_NAME)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Read the list, newest first. A missing, oversized, or unreadable file is an empty list.
///
/// This never fails the caller: a broken convenience index must not stand between an operator and
/// the workspace state that actually matters.
pub fn list(app_data_root: &Path) -> Vec<UpdateHistoryEntry> {
    let path = path_for(app_data_root);
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Vec::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Vec::new();
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    let Ok(file) = serde_json::from_slice::<HistoryFile>(&bytes) else {
        return Vec::new();
    };
    let mut entries: Vec<UpdateHistoryEntry> = file
        .entries
        .into_iter()
        .filter(|entry| {
            !entry.resource.is_empty()
                && entry.resource.chars().count() <= MAX_RESOURCE_CHARS
                && !entry.outcome.is_empty()
                && entry.outcome.chars().count() <= 64
        })
        .take(MAX_ENTRIES)
        .collect();
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.applied_at_ms));
    entries
}

/// One finished update, as its caller knows it. The time it happened is stamped here.
pub struct RecordedUpdate<'a> {
    pub id: &'a str,
    pub resource: &'a str,
    pub outcome: &'a str,
    pub reviewed: u32,
    pub replaced: u32,
    pub total: u32,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
}

/// Time stamped on an update that was found in the workspace rather than watched as it ran.
///
/// The durable evidence says the update happened; it does not say when, and inventing a
/// plausible moment would read exactly like one that was actually observed.
pub const TIME_NOT_RECORDED: u64 = 0;

/// Record one finished update at the front of the list, as having happened now.
pub fn record(app_data_root: &Path, update: RecordedUpdate<'_>) -> DesktopResult<()> {
    record_at(app_data_root, update, now_ms())
}

/// Record one finished update at an explicit time, or at [`TIME_NOT_RECORDED`] when the time it
/// happened is not something this can honestly claim to know.
pub fn record_at(
    app_data_root: &Path,
    update: RecordedUpdate<'_>,
    applied_at_ms: u64,
) -> DesktopResult<()> {
    if update.resource.is_empty() || update.resource.chars().count() > MAX_RESOURCE_CHARS {
        return Err(DesktopFailure::InvalidRequest);
    }
    let mut entries = list(app_data_root);
    entries.insert(
        0,
        UpdateHistoryEntry {
            id: update.id.to_owned(),
            resource: update.resource.to_owned(),
            outcome: update.outcome.to_owned(),
            applied_at_ms,
            reviewed: update.reviewed,
            replaced: update.replaced,
            total: update.total,
            from_version: update.from_version,
            to_version: update.to_version,
        },
    );
    entries.truncate(MAX_ENTRIES);

    let bytes = serde_json::to_vec_pretty(&HistoryFile { entries })
        .map_err(|_| DesktopFailure::Internal)?;
    let path = path_for(app_data_root);
    let temporary = path.with_extension("json.writing");
    // Written whole and renamed over, so an interrupted write leaves the previous list rather
    // than half of a new one.
    {
        let mut file = std::fs::File::create(&temporary).map_err(|_| DesktopFailure::Internal)?;
        file.write_all(&bytes)
            .map_err(|_| DesktopFailure::Internal)?;
        file.sync_all().map_err(|_| DesktopFailure::Internal)?;
    }
    std::fs::rename(&temporary, &path).map_err(|_| DesktopFailure::Internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn a_missing_list_is_empty_rather_than_an_error() {
        assert!(list(temp().path()).is_empty());
    }

    #[test]
    fn updates_are_listed_newest_first() {
        let dir = temp();
        record(
            dir.path(),
            RecordedUpdate {
                id: "first",
                resource: "gksphone",
                outcome: "committed",
                reviewed: 2,
                replaced: 3,
                total: 7,
                from_version: Some("1.0.0".into()),
                to_version: Some("2.0.0".into()),
            },
        )
        .expect("first");
        record(
            dir.path(),
            RecordedUpdate {
                id: "second",
                resource: "gks-tablet",
                outcome: "committed",
                reviewed: 0,
                replaced: 1,
                total: 4,
                from_version: None,
                to_version: None,
            },
        )
        .expect("second");
        let entries = list(dir.path());
        assert_eq!(entries.len(), 2);
        assert!(entries[0].applied_at_ms >= entries[1].applied_at_ms);
        assert!(entries.iter().any(|entry| entry.resource == "gksphone"));
    }

    #[test]
    fn a_corrupt_list_reads_as_empty_instead_of_failing_the_screen() {
        // The workspace overview is what says whether anything is on record. This file is a
        // convenience, and a broken one must not stand in front of the thing that matters.
        let dir = temp();
        std::fs::write(dir.path().join(FILE_NAME), b"{ not json").expect("write");
        assert!(list(dir.path()).is_empty());
    }

    #[test]
    fn the_list_stops_growing() {
        let dir = temp();
        for index in 0..(MAX_ENTRIES + 5) {
            record(
                dir.path(),
                RecordedUpdate {
                    id: &format!("id-{index}"),
                    resource: &format!("resource-{index}"),
                    outcome: "committed",
                    reviewed: 0,
                    replaced: 0,
                    total: 1,
                    from_version: None,
                    to_version: None,
                },
            )
            .expect("record");
        }
        assert_eq!(list(dir.path()).len(), MAX_ENTRIES);
    }

    #[test]
    fn a_nameless_resource_is_refused() {
        let dir = temp();
        assert!(record(
            dir.path(),
            RecordedUpdate {
                id: "x",
                resource: "",
                outcome: "committed",
                reviewed: 0,
                replaced: 0,
                total: 1,
                from_version: None,
                to_version: None,
            }
        )
        .is_err());
        assert!(record(
            dir.path(),
            RecordedUpdate {
                id: "x",
                resource: &"x".repeat(MAX_RESOURCE_CHARS + 1),
                outcome: "committed",
                reviewed: 0,
                replaced: 0,
                total: 1,
                from_version: None,
                to_version: None,
            }
        )
        .is_err());
    }
}
