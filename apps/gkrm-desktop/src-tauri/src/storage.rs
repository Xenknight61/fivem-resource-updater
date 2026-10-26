//! What an update leaves behind, and what nothing needs any more.
//!
//! Two things, and both are the size of a package. A *kept package* is a copy of the official ZIP,
//! held so a later update can tell the operator's own work from the developer's without asking
//! them to have held on to it. A *staged copy* is the verified copy an apply writes from, and what
//! a recovery would replay. Nothing has ever removed either — so an operator who updates every
//! month accumulates one of each per version they ever ran, for questions only the most recent are
//! ever asked.
//!
//! Which are still owed to somebody is not a matter of age or count, and the two are decided
//! differently. A kept package is reached for by exactly two things: an installation, whose next
//! update compares against the one it is on, and an undo, which puts an installation back onto the
//! one it came from — both of which this application knows about. A staged copy is reached for by
//! an authority artifact, which only the workspace can read, so that half is asked of the
//! workspace. Anything nothing names is answering a question nobody can ask, and only that is
//! offered for release. Age is not a reason and neither is size: an operator with one old
//! installation would lose the evidence for it.

use std::collections::BTreeSet;
use std::path::Path;

use gkrm_core::{
    catalog_official_baselines, BaselineCatalogRequest, BaselineId, BaselineResolutionOptions,
    SafeResourceKey,
};

use crate::error::{DesktopFailure, DesktopResult};

/// More resources than one machine updates, and a bound on a directory read either way.
const MAX_RESOURCES: usize = 512;

/// One baseline the store is holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldBaseline {
    pub resource: String,
    pub baseline_id: String,
    /// The version that package declared, for saying which one this is.
    pub version: Option<String>,
    /// What its content occupies. The manifest's own accounting, not a walk of the directory.
    pub bytes: u64,
    /// Why it is still kept, or `None` when nothing reaches for it any more.
    pub needed_for: Option<NeededFor>,
}

/// The reason a baseline is still owed to somebody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeededFor {
    /// An installation is on it, so its next update compares against this.
    Installation,
    /// An update can still be put back onto it.
    Undo,
}

impl NeededFor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installation => "installation",
            Self::Undo => "undo",
        }
    }
}

/// Everything the workspace holds, and how much of it is owed to nobody.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageReport {
    pub baselines: Vec<HeldBaseline>,
    pub held_bytes: u64,
    pub releasable_bytes: u64,
    /// Staged copies of packages, which are the other thing an update leaves behind.
    ///
    /// Sized by walking them rather than by a manifest: unlike a baseline, a staged copy keeps no
    /// accounting of its own, and a number nobody measured is not one to show an operator.
    pub staged: StagedCopies,
}

/// The staged copies of packages, counted and sized.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StagedCopies {
    pub count: u32,
    pub bytes: u64,
    /// What a release would actually free of them, measured from the same reading it will act on.
    ///
    /// Zero where the workspace has something outstanding, because then nothing is releasable:
    /// what is outstanding is exactly what a staged copy is kept for.
    pub releasable_bytes: u64,
}

/// Both ways a baseline is still reached for, as identities to match against.
///
/// Keyed by resource as well as by baseline, because the store is keyed that way and a bare
/// identity from one resource must not spare a baseline of another.
fn spoken_for(app_data_root: &Path) -> BTreeSet<(String, String)> {
    let mut wanted = BTreeSet::new();
    for entry in crate::installed_baseline::all(app_data_root) {
        wanted.insert((entry.resource, entry.baseline_id));
    }
    for record in crate::undo::list(app_data_root) {
        if let Some(baseline_id) = record.previous_baseline_id {
            wanted.insert((record.resource, baseline_id));
        }
    }
    wanted
}

/// The resources the store has baselines under.
///
/// Read off the store's own directory rather than off what this application remembers: a resource
/// nothing remembers any more is precisely the one whose baselines nobody will ever ask for, and
/// listing only the remembered ones would hide them forever.
fn resources_in_store(store_root: &Path) -> Vec<SafeResourceKey> {
    let Ok(entries) = std::fs::read_dir(store_root.join("baselines")) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for entry in entries.flatten().take(MAX_RESOURCES) {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // A name the store could not have written is not one of ours to read or to remove.
        if let Ok(key) = SafeResourceKey::parse(name) {
            keys.push(key);
        }
    }
    keys
}

/// How deep a staged copy is walked, and how many files of it are counted.
const MAX_STAGING_DEPTH: usize = 12;
const MAX_STAGING_FILES: usize = 200_000;

/// What the staged copies occupy, walked because nothing else keeps their accounting.
///
/// Best effort throughout: a directory that will not read contributes nothing, because a size is
/// only worth showing when it was actually measured.
fn staged_copies(staging_root: &Path, releasable: &BTreeSet<String>) -> StagedCopies {
    let bundles = staging_root.join("bundles");
    let Ok(entries) = std::fs::read_dir(&bundles) else {
        return StagedCopies::default();
    };
    let mut staged = StagedCopies::default();
    let mut budget = MAX_STAGING_FILES;
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        staged.count = staged.count.saturating_add(1);
        let bytes = walk_bytes(&entry.path(), MAX_STAGING_DEPTH, &mut budget);
        staged.bytes = staged.bytes.saturating_add(bytes);
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| releasable.contains(name))
        {
            staged.releasable_bytes = staged.releasable_bytes.saturating_add(bytes);
        }
    }
    staged
}

/// Which staged copies a release would take, as the workspace itself reads it.
///
/// A workspace that refuses to say — because something is outstanding in it — releases nothing,
/// and an empty answer is the honest way to say so.
pub fn releasable_staged_names(workspace: &gkrm_core::TrustedUpdateWorkspace) -> BTreeSet<String> {
    gkrm_core::unaccounted_trusted_staging_bundles(
        workspace,
        gkrm_core::TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..gkrm_core::TrustedTerminalEvidenceRetirementOptions::default()
        },
    )
    .map(BTreeSet::from_iter)
    .unwrap_or_default()
}

fn walk_bytes(directory: &Path, depth: usize, budget: &mut usize) -> u64 {
    if depth == 0 || *budget == 0 {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return 0;
    };
    let mut total = 0_u64;
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        // Followed links would count bytes that are not here and could walk out of the workspace.
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            total = total.saturating_add(walk_bytes(&entry.path(), depth - 1, budget));
        } else if let Ok(metadata) = entry.metadata() {
            *budget = budget.saturating_sub(1);
            total = total.saturating_add(metadata.len());
            if *budget == 0 {
                break;
            }
        }
    }
    total
}

/// What the workspace holds, said per baseline and totalled.
pub fn report(
    app_data_root: &Path,
    store_root: &Path,
    staging_root: &Path,
    releasable_staged_names: &BTreeSet<String>,
) -> StorageReport {
    let wanted = spoken_for(app_data_root);
    let durable_references = gkrm_core::open_existing_trusted_update_workspace(app_data_root)
        .and_then(|workspace| match workspace {
            Some(workspace) => gkrm_core::referenced_trusted_baselines(&workspace),
            None => Ok(BTreeSet::new()),
        });
    let mut baselines = Vec::new();
    for key in resources_in_store(store_root) {
        let Ok(request) =
            BaselineCatalogRequest::try_new(store_root, &key, BaselineResolutionOptions::default())
        else {
            continue;
        };
        // A catalog that will not read is one this cannot account for, and guessing at what a
        // directory holds is not the basis on which to offer to delete it.
        let Ok(catalog) = catalog_official_baselines(request) else {
            continue;
        };
        for entry in catalog.entries() {
            let baseline_id = entry.baseline_id().as_str().to_string();
            let resource = key.as_str().to_string();
            let durable = durable_references
                .as_ref()
                .map_or(true, |references| references.contains(entry.baseline_id()));
            let needed_for = if durable || wanted.contains(&(resource.clone(), baseline_id.clone()))
            {
                // An installation is the stronger claim and the one worth naming first.
                Some(
                    if crate::installed_baseline::all(app_data_root)
                        .iter()
                        .any(|held| held.resource == resource && held.baseline_id == baseline_id)
                    {
                        NeededFor::Installation
                    } else {
                        NeededFor::Undo
                    },
                )
            } else {
                None
            };
            baselines.push(HeldBaseline {
                resource,
                baseline_id,
                version: entry.resource_version().map(str::to_owned),
                bytes: entry.counts().total_blob_bytes(),
                needed_for,
            });
        }
    }
    baselines.sort_by(|left, right| {
        left.resource
            .cmp(&right.resource)
            .then_with(|| right.bytes.cmp(&left.bytes))
    });
    let held_bytes = baselines.iter().map(|held| held.bytes).sum();
    let releasable_bytes = baselines
        .iter()
        .filter(|held| held.needed_for.is_none())
        .map(|held| held.bytes)
        .sum();
    StorageReport {
        baselines,
        held_bytes,
        releasable_bytes,
        staged: staged_copies(staging_root, releasable_staged_names),
    }
}

/// What one release actually did, counted rather than intended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReleaseOutcome {
    pub released: u32,
    pub bytes: u64,
}

/// Let go of everything the workspace no longer accounts for.
///
/// Two things, and they are decided differently. A kept package is spoken for by an installation
/// or an undo, which this application knows about. A staged copy is spoken for by an authority
/// artifact, which only the workspace can read — so that half is asked of the workspace, and a
/// workspace with recovery outstanding refuses it outright.
///
/// The report is taken again here rather than trusted from the caller: what is owed to somebody
/// can have changed between the screen being drawn and the button being pressed — an update run in
/// the meantime puts an installation onto a baseline that was releasable a moment ago.
pub fn release(
    app_data_root: &Path,
    workspace: &gkrm_core::TrustedUpdateWorkspace,
) -> DesktopResult<ReleaseOutcome> {
    let store_root = workspace.baseline_store();
    let staging_root = workspace.staging_root();
    // Sized before anything goes, from the same reading the removal will act on.
    let going = releasable_staged_names(workspace);
    let report = report(app_data_root, store_root, staging_root, &going);
    let mut outcome = ReleaseOutcome::default();

    // Staged copies are the workspace's own to decide, and it refuses outright where something is
    // outstanding — which is a reason to release nothing at all, not a reason to take the kept
    // packages and say nothing about the rest.
    if !going.is_empty() {
        let staging = gkrm_core::discard_unaccounted_trusted_staging_bundles(
            workspace,
            gkrm_core::TrustedTerminalEvidenceRetirementOptions {
                acknowledged: true,
                ..gkrm_core::TrustedTerminalEvidenceRetirementOptions::default()
            },
        )
        .map_err(|_| DesktopFailure::Internal)?;
        outcome.released = outcome.released.saturating_add(staging.released);
        outcome.bytes = outcome.bytes.saturating_add(report.staged.releasable_bytes);
    }

    for held in report.baselines {
        if held.needed_for.is_some() {
            continue;
        }
        let (Ok(key), Ok(baseline_id)) = (
            SafeResourceKey::parse(&held.resource),
            BaselineId::parse(&held.baseline_id),
        ) else {
            continue;
        };
        // One that will not go is not a failure of the release: the rest still go, and what is
        // reported is what actually left.
        if gkrm_core::discard_unreferenced_trusted_baseline(workspace, &key, &baseline_id)
            .map_err(|_| DesktopFailure::Internal)?
        {
            outcome.released += 1;
            outcome.bytes = outcome.bytes.saturating_add(held.bytes);
        }
    }
    // Nothing left when something should have: reported as a failure rather than as a release of
    // nothing, which would read on the screen as "there was nothing to do".
    if outcome.released == 0 && (report.releasable_bytes > 0 || !going.is_empty()) {
        return Err(DesktopFailure::Internal);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_that_is_not_there_holds_nothing() {
        let temp = tempfile::tempdir().expect("temp");
        let report = report(
            temp.path(),
            &temp.path().join("missing"),
            temp.path(),
            &BTreeSet::new(),
        );
        assert_eq!(report, StorageReport::default());
    }

    #[test]
    fn a_directory_holding_no_baseline_offers_nothing_to_remove() {
        // The listing is what decides which directories may be deleted, so anything it cannot read
        // as a baseline of ours has to fall out of it before the part that removes things. A
        // resource directory with nothing in it is the ordinary shape of that.
        let temp = tempfile::tempdir().expect("temp");
        let baselines = temp.path().join("baselines");
        std::fs::create_dir_all(baselines.join("gksphone")).expect("resource");
        std::fs::write(baselines.join("stray.txt"), b"not ours").expect("file");

        assert_eq!(
            resources_in_store(temp.path())
                .iter()
                .map(|key| key.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["gksphone".to_string()]
        );
        // Read as a resource, and still nothing to report or release: there is no baseline in it.
        let report = report(temp.path(), temp.path(), temp.path(), &BTreeSet::new());
        assert!(report.baselines.is_empty());
        assert_eq!(report.releasable_bytes, 0);
        assert!(baselines.join("gksphone").exists());
    }

    #[test]
    fn a_name_that_would_leave_the_store_is_not_a_resource() {
        // The names come off a directory listing and are joined to a root, so the one property
        // that matters is that none of them can name something outside it.
        for name in ["..", ".", "a/b", "a\\b", ""] {
            assert!(SafeResourceKey::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn an_installation_and_an_undo_both_speak_for_a_baseline() {
        let temp = tempfile::tempdir().expect("temp");
        crate::installed_baseline::record(
            temp.path(),
            crate::installed_baseline::InstalledBaseline {
                installed_root: "C:/one".into(),
                resource: "gksphone".into(),
                baseline_id: "aaa".into(),
                version: Some("2.7.1".into()),
            },
        );
        crate::undo::write(
            temp.path(),
            &crate::undo::UndoRecord {
                id: "abc-123".into(),
                resource: "gksphone".into(),
                installed_root: "C:/one".into(),
                resource_path: Some(String::new()),
                transaction_id: None,
                previous_baseline_id: Some("bbb".into()),
                previous_baseline_version: Some("2.4.2".into()),
                restore: Vec::new(),
                remove: Vec::new(),
            },
        )
        .expect("write");

        let wanted = spoken_for(temp.path());
        assert!(wanted.contains(&("gksphone".to_string(), "aaa".to_string())));
        assert!(wanted.contains(&("gksphone".to_string(), "bbb".to_string())));
        // And nothing else. A baseline of another resource is not spared by a matching identity.
        assert!(!wanted.contains(&("tablet".to_string(), "aaa".to_string())));
        assert_eq!(wanted.len(), 2);
    }

    #[test]
    fn an_undo_that_was_never_told_speaks_for_nothing() {
        let temp = tempfile::tempdir().expect("temp");
        crate::undo::write(
            temp.path(),
            &crate::undo::UndoRecord {
                id: "abc-123".into(),
                resource: "gksphone".into(),
                installed_root: "C:/one".into(),
                resource_path: Some(String::new()),
                transaction_id: None,
                previous_baseline_id: None,
                previous_baseline_version: None,
                restore: Vec::new(),
                remove: Vec::new(),
            },
        )
        .expect("write");
        assert!(spoken_for(temp.path()).is_empty());
    }
}
