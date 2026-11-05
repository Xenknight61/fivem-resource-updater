//! Updating many resources from a folder of packages, without deciding anything for the operator.
//!
//! A batch is nothing but the single-resource update done once per package. Planning is read-only.
//! Applying touches only the updates that need no answer — every editable file either matches the
//! package, was changed by one side only, or is the operator's alone — and leaves the rest for the
//! one-at-a-time flow where a person can answer. Nothing is merged on a guess to make a batch
//! bigger.
//!
//! Each applied update is its own transaction with its own backup, so each can be put back on its
//! own. The first failure stops the batch: what had not been tried is reported as not tried, and
//! nothing is retried.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::{
    apply_two_way_update, inspect_package_resources, preview_two_way_update,
    scan_installed_resources, BaselineId, InstalledScanLimits, ManifestChanges,
    PackageResourceInspectionOptions, SafeResourceKey, TrustedCliUpdateOptions,
    TrustedUpdateWorkspace, TwoWayApplyOutcome, TwoWayApplyRequest, TwoWayBaselineSource,
    TwoWayPlanSummary, TwoWayUpdateMode, TwoWayUpdatePreview, TwoWayUpdateRequest,
};
use crate::{GkrmError, Result, Sha256Digest};

/// What a batch found out about one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchEntryOutcome {
    /// Nothing to answer. Applying it takes what the developer changed and keeps what is yours.
    Ready,
    /// Every file already matches the package.
    AlreadyUpToDate,
    /// Some editable files differ on both sides, or cannot be compared line by line. A person has
    /// to answer these, so the batch leaves them for the single-resource update.
    NeedsReview { review: usize, unmergeable: usize },
    /// No installed resource has the name this package carries.
    NoInstalledResource,
    /// Another package in the batch carries the same resource. Neither is guessed at.
    DuplicatePackage,
    /// The package holds more or fewer than one resource, or one without a usable name.
    NotASingleResource,
    /// An earlier update to this resource is still on record, finished or interrupted. It has to
    /// be closed or recovered from the history first; nothing new starts on top of it.
    BlockedByEarlierUpdate,
    /// The package or the installation could not be read. Nothing more is said here: the reason
    /// can name paths, and the single-resource update will say it properly.
    Unreadable,
}

/// One package and what it would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchPlanEntry {
    package: PathBuf,
    resource: Option<SafeResourceKey>,
    outcome: BatchEntryOutcome,
    summary: Option<TwoWayPlanSummary>,
    installed_version: Option<String>,
    incoming_version: Option<String>,
    manifest_changes: Option<ManifestChanges>,
    plan_id: Option<Sha256Digest>,
    /// The package this resource was last updated from, when the plan could use it. Applying is
    /// planned against the same one, so what was previewed is what is written.
    baseline: Option<BaselineId>,
}

impl BatchPlanEntry {
    pub fn package(&self) -> &Path {
        &self.package
    }

    pub fn resource(&self) -> Option<&SafeResourceKey> {
        self.resource.as_ref()
    }

    pub fn outcome(&self) -> &BatchEntryOutcome {
        &self.outcome
    }

    pub fn summary(&self) -> Option<TwoWayPlanSummary> {
        self.summary
    }

    pub fn installed_version(&self) -> Option<&str> {
        self.installed_version.as_deref()
    }

    pub fn incoming_version(&self) -> Option<&str> {
        self.incoming_version.as_deref()
    }

    pub fn manifest_changes(&self) -> Option<&ManifestChanges> {
        self.manifest_changes.as_ref()
    }

    fn bare(
        package: PathBuf,
        resource: Option<SafeResourceKey>,
        outcome: BatchEntryOutcome,
    ) -> Self {
        Self {
            package,
            resource,
            outcome,
            summary: None,
            installed_version: None,
            incoming_version: None,
            manifest_changes: None,
            plan_id: None,
            baseline: None,
        }
    }
}

/// The result of planning a batch. Entries are ordered by package path so it is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchPlan {
    entries: Vec<BatchPlanEntry>,
}

impl BatchPlan {
    pub fn entries(&self) -> &[BatchPlanEntry] {
        &self.entries
    }

    /// How many entries applying the batch would write.
    pub fn ready_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.outcome == BatchEntryOutcome::Ready)
            .count()
    }
}

type Identified = (
    PathBuf,
    std::result::Result<SafeResourceKey, BatchEntryOutcome>,
);

/// Preview one package, with the evidence of what the resource was installed from when there is
/// some.
///
/// Evidence only ever asks fewer questions, so when it cannot be used the package is previewed as
/// if there were none: a missing or unreadable kept package costs the operator a question, never a
/// refusal. An earlier update on record is the exception, because no evidence can answer that.
fn preview_one(
    package: &Path,
    installed_root: &Path,
    key: &SafeResourceKey,
    workspace: &TrustedUpdateWorkspace,
    remembered: Option<&BaselineId>,
) -> Result<(TwoWayUpdatePreview, Option<BaselineId>)> {
    let preview_with = |baseline: Option<TwoWayBaselineSource<'_>>| {
        preview_two_way_update(TwoWayUpdateRequest {
            package,
            installed: installed_root,
            baseline,
            resource: Some(key),
            transaction_root: workspace.transaction_root(),
            workspace: Some(workspace),
            options: TrustedCliUpdateOptions::default(),
        })
    };
    if let Some(baseline_id) = remembered {
        match preview_with(Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id,
        })) {
            Ok(preview) => return Ok((preview, Some(baseline_id.clone()))),
            Err(GkrmError::TrustedCliUpdateRecoveryRequired) => {
                return Err(GkrmError::TrustedCliUpdateRecoveryRequired)
            }
            Err(_) => {}
        }
    }
    preview_with(None).map(|preview| (preview, None))
}

/// Plan a batch. Reads the installation and every package; writes nothing.
///
/// `remembered` is what each resource was last updated from, by resource name. It lets a file the
/// developer has not touched since stay the operator's, instead of coming back as a question after
/// every update.
pub fn plan_batch(
    installed_root: &Path,
    packages: &[PathBuf],
    workspace: &TrustedUpdateWorkspace,
    remembered: &BTreeMap<String, BaselineId>,
) -> Result<BatchPlan> {
    let installed = scan_installed_resources(installed_root, InstalledScanLimits::default())?;
    let installed_names: BTreeSet<&str> = installed
        .resources
        .iter()
        .map(|resource| resource.name.as_str())
        .collect();

    let mut sorted: Vec<&PathBuf> = packages.iter().collect();
    sorted.sort();
    sorted.dedup();

    // Which resource each package carries, found before anything is previewed so a duplicate is
    // recognised on both sides rather than only the second.
    let mut identified: Vec<Identified> = Vec::new();
    for package in sorted {
        let key =
            match inspect_package_resources(package, PackageResourceInspectionOptions::default()) {
                Err(_) => Err(BatchEntryOutcome::Unreadable),
                Ok(report) => match report.resources() {
                    [only] => only
                        .resource_key()
                        .cloned()
                        .ok_or(BatchEntryOutcome::NotASingleResource),
                    _ => Err(BatchEntryOutcome::NotASingleResource),
                },
            };
        identified.push((package.clone(), key));
    }

    let mut by_key: BTreeMap<String, usize> = BTreeMap::new();
    for (_, key) in &identified {
        if let Ok(key) = key {
            *by_key.entry(key.as_str().to_owned()).or_default() += 1;
        }
    }

    let mut entries = Vec::new();
    for (package, key) in identified {
        let key = match key {
            Ok(key) => key,
            Err(outcome) => {
                entries.push(BatchPlanEntry::bare(package, None, outcome));
                continue;
            }
        };
        if by_key.get(key.as_str()).copied().unwrap_or(0) > 1 {
            entries.push(BatchPlanEntry::bare(
                package,
                Some(key),
                BatchEntryOutcome::DuplicatePackage,
            ));
            continue;
        }
        if !installed_names.contains(key.as_str()) {
            entries.push(BatchPlanEntry::bare(
                package,
                Some(key),
                BatchEntryOutcome::NoInstalledResource,
            ));
            continue;
        }

        let preview = preview_one(
            &package,
            installed_root,
            &key,
            workspace,
            remembered.get(key.as_str()),
        );
        let (preview, baseline) = match preview {
            Ok(previewed) => previewed,
            Err(error) => {
                let outcome = if matches!(error, GkrmError::TrustedCliUpdateRecoveryRequired) {
                    BatchEntryOutcome::BlockedByEarlierUpdate
                } else {
                    BatchEntryOutcome::Unreadable
                };
                entries.push(BatchPlanEntry::bare(package, Some(key), outcome));
                continue;
            }
        };

        let summary = preview.plan().summary();
        let unmergeable = preview.unmergeable_count();
        let outcome = if summary.review() > 0 || unmergeable > 0 {
            BatchEntryOutcome::NeedsReview {
                review: summary.review(),
                unmergeable,
            }
        } else if summary.take_from_update() == 0 {
            BatchEntryOutcome::AlreadyUpToDate
        } else {
            BatchEntryOutcome::Ready
        };
        entries.push(BatchPlanEntry {
            package,
            resource: Some(key),
            outcome,
            summary: Some(summary),
            installed_version: preview.installed_version().map(str::to_owned),
            incoming_version: preview.incoming_version().map(str::to_owned),
            manifest_changes: preview.manifest_changes().cloned(),
            plan_id: Some(*preview.plan().plan_id().digest()),
            baseline,
        });
    }

    Ok(BatchPlan { entries })
}

/// What happened to one entry when a batch was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchApplyResult {
    /// Written, and recorded so it can be put back.
    Committed,
    /// Left alone because it was not `Ready`.
    Skipped,
    /// Tried and not written. The installation for this resource is as it was.
    Failed,
    /// Not tried, because an earlier one failed.
    NotAttempted,
}

/// The per-entry results of applying a batch, in plan order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchApplyOutcome {
    results: Vec<(PathBuf, BatchApplyResult)>,
    /// What each committed update reported, in the same order as `results`. The caller needs it to
    /// record how to put the update back; the batch itself keeps no history.
    applied: Vec<Option<TwoWayApplyOutcome>>,
}

impl BatchApplyOutcome {
    pub fn results(&self) -> &[(PathBuf, BatchApplyResult)] {
        &self.results
    }

    /// What the update for the entry at `index` reported, when it was committed.
    pub fn applied(&self, index: usize) -> Option<&TwoWayApplyOutcome> {
        self.applied.get(index).and_then(Option::as_ref)
    }

    pub fn committed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, result)| *result == BatchApplyResult::Committed)
            .count()
    }
}

/// Apply the `Ready` entries of a plan, one transaction each, stopping at the first failure.
///
/// Each update is applied against the plan identity it was previewed with, so a file that changed
/// between planning and applying fails that entry instead of being written over.
pub fn apply_batch(
    plan: &BatchPlan,
    installed_root: &Path,
    workspace: &TrustedUpdateWorkspace,
) -> BatchApplyOutcome {
    let mut results = Vec::new();
    let mut applied_outcomes = Vec::new();
    let mut stopped = false;
    for entry in plan.entries() {
        let mut kept = None;
        let result = match (&entry.outcome, &entry.resource, &entry.plan_id) {
            (BatchEntryOutcome::Ready, _, _) if stopped => BatchApplyResult::NotAttempted,
            (BatchEntryOutcome::Ready, Some(key), Some(plan_id)) => {
                let applied = apply_two_way_update(TwoWayApplyRequest {
                    expected_plan_id: Some(plan_id),
                    package: &entry.package,
                    installed: installed_root,
                    baseline: entry.baseline.as_ref().map(|baseline_id| {
                        TwoWayBaselineSource::Stored {
                            store_root: workspace.baseline_store(),
                            baseline_id,
                        }
                    }),
                    resource: Some(key),
                    staging_root: workspace.staging_root(),
                    transaction_root: workspace.transaction_root(),
                    mode: TwoWayUpdateMode::PreserveLocalEdits,
                    choices: &[],
                    workspace: Some(workspace),
                    options: TrustedCliUpdateOptions::default(),
                });
                match applied {
                    Ok(outcome) if outcome.outcome() == "committed" => {
                        kept = Some(outcome);
                        BatchApplyResult::Committed
                    }
                    _ => {
                        stopped = true;
                        BatchApplyResult::Failed
                    }
                }
            }
            _ => BatchApplyResult::Skipped,
        };
        results.push((entry.package.clone(), result));
        applied_outcomes.push(kept);
    }
    BatchApplyOutcome {
        results,
        applied: applied_outcomes,
    }
}
