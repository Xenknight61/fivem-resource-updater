//! Committed two-way updates discovered from durable core evidence alone.
//!
//! After an apply commits, the desktop writes a JSON locator so its History screen can name what
//! the update did and offer to put it back. That write is best effort and the commit is not: a
//! crash between the two leaves an update that happened and a screen that cannot see it, and
//! therefore cannot offer to undo it. The evidence the apply itself published is enough to find
//! that update again, and finding it again is what this does.
//!
//! Nothing here reads the desktop's records, and nothing here mutates anything. An update is
//! reported only when its own authority, artifact, journal and installation binding all still
//! validate against the installation the caller freshly selected.
use super::undo::{inspect_trusted_undo_receipts, TrustedUndoReceipt};
use super::*;
use crate::TwoWayPlanSummary;

/// One committed forward update, named only by the evidence its apply published.
///
/// There is no timestamp here. The durable evidence does not carry one that is worth trusting,
/// and a list ordered by directory enumeration or by a clock nobody verified would be a
/// chronology this cannot actually prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedTwoWayUpdateRecord {
    transaction: Sha256Digest,
    resource: SafeResourceKey,
    summary: TwoWayPlanSummary,
    undone_by: Option<Sha256Digest>,
    preserved_changes: Option<usize>,
}

impl TrustedTwoWayUpdateRecord {
    /// The committed core transaction. This is the only locator Undo needs.
    pub fn transaction_id(&self) -> &Sha256Digest {
        &self.transaction
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource
    }

    /// What the reviewed plan did, reconstructed from the artifact's own descriptor.
    pub fn summary(&self) -> TwoWayPlanSummary {
        self.summary
    }

    /// The Undo that reversed this update, when one completed.
    pub fn undone_by(&self) -> Option<&Sha256Digest> {
        self.undone_by.as_ref()
    }

    pub fn undone(&self) -> bool {
        self.undone_by.is_some()
    }

    /// Changes that Undo left alone because the operator had made them since. Present only for
    /// an update that was actually undone.
    pub fn preserved_changes(&self) -> Option<usize> {
        self.preserved_changes
    }
}

/// Read committed two-way updates for one freshly selected physical installation.
///
/// The returned order is stable across runs but is not a chronology; see
/// [`TrustedTwoWayUpdateRecord`].
pub fn inspect_trusted_two_way_updates(
    workspace: &TrustedUpdateWorkspace,
    selection: &TrustedInstalledRecoverySelection,
) -> Result<Vec<TrustedTwoWayUpdateRecord>> {
    let receipts = inspect_trusted_undo_receipts(workspace, selection)?;
    let (installed, key) =
        reopen_fresh_installed_selection(selection.source(), InstalledScanLimits::default())?;
    let options = TrustedPackageFreeUpdateRecoveryOptions::default();
    let root =
        TrustedTransactionRoot::try_open_in_workspace(workspace).map_err(map_durable_error)?;
    let scan = crate::scan_trusted_transactions(&root, options.scan)?;
    let mut records: Vec<TrustedTwoWayUpdateRecord> = Vec::new();
    for candidate in scan.candidates() {
        let transaction_id = candidate
            .proven_plan_id
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let (transaction, _) = open_candidate_transaction(&root, &transaction_id)?;
        let envelope =
            verify_recovery_authority_envelope(&transaction).map_err(map_durable_error)?;
        let body = envelope.body();
        if body.transactional_plan_id() != &transaction_id {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        // Another installation's history is not this installation's history.
        if verify_selected_resource_commitment(&key, body.selected_resource_commitment()).is_err()
            || verify_installed_authority_commitment(
                &installed,
                &key,
                body.installed_authority_commitment(),
            )
            .is_err()
        {
            continue;
        }
        let artifact = resolve_exact_artifact(
            workspace,
            envelope.artifact_id(),
            options.max_artifact_directory_entries,
            options.max_artifacts,
            options.max_artifact_bytes,
            options.max_total_artifact_bytes,
        )?;
        // An Undo is a transaction too, and it is not one of the updates being listed.
        if artifact.undo_descriptor().is_some() {
            continue;
        }
        let Some(descriptor) = artifact.two_way_descriptor() else {
            continue;
        };
        let journal = open_child_dir(&transaction, "journal").map_err(map_durable_error)?;
        let cursor = load_and_validate_journal_chain(
            &journal,
            &transaction_id,
            body.snapshot_a_id(),
            options.recovery.max_journal_records,
        )
        .map_err(map_durable_error)?;
        // Anything short of a committed tip is outstanding work for recovery, not history.
        if cursor.last_event != Some(TransactionJournalEvent::Committed) {
            continue;
        }
        let plan = descriptor.reconstruct()?;
        if plan.resource_key() != &key {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let receipt: Option<&TrustedUndoReceipt> = receipts
            .iter()
            .find(|receipt| receipt.parent_transaction_id() == &transaction_id);
        records.push(TrustedTwoWayUpdateRecord {
            transaction: transaction_id,
            resource: plan.resource_key().clone(),
            summary: plan.summary(),
            undone_by: receipt.map(|receipt| *receipt.transaction_id()),
            preserved_changes: receipt.map(TrustedUndoReceipt::preserved_changes),
        });
    }
    records.sort_by_key(|record| record.transaction);
    // One transaction identity names one transaction; two rows for it would mean the scan
    // offered the same evidence twice, and a history that double-counts is not one to show.
    if records
        .windows(2)
        .any(|pair| pair[0].transaction == pair[1].transaction)
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    Ok(records)
}
