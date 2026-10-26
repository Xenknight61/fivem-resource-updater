//! Completed Undo receipts derived from immutable committed transaction evidence.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedUndoReceipt {
    parent_transaction: Sha256Digest,
    transaction: Sha256Digest,
    previous_context: Option<Sha256Digest>,
    preserved: usize,
}
impl TrustedUndoReceipt {
    pub fn parent_transaction_id(&self) -> &Sha256Digest {
        &self.parent_transaction
    }
    pub fn transaction_id(&self) -> &Sha256Digest {
        &self.transaction
    }
    pub fn preserved_changes(&self) -> usize {
        self.preserved
    }
    pub fn fully_reversed(&self) -> bool {
        self.preserved == 0
    }
}

/// Read completed Undo history against a fresh physical installation selection.
/// No JSON hint or additional best-effort post-commit write grants completion.
pub fn inspect_trusted_undo_receipts(
    workspace: &TrustedUpdateWorkspace,
    selection: &TrustedInstalledRecoverySelection,
) -> Result<Vec<TrustedUndoReceipt>> {
    let (installed, key) =
        reopen_fresh_installed_selection(selection.source(), InstalledScanLimits::default())?;
    let receipts = receipts_for_source(workspace, &installed, &key)?;
    causal_head(&receipts)?;
    Ok(receipts)
}
pub(crate) fn trusted_two_way_causal_head(
    workspace: &TrustedUpdateWorkspace,
    installed: &InstalledApplyPlanningSource,
    key: &SafeResourceKey,
) -> Result<Option<Sha256Digest>> {
    causal_head(&receipts_for_source(workspace, installed, key)?)
}
pub(super) fn validate_available_parent(
    source: &TrustedUndoSource,
    installed: &InstalledApplyPlanningSource,
) -> Result<()> {
    let receipts = receipts_for_source(&source.workspace, installed, &source.resource_key)?;
    if receipts
        .iter()
        .any(|receipt| receipt.parent_transaction == source.transaction_id)
        || parent_context(&source.workspace, &source.artifact_id)? != causal_head(&receipts)?
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    Ok(())
}
fn parent_context(
    workspace: &TrustedUpdateWorkspace,
    artifact_id: &Sha256Digest,
) -> Result<Option<Sha256Digest>> {
    let options = TrustedPackageFreeUpdateRecoveryOptions::default();
    let artifact = resolve_exact_artifact(
        workspace,
        artifact_id,
        options.max_artifact_directory_entries,
        options.max_artifacts,
        options.max_artifact_bytes,
        options.max_total_artifact_bytes,
    )?;
    if artifact.undo_descriptor().is_some() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
    }
    match artifact.two_way_descriptor() {
        Some(descriptor) => Ok(descriptor.reconstruct()?.causal_context().copied()),
        None => Ok(None),
    }
}
fn receipts_for_source(
    workspace: &TrustedUpdateWorkspace,
    installed: &InstalledApplyPlanningSource,
    key: &SafeResourceKey,
) -> Result<Vec<TrustedUndoReceipt>> {
    let options = TrustedPackageFreeUpdateRecoveryOptions::default();
    let root =
        TrustedTransactionRoot::try_open_in_workspace(workspace).map_err(map_durable_error)?;
    let scan = crate::scan_trusted_transactions(&root, options.scan)?;
    let mut receipts = Vec::new();
    for candidate in scan.candidates() {
        let transaction_id = candidate
            .proven_plan_id
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let (transaction, namespace) = open_candidate_transaction(&root, &transaction_id)?;
        let envelope =
            verify_recovery_authority_envelope(&transaction).map_err(map_durable_error)?;
        let body = envelope.body();
        if body.transactional_plan_id() != &transaction_id {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        if verify_selected_resource_commitment(key, body.selected_resource_commitment()).is_err()
            || verify_installed_authority_commitment(
                installed,
                key,
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
        let Some(descriptor) = artifact.undo_descriptor() else {
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
        if cursor.last_event != Some(TransactionJournalEvent::Committed) {
            continue;
        }
        let graph = reconstruct_v2_authority(
            workspace,
            &transaction,
            installed,
            key,
            installed.selected_resource_root(),
            &transaction_id,
            options,
        )?;
        if graph.journal_event != TransactionJournalEvent::Committed {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let parent = TrustedUndoSource::reopen_committed_parent(
            workspace,
            installed,
            key,
            &descriptor.parent_transaction_id()?,
            options,
        )?;
        let snapshot = body.to_installed_snapshot().map_err(map_durable_error)?;
        let plan = parent.plan_from_snapshot(&snapshot, descriptor.previous_attempt()?)?;
        if super::attempts::committed_attempt(&parent, installed)? != Some(transaction_id) {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let preserved = plan
            .entries()
            .iter()
            .filter(|entry| entry.disposition() == TrustedUndoDisposition::PreserveChanged)
            .count();
        let (_, after) = open_candidate_transaction(&root, &transaction_id)?;
        let terminal = load_and_validate_journal_chain(
            &journal,
            &transaction_id,
            body.snapshot_a_id(),
            options.recovery.max_journal_records,
        )
        .map_err(map_durable_error)?;
        if terminal.last_event != Some(TransactionJournalEvent::Committed)
            || terminal.previous_id != cursor.previous_id
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        if namespace.transactions_parent_identity != after.transactions_parent_identity
            || namespace.transaction_identity != after.transaction_identity
            || namespace.journal_identity != after.journal_identity
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        receipts.push(TrustedUndoReceipt {
            parent_transaction: *parent.transaction_id(),
            transaction: transaction_id,
            previous_context: parent_context(workspace, parent.artifact_id())?,
            preserved,
        });
    }
    installed.validate_identities().map_err(map_durable_error)?;
    root.revalidate_identity().map_err(map_durable_error)?;
    receipts.sort_by_key(|receipt| receipt.transaction);
    Ok(receipts)
}
fn causal_head(receipts: &[TrustedUndoReceipt]) -> Result<Option<Sha256Digest>> {
    if receipts.is_empty() {
        return Ok(None);
    }
    let all: BTreeSet<_> = receipts.iter().map(|receipt| receipt.transaction).collect();
    if all.len() != receipts.len() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
    }
    let mut children = BTreeMap::new();
    for receipt in receipts {
        if receipt
            .previous_context
            .is_some_and(|previous| previous == receipt.transaction || !all.contains(&previous))
            || children
                .insert(receipt.previous_context, receipt.transaction)
                .is_some()
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
        }
    }
    let mut head = None;
    let mut seen = BTreeSet::new();
    while let Some(next) = children.get(&head) {
        if !seen.insert(*next) {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
        }
        head = Some(*next);
    }
    if seen.len() != receipts.len() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(id: u8, previous: Option<u8>) -> TrustedUndoReceipt {
        TrustedUndoReceipt {
            parent_transaction: Sha256Digest::new([id + 10; 32]),
            transaction: Sha256Digest::new([id; 32]),
            previous_context: previous.map(|value| Sha256Digest::new([value; 32])),
            preserved: 0,
        }
    }
    #[test]
    fn receipt_head_requires_one_complete_acyclic_nonbranching_lineage() {
        assert_eq!(causal_head(&[]).unwrap(), None);
        assert_eq!(
            causal_head(&[receipt(2, Some(1)), receipt(1, None)]).unwrap(),
            Some(Sha256Digest::new([2; 32]))
        );
        for invalid in [
            vec![receipt(1, None), receipt(2, None)],
            vec![receipt(1, None), receipt(2, Some(1)), receipt(3, Some(1))],
            vec![receipt(1, Some(2)), receipt(2, Some(1))],
            vec![receipt(1, Some(1))],
            vec![receipt(1, Some(9))],
            vec![receipt(1, None), receipt(1, None)],
        ] {
            assert!(causal_head(&invalid).is_err());
        }
    }
}
