//! Validated predecessor identities for explicit Undo retries. No evidence is deleted.
use super::*;

struct Attempt {
    id: Sha256Digest,
    previous: Option<Sha256Digest>,
    event: TransactionJournalEvent,
}

pub(super) fn previous_attempt(
    source: &TrustedUndoSource,
    installed: &InstalledApplyPlanningSource,
    ignore_current: Option<&Sha256Digest>,
) -> Result<Option<Sha256Digest>> {
    match attempt_head(&load_attempts(source, installed, ignore_current)?)? {
        Some(attempt) if attempt.event == TransactionJournalEvent::Committed => {
            Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)
        }
        Some(attempt) => Ok(Some(attempt.id)),
        None => Ok(None),
    }
}

pub(super) fn committed_attempt(
    source: &TrustedUndoSource,
    installed: &InstalledApplyPlanningSource,
) -> Result<Option<Sha256Digest>> {
    Ok(attempt_head(&load_attempts(source, installed, None)?)?
        .filter(|attempt| attempt.event == TransactionJournalEvent::Committed)
        .map(|attempt| attempt.id))
}

fn load_attempts(
    source: &TrustedUndoSource,
    installed: &InstalledApplyPlanningSource,
    ignore_current: Option<&Sha256Digest>,
) -> Result<Vec<Attempt>> {
    let options = TrustedPackageFreeUpdateRecoveryOptions::default();
    let workspace = &source.workspace;
    let key = &source.resource_key;
    let root =
        TrustedTransactionRoot::try_open_in_workspace(workspace).map_err(map_durable_error)?;
    let scan = crate::scan_trusted_transactions(&root, options.scan)?;
    let mut attempts = Vec::new();
    for candidate in scan.candidates() {
        let id = candidate
            .proven_plan_id
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if ignore_current == Some(&id) {
            continue;
        }
        let (transaction, namespace) = open_candidate_transaction(&root, &id)?;
        let envelope =
            verify_recovery_authority_envelope(&transaction).map_err(map_durable_error)?;
        let body = envelope.body();
        if body.transactional_plan_id() != &id {
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
        if descriptor.parent_transaction_id()? != source.transaction_id {
            continue;
        }
        if descriptor.parent_artifact_id()? != source.artifact_id
            || descriptor.parent_authority_id()? != source.authority_id
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let graph = reconstruct_v2_authority(
            workspace,
            &transaction,
            installed,
            key,
            installed.selected_resource_root(),
            &id,
            options,
        )?;
        if !matches!(
            graph.journal_event,
            TransactionJournalEvent::RolledBack
                | TransactionJournalEvent::AbortedBeforeMutation
                | TransactionJournalEvent::Committed
        ) {
            return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
        }
        let journal = open_child_dir(&transaction, "journal").map_err(map_durable_error)?;
        let cursor = load_and_validate_journal_chain(
            &journal,
            &id,
            body.snapshot_a_id(),
            options.recovery.max_journal_records,
        )
        .map_err(map_durable_error)?;
        if cursor.last_event != Some(graph.journal_event) {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let (_, after) = open_candidate_transaction(&root, &id)?;
        let terminal = load_and_validate_journal_chain(
            &journal,
            &id,
            body.snapshot_a_id(),
            options.recovery.max_journal_records,
        )
        .map_err(map_durable_error)?;
        if namespace.transactions_parent_identity != after.transactions_parent_identity
            || namespace.transaction_identity != after.transaction_identity
            || namespace.journal_identity != after.journal_identity
            || terminal.last_event != cursor.last_event
            || terminal.previous_id != cursor.previous_id
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        attempts.push(Attempt {
            id,
            previous: descriptor.previous_attempt()?,
            event: graph.journal_event,
        });
    }
    installed.validate_identities().map_err(map_durable_error)?;
    root.revalidate_identity().map_err(map_durable_error)?;
    Ok(attempts)
}

fn attempt_head(attempts: &[Attempt]) -> Result<Option<&Attempt>> {
    let all: BTreeMap<_, _> = attempts
        .iter()
        .map(|attempt| (attempt.id, attempt))
        .collect();
    if all.len() != attempts.len() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
    }
    let mut children = BTreeMap::new();
    for attempt in attempts {
        if !matches!(
            attempt.event,
            TransactionJournalEvent::RolledBack
                | TransactionJournalEvent::AbortedBeforeMutation
                | TransactionJournalEvent::Committed
        ) {
            return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
        }
        if let Some(previous) = attempt.previous {
            let parent = all
                .get(&previous)
                .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
            if previous == attempt.id || parent.event == TransactionJournalEvent::Committed {
                return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
            }
        }
        if children.insert(attempt.previous, attempt).is_some() {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
        }
    }
    let mut head = None;
    let mut tip = None;
    let mut seen = BTreeSet::new();
    while let Some(next) = children.get(&head) {
        if !seen.insert(next.id) {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
        }
        head = Some(next.id);
        tip = Some(*next);
    }
    if seen.len() != attempts.len() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
    }
    Ok(tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn attempt(id: u8, previous: Option<u8>, event: TransactionJournalEvent) -> Attempt {
        Attempt {
            id: Sha256Digest::new([id; 32]),
            previous: previous.map(|value| Sha256Digest::new([value; 32])),
            event,
        }
    }
    #[test]
    fn retry_head_requires_complete_terminal_nonbranching_history_and_never_follows_commit() {
        use TransactionJournalEvent::{AbortedBeforeMutation, Applying, Committed, RolledBack};
        assert!(attempt_head(&[]).unwrap().is_none());
        let valid = [
            attempt(3, Some(2), Committed),
            attempt(1, None, RolledBack),
            attempt(2, Some(1), AbortedBeforeMutation),
        ];
        assert_eq!(
            attempt_head(&valid).unwrap().unwrap().id,
            Sha256Digest::new([3; 32])
        );
        for invalid in [
            vec![attempt(1, None, Applying)],
            vec![attempt(1, None, RolledBack), attempt(2, None, RolledBack)],
            vec![attempt(1, None, Committed), attempt(2, Some(1), RolledBack)],
            vec![
                attempt(1, Some(2), RolledBack),
                attempt(2, Some(1), RolledBack),
            ],
            vec![attempt(1, Some(1), RolledBack)],
            vec![attempt(1, Some(9), RolledBack)],
            vec![attempt(1, None, RolledBack), attempt(1, None, RolledBack)],
        ] {
            assert!(attempt_head(&invalid).is_err());
        }
    }
}
