//! Deterministic ID encoding for Task 23 execution seals and journal records.

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, Result, Sha256Digest};

use super::TransactionJournalEvent;

pub(crate) fn encode_journal_record_id(
    plan_id: &Sha256Digest,
    sequence: u32,
    previous: Option<&Sha256Digest>,
    event: TransactionJournalEvent,
    body_commitment: &Sha256Digest,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-journal-record-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.u64(u64::from(sequence));
    match previous {
        Some(prev) => {
            enc.u8(1);
            enc.digest(prev);
        }
        None => enc.u8(0),
    }
    enc.u8(event_tag(event));
    enc.digest(body_commitment);
    Ok(enc.finish())
}

pub(crate) fn encode_journal_record_v2_id(
    plan_id: &Sha256Digest,
    sequence: u32,
    previous: Option<&Sha256Digest>,
    event: TransactionJournalEvent,
    body_commitment: &Sha256Digest,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-journal-record-v2")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.u64(u64::from(sequence));
    write_optional_digest(&mut enc, previous);
    enc.u8(event_tag(event));
    enc.digest(body_commitment);
    Ok(enc.finish())
}

pub(crate) fn encode_body_commitment(
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    backup_seal: Option<&Sha256Digest>,
    forward_step_ids: &[Sha256Digest],
    rollback_step_ids: &[Sha256Digest],
    verification_seal: Option<&Sha256Digest>,
    commit_seal: Option<&Sha256Digest>,
    rollback_seal: Option<&Sha256Digest>,
    related_step_id: Option<&Sha256Digest>,
    related_entry_id: Option<&Sha256Digest>,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-journal-body-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.digest(snapshot_a);
    write_optional_digest(&mut enc, backup_seal);
    enc.usize(forward_step_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    for id in forward_step_ids {
        enc.digest(id);
    }
    enc.usize(rollback_step_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    for id in rollback_step_ids {
        enc.digest(id);
    }
    write_optional_digest(&mut enc, verification_seal);
    write_optional_digest(&mut enc, commit_seal);
    write_optional_digest(&mut enc, rollback_seal);
    write_optional_digest(&mut enc, related_step_id);
    write_optional_digest(&mut enc, related_entry_id);
    Ok(enc.finish())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_body_v2_commitment(
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    publication_binding_id: &Sha256Digest,
    backup_seal: Option<&Sha256Digest>,
    forward_step_ids: &[Sha256Digest],
    rollback_step_ids: &[Sha256Digest],
    verification_seal: Option<&Sha256Digest>,
    commit_seal: Option<&Sha256Digest>,
    rollback_seal: Option<&Sha256Digest>,
    related_step_id: Option<&Sha256Digest>,
    related_entry_id: Option<&Sha256Digest>,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-journal-body-v2")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.digest(snapshot_a);
    enc.digest(publication_binding_id);
    write_optional_digest(&mut enc, backup_seal);
    enc.usize(forward_step_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    for id in forward_step_ids {
        enc.digest(id);
    }
    enc.usize(rollback_step_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    for id in rollback_step_ids {
        enc.digest(id);
    }
    write_optional_digest(&mut enc, verification_seal);
    write_optional_digest(&mut enc, commit_seal);
    write_optional_digest(&mut enc, rollback_seal);
    write_optional_digest(&mut enc, related_step_id);
    write_optional_digest(&mut enc, related_entry_id);
    Ok(enc.finish())
}

fn write_optional_digest(enc: &mut CanonicalFingerprintEncoder, value: Option<&Sha256Digest>) {
    match value {
        Some(d) => {
            enc.u8(1);
            enc.digest(d);
        }
        None => enc.u8(0),
    }
}

pub(crate) fn encode_backup_seal(
    plan_id: &Sha256Digest,
    entry_ids: &[Sha256Digest],
    entry_content: &[(Sha256Digest, u8, Option<Sha256Digest>, Option<u64>)],
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-backup-seal-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.usize(entry_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    for id in entry_ids {
        enc.digest(id);
    }
    enc.usize(entry_content.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    for (entry_id, kind_tag, digest, len) in entry_content {
        enc.digest(entry_id);
        enc.u8(*kind_tag);
        match (digest, len) {
            (Some(d), Some(l)) => {
                enc.u8(1);
                enc.digest(d);
                enc.u64(*l);
            }
            (None, None) => enc.u8(0),
            _ => {
                return Err(GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure);
            }
        }
    }
    Ok(enc.finish())
}

pub(crate) fn encode_verification_seal(
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    installed_fp: &Sha256Digest,
    desired_fp: &Sha256Digest,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-verification-seal-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.digest(snapshot_a);
    enc.digest(installed_fp);
    enc.digest(desired_fp);
    Ok(enc.finish())
}

pub(crate) fn encode_commit_seal(
    plan_id: &Sha256Digest,
    backup_seal: &Sha256Digest,
    verification_seal: &Sha256Digest,
    last_journal_id: &Sha256Digest,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-commit-seal-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.digest(backup_seal);
    enc.digest(verification_seal);
    enc.digest(last_journal_id);
    Ok(enc.finish())
}

pub(crate) fn encode_rollback_seal(
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    restored_fp: &Sha256Digest,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-rollback-seal-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.digest(snapshot_a);
    enc.digest(restored_fp);
    Ok(enc.finish())
}

pub(crate) fn encode_result_id(
    plan_id: &Sha256Digest,
    final_event: TransactionJournalEvent,
    last_journal_id: &Sha256Digest,
    backup_seal: Option<&Sha256Digest>,
    commit_seal: Option<&Sha256Digest>,
    rollback_seal: Option<&Sha256Digest>,
) -> Result<Sha256Digest> {
    #[cfg(test)]
    if super::hooks::force_result_id_encoding_failure() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure);
    }
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-result-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.u8(event_tag(final_event));
    enc.digest(last_journal_id);
    write_optional_digest(&mut enc, backup_seal);
    write_optional_digest(&mut enc, commit_seal);
    write_optional_digest(&mut enc, rollback_seal);
    Ok(enc.finish())
}

pub(crate) fn event_tag(event: TransactionJournalEvent) -> u8 {
    match event {
        TransactionJournalEvent::Prepared => 0,
        TransactionJournalEvent::BackupEntryCompleted => 1,
        TransactionJournalEvent::BackupComplete => 2,
        TransactionJournalEvent::Applying => 3,
        TransactionJournalEvent::ForwardStepCompleted => 4,
        TransactionJournalEvent::Applied => 5,
        TransactionJournalEvent::Verified => 6,
        TransactionJournalEvent::Committed => 7,
        TransactionJournalEvent::RollingBack => 8,
        TransactionJournalEvent::RollbackStepCompleted => 9,
        TransactionJournalEvent::RolledBack => 10,
        TransactionJournalEvent::RecoveryRequired => 11,
        TransactionJournalEvent::AbortedBeforeMutation => 12,
    }
}

pub(crate) fn event_file_tag(event: TransactionJournalEvent) -> &'static str {
    match event {
        TransactionJournalEvent::Prepared => "prepared",
        TransactionJournalEvent::BackupEntryCompleted => "backup-entry",
        TransactionJournalEvent::BackupComplete => "backup-complete",
        TransactionJournalEvent::Applying => "applying",
        TransactionJournalEvent::ForwardStepCompleted => "forward-step",
        TransactionJournalEvent::Applied => "applied",
        TransactionJournalEvent::Verified => "verified",
        TransactionJournalEvent::Committed => "committed",
        TransactionJournalEvent::RollingBack => "rolling-back",
        TransactionJournalEvent::RollbackStepCompleted => "rollback-step",
        TransactionJournalEvent::RolledBack => "rolled-back",
        TransactionJournalEvent::RecoveryRequired => "recovery-required",
        TransactionJournalEvent::AbortedBeforeMutation => "aborted-before-mutation",
    }
}

#[cfg(test)]
mod v2_fixed_vectors {
    use super::*;

    #[test]
    fn prepared_body_and_record_ids_are_literal() {
        let plan = Sha256Digest::new([0x77; 32]);
        let snapshot = Sha256Digest::from_lowercase_hex(
            "f49b8650ca72d2a9fbcf0d6e68b7ef4ad7b098897d95dd81f34a735f3d79cd6d",
        )
        .unwrap();
        let publication = Sha256Digest::from_lowercase_hex(
            "57e5e30ad8f0a3c5316fc7f4506467b27354845100b1953466a515e4df377fe3",
        )
        .unwrap();
        let body = encode_body_v2_commitment(
            &plan,
            &snapshot,
            &publication,
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            body.to_string(),
            "1ef841aa143ded38e740f979824f0c29b25691d992e800ea3004bae524907854"
        );
        let record =
            encode_journal_record_v2_id(&plan, 0, None, TransactionJournalEvent::Prepared, &body)
                .unwrap();
        assert_eq!(
            record.to_string(),
            "69d9ba77f713e144fec075a98481602ccbb12583146600ba65a9e0850e487a86"
        );
    }
}
