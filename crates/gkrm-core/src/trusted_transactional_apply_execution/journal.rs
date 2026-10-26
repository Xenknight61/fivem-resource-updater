//! Append-only hash-linked journal persistence for Task 23.

use std::io::{Read, Write};

use cap_std::fs::Dir as CapDir;
use sha2::{Digest, Sha256};

use crate::baseline::fs_security::{
    create_new_child_dir, create_new_file, open_file_nofollow, verify_regular_file,
};
use crate::baseline::store::{fsync_file, sync_dir};
use crate::{GkrmError, Result, Sha256Digest, TransactionalApplyIoOperation};

use super::id::{
    encode_body_commitment, encode_body_v2_commitment, encode_journal_record_id,
    encode_journal_record_v2_id, event_file_tag, event_tag,
};
use super::TransactionJournalEvent;

pub(crate) const MAX_JOURNAL_RECORD_BYTES: usize = 1_024;
pub(crate) const MAX_JOURNAL_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) struct JournalCursor {
    pub(crate) sequence: u32,
    pub(crate) previous_id: Option<Sha256Digest>,
    pub(crate) forward_completed: Vec<Sha256Digest>,
    pub(crate) rollback_completed: Vec<Sha256Digest>,
    pub(crate) backup_seal: Option<Sha256Digest>,
    pub(crate) verification_seal: Option<Sha256Digest>,
    pub(crate) commit_seal: Option<Sha256Digest>,
    pub(crate) rollback_seal: Option<Sha256Digest>,
    pub(crate) total_journal_bytes: u64,
    pub(crate) record_count: usize,
    pub(crate) last_event: Option<TransactionJournalEvent>,
    pub(crate) publication_binding_id: Option<Sha256Digest>,
}

impl JournalCursor {
    pub(crate) fn new() -> Self {
        Self {
            sequence: 0,
            previous_id: None,
            forward_completed: Vec::new(),
            rollback_completed: Vec::new(),
            backup_seal: None,
            verification_seal: None,
            commit_seal: None,
            rollback_seal: None,
            total_journal_bytes: 0,
            record_count: 0,
            last_event: None,
            publication_binding_id: None,
        }
    }

    pub(crate) fn new_v2(publication_binding_id: Sha256Digest) -> Self {
        Self {
            publication_binding_id: Some(publication_binding_id),
            ..Self::new()
        }
    }
}

pub(crate) struct AppendArgs<'a> {
    pub(crate) plan_id: &'a Sha256Digest,
    pub(crate) snapshot_a: &'a Sha256Digest,
    pub(crate) event: TransactionJournalEvent,
    pub(crate) related_step_id: Option<&'a Sha256Digest>,
    pub(crate) related_entry_id: Option<&'a Sha256Digest>,
    pub(crate) max_journal_bytes: u64,
    pub(crate) max_journal_records: usize,
}

pub(crate) fn ensure_journal_dir(txn_dir: &CapDir) -> Result<CapDir> {
    match try_open(txn_dir, "journal") {
        Ok(Some(dir)) => Ok(dir),
        Ok(None) => create_new_child_dir(txn_dir, "journal").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
        }),
        Err(e) => Err(e),
    }
}

fn try_open(parent: &CapDir, name: &str) -> Result<Option<CapDir>> {
    use crate::baseline::fs_security::try_open_child_dir;
    try_open_child_dir(parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenPublishedTransaction, e))
}

fn write_optional_digest(bytes: &mut Vec<u8>, value: Option<&Sha256Digest>) {
    match value {
        Some(d) => {
            bytes.push(1);
            bytes.extend_from_slice(d.as_bytes());
        }
        None => bytes.push(0),
    }
}

pub(crate) fn append_record(
    journal_dir: &CapDir,
    cursor: &mut JournalCursor,
    args: AppendArgs<'_>,
) -> Result<Sha256Digest> {
    append_record_inner(journal_dir, None, cursor, args, false)
}

/// Append a terminal journal record with durability ordering:
/// write â†’ fsync record â†’ sync journal dir â†’ sync txn dir â†’ reopen â†’ chain validate.
///
/// Caller must precompute all fallible result data first. On success the terminal event is
/// durably validated; the caller returns the prepared public result with no further fallible work.
pub(crate) fn append_terminal_record(
    journal_dir: &CapDir,
    txn_dir: Option<&CapDir>,
    cursor: &mut JournalCursor,
    args: AppendArgs<'_>,
) -> Result<Sha256Digest> {
    if !is_terminal_event(args.event) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    append_record_inner(journal_dir, txn_dir, cursor, args, true)
}

fn append_record_inner(
    journal_dir: &CapDir,
    txn_dir: Option<&CapDir>,
    cursor: &mut JournalCursor,
    args: AppendArgs<'_>,
    terminal: bool,
) -> Result<Sha256Digest> {
    #[cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
    if super::hooks::journal_fault_matches(args.event) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    if cursor.record_count >= args.max_journal_records {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_journal_records",
        });
    }
    let body = encode_cursor_body(cursor, &args)?;
    let record_id = encode_cursor_record_id(cursor, &args, &body)?;

    let mut bytes = Vec::new();
    if cursor.publication_binding_id.is_some() {
        bytes.extend_from_slice(b"gkrm-txn-journal-v2\n");
    } else {
        bytes.extend_from_slice(b"gkrm-txn-journal-v1\n");
    }
    bytes.push(event_tag(args.event));
    bytes.extend_from_slice(&(cursor.sequence.to_be_bytes()));
    bytes.extend_from_slice(args.plan_id.as_bytes());
    if let Some(binding) = cursor.publication_binding_id.as_ref() {
        bytes.extend_from_slice(binding.as_bytes());
    }
    bytes.extend_from_slice(record_id.as_bytes());
    bytes.extend_from_slice(body.as_bytes());
    write_optional_digest(&mut bytes, cursor.previous_id.as_ref());
    write_optional_digest(&mut bytes, args.related_step_id);
    write_optional_digest(&mut bytes, args.related_entry_id);
    // Persist seals so the active reader can recompute body commitments.
    write_optional_digest(&mut bytes, cursor.backup_seal.as_ref());
    write_optional_digest(&mut bytes, cursor.verification_seal.as_ref());
    write_optional_digest(&mut bytes, cursor.commit_seal.as_ref());
    write_optional_digest(&mut bytes, cursor.rollback_seal.as_ref());

    let len = u64::try_from(bytes.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_journal_record_bytes",
        });
    }
    cursor.total_journal_bytes = cursor
        .total_journal_bytes
        .checked_add(len)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    if cursor.total_journal_bytes > args.max_journal_bytes {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_journal_bytes",
        });
    }

    let name = format!("{:08x}-{}.bin", cursor.sequence, event_file_tag(args.event));
    let mut file = create_new_file(journal_dir, &name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::CreateJournalRecord, e))?;
    file.write_all(&bytes)
        .map_err(|e| map_io(TransactionalApplyIoOperation::WriteJournalRecord, e))?;
    #[cfg(test)]
    if terminal && super::hooks::force_journal_record_sync_failure() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
            operation: TransactionalApplyIoOperation::SyncJournalRecord,
            kind: std::io::ErrorKind::Other,
        });
    }
    fsync_file(&file, &name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncJournalRecord, e))?;
    drop(file);

    if terminal {
        // Terminal durability: journal sync â†’ txn sync â†’ reopen â†’ chain validate (last).
        #[cfg(test)]
        if super::hooks::force_journal_dir_sync_failure() {
            return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
                operation: TransactionalApplyIoOperation::SyncJournalDirectory,
                kind: std::io::ErrorKind::Other,
            });
        }
        sync_dir(journal_dir, "journal").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::SyncJournalDirectory, e)
        })?;
        if let Some(txn_dir) = txn_dir {
            #[cfg(test)]
            if super::hooks::force_txn_dir_sync_failure() {
                return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
                    operation: TransactionalApplyIoOperation::SyncInstalledDirectory,
                    kind: std::io::ErrorKind::Other,
                });
            }
            sync_dir(txn_dir, "transaction").map_err(|e| {
                map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
            })?;
        }
        #[cfg(test)]
        if super::hooks::force_journal_reopen_failure() {
            return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
                operation: TransactionalApplyIoOperation::OpenJournalRecord,
                kind: std::io::ErrorKind::Other,
            });
        }
        let got = read_journal_file_bounded(journal_dir, &name)?;
        if got != bytes {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
    } else {
        let got = read_journal_file_bounded(journal_dir, &name)?;
        if got != bytes {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        sync_dir(journal_dir, "journal").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::SyncJournalDirectory, e)
        })?;
    }

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let _ = Sha256Digest::new(hasher.finalize().into());

    cursor.previous_id = Some(record_id);
    cursor.sequence = cursor
        .sequence
        .checked_add(1)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    cursor.record_count = cursor
        .record_count
        .checked_add(1)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    cursor.last_event = Some(args.event);

    #[cfg(test)]
    if terminal && super::hooks::force_journal_chain_validation_failure() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    let validated = load_and_validate_journal_chain(
        journal_dir,
        args.plan_id,
        args.snapshot_a,
        args.max_journal_records,
    )?;
    if validated.sequence != cursor.sequence
        || validated.previous_id != cursor.previous_id
        || validated.forward_completed != cursor.forward_completed
        || validated.rollback_completed != cursor.rollback_completed
        || validated.backup_seal != cursor.backup_seal
        || validated.verification_seal != cursor.verification_seal
        || validated.commit_seal != cursor.commit_seal
        || validated.rollback_seal != cursor.rollback_seal
        || validated.record_count != cursor.record_count
        || validated.last_event != cursor.last_event
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }

    Ok(record_id)
}

fn is_terminal_event(event: TransactionJournalEvent) -> bool {
    matches!(
        event,
        TransactionJournalEvent::Committed
            | TransactionJournalEvent::RolledBack
            | TransactionJournalEvent::RecoveryRequired
            | TransactionJournalEvent::AbortedBeforeMutation
    )
}

fn encode_cursor_body(cursor: &JournalCursor, args: &AppendArgs<'_>) -> Result<Sha256Digest> {
    if let Some(binding) = cursor.publication_binding_id.as_ref() {
        encode_body_v2_commitment(
            args.plan_id,
            args.snapshot_a,
            binding,
            cursor.backup_seal.as_ref(),
            &cursor.forward_completed,
            &cursor.rollback_completed,
            cursor.verification_seal.as_ref(),
            cursor.commit_seal.as_ref(),
            cursor.rollback_seal.as_ref(),
            args.related_step_id,
            args.related_entry_id,
        )
    } else {
        encode_body_commitment(
            args.plan_id,
            args.snapshot_a,
            cursor.backup_seal.as_ref(),
            &cursor.forward_completed,
            &cursor.rollback_completed,
            cursor.verification_seal.as_ref(),
            cursor.commit_seal.as_ref(),
            cursor.rollback_seal.as_ref(),
            args.related_step_id,
            args.related_entry_id,
        )
    }
}

fn encode_cursor_record_id(
    cursor: &JournalCursor,
    args: &AppendArgs<'_>,
    body: &Sha256Digest,
) -> Result<Sha256Digest> {
    if cursor.publication_binding_id.is_some() {
        encode_journal_record_v2_id(
            args.plan_id,
            cursor.sequence,
            cursor.previous_id.as_ref(),
            args.event,
            body,
        )
    } else {
        encode_journal_record_id(
            args.plan_id,
            cursor.sequence,
            cursor.previous_id.as_ref(),
            args.event,
            body,
        )
    }
}

/// Predict the record ID that [`append_record`] will produce for the current cursor state.
pub(crate) fn predict_record_id(
    cursor: &JournalCursor,
    args: &AppendArgs<'_>,
) -> Result<Sha256Digest> {
    let body = encode_cursor_body(cursor, args)?;
    encode_cursor_record_id(cursor, args, &body)
}

#[derive(Debug)]
struct ParsedJournalRecord {
    sequence: u32,
    event: TransactionJournalEvent,
    plan_id: Sha256Digest,
    record_id: Sha256Digest,
    body: Sha256Digest,
    previous_id: Option<Sha256Digest>,
    related_step_id: Option<Sha256Digest>,
    related_entry_id: Option<Sha256Digest>,
    backup_seal: Option<Sha256Digest>,
    verification_seal: Option<Sha256Digest>,
    commit_seal: Option<Sha256Digest>,
    rollback_seal: Option<Sha256Digest>,
    publication_binding_id: Option<Sha256Digest>,
}

fn event_from_tag(tag: u8) -> Result<TransactionJournalEvent> {
    Ok(match tag {
        0 => TransactionJournalEvent::Prepared,
        1 => TransactionJournalEvent::BackupEntryCompleted,
        2 => TransactionJournalEvent::BackupComplete,
        3 => TransactionJournalEvent::Applying,
        4 => TransactionJournalEvent::ForwardStepCompleted,
        5 => TransactionJournalEvent::Applied,
        6 => TransactionJournalEvent::Verified,
        7 => TransactionJournalEvent::Committed,
        8 => TransactionJournalEvent::RollingBack,
        9 => TransactionJournalEvent::RollbackStepCompleted,
        10 => TransactionJournalEvent::RolledBack,
        11 => TransactionJournalEvent::RecoveryRequired,
        12 => TransactionJournalEvent::AbortedBeforeMutation,
        _ => return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid),
    })
}

fn read_optional_digest(bytes: &[u8], offset: &mut usize) -> Result<Option<Sha256Digest>> {
    if *offset >= bytes.len() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    let flag = bytes[*offset];
    *offset = offset
        .checked_add(1)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
    match flag {
        0 => Ok(None),
        1 => {
            let end = offset
                .checked_add(32)
                .ok_or(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
            if end > bytes.len() {
                return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
            }
            let digest = Sha256Digest::new(
                bytes[*offset..end]
                    .try_into()
                    .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
            );
            *offset = end;
            Ok(Some(digest))
        }
        _ => Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid),
    }
}

fn parse_journal_bytes(bytes: &[u8]) -> Result<ParsedJournalRecord> {
    const V1_PREFIX: &[u8] = b"gkrm-txn-journal-v1\n";
    const V2_PREFIX: &[u8] = b"gkrm-txn-journal-v2\n";
    let (prefix, is_v2) = if bytes.starts_with(V1_PREFIX) {
        (V1_PREFIX, false)
    } else if bytes.starts_with(V2_PREFIX) {
        (V2_PREFIX, true)
    } else if recognizable_future_journal_version(bytes) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported);
    } else {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    };
    let mut offset = prefix.len();
    let take = |offset: &mut usize, n: usize| -> Result<&[u8]> {
        let end = offset
            .checked_add(n)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
        if end > bytes.len() {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        let slice = &bytes[*offset..end];
        *offset = end;
        Ok(slice)
    };
    let event = event_from_tag(take(&mut offset, 1)?[0])?;
    let seq_bytes = take(&mut offset, 4)?;
    let sequence = u32::from_be_bytes(
        seq_bytes
            .try_into()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
    );
    let plan_id = Sha256Digest::new(
        take(&mut offset, 32)?
            .try_into()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
    );
    let publication_binding_id = if is_v2 {
        Some(Sha256Digest::new(
            take(&mut offset, 32)?
                .try_into()
                .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
        ))
    } else {
        None
    };
    let record_id = Sha256Digest::new(
        take(&mut offset, 32)?
            .try_into()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
    );
    let body = Sha256Digest::new(
        take(&mut offset, 32)?
            .try_into()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
    );
    let previous_id = read_optional_digest(bytes, &mut offset)?;
    let related_step_id = read_optional_digest(bytes, &mut offset)?;
    let related_entry_id = read_optional_digest(bytes, &mut offset)?;
    let backup_seal = read_optional_digest(bytes, &mut offset)?;
    let verification_seal = read_optional_digest(bytes, &mut offset)?;
    let commit_seal = read_optional_digest(bytes, &mut offset)?;
    let rollback_seal = read_optional_digest(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    Ok(ParsedJournalRecord {
        sequence,
        event,
        plan_id,
        record_id,
        body,
        previous_id,
        related_step_id,
        related_entry_id,
        backup_seal,
        verification_seal,
        commit_seal,
        rollback_seal,
        publication_binding_id,
    })
}

#[cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
pub(crate) fn reseal_v2_publication_binding_for_test(
    journal: &std::path::Path,
    expected_plan_id: &Sha256Digest,
    expected_snapshot_a: &Sha256Digest,
    publication_binding_id: Sha256Digest,
) -> Result<()> {
    let mut records = std::fs::read_dir(journal)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)
        })
        .collect::<Result<Vec<_>>>()?;
    records.sort();
    let mut cursor = JournalCursor::new_v2(publication_binding_id);
    for path in records {
        let original = std::fs::read(&path)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
        let record = parse_journal_bytes(&original)?;
        if &record.plan_id != expected_plan_id || record.sequence != cursor.sequence {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        cursor.backup_seal = record.backup_seal;
        cursor.verification_seal = record.verification_seal;
        cursor.commit_seal = record.commit_seal;
        cursor.rollback_seal = record.rollback_seal;
        match record.event {
            TransactionJournalEvent::ForwardStepCompleted => cursor.forward_completed.push(
                record
                    .related_step_id
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
            ),
            TransactionJournalEvent::RollbackStepCompleted => cursor.rollback_completed.push(
                record
                    .related_step_id
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?,
            ),
            _ => {}
        }
        let args = AppendArgs {
            plan_id: expected_plan_id,
            snapshot_a: expected_snapshot_a,
            event: record.event,
            related_step_id: record.related_step_id.as_ref(),
            related_entry_id: record.related_entry_id.as_ref(),
            max_journal_bytes: u64::MAX,
            max_journal_records: usize::MAX,
        };
        let body = encode_cursor_body(&cursor, &args)?;
        let record_id = encode_cursor_record_id(&cursor, &args, &body)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"gkrm-txn-journal-v2\n");
        bytes.push(event_tag(record.event));
        bytes.extend_from_slice(&cursor.sequence.to_be_bytes());
        bytes.extend_from_slice(expected_plan_id.as_bytes());
        bytes.extend_from_slice(publication_binding_id.as_bytes());
        bytes.extend_from_slice(record_id.as_bytes());
        bytes.extend_from_slice(body.as_bytes());
        write_optional_digest(&mut bytes, cursor.previous_id.as_ref());
        write_optional_digest(&mut bytes, record.related_step_id.as_ref());
        write_optional_digest(&mut bytes, record.related_entry_id.as_ref());
        write_optional_digest(&mut bytes, cursor.backup_seal.as_ref());
        write_optional_digest(&mut bytes, cursor.verification_seal.as_ref());
        write_optional_digest(&mut bytes, cursor.commit_seal.as_ref());
        write_optional_digest(&mut bytes, cursor.rollback_seal.as_ref());
        std::fs::write(&path, bytes)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
        cursor.previous_id = Some(record_id);
        cursor.sequence = cursor
            .sequence
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    }
    Ok(())
}

fn expected_file_name(sequence: u32, event: TransactionJournalEvent) -> String {
    format!("{:08x}-{}.bin", sequence, event_file_tag(event))
}

fn validate_transition(
    previous: Option<TransactionJournalEvent>,
    next: TransactionJournalEvent,
) -> Result<()> {
    use TransactionJournalEvent::*;
    // All terminal journal states are final: no successor records are valid.
    if matches!(
        previous,
        Some(Committed | RolledBack | RecoveryRequired | AbortedBeforeMutation)
    ) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    match (previous, next) {
        (None, Prepared) => Ok(()),
        (Some(Prepared), BackupEntryCompleted | BackupComplete | AbortedBeforeMutation) => Ok(()),
        (Some(BackupEntryCompleted), BackupEntryCompleted | BackupComplete) => Ok(()),
        (Some(BackupComplete), Applying | Verified | AbortedBeforeMutation) => Ok(()),
        (Some(Applying), ForwardStepCompleted | Applied | RollingBack) => Ok(()),
        (Some(ForwardStepCompleted), ForwardStepCompleted | Applied | RollingBack) => Ok(()),
        (Some(Applied), Verified | RollingBack) => Ok(()),
        (Some(Verified), Committed | RollingBack) => Ok(()),
        (Some(RollingBack), RollbackStepCompleted | RolledBack | RecoveryRequired) => Ok(()),
        (Some(RollbackStepCompleted), RollbackStepCompleted | RolledBack | RecoveryRequired) => {
            Ok(())
        }
        (_, ForwardStepCompleted) => {
            Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)
        }
        (_, RollbackStepCompleted) => {
            Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)
        }
        (Some(_), RecoveryRequired) => Ok(()),
        _ => Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid),
    }
}

/// Load and validate the complete contiguous hash-linked journal chain.
///
/// Directory order and filenames alone are never authoritative.
pub(crate) fn load_and_validate_journal_chain(
    journal_dir: &CapDir,
    expected_plan_id: &Sha256Digest,
    expected_snapshot_a: &Sha256Digest,
    max_records: usize,
) -> Result<JournalCursor> {
    load_and_validate_journal_chain_with_limits(
        journal_dir,
        expected_plan_id,
        expected_snapshot_a,
        max_records,
        MAX_JOURNAL_RECORD_BYTES,
        MAX_JOURNAL_TOTAL_BYTES,
    )
}

fn load_and_validate_journal_chain_with_limits(
    journal_dir: &CapDir,
    expected_plan_id: &Sha256Digest,
    expected_snapshot_a: &Sha256Digest,
    max_records: usize,
    max_record_bytes: usize,
    max_total_bytes: u64,
) -> Result<JournalCursor> {
    let mut by_seq: std::collections::BTreeMap<u32, (String, ParsedJournalRecord)> =
        std::collections::BTreeMap::new();
    let mut observed_records = 0usize;
    let mut total_bytes = 0u64;
    for entry in journal_dir
        .entries()
        .map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateJournal, e))?
    {
        observed_records = observed_records
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
        if observed_records > max_records {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
                limit: "max_journal_records",
            });
        }
        let entry =
            entry.map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateJournal, e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
        if !name.ends_with(".bin") {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        let bytes = read_journal_file_bounded_with_limit(journal_dir, &name, max_record_bytes)?;
        total_bytes = total_bytes
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?,
            )
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
        if total_bytes > max_total_bytes {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
                limit: "max_journal_bytes",
            });
        }
        let parsed = parse_journal_bytes(&bytes)?;
        if expected_file_name(parsed.sequence, parsed.event) != name {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        if by_seq.insert(parsed.sequence, (name, parsed)).is_some() {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
    }

    if by_seq.len() > max_records {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_journal_records",
        });
    }

    let mut cursor = JournalCursor::new();
    let mut previous_event: Option<TransactionJournalEvent> = None;
    let mut expected_seq = 0_u32;
    for (seq, (_name, record)) in by_seq {
        if seq != expected_seq {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        if &record.plan_id != expected_plan_id {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        if seq == 0 {
            cursor.publication_binding_id = record.publication_binding_id;
        } else if record.publication_binding_id != cursor.publication_binding_id {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        validate_transition(previous_event, record.event)?;
        if record.previous_id != cursor.previous_id {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }

        // Seals on the record are the writer cursor seals at append time.
        cursor.backup_seal = record.backup_seal;
        cursor.verification_seal = record.verification_seal;
        cursor.commit_seal = record.commit_seal;
        cursor.rollback_seal = record.rollback_seal;

        match record.event {
            TransactionJournalEvent::ForwardStepCompleted => {
                let step = record
                    .related_step_id
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
                cursor.forward_completed.push(step);
            }
            TransactionJournalEvent::RollbackStepCompleted => {
                let step = record
                    .related_step_id
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
                cursor.rollback_completed.push(step);
            }
            _ => {}
        }

        let args = AppendArgs {
            plan_id: expected_plan_id,
            snapshot_a: expected_snapshot_a,
            event: record.event,
            related_step_id: record.related_step_id.as_ref(),
            related_entry_id: record.related_entry_id.as_ref(),
            max_journal_bytes: u64::MAX,
            max_journal_records: usize::MAX,
        };
        let body = encode_cursor_body(&cursor, &args)?;
        if body != record.body {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
        let computed_id = encode_cursor_record_id(&cursor, &args, &body)?;
        if computed_id != record.record_id {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }

        cursor.previous_id = Some(record.record_id);
        cursor.sequence = cursor
            .sequence
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
        cursor.record_count = cursor
            .record_count
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
        cursor.last_event = Some(record.event);
        previous_event = Some(record.event);
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    }
    Ok(cursor)
}

fn recognizable_future_journal_version(bytes: &[u8]) -> bool {
    const PREFIX: &[u8] = b"gkrm-txn-journal-v";
    let Some(rest) = bytes.strip_prefix(PREFIX) else {
        return false;
    };
    let Some(newline) = rest.iter().position(|byte| *byte == b'\n') else {
        return false;
    };
    newline > 0
        && rest[..newline].iter().all(u8::is_ascii_digit)
        && !matches!(&rest[..newline], b"1" | b"2")
}

pub(crate) fn read_journal_file_bounded(journal_dir: &CapDir, name: &str) -> Result<Vec<u8>> {
    read_journal_file_bounded_with_limit(journal_dir, name, MAX_JOURNAL_RECORD_BYTES)
}

pub(crate) fn read_journal_plan_id_bounded(
    journal_dir: &CapDir,
    name: &str,
) -> Result<Sha256Digest> {
    let bytes = read_journal_file_bounded(journal_dir, name)?;
    Ok(parse_journal_bytes(&bytes)?.plan_id)
}

fn read_journal_file_bounded_with_limit(
    journal_dir: &CapDir,
    name: &str,
    max_record_bytes: usize,
) -> Result<Vec<u8>> {
    let mut file = open_file_nofollow(journal_dir, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenJournalRecord, e))?;
    verify_regular_file(&file, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenJournalRecord, e))?;
    let metadata_len = file
        .metadata()
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenJournalRecord, e))?
        .len();
    #[cfg(test)]
    let metadata_len = super::hooks::journal_metadata_len_override().unwrap_or(metadata_len);
    if metadata_len
        > u64::try_from(max_record_bytes)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_journal_record_bytes",
        });
    }
    let capacity = max_record_bytes
        .checked_add(1)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_journal_record_bytes",
        }
    })?;
    std::io::Read::by_ref(&mut file)
        .take(
            u64::try_from(capacity)
                .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?,
        )
        .read_to_end(&mut bytes)
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenJournalRecord, e))?;
    if bytes.len() > max_record_bytes {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_journal_record_bytes",
        });
    }
    Ok(bytes)
}

pub(crate) fn map_io(operation: TransactionalApplyIoOperation, error: std::io::Error) -> GkrmError {
    let kind = error.kind();
    drop(error);
    GkrmError::TrustedTransactionalApplyExecutionIo { operation, kind }
}

pub(crate) fn map_baseline_to_io(
    operation: TransactionalApplyIoOperation,
    error: GkrmError,
) -> GkrmError {
    match error {
        GkrmError::BaselineStoreIo { cause: source, .. } => map_io(operation, source),
        GkrmError::BaselineStoreUnexpectedType { .. }
        | GkrmError::BaselineStoreSymlink { .. }
        | GkrmError::BaselineStoreHardLink { .. } => {
            GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject
        }
        other => {
            let _ = other;
            GkrmError::TrustedTransactionalApplyExecutionIo {
                operation,
                kind: std::io::ErrorKind::Other,
            }
        }
    }
}

#[cfg(test)]
mod bounded_tests {
    use std::fs;

    use cap_fs_ext::ambient_authority;
    use tempfile::tempdir;

    use super::*;
    use crate::trusted_transactional_apply_execution::hooks::{
        lock_execution_hooks, set_journal_metadata_len_override,
    };

    fn open_cap(path: &std::path::Path) -> CapDir {
        CapDir::open_ambient_dir(path, ambient_authority()).unwrap()
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_limit_plus_one_and_sparse_files() {
        let tmp = tempdir().unwrap();
        let cap = open_cap(tmp.path());
        fs::write(tmp.path().join("exact.bin"), vec![0x41; 1_024]).unwrap();
        assert_eq!(
            read_journal_file_bounded_with_limit(&cap, "exact.bin", 1_024)
                .unwrap()
                .len(),
            1_024
        );

        fs::write(tmp.path().join("over.bin"), vec![0x41; 1_025]).unwrap();
        assert!(matches!(
            read_journal_file_bounded_with_limit(&cap, "over.bin", 1_024),
            Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
                limit: "max_journal_record_bytes"
            })
        ));

        let sparse = fs::File::create(tmp.path().join("sparse.bin")).unwrap();
        sparse.set_len(8 * 1024 * 1024 * 1024).unwrap();
        assert!(matches!(
            read_journal_file_bounded_with_limit(&cap, "sparse.bin", 1_024),
            Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded { .. })
        ));
    }

    #[test]
    fn bounded_reader_rejects_file_growth_after_metadata_without_overallocation() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("grow.bin"), vec![0x41; 1_025]).unwrap();
        let cap = open_cap(tmp.path());
        let _guard = lock_execution_hooks();
        // Deterministically model a file that reported one byte at metadata time and
        // grew before the bounded read. The +1 sentinel, not metadata, is authoritative.
        set_journal_metadata_len_override(Some(1));
        assert!(matches!(
            read_journal_file_bounded_with_limit(&cap, "grow.bin", 1_024),
            Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded { .. })
        ));
    }

    #[test]
    fn journal_limits_are_enforced_before_extra_reads_and_with_checked_total_budget() {
        let tmp = tempdir().unwrap();
        let root = open_cap(tmp.path());
        let journal = ensure_journal_dir(&root).unwrap();
        fs::create_dir(tmp.path().join("journal").join("attacker.bin")).unwrap();
        let digest = Sha256Digest::new([7; 32]);
        assert!(matches!(
            load_and_validate_journal_chain(&journal, &digest, &digest, 0),
            Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
                limit: "max_journal_records"
            })
        ));

        fs::remove_dir(tmp.path().join("journal").join("attacker.bin")).unwrap();
        let mut cursor = JournalCursor::new();
        append_record(
            &journal,
            &mut cursor,
            AppendArgs {
                plan_id: &digest,
                snapshot_a: &digest,
                event: TransactionJournalEvent::Prepared,
                related_step_id: None,
                related_entry_id: None,
                max_journal_bytes: MAX_JOURNAL_TOTAL_BYTES,
                max_journal_records: 2,
            },
        )
        .unwrap();
        cursor.backup_seal = Some(Sha256Digest::new([8; 32]));
        append_record(
            &journal,
            &mut cursor,
            AppendArgs {
                plan_id: &digest,
                snapshot_a: &digest,
                event: TransactionJournalEvent::BackupComplete,
                related_step_id: None,
                related_entry_id: None,
                max_journal_bytes: MAX_JOURNAL_TOTAL_BYTES,
                max_journal_records: 2,
            },
        )
        .unwrap();
        let total = cursor.total_journal_bytes;
        assert!(matches!(
            load_and_validate_journal_chain_with_limits(
                &journal,
                &digest,
                &digest,
                2,
                MAX_JOURNAL_RECORD_BYTES,
                total - 1,
            ),
            Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
                limit: "max_journal_bytes"
            })
        ));
        load_and_validate_journal_chain_with_limits(
            &journal,
            &digest,
            &digest,
            2,
            MAX_JOURNAL_RECORD_BYTES,
            total,
        )
        .unwrap();
    }

    #[test]
    fn journal_format_classification_distinguishes_unsupported_from_malformed() {
        assert!(matches!(
            parse_journal_bytes(b"gkrm-txn-journal-v3\n"),
            Err(GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported)
        ));
        for bytes in [
            b"gkrm-txn-journal-v1\n".as_slice(),
            b"gkrm-txn-journal-v2\n".as_slice(),
            b"gkrm-txn-journal-vx\n".as_slice(),
            b"garbage".as_slice(),
        ] {
            assert!(matches!(
                parse_journal_bytes(bytes),
                Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)
            ));
        }
    }

    #[test]
    fn prepared_v2_wire_bytes_are_an_independent_literal_vector() {
        let tmp = tempdir().unwrap();
        let root = open_cap(tmp.path());
        let journal = ensure_journal_dir(&root).unwrap();
        let plan = Sha256Digest::new([0x77; 32]);
        let snapshot = Sha256Digest::from_lowercase_hex(
            "f49b8650ca72d2a9fbcf0d6e68b7ef4ad7b098897d95dd81f34a735f3d79cd6d",
        )
        .unwrap();
        let publication = Sha256Digest::from_lowercase_hex(
            "57e5e30ad8f0a3c5316fc7f4506467b27354845100b1953466a515e4df377fe3",
        )
        .unwrap();
        let mut cursor = JournalCursor::new_v2(publication);
        append_record(
            &journal,
            &mut cursor,
            AppendArgs {
                plan_id: &plan,
                snapshot_a: &snapshot,
                event: TransactionJournalEvent::Prepared,
                related_step_id: None,
                related_entry_id: None,
                max_journal_bytes: 1_024,
                max_journal_records: 1,
            },
        )
        .unwrap();
        let expected_hex = concat!(
            "676b726d2d74786e2d6a6f75726e616c2d76320a0000000000",
            "7777777777777777777777777777777777777777777777777777777777777777",
            "57e5e30ad8f0a3c5316fc7f4506467b27354845100b1953466a515e4df377fe3",
            "69d9ba77f713e144fec075a98481602ccbb12583146600ba65a9e0850e487a86",
            "1ef841aa143ded38e740f979824f0c29b25691d992e800ea3004bae524907854",
            "00000000000000"
        );
        let expected = expected_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid literal hex"),
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fs::read(tmp.path().join("journal/00000000-prepared.bin")).unwrap(),
            expected
        );
    }
}
