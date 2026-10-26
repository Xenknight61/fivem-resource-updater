//! Test-only fault injection for Task 23 security verification.

#![cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
#![cfg_attr(
    all(feature = "desktop-test-support", debug_assertions, not(test)),
    allow(dead_code)
)]

use std::sync::{Mutex, MutexGuard};
use std::thread::ThreadId;

use super::TransactionJournalEvent;
use crate::{SafeResourceKey, TrustedApplyOperationKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JournalFault {
    Prepared,
    BackupComplete,
    Applying,
    ForwardStepCompleted,
    Applied,
    Verified,
    Committed,
    RollingBack,
    RollbackStepCompleted,
    RolledBack,
    RecoveryRequired,
    BackupEntryCompleted,
    #[allow(dead_code)]
    AbortedBeforeMutation,
}

impl JournalFault {
    fn matches(self, event: TransactionJournalEvent) -> bool {
        matches!(
            (self, event),
            (Self::Prepared, TransactionJournalEvent::Prepared)
                | (
                    Self::BackupEntryCompleted,
                    TransactionJournalEvent::BackupEntryCompleted
                )
                | (
                    Self::BackupComplete,
                    TransactionJournalEvent::BackupComplete
                )
                | (Self::Applying, TransactionJournalEvent::Applying)
                | (
                    Self::ForwardStepCompleted,
                    TransactionJournalEvent::ForwardStepCompleted
                )
                | (Self::Applied, TransactionJournalEvent::Applied)
                | (Self::Verified, TransactionJournalEvent::Verified)
                | (Self::Committed, TransactionJournalEvent::Committed)
                | (Self::RollingBack, TransactionJournalEvent::RollingBack)
                | (
                    Self::RollbackStepCompleted,
                    TransactionJournalEvent::RollbackStepCompleted
                )
                | (Self::RolledBack, TransactionJournalEvent::RolledBack)
                | (
                    Self::RecoveryRequired,
                    TransactionJournalEvent::RecoveryRequired
                )
                | (
                    Self::AbortedBeforeMutation,
                    TransactionJournalEvent::AbortedBeforeMutation
                )
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardOpFault {
    InstallFile,
    ReplaceFile,
    DeleteFile,
    CreateDirectory,
    RemoveDirectory,
}

impl ForwardOpFault {
    fn matches(self, kind: TrustedApplyOperationKind) -> bool {
        matches!(
            (self, kind),
            (Self::InstallFile, TrustedApplyOperationKind::InstallFile)
                | (Self::ReplaceFile, TrustedApplyOperationKind::ReplaceFile)
                | (Self::DeleteFile, TrustedApplyOperationKind::DeleteFile)
                | (
                    Self::CreateDirectory,
                    TrustedApplyOperationKind::CreateDirectory
                )
                | (
                    Self::RemoveDirectory,
                    TrustedApplyOperationKind::RemoveDirectory
                )
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RollbackActionFault {
    RemoveInstalledFile,
    RestoreInstalledFile,
    RecreateDirectoryWithMetadata,
    RemoveCreatedDirectory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerRacePoint {
    BeforeBackupRevalidate,
    BeforeFirstRollbackMutation,
    BeforeRollbackStepMutation,
    BeforeCommitDesiredState,
    BeforeVerifiedAppend,
    BeforeCommitTerminalAppend,
    BeforeSafeAbortTerminal,
    BeforeRolledBackTerminal,
    BeforeReadonlyTerminalFinalization,
    DuringPeerEnumeration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationPoint {
    BeforeAuthorityWrite,
    DuringAuthorityWrite,
    AfterAuthorityFsync,
    AfterAuthorityVerify,
    AfterSnapshotFsync,
    AfterResourceLockFsync,
    AfterPreparedAppend,
    BeforeTempDirectorySync,
    AfterTempDirectorySync,
    BeforeRename,
    AfterRename,
    AfterParentSync,
    AfterPublishedReopen,
    AfterResourceLock,
    AfterRecoveryLock,
    DuringFinalRevalidation,
    BeforeBackup,
    AfterFilePublish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityVerificationEvent {
    InitialDesktopAuthorityValidationPassed,
    EarlySelectedResourceCommitmentVerified,
    ResourceLockAcquired,
    PreMutationArtifactRevalidationPassed,
    RecoveryLockAcquired,
    PostLockArtifactRevalidationPassed,
    FinalSelectedResourceCommitmentVerificationStarted,
    FinalSelectedResourceCommitmentMismatch,
}

struct ExecutionHooks {
    owner: ThreadId,
    journal_fault: Option<JournalFault>,
    journal_faults: Vec<JournalFault>,
    forward_op_fault: Option<ForwardOpFault>,
    rollback_action_fault: Option<RollbackActionFault>,
    force_publish_failure: bool,
    force_post_lock_root_replaced: bool,
    force_post_lock_installed_stale: bool,
    force_post_publish_setup_io: bool,
    force_backup_copy_failure: bool,
    force_backup_sync_failure: bool,
    force_backup_seal_failure: bool,
    force_backup_final_revalidate_failure: bool,
    interrupt_before_file_publish: bool,
    interrupt_after_file_publish: bool,
    force_rename_failure: bool,
    force_parent_sync_failure: bool,
    force_remove_directory_failure: bool,
    force_directory_remains_after_remove: bool,
    force_parent_identity_replacement_on_remove: bool,
    force_rollback_probe_ambiguous: bool,
    force_result_id_encoding_failure: bool,
    force_journal_record_sync_failure: bool,
    force_journal_dir_sync_failure: bool,
    force_journal_reopen_failure: bool,
    force_journal_chain_validation_failure: bool,
    force_txn_dir_sync_failure: bool,
    force_temp_directory_sync_failure: bool,
    inject_backup_root_extra_file: bool,
    inject_backup_root_extra_dir: bool,
    inject_backup_root_temp_file: bool,
    peer_race_point: Option<PeerRacePoint>,
    peer_race_hook: Option<Box<dyn FnMut() + Send>>,
    publication_point: Option<PublicationPoint>,
    publication_hook: Option<Box<dyn FnMut() + Send>>,
    journal_metadata_len_override: Option<u64>,
    post_lock_resource_key: Option<SafeResourceKey>,
    authority_verification_events: Vec<AuthorityVerificationEvent>,
}

static HOOK_LOCK: Mutex<()> = Mutex::new(());
static HOOKS: Mutex<Option<ExecutionHooks>> = Mutex::new(None);

pub(crate) struct ExecutionHookGuard {
    _guard: MutexGuard<'static, ()>,
}

impl Drop for ExecutionHookGuard {
    fn drop(&mut self) {
        *HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

pub(crate) fn lock_execution_hooks() -> ExecutionHookGuard {
    let guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    *HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = Some(ExecutionHooks {
        owner: std::thread::current().id(),
        journal_fault: None,
        journal_faults: Vec::new(),
        forward_op_fault: None,
        rollback_action_fault: None,
        force_publish_failure: false,
        force_post_lock_root_replaced: false,
        force_post_lock_installed_stale: false,
        force_post_publish_setup_io: false,
        force_backup_copy_failure: false,
        force_backup_sync_failure: false,
        force_backup_seal_failure: false,
        force_backup_final_revalidate_failure: false,
        interrupt_before_file_publish: false,
        interrupt_after_file_publish: false,
        force_rename_failure: false,
        force_parent_sync_failure: false,
        force_remove_directory_failure: false,
        force_directory_remains_after_remove: false,
        force_parent_identity_replacement_on_remove: false,
        force_rollback_probe_ambiguous: false,
        force_result_id_encoding_failure: false,
        force_journal_record_sync_failure: false,
        force_journal_dir_sync_failure: false,
        force_journal_reopen_failure: false,
        force_journal_chain_validation_failure: false,
        force_txn_dir_sync_failure: false,
        force_temp_directory_sync_failure: false,
        inject_backup_root_extra_file: false,
        inject_backup_root_extra_dir: false,
        inject_backup_root_temp_file: false,
        peer_race_point: None,
        peer_race_hook: None,
        publication_point: None,
        publication_hook: None,
        journal_metadata_len_override: None,
        post_lock_resource_key: None,
        authority_verification_events: Vec::new(),
    });
    ExecutionHookGuard { _guard: guard }
}

fn with_hooks_mut(f: impl FnOnce(&mut ExecutionHooks)) {
    let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            f(hooks);
        }
    }
}

fn with_hooks<R>(f: impl FnOnce(&ExecutionHooks) -> R) -> Option<R> {
    let hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
    hooks.as_ref().and_then(|h| {
        if h.owner == std::thread::current().id() {
            Some(f(h))
        } else {
            None
        }
    })
}

pub(crate) fn set_journal_fault(fault: Option<JournalFault>) {
    with_hooks_mut(|h| {
        h.journal_fault = fault;
        h.journal_faults.clear();
    });
}

pub(crate) fn set_journal_faults(faults: &[JournalFault]) {
    with_hooks_mut(|h| {
        h.journal_fault = None;
        h.journal_faults = faults.to_vec();
    });
}

pub(crate) fn set_forward_op_fault(fault: Option<ForwardOpFault>) {
    with_hooks_mut(|h| h.forward_op_fault = fault);
}

pub(crate) fn set_rollback_action_fault(fault: Option<RollbackActionFault>) {
    with_hooks_mut(|h| h.rollback_action_fault = fault);
}

pub(crate) fn set_force_publish_failure(value: bool) {
    with_hooks_mut(|h| h.force_publish_failure = value);
}

pub(crate) fn set_force_post_lock_root_replaced(value: bool) {
    with_hooks_mut(|h| h.force_post_lock_root_replaced = value);
}

pub(crate) fn set_force_post_lock_installed_stale(value: bool) {
    with_hooks_mut(|h| h.force_post_lock_installed_stale = value);
}

pub(crate) fn set_force_post_publish_setup_io(value: bool) {
    with_hooks_mut(|h| h.force_post_publish_setup_io = value);
}

pub(crate) fn set_force_backup_copy_failure(value: bool) {
    with_hooks_mut(|h| h.force_backup_copy_failure = value);
}

pub(crate) fn set_force_backup_sync_failure(value: bool) {
    with_hooks_mut(|h| h.force_backup_sync_failure = value);
}

pub(crate) fn set_force_backup_seal_failure(value: bool) {
    with_hooks_mut(|h| h.force_backup_seal_failure = value);
}

pub(crate) fn set_force_backup_final_revalidate_failure(value: bool) {
    with_hooks_mut(|h| h.force_backup_final_revalidate_failure = value);
}

pub(crate) fn set_interrupt_before_file_publish(value: bool) {
    with_hooks_mut(|h| h.interrupt_before_file_publish = value);
}

pub(crate) fn set_interrupt_after_file_publish(value: bool) {
    with_hooks_mut(|h| h.interrupt_after_file_publish = value);
}

pub(crate) fn set_force_rename_failure(value: bool) {
    with_hooks_mut(|h| h.force_rename_failure = value);
}

pub(crate) fn set_force_parent_sync_failure(value: bool) {
    with_hooks_mut(|h| h.force_parent_sync_failure = value);
}

pub(crate) fn journal_fault_matches(event: TransactionJournalEvent) -> bool {
    with_hooks(|h| {
        h.journal_fault.is_some_and(|f| f.matches(event))
            || h.journal_faults.iter().any(|f| f.matches(event))
    })
    .unwrap_or(false)
}

pub(crate) fn forward_op_fault_matches(kind: TrustedApplyOperationKind) -> bool {
    with_hooks(|h| h.forward_op_fault.is_some_and(|f| f.matches(kind))).unwrap_or(false)
}

pub(crate) fn rollback_action_fault_matches(action: crate::RollbackAction) -> bool {
    with_hooks(|h| {
        h.rollback_action_fault.is_some_and(|f| {
            matches!(
                (f, action),
                (
                    RollbackActionFault::RemoveInstalledFile,
                    crate::RollbackAction::RemoveInstalledFile,
                ) | (
                    RollbackActionFault::RestoreInstalledFile,
                    crate::RollbackAction::RestoreInstalledFile,
                ) | (
                    RollbackActionFault::RecreateDirectoryWithMetadata,
                    crate::RollbackAction::RecreateDirectoryWithMetadata,
                ) | (
                    RollbackActionFault::RemoveCreatedDirectory,
                    crate::RollbackAction::RemoveCreatedDirectory,
                )
            )
        })
    })
    .unwrap_or(false)
}

pub(crate) fn force_publish_failure() -> bool {
    with_hooks(|h| h.force_publish_failure).unwrap_or(false)
}

pub(crate) fn force_post_lock_root_replaced() -> bool {
    with_hooks(|h| h.force_post_lock_root_replaced).unwrap_or(false)
}

pub(crate) fn force_post_lock_installed_stale() -> bool {
    with_hooks(|h| h.force_post_lock_installed_stale).unwrap_or(false)
}

pub(crate) fn force_post_publish_setup_io() -> bool {
    with_hooks(|h| h.force_post_publish_setup_io).unwrap_or(false)
}

pub(crate) fn force_backup_copy_failure() -> bool {
    with_hooks(|h| h.force_backup_copy_failure).unwrap_or(false)
}

pub(crate) fn force_backup_sync_failure() -> bool {
    with_hooks(|h| h.force_backup_sync_failure).unwrap_or(false)
}

pub(crate) fn force_backup_seal_failure() -> bool {
    with_hooks(|h| h.force_backup_seal_failure).unwrap_or(false)
}

pub(crate) fn force_backup_final_revalidate_failure() -> bool {
    with_hooks(|h| h.force_backup_final_revalidate_failure).unwrap_or(false)
}

pub(crate) fn interrupt_before_file_publish() -> bool {
    with_hooks(|h| h.interrupt_before_file_publish).unwrap_or(false)
}

pub(crate) fn interrupt_after_file_publish() -> bool {
    with_hooks(|h| h.interrupt_after_file_publish).unwrap_or(false)
}

pub(crate) fn force_rename_failure() -> bool {
    with_hooks(|h| h.force_rename_failure).unwrap_or(false)
}

pub(crate) fn force_parent_sync_failure() -> bool {
    with_hooks(|h| h.force_parent_sync_failure).unwrap_or(false)
}

pub(crate) fn set_force_remove_directory_failure(value: bool) {
    with_hooks_mut(|h| h.force_remove_directory_failure = value);
}

pub(crate) fn set_force_directory_remains_after_remove(value: bool) {
    with_hooks_mut(|h| h.force_directory_remains_after_remove = value);
}

pub(crate) fn set_force_parent_identity_replacement_on_remove(value: bool) {
    with_hooks_mut(|h| h.force_parent_identity_replacement_on_remove = value);
}

pub(crate) fn set_force_rollback_probe_ambiguous(value: bool) {
    with_hooks_mut(|h| h.force_rollback_probe_ambiguous = value);
}

pub(crate) fn set_force_result_id_encoding_failure(value: bool) {
    with_hooks_mut(|h| h.force_result_id_encoding_failure = value);
}

pub(crate) fn set_force_journal_record_sync_failure(value: bool) {
    with_hooks_mut(|h| h.force_journal_record_sync_failure = value);
}

pub(crate) fn set_force_journal_dir_sync_failure(value: bool) {
    with_hooks_mut(|h| h.force_journal_dir_sync_failure = value);
}

pub(crate) fn set_force_journal_reopen_failure(value: bool) {
    with_hooks_mut(|h| h.force_journal_reopen_failure = value);
}

pub(crate) fn set_force_journal_chain_validation_failure(value: bool) {
    with_hooks_mut(|h| h.force_journal_chain_validation_failure = value);
}

pub(crate) fn set_force_txn_dir_sync_failure(value: bool) {
    with_hooks_mut(|h| h.force_txn_dir_sync_failure = value);
}

pub(crate) fn set_force_temp_directory_sync_failure(value: bool) {
    with_hooks_mut(|h| h.force_temp_directory_sync_failure = value);
}

pub(crate) fn set_inject_backup_root_extra_file(value: bool) {
    with_hooks_mut(|h| h.inject_backup_root_extra_file = value);
}

pub(crate) fn set_inject_backup_root_extra_dir(value: bool) {
    with_hooks_mut(|h| h.inject_backup_root_extra_dir = value);
}

pub(crate) fn set_inject_backup_root_temp_file(value: bool) {
    with_hooks_mut(|h| h.inject_backup_root_temp_file = value);
}

pub(crate) fn force_remove_directory_failure() -> bool {
    with_hooks(|h| h.force_remove_directory_failure).unwrap_or(false)
}

pub(crate) fn force_directory_remains_after_remove() -> bool {
    with_hooks(|h| h.force_directory_remains_after_remove).unwrap_or(false)
}

pub(crate) fn force_parent_identity_replacement_on_remove() -> bool {
    with_hooks(|h| h.force_parent_identity_replacement_on_remove).unwrap_or(false)
}

pub(crate) fn force_rollback_probe_ambiguous() -> bool {
    with_hooks(|h| h.force_rollback_probe_ambiguous).unwrap_or(false)
}

pub(crate) fn force_result_id_encoding_failure() -> bool {
    with_hooks(|h| h.force_result_id_encoding_failure).unwrap_or(false)
}

pub(crate) fn force_journal_record_sync_failure() -> bool {
    with_hooks(|h| h.force_journal_record_sync_failure).unwrap_or(false)
}

pub(crate) fn force_journal_dir_sync_failure() -> bool {
    with_hooks(|h| h.force_journal_dir_sync_failure).unwrap_or(false)
}

pub(crate) fn force_journal_reopen_failure() -> bool {
    with_hooks(|h| h.force_journal_reopen_failure).unwrap_or(false)
}

pub(crate) fn force_journal_chain_validation_failure() -> bool {
    with_hooks(|h| h.force_journal_chain_validation_failure).unwrap_or(false)
}

pub(crate) fn force_txn_dir_sync_failure() -> bool {
    with_hooks(|h| h.force_txn_dir_sync_failure).unwrap_or(false)
}

pub(crate) fn force_temp_directory_sync_failure() -> bool {
    with_hooks(|h| h.force_temp_directory_sync_failure).unwrap_or(false)
}

pub(crate) fn inject_backup_root_extra_file() -> bool {
    with_hooks(|h| h.inject_backup_root_extra_file).unwrap_or(false)
}

pub(crate) fn inject_backup_root_extra_dir() -> bool {
    with_hooks(|h| h.inject_backup_root_extra_dir).unwrap_or(false)
}

pub(crate) fn inject_backup_root_temp_file() -> bool {
    with_hooks(|h| h.inject_backup_root_temp_file).unwrap_or(false)
}

/// Install a one-shot peer-namespace mutation hook for Task 24 race tests.
pub(crate) fn set_peer_race_hook(point: PeerRacePoint, hook: impl FnMut() + Send + 'static) {
    with_hooks_mut(|h| {
        h.peer_race_point = Some(point);
        h.peer_race_hook = Some(Box::new(hook));
    });
}

/// Fire the installed peer-race hook when `point` matches (at most once).
pub(crate) fn fire_peer_race_hook(point: PeerRacePoint) {
    let mut hook = None;
    with_hooks_mut(|h| {
        if h.peer_race_point == Some(point) {
            h.peer_race_point = None;
            hook = h.peer_race_hook.take();
        }
    });
    if let Some(mut hook) = hook {
        hook();
    }
}

pub(crate) fn set_publication_hook(point: PublicationPoint, hook: impl FnMut() + Send + 'static) {
    with_hooks_mut(|h| {
        h.publication_point = Some(point);
        h.publication_hook = Some(Box::new(hook));
    });
}

pub(crate) fn fire_publication_hook(point: PublicationPoint) {
    let mut hook = None;
    with_hooks_mut(|h| {
        if h.publication_point == Some(point) {
            h.publication_point = None;
            hook = h.publication_hook.take();
        }
    });
    if let Some(mut hook) = hook {
        hook();
    }
}

pub(crate) fn set_journal_metadata_len_override(value: Option<u64>) {
    with_hooks_mut(|hooks| hooks.journal_metadata_len_override = value);
}

pub(crate) fn journal_metadata_len_override() -> Option<u64> {
    with_hooks(|hooks| hooks.journal_metadata_len_override).flatten()
}

pub(crate) fn set_post_lock_resource_key(resource_key: Option<SafeResourceKey>) {
    with_hooks_mut(|hooks| hooks.post_lock_resource_key = resource_key);
}

pub(crate) fn resolve_post_lock_resource_key(default: &SafeResourceKey) -> SafeResourceKey {
    with_hooks(|hooks| hooks.post_lock_resource_key.clone())
        .flatten()
        .unwrap_or_else(|| default.clone())
}

pub(crate) fn record_authority_verification_event(event: AuthorityVerificationEvent) {
    with_hooks_mut(|hooks| hooks.authority_verification_events.push(event));
}

pub(crate) fn record_artifact_revalidation_passed() {
    with_hooks_mut(|hooks| {
        let event = if hooks
            .authority_verification_events
            .contains(&AuthorityVerificationEvent::RecoveryLockAcquired)
        {
            AuthorityVerificationEvent::PostLockArtifactRevalidationPassed
        } else {
            AuthorityVerificationEvent::PreMutationArtifactRevalidationPassed
        };
        hooks.authority_verification_events.push(event);
    });
}

pub(crate) fn authority_verification_events() -> Vec<AuthorityVerificationEvent> {
    with_hooks(|hooks| hooks.authority_verification_events.clone()).unwrap_or_default()
}
