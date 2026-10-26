//! Read-only Undo authority from a verified committed transaction. Desktop history/JSON
//! records never supply trusted destinations, prior bytes, or expected output digests.

mod attempts;
mod execution;
mod receipts;
pub use execution::TrustedUndoExecutionOutcome;
pub(crate) use receipts::trusted_two_way_causal_head;
pub use receipts::{inspect_trusted_undo_receipts, TrustedUndoReceipt};

use super::*;
use crate::baseline::fs_security::verify_regular_file;
use crate::{ResourceRelativePath, TrustedApplyOperationKind};
use sha2::{Digest, Sha256};

/// One original file transition, reproduced from the committed execution graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedUndoFileChange {
    path: ResourceRelativePath,
    before: Option<Sha256Digest>,
    after: Option<Sha256Digest>,
    before_length: Option<u64>,
    backup_name: Option<String>,
}

impl TrustedUndoFileChange {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }
    pub fn before(&self) -> Option<&Sha256Digest> {
        self.before.as_ref()
    }
    pub fn before_length(&self) -> Option<u64> {
        self.before_length
    }
    pub fn after(&self) -> Option<&Sha256Digest> {
        self.after.as_ref()
    }
}

/// Backend-only retained Undo source. Opening/reading this source never changes an
/// installed file. It is not authorization to mutate the current installation.
pub struct TrustedUndoSource {
    transaction_id: Sha256Digest,
    artifact_id: Sha256Digest,
    authority_id: Sha256Digest,
    resource_key: SafeResourceKey,
    transaction: CapDir,
    backup_files: CapDir,
    workspace: TrustedUpdateWorkspace,
    created_directories: BTreeSet<ResourceRelativePath>,
    removed_directories: BTreeSet<ResourceRelativePath>,
    changes: Vec<TrustedUndoFileChange>,
}

/// An explicit reverse disposition. Later edits and type changes are never overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedUndoDisposition {
    RestoreOriginal,
    RemoveCreated,
    AlreadyOriginal,
    PreserveChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedUndoPlanEntry {
    path: ResourceRelativePath,
    disposition: TrustedUndoDisposition,
    expected_current: Option<Sha256Digest>,
    original: Option<Sha256Digest>,
}

impl TrustedUndoPlanEntry {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }
    pub fn disposition(&self) -> TrustedUndoDisposition {
        self.disposition
    }
    pub fn expected_current(&self) -> Option<&Sha256Digest> {
        self.expected_current.as_ref()
    }
    pub fn original(&self) -> Option<&Sha256Digest> {
        self.original.as_ref()
    }
}

/// Immutable point-in-time proposal; not filesystem mutation authorization. Execution must
/// rebind the parent, revalidate the full current tree, stage, back up and journal separately.
pub struct TrustedUndoPlan {
    plan_id: Sha256Digest,
    transaction_id: Sha256Digest,
    current_fingerprint: Sha256Digest,
    previous_attempt: Option<Sha256Digest>,
    entries: Vec<TrustedUndoPlanEntry>,
}

impl std::fmt::Debug for TrustedUndoPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedUndoPlan")
    }
}

impl TrustedUndoPlan {
    pub(crate) fn previous_attempt(&self) -> Option<&Sha256Digest> {
        self.previous_attempt.as_ref()
    }

    pub fn plan_id(&self) -> &Sha256Digest {
        &self.plan_id
    }
    pub fn transaction_id(&self) -> &Sha256Digest {
        &self.transaction_id
    }
    pub fn current_fingerprint(&self) -> &Sha256Digest {
        &self.current_fingerprint
    }
    pub fn entries(&self) -> &[TrustedUndoPlanEntry] {
        &self.entries
    }
}

impl std::fmt::Debug for TrustedUndoSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedUndoSource")
    }
}

impl TrustedUndoSource {
    /// Resolve only the prior official baseline bound by the verified forward
    /// artifact. Desktop JSON baseline hints never participate in this lookup.
    pub fn previous_baseline(&self) -> Result<Option<crate::StoredBaseline>> {
        let options = TrustedPackageFreeUpdateRecoveryOptions::default();
        let artifact = resolve_exact_artifact(
            &self.workspace,
            &self.artifact_id,
            options.max_artifact_directory_entries,
            options.max_artifacts,
            options.max_artifact_bytes,
            options.max_total_artifact_bytes,
        )?;
        let Some(descriptor) = artifact.two_way_descriptor() else {
            return Ok(None);
        };
        let Some(transition) = descriptor.baseline_transition() else {
            return Ok(None);
        };
        transition
            .before()?
            .map(|id| super::baselines::resolve_baseline(&self.workspace, &self.resource_key, &id))
            .transpose()
    }
    /// Recovery already owns the selected operation's locks. Reopen immutable
    /// forward-parent evidence without reacquiring the same resource lock.
    pub(super) fn reopen_committed_parent(
        workspace: &TrustedUpdateWorkspace,
        installed: &InstalledApplyPlanningSource,
        key: &SafeResourceKey,
        transaction_id: &Sha256Digest,
        options: TrustedPackageFreeUpdateRecoveryOptions,
    ) -> Result<Self> {
        let root =
            TrustedTransactionRoot::try_open_in_workspace(workspace).map_err(map_durable_error)?;
        let (transaction, before) = open_candidate_transaction(&root, transaction_id)?;
        let graph = reconstruct_forward_v2_authority(
            workspace,
            &transaction,
            installed,
            key,
            installed.selected_resource_root(),
            transaction_id,
            options,
        )?;
        let source = Self::from_committed_graph(
            workspace,
            &transaction,
            key.clone(),
            transaction_id,
            &graph,
        )?;
        let (_, after) = open_candidate_transaction(&root, transaction_id)?;
        if before.transactions_parent_identity != after.transactions_parent_identity
            || before.transaction_identity != after.transaction_identity
            || before.journal_identity != after.journal_identity
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        root.revalidate_identity().map_err(map_durable_error)?;
        Ok(source)
    }

    /// Bind the reverse proposal to a fresh selected installation and its complete current
    /// tree. Original transaction data comes only from this verified source.
    pub fn plan(&self, selection: &TrustedInstalledRecoverySelection) -> Result<TrustedUndoPlan> {
        let (source, key) =
            reopen_fresh_installed_selection(selection.source(), InstalledScanLimits::default())?;
        let envelope =
            verify_recovery_authority_envelope(&self.transaction).map_err(map_durable_error)?;
        if key != self.resource_key
            || envelope.artifact_id() != &self.artifact_id
            || envelope.authority_id().digest() != &self.authority_id
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        verify_installed_authority_commitment(
            &source,
            &key,
            envelope.body().installed_authority_commitment(),
        )
        .map_err(map_durable_error)?;
        let current = source
            .capture_tree_snapshot(&key)
            .map_err(map_durable_error)?;
        receipts::validate_available_parent(self, &source)?;
        let previous = attempts::previous_attempt(self, &source, None)?;
        self.plan_from_snapshot(&current, previous)
    }

    pub(crate) fn plan_from_snapshot(
        &self,
        current: &crate::trusted_apply_planning::InstalledApplyTreeSnapshot,
        previous_attempt: Option<Sha256Digest>,
    ) -> Result<TrustedUndoPlan> {
        let mut entries = Vec::with_capacity(self.changes.len());
        let mut encoder = CanonicalFingerprintEncoder::new(if previous_attempt.is_some() {
            "gkrm-trusted-undo-plan-v2"
        } else {
            "gkrm-trusted-undo-plan-v1"
        })
        .map_err(map_durable_error)?;
        if let Some(previous) = previous_attempt {
            encoder.digest(&previous);
        }
        for digest in [
            &self.transaction_id,
            &self.artifact_id,
            &self.authority_id,
            &current.fingerprint,
        ] {
            encoder.digest(digest);
        }
        encoder
            .usize(self.changes.len())
            .map_err(map_durable_error)?;
        for change in &self.changes {
            let now = current
                .files
                .get(&change.path)
                .and_then(|state| state.digest_opt())
                .copied();
            let type_conflict = current.directories.contains(&change.path)
                || crate::trusted_apply_planning::parents_of(&change.path)
                    .iter()
                    .any(|parent| current.files.contains_key(parent));
            let disposition = if type_conflict {
                TrustedUndoDisposition::PreserveChanged
            } else if now == change.before {
                TrustedUndoDisposition::AlreadyOriginal
            } else if now != change.after {
                TrustedUndoDisposition::PreserveChanged
            } else if change.before.is_some() {
                TrustedUndoDisposition::RestoreOriginal
            } else {
                TrustedUndoDisposition::RemoveCreated
            };
            encoder.path(&change.path).map_err(map_durable_error)?;
            encoder.u8(match disposition {
                TrustedUndoDisposition::RestoreOriginal => 1,
                TrustedUndoDisposition::RemoveCreated => 2,
                TrustedUndoDisposition::AlreadyOriginal => 3,
                TrustedUndoDisposition::PreserveChanged => 4,
            });
            for digest in [now, change.before] {
                match digest {
                    Some(digest) => {
                        encoder.u8(1);
                        encoder.digest(&digest);
                    }
                    None => encoder.u8(0),
                }
            }
            entries.push(TrustedUndoPlanEntry {
                path: change.path.clone(),
                disposition,
                expected_current: now,
                original: change.before,
            });
        }
        Ok(TrustedUndoPlan {
            plan_id: encoder.finish(),
            transaction_id: self.transaction_id,
            current_fingerprint: current.fingerprint,
            previous_attempt,
            entries,
        })
    }
    /// Select one exact committed transaction for one freshly selected installation.
    /// Original apply/backup/recovery bindings are verified again after OS locking.
    pub fn try_open(
        workspace: &TrustedUpdateWorkspace,
        selection: &TrustedInstalledRecoverySelection,
        transaction_id: &Sha256Digest,
    ) -> Result<Self> {
        let options = TrustedPackageFreeUpdateRecoveryOptions::default();
        let workspace = open_existing_trusted_update_workspace(workspace.app_root())
            .map_err(map_durable_error)?
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let overview = inspect_trusted_recovery_workspace_overview(Some(&workspace), options)?;
        if overview.has_active_recovery()
            || overview.has_manual_attention()
            || overview.has_unsupported_evidence()
        {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementBlocked);
        }
        let root =
            TrustedTransactionRoot::try_open_in_workspace(&workspace).map_err(map_durable_error)?;
        let (source, key) =
            reopen_fresh_installed_selection(selection.source(), options.installed_scan_limits)?;
        let (transaction, namespace) = open_candidate_transaction(&root, transaction_id)?;
        let pre = reconstruct_forward_v2_authority(
            &workspace,
            &transaction,
            &source,
            &key,
            source.selected_resource_root(),
            transaction_id,
            options,
        )?;
        if pre.journal_event != TransactionJournalEvent::Committed {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        drop(pre);
        drop(transaction);
        let verified = VerifiedPublishedTransaction::acquire_with_expected_namespace(
            &root,
            key.as_str(),
            transaction_id,
            &namespace.transactions_parent_identity,
            &namespace.transaction_identity,
            &namespace.journal_identity,
        )?;
        let (source, key) =
            reopen_fresh_installed_selection(selection.source(), options.installed_scan_limits)?;
        verified.reassert(&root)?;
        let graph = reconstruct_forward_v2_authority(
            &workspace,
            &verified.txn_dir,
            &source,
            &key,
            source.selected_resource_root(),
            transaction_id,
            options,
        )?;
        if graph.journal_event != TransactionJournalEvent::Committed {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let result =
            Self::from_committed_graph(&workspace, &verified.txn_dir, key, transaction_id, &graph)?;
        receipts::validate_available_parent(&result, &source)?;
        attempts::previous_attempt(&result, &source, None)?;
        verified.reassert(&root)?;
        Ok(result)
    }

    fn from_committed_graph(
        workspace: &TrustedUpdateWorkspace,
        transaction: &CapDir,
        key: SafeResourceKey,
        transaction_id: &Sha256Digest,
        graph: &ReconstructedV2Authority,
    ) -> Result<Self> {
        if graph.journal_event != TransactionJournalEvent::Committed {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let envelope =
            verify_recovery_authority_envelope(transaction).map_err(map_durable_error)?;
        let backup = open_child_dir(transaction, "backup").map_err(map_durable_error)?;
        let backup_files = open_child_dir(&backup, "files").map_err(map_durable_error)?;
        let mut changes = Vec::new();
        let mut created_directories = BTreeSet::new();
        let mut removed_directories = BTreeSet::new();
        for operation in graph.apply_plan.operations() {
            match operation.kind() {
                TrustedApplyOperationKind::CreateDirectory => {
                    created_directories.insert(operation.destination().clone());
                }
                TrustedApplyOperationKind::RemoveDirectory => {
                    removed_directories.insert(operation.destination().clone());
                }
                _ => {}
            }
            if !matches!(
                operation.kind(),
                TrustedApplyOperationKind::InstallFile
                    | TrustedApplyOperationKind::ReplaceFile
                    | TrustedApplyOperationKind::DeleteFile
            ) {
                continue;
            }
            let before = operation.pre_state().digest_opt().copied();
            let after = operation.post_state().digest_opt().copied();
            let backup_name = match before {
                Some(digest) => {
                    let entry = graph
                        .tx_plan
                        .backup()
                        .entries()
                        .iter()
                        .find(|entry| {
                            entry.operation_id == *operation.operation_id()
                                && entry.destination == *operation.destination()
                        })
                        .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
                    if entry.digest != Some(digest)
                        || entry.byte_length != operation.pre_state().length_opt()
                    {
                        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
                    }
                    Some(entry.entry_id.digest().to_string())
                }
                None => None,
            };
            changes.push(TrustedUndoFileChange {
                path: operation.destination().clone(),
                before,
                after,
                before_length: operation.pre_state().length_opt(),
                backup_name,
            });
        }
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        if changes.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        Ok(Self {
            transaction_id: *transaction_id,
            artifact_id: *envelope.artifact_id(),
            authority_id: *envelope.authority_id().digest(),
            resource_key: key,
            transaction: transaction
                .try_clone()
                .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
            backup_files,
            workspace: workspace.clone(),
            created_directories,
            removed_directories,
            changes,
        })
    }

    /// Publish a complete isolated reverse candidate, refusing any drift since review.
    /// This changes staging only; a separate transaction must authorize live installation writes.
    pub fn stage(
        &self,
        selection: &TrustedInstalledRecoverySelection,
        plan: &TrustedUndoPlan,
    ) -> Result<crate::TrustedUndoStagingBundle> {
        let fresh = Self::try_open(&self.workspace, selection, &self.transaction_id)?;
        if fresh.artifact_id != self.artifact_id || fresh.authority_id != self.authority_id {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let current_plan = fresh.plan(selection)?;
        if current_plan.plan_id() != plan.plan_id() {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        let (installed, key) =
            reopen_fresh_installed_selection(selection.source(), InstalledScanLimits::default())?;
        let current = installed
            .capture_tree_snapshot(&key)
            .map_err(map_durable_error)?;
        for root in [
            self.workspace.staging_root(),
            self.workspace.baseline_store(),
            self.workspace.transaction_root(),
            self.workspace.app_root(),
        ] {
            crate::baseline::ensure_baseline_store_disjoint_from_installed(
                root,
                installed.installed_root_path(),
            )?;
        }
        let installed_content = crate::InstalledStagingContentSource::try_new(
            installed.installed_root_path(),
            installed.selected_resource_root().clone(),
            InstalledScanLimits::default(),
        )?;
        let staging_root = crate::TrustedStagingRoot::try_open(self.workspace.staging_root())?;
        crate::trusted_staging::stage_undo_candidate(
            &fresh,
            plan,
            &current,
            &installed,
            &installed_content,
            &staging_root,
            &self.workspace,
        )
    }

    pub(crate) fn created_directories(&self) -> &BTreeSet<ResourceRelativePath> {
        &self.created_directories
    }
    pub(crate) fn removed_directories(&self) -> &BTreeSet<ResourceRelativePath> {
        &self.removed_directories
    }
    pub(crate) fn artifact_id(&self) -> &Sha256Digest {
        &self.artifact_id
    }
    pub(crate) fn authority_id(&self) -> &Sha256Digest {
        &self.authority_id
    }

    pub fn transaction_id(&self) -> &Sha256Digest {
        &self.transaction_id
    }
    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }
    pub fn changes(&self) -> &[TrustedUndoFileChange] {
        &self.changes
    }

    /// Read a bounded verified original object through retained no-follow capabilities.
    /// `None` denotes an originally absent file, never an unverified/missing backup.
    pub fn original_bytes(&self, path: &ResourceRelativePath) -> Result<Option<Vec<u8>>> {
        let change = self
            .changes
            .iter()
            .find(|entry| entry.path == *path)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let Some(expected) = change.before else {
            return Ok(None);
        };
        let length = change
            .before_length
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if length > 512 * 1024 * 1024 {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let envelope =
            verify_recovery_authority_envelope(&self.transaction).map_err(map_durable_error)?;
        if envelope.artifact_id() != &self.artifact_id
            || envelope.authority_id().digest() != &self.authority_id
            || envelope.body().transactional_plan_id() != &self.transaction_id
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let name = change
            .backup_name
            .as_deref()
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let file = open_file_nofollow(&self.backup_files, name).map_err(map_durable_error)?;
        verify_regular_file(&file, name).map_err(map_durable_error)?;
        if file
            .metadata()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
            .len()
            != length
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let identity = capture_stable_file_identity(&file)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let mut bytes = Vec::new();
        (&file)
            .take(length + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if bytes.len() as u64 != length
            || Sha256Digest::new(Sha256::digest(&bytes).into()) != expected
            || capture_stable_file_identity(&file)
                .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
                != identity
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        Ok(Some(bytes))
    }
}
