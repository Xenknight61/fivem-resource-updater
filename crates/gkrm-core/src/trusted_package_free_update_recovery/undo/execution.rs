//! Explicit reverse execution through the ordinary core transaction engine.

use super::*;
use crate::trusted_cli_update_artifact::{
    encode_cli_artifact_v2_with_undo_descriptor, publish_bytes_no_replace,
    read_regular_file_limited,
};
use crate::trusted_recovery_authority::{
    build_recovery_authority_body, RecoveryAuthorityLimits, RecoveryAuthorityPublication,
};
use crate::{
    TrustedCliUpdateArtifactBody, TrustedTransactionResult,
    TrustedTransactionalApplyExecutionOptions, TrustedTransactionalApplyExecutionRequest,
};

/// Durable result of explicit Undo, including an already-restored installation.
/// Partial preservation is explicit and never silently clears desktop history.
pub struct TrustedUndoExecutionOutcome {
    parent_transaction_id: Sha256Digest,
    transaction_id: Option<Sha256Digest>,
    result: Option<TrustedTransactionResult>,
    preserved_changes: usize,
}

impl std::fmt::Debug for TrustedUndoExecutionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedUndoExecutionOutcome")
            .field("has_transaction", &self.transaction_id.is_some())
            .field("preserved_changes", &self.preserved_changes)
            .finish_non_exhaustive()
    }
}
impl TrustedUndoExecutionOutcome {
    pub fn parent_transaction_id(&self) -> &Sha256Digest {
        &self.parent_transaction_id
    }
    pub fn transaction_id(&self) -> Option<&Sha256Digest> {
        self.transaction_id.as_ref()
    }
    pub fn result(&self) -> Option<&TrustedTransactionResult> {
        self.result.as_ref()
    }
    pub fn preserved_changes(&self) -> usize {
        self.preserved_changes
    }
}

impl TrustedUndoSource {
    /// Explicitly execute this exact reviewed reverse plan. Retains all original
    /// evidence and publishes independent Undo recovery authority before mutation.
    pub fn execute(
        &self,
        selection: &TrustedInstalledRecoverySelection,
        plan: &TrustedUndoPlan,
    ) -> Result<TrustedUndoExecutionOutcome> {
        self.previous_baseline()?;
        let staged = self.stage(selection, plan)?;
        let installed = selection
            .source()
            .reopen_for_package_free_recovery(InstalledScanLimits::default())?;
        staged.validate_installed_binding(&installed)?;
        let apply = staged.plan_apply(selection)?;
        let preserved_changes = plan
            .entries()
            .iter()
            .filter(|entry| entry.disposition() == TrustedUndoDisposition::PreserveChanged)
            .count();
        // Even an empty reverse plan must commit the user's explicit completion:
        // the durable receipt advances history without changing installed bytes.
        let transaction = staged.plan_transaction(selection, &apply)?;
        let transaction_id = *transaction.plan_id().digest();
        let root = TrustedTransactionRoot::try_open_in_workspace(&self.workspace)?;
        if crate::trusted_transaction_is_on_record(&root, &transaction_id)? {
            return Err(GkrmError::TrustedTransactionalApplyExecutionTransactionExists);
        }
        let snapshot = installed.capture_tree_snapshot(&self.resource_key)?;
        if &snapshot.fingerprint != plan.current_fingerprint() {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        let descriptor = staged.execution_descriptor()?;
        let marker = crate::trusted_staging::undo_record_marker("baseline")?;
        let (body, authority_id) = build_recovery_authority_body(
            &installed,
            &self.resource_key,
            marker,
            *staged.bundle().manifest().manifest_id().digest(),
            *staged.bundle().bundle_id().digest(),
            *apply.plan_id().digest(),
            transaction_id,
            &snapshot,
            RecoveryAuthorityLimits::default(),
        )?;
        let artifact_body = TrustedCliUpdateArtifactBody {
            package_fingerprint: self.artifact_id,
            selected_resource_commitment: *body.selected_resource_commitment(),
            baseline_id_digest: marker,
            plan_id: *plan.plan_id(),
            review_id: descriptor.review_id()?,
            analysis_id: None,
            text_diff_id: None,
            synthesis_id: None,
            merged_bytes_id: None,
            operator_merge_set_id: crate::trusted_staging::undo_record_marker("operator-merges")?,
            staging_manifest_id: *staged.bundle().manifest().manifest_id().digest(),
            staging_bundle_id: *staged.bundle().bundle_id().digest(),
            apply_plan_id: *apply.plan_id().digest(),
            snapshot_a: snapshot.fingerprint,
            transactional_plan_id: transaction_id,
            recovery_authority_id: Some(*authority_id.digest()),
            decision_document_id: crate::trusted_staging::undo_record_marker("decision-document")?,
        };
        let artifact = encode_cli_artifact_v2_with_undo_descriptor(&artifact_body, &descriptor)?;
        let path = self
            .workspace
            .artifact_root()
            .path()
            .join(format!("plan-undo-{}.bin", artifact.artifact_id().to_hex()));
        let limits = TrustedCliUpdateOptions::default();
        if artifact.canonical_bytes().len() > limits.max_artifact_bytes {
            return Err(GkrmError::TrustedCliUpdateLimitExceeded {
                limit: "max_artifact_bytes",
            });
        }
        {
            let _publication_lock =
                crate::acquire_trusted_update_workspace_publication_lock(&self.workspace)?;
            match read_regular_file_limited(&path, limits.max_artifact_bytes) {
                Ok(bytes) => {
                    if bytes != artifact.canonical_bytes() {
                        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
                    }
                }
                Err(_) => {
                    crate::enforce_trusted_update_workspace_capacity_for_new_plan_artifact(
                        &self.workspace,
                        TrustedUpdateWorkspaceOptions::default(),
                        artifact.canonical_bytes().len() as u64,
                    )?;
                    publish_bytes_no_replace(&path, artifact.canonical_bytes())?;
                }
            }
        }
        let publication =
            RecoveryAuthorityPublication::new(body, authority_id, *artifact.artifact_id().digest());
        let revalidate = || {
            let bytes = read_regular_file_limited(&path, limits.max_artifact_bytes)?;
            let current = parse_cli_artifact(&bytes, &limits)?;
            if current.artifact_id().digest() != publication.artifact_id()
                || current.undo_descriptor() != Some(&descriptor)
                || current.body() != &artifact_body
            {
                return Err(GkrmError::TrustedCliUpdateBindingMismatch);
            }
            let parent = Self::reopen_committed_parent(
                &self.workspace,
                &installed,
                &self.resource_key,
                &self.transaction_id,
                TrustedPackageFreeUpdateRecoveryOptions::default(),
            )?;
            parent.previous_baseline()?;
            if super::attempts::previous_attempt(&parent, &installed, Some(&transaction_id))?
                .as_ref()
                != plan.previous_attempt()
            {
                return Err(GkrmError::TrustedCliUpdateBindingMismatch);
            }
            crate::trusted_staging::reopen_undo_candidate(
                &self.workspace,
                &parent,
                &snapshot,
                &installed,
                current.body(),
                &descriptor,
            )?;
            Ok(publication.clone())
        };
        revalidate()?;
        // Undo acknowledges only its verified forward parent. Other history is retained
        // and cannot be silently retired by this operation.
        retire_terminal_update_evidence(
            &self.workspace,
            TrustedTerminalEvidenceRetirementOptions {
                acknowledged: true,
                ..TrustedTerminalEvidenceRetirementOptions::default()
            },
            Some(&self.transaction_id),
        )?;
        if let Some(previous) = plan.previous_attempt() {
            retire_terminal_update_evidence(
                &self.workspace,
                TrustedTerminalEvidenceRetirementOptions {
                    acknowledged: true,
                    ..TrustedTerminalEvidenceRetirementOptions::default()
                },
                Some(previous),
            )?;
        }
        let request =
            TrustedTransactionalApplyExecutionRequest::try_new_undo_with_recovery_authority(
                &transaction,
                &apply,
                &staged,
                &installed,
                &root,
                &publication,
                &revalidate,
                TrustedTransactionalApplyExecutionOptions::default(),
            )?;
        let result = crate::execute_trusted_transactional_apply(request)?;
        Ok(TrustedUndoExecutionOutcome {
            parent_transaction_id: self.transaction_id,
            transaction_id: Some(transaction_id),
            result: Some(result),
            preserved_changes,
        })
    }
}
