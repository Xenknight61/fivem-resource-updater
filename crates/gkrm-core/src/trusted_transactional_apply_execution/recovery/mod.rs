//! Trusted interrupted-transaction recovery (Milestone 2 Task 24).
//!
//! Discovery (`scan_trusted_transactions`) is strictly read-only.
//! Mutation recovery (`recover_trusted_transaction`) handles one candidate.

#![allow(clippy::too_many_arguments)]

pub(crate) mod binding;
mod id;

#[cfg(test)]
mod boundary_tests;
#[cfg(test)]
mod peer_safety_tests;
#[cfg(test)]
mod review_fix_tests;
#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod trusted_transaction_recovery;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{
    dir_identity, open_child_dir, try_open_child_dir, validate_single_component,
};
use crate::installed_path::case_collision_key;
use crate::trusted_staging::verify_published_bundle_readonly;
use crate::trusted_transactional_apply_execution::journal::{
    append_terminal_record, load_and_validate_journal_chain, map_io, AppendArgs, JournalCursor,
};
use crate::trusted_transactional_apply_execution::locks;
use crate::trusted_transactional_apply_execution::{
    probe_desired_state, read_resource_lock_id_binding, read_snapshot_a_binding, DesiredStateProbe,
    TransactionJournalEvent, TrustedTransactionRoot,
};
use crate::trusted_transactional_apply_planning::{
    backup::build_backup_plan, id::encode_execution_plan_id, id::PlanIdInputs,
    journal::build_journal_plan, journal::build_recovery_table, rollback::build_rollback_steps,
    steps::build_forward_steps,
};
use crate::{
    plan_trusted_apply, plan_trusted_transactional_apply, GkrmError, InstalledApplyPlanningSource,
    ResolvedOfficialBaseline, Result, Sha256Digest, ThreeWayMergeAnalysisPlan,
    ThreeWayMergeSynthesisPlan, ThreeWayMergedBytesPlan, ThreeWayPlanReview, ThreeWayTextDiffPlan,
    ThreeWayUpdatePlan, TransactionalApplyIoOperation, TrustedApplyPlan,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedStagingBundle,
    TrustedTransactionalApplyPlan, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest, TrustedTransactionalApplySummary,
};

use id::{
    encode_candidate_id, encode_malformed_candidate_id, encode_recovery_result_id,
    encode_scan_result_id,
};

use binding::VerifiedPublishedTransaction;

pub(crate) use id::encode_recovery_result_id_pub;

/// Scan options for read-only transaction discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedRecoveryScanOptions {
    pub max_transactions: usize,
    pub max_journal_records: usize,
    pub max_total_scan_entries: usize,
    pub max_path_depth: usize,
    pub max_path_component_bytes: usize,
}

impl Default for TrustedRecoveryScanOptions {
    fn default() -> Self {
        Self {
            max_transactions: 10_000,
            max_journal_records: 200_000,
            max_total_scan_entries: 200_000,
            max_path_depth: 64,
            max_path_component_bytes: 255,
        }
    }
}

impl TrustedRecoveryScanOptions {
    pub fn validate(self) -> Result<()> {
        for (name, value) in [
            ("max_transactions", self.max_transactions),
            ("max_journal_records", self.max_journal_records),
            ("max_total_scan_entries", self.max_total_scan_entries),
            ("max_path_depth", self.max_path_depth),
            ("max_path_component_bytes", self.max_path_component_bytes),
        ] {
            if value == 0 {
                return Err(GkrmError::TrustedTransactionRecoveryOptionsInvalid { limit: name });
            }
        }
        Ok(())
    }
}

/// Recovery mutation options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedRecoveryOptions {
    pub max_journal_records: usize,
    pub max_backup_bytes: u64,
    pub max_recovery_steps: usize,
    pub max_path_depth: usize,
    pub max_path_component_bytes: usize,
}

impl Default for TrustedRecoveryOptions {
    fn default() -> Self {
        Self {
            max_journal_records: 200_000,
            max_backup_bytes: 2 * 1024 * 1024 * 1024,
            max_recovery_steps: 200_000,
            max_path_depth: 64,
            max_path_component_bytes: 255,
        }
    }
}

impl TrustedRecoveryOptions {
    pub fn validate(self) -> Result<()> {
        for (name, value) in [
            ("max_journal_records", self.max_journal_records),
            ("max_recovery_steps", self.max_recovery_steps),
            ("max_path_depth", self.max_path_depth),
            ("max_path_component_bytes", self.max_path_component_bytes),
        ] {
            if value == 0 {
                return Err(GkrmError::TrustedTransactionRecoveryOptionsInvalid { limit: name });
            }
        }
        if self.max_backup_bytes == 0 {
            return Err(GkrmError::TrustedTransactionRecoveryOptionsInvalid {
                limit: "max_backup_bytes",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedRecoveryCandidateId(Sha256Digest);
impl TrustedRecoveryCandidateId {
    #[allow(dead_code)]
    pub(crate) fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    /// Opaque reusable selector for CLI recover (never a plan-ID directory name).
    pub fn to_selector_hex(&self) -> String {
        self.0.to_string()
    }

    /// Parse an opaque candidate selector produced by [`Self::to_selector_hex`].
    pub fn from_selector_hex(value: &str) -> Result<Self> {
        Ok(Self(Sha256Digest::from_lowercase_hex(value).map_err(
            |_| GkrmError::TrustedTransactionRecoveryCandidateInvalid,
        )?))
    }

    #[cfg(test)]
    #[allow(dead_code, clippy::wrong_self_convention)]
    pub(crate) fn to_hex(&self) -> String {
        self.to_selector_hex()
    }
}
impl std::fmt::Debug for TrustedRecoveryCandidateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedRecoveryCandidateId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedRecoveryResultId(pub(crate) Sha256Digest);
impl TrustedRecoveryResultId {
    #[allow(dead_code)]
    pub(crate) fn digest(&self) -> &Sha256Digest {
        &self.0
    }
    #[cfg(test)]
    #[allow(dead_code, clippy::wrong_self_convention)]
    pub(crate) fn to_hex(&self) -> String {
        self.0.to_string()
    }
}
impl std::fmt::Debug for TrustedRecoveryResultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedRecoveryResultId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedRecoveryScanResultId(Sha256Digest);
impl TrustedRecoveryScanResultId {
    #[cfg(test)]
    #[allow(dead_code, clippy::wrong_self_convention)]
    pub(crate) fn to_hex(&self) -> String {
        self.0.to_string()
    }
}
impl std::fmt::Debug for TrustedRecoveryScanResultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedRecoveryScanResultId")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedRecoveryCandidateKind {
    Bound,
    Malformed,
}

/// Opaque scan candidate. Directory names / plan IDs are never exposed.
pub struct TrustedRecoveryCandidate {
    candidate_id: TrustedRecoveryCandidateId,
    kind: TrustedRecoveryCandidateKind,
    /// Proven plan id when bound; used only within the crate for recovery selection.
    pub(crate) proven_plan_id: Option<Sha256Digest>,
}

impl TrustedRecoveryCandidate {
    pub fn candidate_id(&self) -> &TrustedRecoveryCandidateId {
        &self.candidate_id
    }
    pub fn kind(&self) -> TrustedRecoveryCandidateKind {
        self.kind
    }
}
impl std::fmt::Debug for TrustedRecoveryCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedRecoveryCandidate")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

pub struct TrustedRecoveryScanResult {
    scan_id: TrustedRecoveryScanResultId,
    candidates: Vec<TrustedRecoveryCandidate>,
}

impl TrustedRecoveryScanResult {
    pub fn scan_id(&self) -> &TrustedRecoveryScanResultId {
        &self.scan_id
    }
    pub fn candidates(&self) -> &[TrustedRecoveryCandidate] {
        &self.candidates
    }
}
impl std::fmt::Debug for TrustedRecoveryScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedRecoveryScanResult")
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

pub struct RecoveredCommittedTransaction {
    result_id: TrustedRecoveryResultId,
}
impl RecoveredCommittedTransaction {
    pub fn result_id(&self) -> &TrustedRecoveryResultId {
        &self.result_id
    }
}
impl std::fmt::Debug for RecoveredCommittedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveredCommittedTransaction")
    }
}

pub struct RecoveredRolledBackTransaction {
    pub(crate) result_id: TrustedRecoveryResultId,
}
impl RecoveredRolledBackTransaction {
    pub fn result_id(&self) -> &TrustedRecoveryResultId {
        &self.result_id
    }
}
impl std::fmt::Debug for RecoveredRolledBackTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveredRolledBackTransaction")
    }
}

pub struct RecoveryStillRequired {
    pub(crate) result_id: TrustedRecoveryResultId,
}
impl RecoveryStillRequired {
    pub fn result_id(&self) -> &TrustedRecoveryResultId {
        &self.result_id
    }
}
impl std::fmt::Debug for RecoveryStillRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryStillRequired")
    }
}

pub struct SafeRestartTransaction {
    result_id: TrustedRecoveryResultId,
}
impl SafeRestartTransaction {
    pub fn result_id(&self) -> &TrustedRecoveryResultId {
        &self.result_id
    }
}
impl std::fmt::Debug for SafeRestartTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SafeRestartTransaction")
    }
}

pub enum TrustedRecoveryResult {
    RecoveredCommitted(RecoveredCommittedTransaction),
    RecoveredRolledBack(RecoveredRolledBackTransaction),
    RecoveryStillRequired(RecoveryStillRequired),
    SafeRestart(SafeRestartTransaction),
}
impl std::fmt::Debug for TrustedRecoveryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecoveredCommitted(v) => f.debug_tuple("RecoveredCommitted").field(v).finish(),
            Self::RecoveredRolledBack(v) => f.debug_tuple("RecoveredRolledBack").field(v).finish(),
            Self::RecoveryStillRequired(v) => {
                f.debug_tuple("RecoveryStillRequired").field(v).finish()
            }
            Self::SafeRestart(v) => f.debug_tuple("SafeRestart").field(v).finish(),
        }
    }
}

pub struct TrustedTransactionRecoveryRequest<'a> {
    pub(crate) candidate: &'a TrustedRecoveryCandidate,
    pub(crate) tx_plan: &'a TrustedTransactionalApplyPlan,
    pub(crate) apply_plan: &'a TrustedApplyPlan,
    pub(crate) bundle: &'a TrustedStagingBundle,
    pub(crate) plan: &'a ThreeWayUpdatePlan,
    pub(crate) review: &'a ThreeWayPlanReview,
    pub(crate) analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
    pub(crate) text_diff: Option<&'a ThreeWayTextDiffPlan>,
    pub(crate) synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
    pub(crate) merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
    pub(crate) baseline: &'a ResolvedOfficialBaseline,
    pub(crate) installed_source: &'a InstalledApplyPlanningSource,
    pub(crate) transaction_root: &'a TrustedTransactionRoot,
    pub(crate) package_path: &'a Path,
    pub(crate) options: TrustedRecoveryOptions,
}

pub(crate) struct TrustedRecoveryExecutionAuthority<'a> {
    pub(crate) tx_plan: &'a TrustedTransactionalApplyPlan,
    pub(crate) apply_plan: &'a TrustedApplyPlan,
    pub(crate) bundle: &'a TrustedStagingBundle,
    pub(crate) resource_key: &'a crate::SafeResourceKey,
    pub(crate) installed_source: &'a InstalledApplyPlanningSource,
    pub(crate) transaction_root: &'a TrustedTransactionRoot,
    pub(crate) options: TrustedRecoveryOptions,
    legacy: Option<LegacyRecoveryExecutionAuthority<'a>>,
}

impl<'a> TrustedRecoveryExecutionAuthority<'a> {
    pub(crate) fn package_free(
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        resource_key: &'a crate::SafeResourceKey,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        options: TrustedRecoveryOptions,
    ) -> Self {
        Self {
            tx_plan,
            apply_plan,
            bundle,
            resource_key,
            installed_source,
            transaction_root,
            options,
            legacy: None,
        }
    }
}

struct LegacyRecoveryExecutionAuthority<'a> {
    pub(crate) tx_plan: &'a TrustedTransactionalApplyPlan,
    pub(crate) apply_plan: &'a TrustedApplyPlan,
    pub(crate) bundle: &'a TrustedStagingBundle,
    pub(crate) plan: &'a ThreeWayUpdatePlan,
    pub(crate) review: &'a ThreeWayPlanReview,
    pub(crate) analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
    pub(crate) text_diff: Option<&'a ThreeWayTextDiffPlan>,
    pub(crate) synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
    pub(crate) merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
    pub(crate) baseline: &'a ResolvedOfficialBaseline,
    pub(crate) installed_source: &'a InstalledApplyPlanningSource,
    pub(crate) options: TrustedRecoveryOptions,
}

impl<'a> TrustedTransactionRecoveryRequest<'a> {
    pub fn try_new(
        candidate: &'a TrustedRecoveryCandidate,
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
        text_diff: Option<&'a ThreeWayTextDiffPlan>,
        synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        package_path: &'a Path,
        options: TrustedRecoveryOptions,
    ) -> Result<Self> {
        options.validate()?;
        if candidate.kind != TrustedRecoveryCandidateKind::Bound
            || candidate.proven_plan_id.is_none()
        {
            return Err(GkrmError::TrustedTransactionRecoveryCandidateInvalid);
        }
        Ok(Self {
            candidate,
            tx_plan,
            apply_plan,
            bundle,
            plan,
            review,
            analysis,
            text_diff,
            synthesis,
            merged_bytes,
            baseline,
            installed_source,
            transaction_root,
            package_path,
            options,
        })
    }

    fn execution_authority(&self) -> TrustedRecoveryExecutionAuthority<'_> {
        let legacy = LegacyRecoveryExecutionAuthority {
            tx_plan: self.tx_plan,
            apply_plan: self.apply_plan,
            bundle: self.bundle,
            plan: self.plan,
            review: self.review,
            analysis: self.analysis,
            text_diff: self.text_diff,
            synthesis: self.synthesis,
            merged_bytes: self.merged_bytes,
            baseline: self.baseline,
            installed_source: self.installed_source,
            options: self.options,
        };
        TrustedRecoveryExecutionAuthority {
            tx_plan: self.tx_plan,
            apply_plan: self.apply_plan,
            bundle: self.bundle,
            resource_key: self.plan.resource_key(),
            installed_source: self.installed_source,
            transaction_root: self.transaction_root,
            options: self.options,
            legacy: Some(legacy),
        }
    }
}

/// Read-only discovery of opaque transaction candidates under the trusted root.
pub fn scan_trusted_transactions(
    root: &TrustedTransactionRoot,
    options: TrustedRecoveryScanOptions,
) -> Result<TrustedRecoveryScanResult> {
    options.validate()?;
    root.revalidate_identity()?;

    let (transactions, entries) = match enumerate_transaction_candidates(root, options)? {
        Some(scan) => scan,
        None => {
            let scan_id = TrustedRecoveryScanResultId(encode_scan_result_id(&[])?);
            return Ok(TrustedRecoveryScanResult {
                scan_id,
                candidates: Vec::new(),
            });
        }
    };

    let mut bound: BTreeMap<Sha256Digest, TrustedRecoveryCandidate> = BTreeMap::new();
    let mut malformed = Vec::new();
    let mut malformed_index = 0_u64;

    for name in entries {
        match inspect_candidate(&transactions, &name, options) {
            Ok(plan_id) => {
                let candidate_id = TrustedRecoveryCandidateId(encode_candidate_id(&plan_id)?);
                bound.insert(
                    plan_id,
                    TrustedRecoveryCandidate {
                        candidate_id,
                        kind: TrustedRecoveryCandidateKind::Bound,
                        proven_plan_id: Some(plan_id),
                    },
                );
            }
            Err(GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported) => {
                return Err(GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported);
            }
            Err(_) => {
                let class = encode_malformed_candidate_id(malformed_index)?;
                malformed_index = malformed_index.saturating_add(1);
                malformed.push(TrustedRecoveryCandidate {
                    candidate_id: TrustedRecoveryCandidateId(class),
                    kind: TrustedRecoveryCandidateKind::Malformed,
                    proven_plan_id: None,
                });
            }
        }
    }

    let mut candidates: Vec<_> = bound.into_values().collect();
    candidates.extend(malformed);
    let plan_ids_for_scan: Vec<_> = candidates.iter().filter_map(|c| c.proven_plan_id).collect();
    let scan_id = TrustedRecoveryScanResultId(encode_scan_result_id(&plan_ids_for_scan)?);
    Ok(TrustedRecoveryScanResult {
        scan_id,
        candidates,
    })
}

/// Internal aggregate-discovery result used by the identifier-free desktop
/// overview. Unlike the public candidate scan, unsupported journal evidence is
/// retained as one independent class so peer candidates can still be inspected.
pub(crate) enum TrustedRecoveryOverviewCandidate {
    Bound(Sha256Digest),
    Malformed,
    Unsupported,
}

pub(crate) fn scan_trusted_transactions_for_overview(
    root: &TrustedTransactionRoot,
    options: TrustedRecoveryScanOptions,
) -> Result<Vec<TrustedRecoveryOverviewCandidate>> {
    options.validate()?;
    root.revalidate_identity()?;
    let Some((transactions, entries)) = enumerate_transaction_candidates(root, options)? else {
        return Ok(Vec::new());
    };

    let mut candidates = Vec::with_capacity(entries.len());
    for name in entries {
        candidates.push(match inspect_candidate(&transactions, &name, options) {
            Ok(plan_id) => TrustedRecoveryOverviewCandidate::Bound(plan_id),
            Err(GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported) => {
                TrustedRecoveryOverviewCandidate::Unsupported
            }
            Err(_) => TrustedRecoveryOverviewCandidate::Malformed,
        });
    }
    Ok(candidates)
}

fn enumerate_transaction_candidates(
    root: &TrustedTransactionRoot,
    options: TrustedRecoveryScanOptions,
) -> Result<Option<(CapDir, Vec<String>)>> {
    let Some(transactions) = try_open_child_dir(root.dir(), "transactions")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?
    else {
        return Ok(None);
    };

    let mut entries = Vec::new();
    let mut total = 0_usize;
    for entry in transactions
        .entries()
        .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?;
        total = total
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionRecoveryLimitExceeded {
                limit: "max_total_scan_entries",
            })?;
        if total > options.max_total_scan_entries {
            return Err(GkrmError::TrustedTransactionRecoveryLimitExceeded {
                limit: "max_total_scan_entries",
            });
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?;
        // Never trust names; .tmp at transaction-root is ignored entirely (not under transactions/).
        entries.push(name);
    }
    entries.sort();
    if entries.len() > options.max_transactions {
        return Err(GkrmError::TrustedTransactionRecoveryLimitExceeded {
            limit: "max_transactions",
        });
    }
    Ok(Some((transactions, entries)))
}

fn inspect_candidate(
    transactions: &CapDir,
    name: &str,
    options: TrustedRecoveryScanOptions,
) -> Result<Sha256Digest> {
    if name.len() > options.max_path_component_bytes {
        return Err(GkrmError::TrustedTransactionRecoveryCandidateInvalid);
    }
    validate_single_component(name)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
    let txn = open_child_dir(transactions, name)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
    let journal = open_child_dir(&txn, "journal")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
    let snapshot_a = read_snapshot_a_binding(&txn)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
    let plan_id = peek_plan_id_from_journal(&journal, options.max_journal_records)?;
    // Directory name binds only after journal proves plan id.
    if name != plan_id.to_string() {
        return Err(GkrmError::TrustedTransactionRecoveryCandidateInvalid);
    }
    let _cursor = load_and_validate_journal_chain(
        &journal,
        &plan_id,
        &snapshot_a,
        options.max_journal_records,
    )
    .map_err(map_journal_scan_error)?;
    Ok(plan_id)
}

fn peek_plan_id_from_journal(journal: &CapDir, max_records: usize) -> Result<Sha256Digest> {
    let mut found: Option<Sha256Digest> = None;
    let mut observed = 0usize;
    for entry in journal
        .entries()
        .map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateJournal, e))?
    {
        observed = observed
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
        if observed > max_records {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
                limit: "max_journal_records",
            });
        }
        let entry =
            entry.map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateJournal, e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionRecoveryJournalInvalid)?;
        if !name.ends_with(".bin") {
            return Err(GkrmError::TrustedTransactionRecoveryJournalInvalid);
        }
        let plan = super::journal::read_journal_plan_id_bounded(journal, &name)
            .map_err(map_journal_scan_error)?;
        match &found {
            None => found = Some(plan),
            Some(existing) if existing == &plan => {}
            Some(_) => return Err(GkrmError::TrustedTransactionRecoveryJournalInvalid),
        }
    }
    found.ok_or(GkrmError::TrustedTransactionRecoveryJournalInvalid)
}

fn map_journal_scan_error(error: GkrmError) -> GkrmError {
    if matches!(
        error,
        GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported
    ) {
        GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported
    } else {
        GkrmError::TrustedTransactionRecoveryJournalInvalid
    }
}

/// Recover exactly one scanned candidate using the complete Task 14–23 artifact chain.
pub fn recover_trusted_transaction(
    request: TrustedTransactionRecoveryRequest<'_>,
) -> Result<TrustedRecoveryResult> {
    request.options.validate()?;
    request.transaction_root.revalidate_identity()?;

    let plan_id = request
        .candidate
        .proven_plan_id
        .ok_or(GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
    if request.tx_plan.plan_id().digest() != &plan_id {
        return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
    }

    // Resource lock → open → identity → transaction lock → reopen+bind → reload authority.
    let verified = match VerifiedPublishedTransaction::acquire(
        request.transaction_root,
        request.plan.resource_key().as_str(),
        &plan_id,
    ) {
        Ok(v) => v,
        Err(GkrmError::TrustedTransactionalApplyExecutionLockContention) => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLockContention);
        }
        Err(_) => return still_required(&plan_id, b"txn-bind"),
    };

    // Discard any pre-lock authority: reload everything from the retained capability.
    request.transaction_root.revalidate_identity()?;
    request
        .installed_source
        .validate_identities()
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
    rebind_package_and_artifacts(&request)?;
    request
        .bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
    verify_published_bundle_readonly(
        request.bundle.published_dir_for_apply_planning(),
        request.bundle.resource_dir_for_apply_planning(),
        request.bundle.manifest(),
    )
    .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;

    let authority = request.execution_authority();
    recover_with_verified(&authority, verified)
}

pub(crate) fn recover_with_verified(
    request: &TrustedRecoveryExecutionAuthority<'_>,
    verified: VerifiedPublishedTransaction,
) -> Result<TrustedRecoveryResult> {
    let plan_id = *request.tx_plan.plan_id().digest();

    verified.reassert(request.transaction_root)?;

    let snapshot_a = read_snapshot_a_binding(&verified.txn_dir)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryJournalInvalid)?;
    let expected_resource_lock = locks::encode_resource_lock_id(request.resource_key.as_str())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    let bound_resource_lock = read_resource_lock_id_binding(&verified.txn_dir)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryJournalInvalid)?;
    if bound_resource_lock != expected_resource_lock {
        return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
    }

    if let Some(blocked) =
        revalidate_peers_or_still_required(request, &verified, &plan_id, &expected_resource_lock)?
    {
        return Ok(blocked);
    }

    if let Some(legacy) = &request.legacy {
        rebind_against_original_snapshot_a(legacy, &snapshot_a)?;
    }

    verified.reassert(request.transaction_root)?;
    let cursor = match load_and_validate_journal_chain(
        &verified.journal_dir,
        &plan_id,
        &snapshot_a,
        request.options.max_journal_records,
    ) {
        Ok(c) => c,
        Err(_) => return still_required(&plan_id, b"invalid-journal"),
    };

    let last = cursor
        .last_event
        .ok_or(GkrmError::TrustedTransactionRecoveryJournalInvalid)?;

    match last {
        TransactionJournalEvent::Prepared | TransactionJournalEvent::BackupComplete => {
            let live = request
                .installed_source
                .capture_tree_snapshot(request.resource_key)
                .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
            if live.fingerprint != snapshot_a
                || !cursor.forward_completed.is_empty()
                || matches!(last, TransactionJournalEvent::Applying)
            {
                return still_required(&plan_id, b"unsafe-abort");
            }
            verified.reassert(request.transaction_root)?;
            durable_safe_abort(request, &verified, cursor, &plan_id, &snapshot_a)
        }
        TransactionJournalEvent::AbortedBeforeMutation => {
            if let Some(blocked) = revalidate_peers_or_still_required(
                request,
                &verified,
                &plan_id,
                &expected_resource_lock,
            )? {
                return Ok(blocked);
            }
            let live = request
                .installed_source
                .capture_tree_snapshot(request.resource_key)
                .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
            if live.fingerprint != snapshot_a || !cursor.forward_completed.is_empty() {
                return still_required(&plan_id, b"abort-drift");
            }
            let result = TrustedRecoveryResult::SafeRestart(SafeRestartTransaction {
                result_id: TrustedRecoveryResultId(encode_recovery_result_id(
                    &plan_id,
                    b"safe-restart-existing",
                    cursor.previous_id.as_ref(),
                )?),
            });
            finalize_readonly_recovery_result(
                request,
                &verified,
                &plan_id,
                &snapshot_a,
                ReadonlyTerminalTip::from_cursor(
                    TransactionJournalEvent::AbortedBeforeMutation,
                    &cursor,
                )?,
                result,
            )
        }
        TransactionJournalEvent::Committed => {
            if let Some(blocked) = revalidate_peers_or_still_required(
                request,
                &verified,
                &plan_id,
                &expected_resource_lock,
            )? {
                return Ok(blocked);
            }
            match probe_desired_state(
                request.bundle,
                request.installed_source,
                request.resource_key,
            ) {
                DesiredStateProbe::ProvenMatch => {
                    let result =
                        TrustedRecoveryResult::RecoveredCommitted(RecoveredCommittedTransaction {
                            result_id: TrustedRecoveryResultId(encode_recovery_result_id(
                                &plan_id,
                                b"recovered-committed",
                                cursor.previous_id.as_ref(),
                            )?),
                        });
                    finalize_readonly_recovery_result(
                        request,
                        &verified,
                        &plan_id,
                        &snapshot_a,
                        ReadonlyTerminalTip::from_cursor(
                            TransactionJournalEvent::Committed,
                            &cursor,
                        )?,
                        result,
                    )
                }
                DesiredStateProbe::ProvenMismatch | DesiredStateProbe::Ambiguous => {
                    // Never auto-rollback committed.
                    still_required(&plan_id, b"committed-drift")
                }
            }
        }
        TransactionJournalEvent::RolledBack => {
            if let Some(blocked) = revalidate_peers_or_still_required(
                request,
                &verified,
                &plan_id,
                &expected_resource_lock,
            )? {
                return Ok(blocked);
            }
            let live = request
                .installed_source
                .capture_tree_snapshot(request.resource_key)
                .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
            if live.fingerprint != snapshot_a {
                return still_required(&plan_id, b"rolledback-drift");
            }
            let result =
                TrustedRecoveryResult::RecoveredRolledBack(RecoveredRolledBackTransaction {
                    result_id: TrustedRecoveryResultId(encode_recovery_result_id(
                        &plan_id,
                        b"recovered-rolled-back",
                        cursor.previous_id.as_ref(),
                    )?),
                });
            finalize_readonly_recovery_result(
                request,
                &verified,
                &plan_id,
                &snapshot_a,
                ReadonlyTerminalTip::from_cursor(TransactionJournalEvent::RolledBack, &cursor)?,
                result,
            )
        }
        TransactionJournalEvent::RecoveryRequired => {
            let result = still_required(&plan_id, b"recovery-required")?;
            finalize_readonly_recovery_result(
                request,
                &verified,
                &plan_id,
                &snapshot_a,
                ReadonlyTerminalTip::from_cursor(
                    TransactionJournalEvent::RecoveryRequired,
                    &cursor,
                )?,
                result,
            )
        }
        TransactionJournalEvent::Applying
        | TransactionJournalEvent::ForwardStepCompleted
        | TransactionJournalEvent::Applied
        | TransactionJournalEvent::Verified
        | TransactionJournalEvent::RollingBack
        | TransactionJournalEvent::RollbackStepCompleted => {
            resume_via_task23_executor(request, &verified, last, &snapshot_a, cursor)
        }
        TransactionJournalEvent::BackupEntryCompleted => {
            still_required(&plan_id, b"incomplete-backup")
        }
    }
}

fn still_required(plan_id: &Sha256Digest, tag: &[u8]) -> Result<TrustedRecoveryResult> {
    Ok(TrustedRecoveryResult::RecoveryStillRequired(
        RecoveryStillRequired {
            result_id: TrustedRecoveryResultId(encode_recovery_result_id(plan_id, tag, None)?),
        },
    ))
}

#[derive(Clone, Copy)]
struct ReadonlyTerminalTip {
    event: TransactionJournalEvent,
    record_id: Sha256Digest,
}

impl ReadonlyTerminalTip {
    fn from_cursor(event: TransactionJournalEvent, cursor: &JournalCursor) -> Result<Self> {
        if cursor.last_event != Some(event) {
            return Err(GkrmError::TrustedTransactionRecoveryJournalInvalid);
        }
        let record_id = cursor
            .previous_id
            .ok_or(GkrmError::TrustedTransactionRecoveryJournalInvalid)?;
        Ok(Self { event, record_id })
    }
}

/// Finalize a read-only terminal rediscovery only after confirming that its
/// selected authority, terminal journal tip, and peer namespace are unchanged.
fn finalize_readonly_recovery_result(
    request: &TrustedRecoveryExecutionAuthority<'_>,
    published: &VerifiedPublishedTransaction,
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    expected_tip: ReadonlyTerminalTip,
    result: TrustedRecoveryResult,
) -> Result<TrustedRecoveryResult> {
    #[cfg(test)]
    super::hooks::fire_peer_race_hook(
        super::hooks::PeerRacePoint::BeforeReadonlyTerminalFinalization,
    );

    if published.reassert(request.transaction_root).is_err() {
        return still_required(plan_id, b"terminal-reassert");
    }
    let cursor = match load_and_validate_journal_chain(
        &published.journal_dir,
        plan_id,
        snapshot_a,
        request.options.max_journal_records,
    ) {
        Ok(cursor) => cursor,
        Err(_) => return still_required(plan_id, b"terminal-tip-invalid"),
    };
    if cursor.last_event != Some(expected_tip.event)
        || cursor.previous_id != Some(expected_tip.record_id)
    {
        return still_required(plan_id, b"terminal-tip-changed");
    }

    let expected_resource_lock = locks::encode_resource_lock_id(request.resource_key.as_str())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    match revalidate_peers_or_still_required(request, published, plan_id, &expected_resource_lock) {
        Ok(Some(blocked)) => Ok(blocked),
        Ok(None) => Ok(result),
        Err(_) => still_required(plan_id, b"terminal-peer-revalidate"),
    }
}

fn desired_fp(request: &TrustedRecoveryExecutionAuthority<'_>) -> Result<Sha256Digest> {
    use crate::trusted_apply_planning::{
        encode_installed_apply_tree_snapshot, parents_of, ApplyFileState,
    };
    use crate::trusted_staging::StagingFinalState;
    use std::collections::{BTreeMap, BTreeSet};

    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    for entry in request.bundle.manifest().entries() {
        match entry.final_state() {
            StagingFinalState::Absent => {}
            StagingFinalState::Installed
            | StagingFinalState::Incoming
            | StagingFinalState::Merged => {
                let digest = *entry
                    .expected_digest()
                    .ok_or(GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
                let len = entry
                    .expected_byte_length()
                    .ok_or(GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
                files.insert(
                    entry.path().clone(),
                    ApplyFileState::Present {
                        digest,
                        byte_length: len,
                    },
                );
                for parent in parents_of(entry.path()) {
                    directories.insert(parent);
                }
            }
        }
    }
    encode_installed_apply_tree_snapshot(&files, &directories)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)
}

fn durable_safe_abort(
    request: &TrustedRecoveryExecutionAuthority<'_>,
    verified: &VerifiedPublishedTransaction,
    mut cursor: JournalCursor,
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
) -> Result<TrustedRecoveryResult> {
    verified.reassert(request.transaction_root)?;
    #[cfg(test)]
    super::hooks::fire_peer_race_hook(super::hooks::PeerRacePoint::BeforeSafeAbortTerminal);
    let expected_resource_lock = locks::encode_resource_lock_id(request.resource_key.as_str())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    if let Some(blocked) =
        revalidate_peers_or_still_required(request, verified, plan_id, &expected_resource_lock)?
    {
        return Ok(blocked);
    }
    let terminal_args = AppendArgs {
        plan_id,
        snapshot_a,
        event: TransactionJournalEvent::AbortedBeforeMutation,
        related_step_id: None,
        related_entry_id: None,
        max_journal_bytes: u64::MAX / 4,
        max_journal_records: request.options.max_journal_records,
    };
    let record_id = crate::trusted_transactional_apply_execution::journal::predict_record_id(
        &cursor,
        &terminal_args,
    )?;
    let result_id = TrustedRecoveryResultId(encode_recovery_result_id(
        plan_id,
        b"safe-restart",
        Some(&record_id),
    )?);
    verified.reassert(request.transaction_root)?;
    let got = append_terminal_record(
        &verified.journal_dir,
        Some(&verified.txn_dir),
        &mut cursor,
        terminal_args,
    )?;
    debug_assert_eq!(got, record_id);
    let _ = got;
    Ok(TrustedRecoveryResult::SafeRestart(SafeRestartTransaction {
        result_id,
    }))
}

fn rebind_package_and_artifacts(request: &TrustedTransactionRecoveryRequest<'_>) -> Result<()> {
    use crate::package_source::PackageSnapshot;

    // Secure package inspection into an immutable snapshot (rejects symlink/reparse/hard-link).
    let package = PackageSnapshot::create(
        request.package_path,
        request.options.max_backup_bytes.max(64 * 1024 * 1024),
    )
    .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
    if package.fingerprint() != request.plan.incoming_package_fingerprint() {
        return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
    }
    // Bind selected resource identity from the original Task 14 plan.
    if request.review.resource_key() != request.plan.resource_key()
        || request.baseline.resource_key() != request.plan.resource_key()
    {
        return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
    }
    if request.tx_plan.apply_plan_id().digest() != request.apply_plan.plan_id().digest()
        || request.tx_plan.bundle_id().digest() != request.bundle.bundle_id().digest()
        || request.tx_plan.manifest_id().digest()
            != request.bundle.manifest().manifest_id().digest()
    {
        return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
    }
    Ok(())
}

fn rebind_against_original_snapshot_a(
    request: &LegacyRecoveryExecutionAuthority<'_>,
    snapshot_a: &Sha256Digest,
) -> Result<()> {
    if request.tx_plan.apply_plan_id().digest() != request.apply_plan.plan_id().digest()
        || request.tx_plan.bundle_id().digest() != request.bundle.bundle_id().digest()
    {
        return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
    }

    let live = request
        .installed_source
        .capture_tree_snapshot(request.plan.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;

    if &live.fingerprint == snapshot_a {
        // Full Task 21/22 recompute when live equals original snapshot A.
        let apply = plan_trusted_apply(
            TrustedApplyPlanningRequest::try_new(
                request.bundle,
                request.plan,
                request.review,
                request.analysis,
                request.text_diff,
                request.synthesis,
                request.merged_bytes,
                request.baseline,
                request.installed_source,
                TrustedApplyPlanningOptions::default(),
            )
            .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?,
        )
        .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
        if apply.plan_id().digest() != request.apply_plan.plan_id().digest() {
            return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
        }
        let tx = plan_trusted_transactional_apply(
            TrustedTransactionalApplyPlanningRequest::try_new(
                request.apply_plan,
                request.bundle,
                request.plan,
                request.review,
                request.analysis,
                request.text_diff,
                request.synthesis,
                request.merged_bytes,
                request.baseline,
                request.installed_source,
                TrustedTransactionalApplyPlanningOptions::default(),
            )
            .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?,
        )
        .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
        if tx.plan_id().digest() != request.tx_plan.plan_id().digest() {
            return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
        }
        return Ok(());
    }

    // Live differs from original A: recompute Task 22 structures using journal snapshot A.
    let backup = build_backup_plan(
        request.apply_plan.plan_id().digest(),
        request.apply_plan.backup_set_id().digest(),
        request.apply_plan.operations(),
        40_000,
        request.options.max_backup_bytes,
    )
    .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
    let (forward, status) = build_forward_steps(
        request.apply_plan.status(),
        request.apply_plan.operations(),
        &backup,
        request.options.max_recovery_steps,
    )
    .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
    let rollback = build_rollback_steps(
        request.apply_plan.operations(),
        &forward.steps,
        &backup,
        request.options.max_recovery_steps,
    )
    .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
    let journal = build_journal_plan(request.options.max_journal_records)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
    let recovery =
        build_recovery_table().map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;

    let summary = TrustedTransactionalApplySummary {
        forward_step_count: forward.steps.len(),
        rollback_step_count: rollback.len(),
        backup_entry_count: backup.entries.len(),
        journal_record_count: journal.records.len(),
        total_expected_write_bytes: forward.total_write_bytes,
        total_backup_bytes: backup.total_backup_bytes(),
    };
    let options_tag = TrustedTransactionalApplyPlanningOptions::default()
        .options_tag()
        .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
    let forward_ids: Vec<_> = forward.steps.iter().map(|s| *s.step_id.digest()).collect();
    let rollback_ids: Vec<_> = rollback.iter().map(|s| *s.step_id().digest()).collect();
    let journal_ids: Vec<_> = journal
        .records
        .iter()
        .map(|r| *r.record_id.digest())
        .collect();
    let recomputed = encode_execution_plan_id(PlanIdInputs {
        apply_plan_id: request.apply_plan.plan_id().digest(),
        review_id: request.review.review_id().digest(),
        analysis_id: request.analysis.map(|a| a.analysis_id().digest()),
        text_diff_id: request.text_diff.map(|t| t.text_diff_plan_id().digest()),
        synthesis_id: request.synthesis.map(|s| s.synthesis_plan_id().digest()),
        merged_bytes_id: request
            .merged_bytes
            .map(|m| m.merged_bytes_plan_id().digest()),
        bundle_id: request.bundle.bundle_id().digest(),
        manifest_id: request.bundle.manifest().manifest_id().digest(),
        resource_key: request.plan.resource_key().as_str(),
        baseline_id: request.plan.baseline_id().as_str(),
        installed_fp: request.plan.installed_snapshot_fingerprint(),
        incoming_package_fp: request.plan.incoming_package_fingerprint(),
        incoming_resource_fp: request.plan.incoming_resource_fingerprint(),
        installed_tree_snapshot_fp: snapshot_a,
        options_tag: &options_tag,
        backup_plan_id: backup.plan_id().digest(),
        forward_step_ids: &forward_ids,
        rollback_step_ids: &rollback_ids,
        journal_record_ids: &journal_ids,
        recovery_table_id: recovery.table_id().digest(),
        summary: &summary,
        status,
    })
    .map_err(|_| GkrmError::TrustedTransactionRecoveryBindingMismatch)?;
    if recomputed.digest() != request.tx_plan.plan_id().digest() {
        return Err(GkrmError::TrustedTransactionRecoveryBindingMismatch);
    }
    let _ = status;
    Ok(())
}

/// Validated durable state of a same-resource peer transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValidatedPeerState {
    pub(crate) plan_id: Sha256Digest,
    pub(crate) last_event: TransactionJournalEvent,
}

/// Tri-state classification of another published transaction under the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SameResourcePeerProbe {
    ProvenDifferentResource,
    ProvenSameResource(ValidatedPeerState),
    AmbiguousPotentialConflict,
}

/// Outcome of a point-of-use peer-namespace validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerValidationOutcome {
    Clear,
    ConflictOrAmbiguous,
}

/// Read-only gate for Task 25: block plan/apply when any same-resource or
/// ambiguous published transaction exists under the root.
pub(crate) fn same_resource_recovery_blocks_new_work(
    root: &TrustedTransactionRoot,
    resource_key: &crate::SafeResourceKey,
    max_journal_records: usize,
) -> Result<bool> {
    root.revalidate_identity()
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
    let expected = locks::encode_resource_lock_id(resource_key.as_str())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    let transactions = match try_open_child_dir(root.dir(), "transactions") {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(false),
        Err(_) => return Err(GkrmError::TrustedTransactionRecoveryScanUnsafe),
    };
    let retired_plan_ids = match root.workspace() {
        Some(_) => {
            match crate::trusted_package_free_update_recovery::validated_retired_terminal_plan_ids(
                root,
                max_journal_records,
            ) {
                Ok(ids) => ids,
                Err(_) => return Ok(true),
            }
        }
        None => BTreeSet::new(),
    };
    let mut names = Vec::new();
    for entry in transactions
        .entries()
        .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?;
        if name == ".tmp" {
            continue;
        }
        if validate_single_component(&name).is_err() {
            return Ok(true);
        }
        names.push(name);
    }
    names.sort();
    for name in names {
        match probe_same_resource_peer(&transactions, &name, &expected, max_journal_records) {
            SameResourcePeerProbe::ProvenDifferentResource => {}
            SameResourcePeerProbe::ProvenSameResource(state)
                if is_terminal_event(state.last_event)
                    && retired_plan_ids.contains(&state.plan_id) => {}
            SameResourcePeerProbe::ProvenSameResource(_)
            | SameResourcePeerProbe::AmbiguousPotentialConflict => {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Probe one published peer directory for same-resource conflict potential.
fn probe_same_resource_peer(
    transactions: &cap_std::fs::Dir,
    name: &str,
    expected_resource_lock: &Sha256Digest,
    max_journal_records: usize,
) -> SameResourcePeerProbe {
    if validate_single_component(name).is_err() {
        return SameResourcePeerProbe::AmbiguousPotentialConflict;
    }
    let txn = match open_child_dir(transactions, name) {
        Ok(d) => d,
        Err(_) => return SameResourcePeerProbe::AmbiguousPotentialConflict,
    };
    if dir_identity(&txn, "peer-transaction").is_err() {
        return SameResourcePeerProbe::AmbiguousPotentialConflict;
    }

    let other_lock =
        match crate::trusted_transactional_apply_execution::read_resource_lock_id_binding(&txn) {
            Ok(id) => id,
            Err(_) => return SameResourcePeerProbe::AmbiguousPotentialConflict,
        };
    if &other_lock != expected_resource_lock {
        // Positively proven irrelevant to the selected installed resource.
        return SameResourcePeerProbe::ProvenDifferentResource;
    }

    // Appears to target the same resource: full peer authority required.
    let plan_id = match Sha256Digest::from_lowercase_hex(name) {
        Ok(id) => id,
        Err(_) => return SameResourcePeerProbe::AmbiguousPotentialConflict,
    };
    let snapshot_a = match read_snapshot_a_binding(&txn) {
        Ok(s) => s,
        Err(_) => return SameResourcePeerProbe::AmbiguousPotentialConflict,
    };
    let journal = match try_open_child_dir(&txn, "journal") {
        Ok(Some(j)) => j,
        Ok(None) | Err(_) => return SameResourcePeerProbe::AmbiguousPotentialConflict,
    };
    if dir_identity(&journal, "peer-journal").is_err() {
        return SameResourcePeerProbe::AmbiguousPotentialConflict;
    }
    let cursor =
        match load_and_validate_journal_chain(&journal, &plan_id, &snapshot_a, max_journal_records)
        {
            Ok(c) => c,
            Err(_) => return SameResourcePeerProbe::AmbiguousPotentialConflict,
        };
    let Some(last_event) = cursor.last_event else {
        return SameResourcePeerProbe::AmbiguousPotentialConflict;
    };
    SameResourcePeerProbe::ProvenSameResource(ValidatedPeerState {
        plan_id,
        last_event,
    })
}

fn is_terminal_event(event: TransactionJournalEvent) -> bool {
    matches!(
        event,
        TransactionJournalEvent::Committed
            | TransactionJournalEvent::RolledBack
            | TransactionJournalEvent::AbortedBeforeMutation
    )
}

/// Point-of-use peer validation: never trust an earlier peer enumeration.
///
/// Reasserts the selected transaction, reopens `transactions/` through the verified
/// root, excludes the selected directory by proven identity, and tri-state probes
/// every sibling. Same-resource or ambiguous peers yield [`PeerValidationOutcome::ConflictOrAmbiguous`].
pub(crate) fn revalidate_no_conflicting_peers(
    root: &TrustedTransactionRoot,
    published: &VerifiedPublishedTransaction,
    selected_resource_lock_id: &Sha256Digest,
    limits: &TrustedRecoveryOptions,
) -> Result<PeerValidationOutcome> {
    published.reassert(root)?;
    let retired_plan_ids = match root.workspace() {
        Some(_) => {
            match crate::trusted_package_free_update_recovery::validated_retired_terminal_plan_ids(
                root,
                limits.max_journal_records,
            ) {
                Ok(ids) => ids,
                Err(_) => return Ok(PeerValidationOutcome::ConflictOrAmbiguous),
            }
        }
        None => BTreeSet::new(),
    };

    let transactions = try_open_child_dir(root.dir(), "transactions")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?
        .ok_or(GkrmError::TrustedTransactionRecoveryScanUnsafe)?;
    let parent_id = dir_identity(&transactions, "transactions")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
    if parent_id != published.transactions_parent_identity {
        return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
    }
    let retained_parent_id = dir_identity(&published.transactions_parent, "transactions")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
    if retained_parent_id != published.transactions_parent_identity {
        return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
    }

    let scan_defaults = TrustedRecoveryScanOptions::default();
    let mut names = Vec::new();
    let mut case_keys = BTreeSet::new();
    let mut total = 0_usize;
    for entry in transactions
        .entries()
        .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?;
        total = total
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionRecoveryLimitExceeded {
                limit: "max_total_scan_entries",
            })?;
        if total > scan_defaults.max_total_scan_entries {
            return Err(GkrmError::TrustedTransactionRecoveryLimitExceeded {
                limit: "max_total_scan_entries",
            });
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionRecoveryScanUnsafe)?;
        if name.len() > limits.max_path_component_bytes {
            return Ok(PeerValidationOutcome::ConflictOrAmbiguous);
        }
        if validate_single_component(&name).is_err() {
            return Ok(PeerValidationOutcome::ConflictOrAmbiguous);
        }
        let folded = case_collision_key(&name);
        if !case_keys.insert(folded) {
            return Ok(PeerValidationOutcome::ConflictOrAmbiguous);
        }
        names.push(name);
    }
    names.sort();
    if names.len() > scan_defaults.max_transactions {
        return Err(GkrmError::TrustedTransactionRecoveryLimitExceeded {
            limit: "max_transactions",
        });
    }

    for name in names {
        let txn = match open_child_dir(&transactions, &name) {
            Ok(d) => d,
            Err(_) => return Ok(PeerValidationOutcome::ConflictOrAmbiguous),
        };
        let first_id = match dir_identity(&txn, "peer-transaction") {
            Ok(id) => id,
            Err(_) => return Ok(PeerValidationOutcome::ConflictOrAmbiguous),
        };
        // Drop the open handle before the stability re-open so a racing
        // replacement is observable (Windows may refuse rename while held).
        drop(txn);
        if first_id != published.txn_identity {
            #[cfg(test)]
            super::hooks::fire_peer_race_hook(super::hooks::PeerRacePoint::DuringPeerEnumeration);
        }
        let reopened = match open_child_dir(&transactions, &name) {
            Ok(d) => d,
            Err(_) => return Ok(PeerValidationOutcome::ConflictOrAmbiguous),
        };
        let second_id = match dir_identity(&reopened, "peer-transaction") {
            Ok(id) => id,
            Err(_) => return Ok(PeerValidationOutcome::ConflictOrAmbiguous),
        };
        if first_id != second_id {
            return Ok(PeerValidationOutcome::ConflictOrAmbiguous);
        }
        if first_id == published.txn_identity {
            continue;
        }
        match probe_same_resource_peer(
            &transactions,
            &name,
            selected_resource_lock_id,
            limits.max_journal_records,
        ) {
            SameResourcePeerProbe::ProvenDifferentResource => {}
            SameResourcePeerProbe::ProvenSameResource(state)
                if is_terminal_event(state.last_event)
                    && retired_plan_ids.contains(&state.plan_id) => {}
            SameResourcePeerProbe::ProvenSameResource(_)
            | SameResourcePeerProbe::AmbiguousPotentialConflict => {
                return Ok(PeerValidationOutcome::ConflictOrAmbiguous);
            }
        }
    }
    Ok(PeerValidationOutcome::Clear)
}

/// Revalidate peers and map conflict/ambiguity to `RecoveryStillRequired`.
pub(crate) fn revalidate_peers_or_still_required(
    request: &TrustedRecoveryExecutionAuthority<'_>,
    published: &VerifiedPublishedTransaction,
    plan_id: &Sha256Digest,
    selected_resource_lock_id: &Sha256Digest,
) -> Result<Option<TrustedRecoveryResult>> {
    match revalidate_no_conflicting_peers(
        request.transaction_root,
        published,
        selected_resource_lock_id,
        &request.options,
    )? {
        PeerValidationOutcome::Clear => Ok(None),
        PeerValidationOutcome::ConflictOrAmbiguous => {
            Ok(Some(still_required(plan_id, b"conflict")?))
        }
    }
}

fn resume_via_task23_executor(
    request: &TrustedRecoveryExecutionAuthority<'_>,
    verified: &VerifiedPublishedTransaction,
    last: TransactionJournalEvent,
    snapshot_a: &Sha256Digest,
    cursor: JournalCursor,
) -> Result<TrustedRecoveryResult> {
    let plan_id = *request.tx_plan.plan_id().digest();
    match last {
        TransactionJournalEvent::Applied | TransactionJournalEvent::Verified => {
            match probe_desired_state(
                request.bundle,
                request.installed_source,
                request.resource_key,
            ) {
                DesiredStateProbe::ProvenMatch => {
                    return finalize_commit_like(request, verified, &plan_id, snapshot_a, cursor);
                }
                DesiredStateProbe::ProvenMismatch => {
                    return rollback_like(request, verified, &plan_id, snapshot_a, cursor);
                }
                DesiredStateProbe::Ambiguous => {
                    return still_required(&plan_id, b"desired-ambiguous");
                }
            }
        }
        TransactionJournalEvent::Applying
        | TransactionJournalEvent::ForwardStepCompleted
        | TransactionJournalEvent::RollingBack
        | TransactionJournalEvent::RollbackStepCompleted => {
            return rollback_like(request, verified, &plan_id, snapshot_a, cursor);
        }
        _ => {}
    }
    still_required(&plan_id, b"resume-boundary")
}

fn finalize_commit_like(
    request: &TrustedRecoveryExecutionAuthority<'_>,
    verified: &VerifiedPublishedTransaction,
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    mut cursor: JournalCursor,
) -> Result<TrustedRecoveryResult> {
    verified.reassert(request.transaction_root)?;
    #[cfg(test)]
    super::hooks::fire_peer_race_hook(super::hooks::PeerRacePoint::BeforeCommitDesiredState);
    let expected_resource_lock = locks::encode_resource_lock_id(request.resource_key.as_str())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    if let Some(blocked) =
        revalidate_peers_or_still_required(request, verified, plan_id, &expected_resource_lock)?
    {
        return Ok(blocked);
    }
    let backup_seal = cursor
        .backup_seal
        .ok_or(GkrmError::TrustedTransactionRecoveryJournalInvalid)?;

    // Re-probe under locks; Ambiguous/Mismatch must not commit.
    match probe_desired_state(
        request.bundle,
        request.installed_source,
        request.resource_key,
    ) {
        DesiredStateProbe::ProvenMatch => {}
        DesiredStateProbe::ProvenMismatch => {
            return still_required(plan_id, b"commit-live-mismatch");
        }
        DesiredStateProbe::Ambiguous => {
            return still_required(plan_id, b"commit-live-ambiguous");
        }
    }

    let live = request
        .installed_source
        .capture_tree_snapshot(request.resource_key)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
    let desired = desired_fp(request)?;

    if cursor.last_event != Some(TransactionJournalEvent::Verified) {
        let verification_seal =
            crate::trusted_transactional_apply_execution::id::encode_verification_seal(
                plan_id,
                snapshot_a,
                &live.fingerprint,
                &desired,
            )?;
        cursor.verification_seal = Some(verification_seal);
        verified.reassert(request.transaction_root)?;
        #[cfg(test)]
        super::hooks::fire_peer_race_hook(super::hooks::PeerRacePoint::BeforeVerifiedAppend);
        if let Some(blocked) =
            revalidate_peers_or_still_required(request, verified, plan_id, &expected_resource_lock)?
        {
            return Ok(blocked);
        }
        crate::trusted_transactional_apply_execution::journal::append_record(
            &verified.journal_dir,
            &mut cursor,
            AppendArgs {
                plan_id,
                snapshot_a,
                event: TransactionJournalEvent::Verified,
                related_step_id: None,
                related_entry_id: None,
                max_journal_bytes: u64::MAX / 4,
                max_journal_records: request.options.max_journal_records,
            },
        )?;
    }

    let verification_seal = cursor
        .verification_seal
        .ok_or(GkrmError::TrustedTransactionRecoveryJournalInvalid)?;
    let last_id = cursor
        .previous_id
        .ok_or(GkrmError::TrustedTransactionRecoveryJournalInvalid)?;
    let commit_seal = crate::trusted_transactional_apply_execution::id::encode_commit_seal(
        plan_id,
        &backup_seal,
        &verification_seal,
        &last_id,
    )?;
    cursor.commit_seal = Some(commit_seal);
    let terminal_args = AppendArgs {
        plan_id,
        snapshot_a,
        event: TransactionJournalEvent::Committed,
        related_step_id: None,
        related_entry_id: None,
        max_journal_bytes: u64::MAX / 4,
        max_journal_records: request.options.max_journal_records,
    };
    let committed_id = crate::trusted_transactional_apply_execution::journal::predict_record_id(
        &cursor,
        &terminal_args,
    )?;
    let result_id = TrustedRecoveryResultId(encode_recovery_result_id(
        plan_id,
        b"recovered-committed",
        Some(&committed_id),
    )?);
    verified.reassert(request.transaction_root)?;
    #[cfg(test)]
    super::hooks::fire_peer_race_hook(super::hooks::PeerRacePoint::BeforeCommitTerminalAppend);
    if let Some(blocked) =
        revalidate_peers_or_still_required(request, verified, plan_id, &expected_resource_lock)?
    {
        return Ok(blocked);
    }
    let got = append_terminal_record(
        &verified.journal_dir,
        Some(&verified.txn_dir),
        &mut cursor,
        terminal_args,
    )?;
    debug_assert_eq!(got, committed_id);
    let _ = got;
    Ok(TrustedRecoveryResult::RecoveredCommitted(
        RecoveredCommittedTransaction { result_id },
    ))
}

fn rollback_like(
    request: &TrustedRecoveryExecutionAuthority<'_>,
    verified: &VerifiedPublishedTransaction,
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    cursor: JournalCursor,
) -> Result<TrustedRecoveryResult> {
    verified.reassert(request.transaction_root)?;
    #[cfg(test)]
    super::hooks::fire_peer_race_hook(super::hooks::PeerRacePoint::BeforeBackupRevalidate);
    let expected_resource_lock = locks::encode_resource_lock_id(request.resource_key.as_str())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    if let Some(blocked) =
        revalidate_peers_or_still_required(request, verified, plan_id, &expected_resource_lock)?
    {
        return Ok(blocked);
    }
    if cursor.backup_seal.is_none() {
        return still_required(plan_id, b"incomplete-backup-mutation");
    }
    let seal = cursor.backup_seal.expect("checked");

    // Complete sealed backup revalidation before any rollback mutation.
    if crate::trusted_transactional_apply_execution::backup::revalidate_sealed_backup_for_recovery(
        &verified.txn_dir,
        plan_id,
        request.tx_plan.backup().entries(),
        &seal,
    )
    .is_err()
    {
        return still_required(plan_id, b"backup-revalidate");
    }

    verified.reassert(request.transaction_root)?;
    super::recovery_run_rollback(request, verified, cursor, snapshot_a)
}
