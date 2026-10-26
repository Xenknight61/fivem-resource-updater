//! Positive publication-state classification for Task 25 apply failure mapping.
//!
//! Classification is strictly read-only: reopen/inspect only; never create locks,
//! append journals, create/remove directories, or mutate installed trees.

use std::path::Path;

use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{dir_identity, open_child_dir, try_open_child_dir};
use crate::file_identity::StableFileIdentity;
use crate::installed_path::case_collision_key;
use crate::trusted_transactional_apply_execution::TrustedTransactionRoot;
use crate::{
    scan_trusted_transactions, GkrmError, Sha256Digest, TrustedRecoveryCandidateKind,
    TrustedRecoveryScanOptions,
};

use super::limits::TrustedCliUpdateOptions;

/// Positive classification of whether Task 23 published the rebound transaction plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyFailurePublicationState {
    /// Exact absence proven twice under a stable existing `transactions/` parent.
    ProvenNotPublished,
    /// Exact rebound Task 22 plan publication proven via capability/journal authority.
    Published,
    /// Scan, revalidation, I/O, or unsafe-object ambiguity — never claim pre-publication safety.
    Ambiguous,
}

/// Typed probe of the exact plan-named transaction child under an open parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactTransactionProbe {
    ProvenAbsent,
    PresentTrusted,
    PresentUnsafe,
    Ambiguous,
}

/// Securely classify whether the rebound transactional plan was published.
///
/// Absence is never inferred from a missing `transactions/` parent, failed opens,
/// root/parent replacement, malformed journal, incomplete scan, or arbitrary errors.
pub(crate) fn classify_apply_failure_publication_state(
    transaction_root: &Path,
    transactional_plan_id: &Sha256Digest,
    options: &TrustedCliUpdateOptions,
) -> ApplyFailurePublicationState {
    let root = match TrustedTransactionRoot::try_open(transaction_root) {
        Ok(root) => root,
        Err(_) => return ApplyFailurePublicationState::Ambiguous,
    };
    if root.revalidate_identity().is_err() {
        return ApplyFailurePublicationState::Ambiguous;
    }

    #[cfg(test)]
    classify_hooks::fire_before_parent_open(root.path_for_disjointness(), transactional_plan_id);

    // Missing parent is Ambiguous — never "publication did not happen".
    let transactions = match try_open_child_dir(root.dir(), "transactions") {
        Ok(Some(dir)) => dir,
        Ok(None) | Err(_) => return ApplyFailurePublicationState::Ambiguous,
    };
    let parent_identity = match dir_identity(&transactions, "transactions") {
        Ok(id) => id,
        Err(_) => return ApplyFailurePublicationState::Ambiguous,
    };
    // Drop the first handle before probing/reopening so parent replacement is observable.
    drop(transactions);

    let plan_hex = transactional_plan_id.to_string();
    match probe_exact_transaction_child(root.dir(), &plan_hex, &parent_identity) {
        ExactTransactionProbe::ProvenAbsent => {}
        ExactTransactionProbe::PresentTrusted => {
            return prove_published_plan_via_scan(&root, transactional_plan_id, options);
        }
        ExactTransactionProbe::PresentUnsafe | ExactTransactionProbe::Ambiguous => {
            return ApplyFailurePublicationState::Ambiguous;
        }
    }

    if root.revalidate_identity().is_err() {
        return ApplyFailurePublicationState::Ambiguous;
    }

    #[cfg(test)]
    classify_hooks::fire_between_absence_probes(
        root.path_for_disjointness(),
        transactional_plan_id,
    );

    // Second observation: reopen parent from root, require same identity, re-probe absence.
    let transactions_again = match try_open_child_dir(root.dir(), "transactions") {
        Ok(Some(dir)) => dir,
        Ok(None) | Err(_) => return ApplyFailurePublicationState::Ambiguous,
    };
    let parent_again = match dir_identity(&transactions_again, "transactions") {
        Ok(id) => id,
        Err(_) => return ApplyFailurePublicationState::Ambiguous,
    };
    if parent_again != parent_identity {
        return ApplyFailurePublicationState::Ambiguous;
    }
    drop(transactions_again);

    if root.revalidate_identity().is_err() {
        return ApplyFailurePublicationState::Ambiguous;
    }

    match probe_exact_transaction_child(root.dir(), &plan_hex, &parent_identity) {
        ExactTransactionProbe::ProvenAbsent => {
            if root.revalidate_identity().is_err() {
                return ApplyFailurePublicationState::Ambiguous;
            }
            // Confirm parent identity still matches after the second absence.
            let final_parent = match try_open_child_dir(root.dir(), "transactions") {
                Ok(Some(dir)) => dir,
                Ok(None) | Err(_) => return ApplyFailurePublicationState::Ambiguous,
            };
            match dir_identity(&final_parent, "transactions") {
                Ok(id) if id == parent_identity => ApplyFailurePublicationState::ProvenNotPublished,
                _ => ApplyFailurePublicationState::Ambiguous,
            }
        }
        ExactTransactionProbe::PresentTrusted => {
            prove_published_plan_via_scan(&root, transactional_plan_id, options)
        }
        ExactTransactionProbe::PresentUnsafe | ExactTransactionProbe::Ambiguous => {
            ApplyFailurePublicationState::Ambiguous
        }
    }
}

/// Fail closed on case-colliding names or unreadable enumeration in the parent.
/// Returns whether the exact plan_hex name was listed.
fn parent_enumeration_check(parent: &CapDir, plan_hex: &str) -> Result<bool, ()> {
    let entries = parent.entries().map_err(|_| ())?;
    let target_key = case_collision_key(plan_hex);
    let mut saw_exact = false;
    let mut case_keys = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name().into_string().map_err(|_| ())?;
        let folded = case_collision_key(&name);
        if !case_keys.insert(folded.clone()) {
            return Err(());
        }
        if folded == target_key {
            if name == plan_hex {
                saw_exact = true;
            } else {
                // Case-colliding distinct spelling for the plan id.
                return Err(());
            }
        }
    }
    Ok(saw_exact)
}

/// Probe the exact plan-named child under a parent whose identity must still match `expected`.
fn probe_exact_transaction_child(
    root_dir: &CapDir,
    plan_hex: &str,
    expected_parent_identity: &StableFileIdentity,
) -> ExactTransactionProbe {
    let parent = match try_open_child_dir(root_dir, "transactions") {
        Ok(Some(dir)) => dir,
        Ok(None) | Err(_) => return ExactTransactionProbe::Ambiguous,
    };
    let parent_id = match dir_identity(&parent, "transactions") {
        Ok(id) => id,
        Err(_) => return ExactTransactionProbe::Ambiguous,
    };
    if &parent_id != expected_parent_identity {
        return ExactTransactionProbe::Ambiguous;
    }

    let saw_exact = match parent_enumeration_check(&parent, plan_hex) {
        Ok(v) => v,
        Err(()) => return ExactTransactionProbe::Ambiguous,
    };

    match open_child_dir(&parent, plan_hex) {
        Ok(_dir) => ExactTransactionProbe::PresentTrusted,
        Err(GkrmError::BaselineStoreMissing { .. }) => {
            // Listed exact name but open reports missing → TOCTOU/ambiguous.
            if saw_exact {
                ExactTransactionProbe::Ambiguous
            } else {
                ExactTransactionProbe::ProvenAbsent
            }
        }
        Err(GkrmError::BaselineStoreUnexpectedType { .. })
        | Err(GkrmError::BaselineStoreSymlink { .. }) => ExactTransactionProbe::PresentUnsafe,
        Err(_) => ExactTransactionProbe::Ambiguous,
    }
}

fn prove_published_plan_via_scan(
    root: &TrustedTransactionRoot,
    transactional_plan_id: &Sha256Digest,
    options: &TrustedCliUpdateOptions,
) -> ApplyFailurePublicationState {
    if root.revalidate_identity().is_err() {
        return ApplyFailurePublicationState::Ambiguous;
    }
    let scan = scan_trusted_transactions(
        root,
        TrustedRecoveryScanOptions {
            max_transactions: options.max_transactions,
            max_journal_records: options.max_journal_records,
            ..TrustedRecoveryScanOptions::default()
        },
    );
    match scan {
        Ok(result) => {
            if result.candidates().iter().any(|c| {
                c.kind() == TrustedRecoveryCandidateKind::Bound
                    && c.proven_plan_id.as_ref() == Some(transactional_plan_id)
            }) {
                ApplyFailurePublicationState::Published
            } else {
                // Present but journal/authority did not prove Bound.
                ApplyFailurePublicationState::Ambiguous
            }
        }
        Err(_) => ApplyFailurePublicationState::Ambiguous,
    }
}

/// Map a non-terminal Task 23 execution error using positive publication-state classification.
///
/// `SafeFailureBeforePublication` is returned only for [`ApplyFailurePublicationState::ProvenNotPublished`].
pub(crate) fn outcome_for_classified_apply_failure(
    publication: ApplyFailurePublicationState,
) -> &'static str {
    match publication {
        ApplyFailurePublicationState::ProvenNotPublished => "safe_failure_before_publication",
        ApplyFailurePublicationState::Published => "published_recovery_unsealed",
        ApplyFailurePublicationState::Ambiguous => "recovery_still_required",
    }
}

/// Test-only race injection for publication-state classification.
#[cfg(test)]
pub(crate) mod classify_hooks {
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};
    use std::thread::ThreadId;

    use crate::Sha256Digest;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum BetweenAbsenceRace {
        /// Remove `transactions/` entirely.
        RemoveTransactions,
        /// Replace `transactions/` with a newly created empty directory (new identity).
        ReplaceTransactionsEmpty,
        /// Insert an empty plan-named child directory.
        InsertPlanChild,
        /// Insert then remove/recreate plan child (presence flicker).
        RecreatePlanChild,
    }

    struct ClassifyHooks {
        owner: ThreadId,
        before_parent_open: Option<BetweenAbsenceRace>,
        between_absence_probes: Option<BetweenAbsenceRace>,
    }

    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    static HOOKS: Mutex<Option<ClassifyHooks>> = Mutex::new(None);

    pub(crate) struct ClassifyHookGuard {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for ClassifyHookGuard {
        fn drop(&mut self) {
            *HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
    }

    pub(crate) fn lock_classify_hooks() -> ClassifyHookGuard {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        *HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = Some(ClassifyHooks {
            owner: std::thread::current().id(),
            before_parent_open: None,
            between_absence_probes: None,
        });
        ClassifyHookGuard { _guard: guard }
    }

    fn with_hooks_mut(f: impl FnOnce(&mut ClassifyHooks)) {
        let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(hooks) = hooks.as_mut() {
            if hooks.owner == std::thread::current().id() {
                f(hooks);
            }
        }
    }

    pub(crate) fn set_before_parent_open(race: Option<BetweenAbsenceRace>) {
        with_hooks_mut(|h| h.before_parent_open = race);
    }

    pub(crate) fn set_between_absence_probes(race: Option<BetweenAbsenceRace>) {
        with_hooks_mut(|h| h.between_absence_probes = race);
    }

    fn take_before() -> Option<BetweenAbsenceRace> {
        let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        hooks.as_mut().and_then(|h| {
            if h.owner == std::thread::current().id() {
                h.before_parent_open.take()
            } else {
                None
            }
        })
    }

    fn take_between() -> Option<BetweenAbsenceRace> {
        let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        hooks.as_mut().and_then(|h| {
            if h.owner == std::thread::current().id() {
                h.between_absence_probes.take()
            } else {
                None
            }
        })
    }

    pub(crate) fn fire_before_parent_open(root: &Path, plan_id: &Sha256Digest) {
        if let Some(race) = take_before() {
            apply_race(root, plan_id, race);
        }
    }

    pub(crate) fn fire_between_absence_probes(root: &Path, plan_id: &Sha256Digest) {
        if let Some(race) = take_between() {
            apply_race(root, plan_id, race);
        }
    }

    fn apply_race(root: &Path, plan_id: &Sha256Digest, race: BetweenAbsenceRace) {
        use std::fs;

        let transactions = root.join("transactions");
        let plan_hex = plan_id.to_string();
        let child = transactions.join(&plan_hex);
        match race {
            BetweenAbsenceRace::RemoveTransactions => {
                let _ = fs::remove_dir_all(&transactions);
            }
            BetweenAbsenceRace::ReplaceTransactionsEmpty => {
                let _ = fs::remove_dir_all(&transactions);
                let _ = fs::create_dir_all(&transactions);
            }
            BetweenAbsenceRace::InsertPlanChild => {
                let _ = fs::create_dir_all(&child);
            }
            BetweenAbsenceRace::RecreatePlanChild => {
                let _ = fs::create_dir_all(&child);
                let _ = fs::remove_dir_all(&child);
                let _ = fs::create_dir_all(&child);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    use crate::Sha256Digest;

    fn plan_digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    #[test]
    fn missing_transactions_parent_is_ambiguous_never_not_published() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(&root).unwrap();
        let plan = plan_digest(0x42);
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::Ambiguous);
        assert_eq!(
            outcome_for_classified_apply_failure(state),
            "recovery_still_required"
        );
        assert_ne!(
            outcome_for_classified_apply_failure(state),
            "safe_failure_before_publication"
        );
    }

    #[test]
    fn stable_existing_parent_with_double_absence_is_proven_not_published() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(root.join("transactions")).unwrap();
        let plan = plan_digest(0x42);
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::ProvenNotPublished);
        assert_eq!(
            outcome_for_classified_apply_failure(state),
            "safe_failure_before_publication"
        );
    }

    #[test]
    fn ambiguous_when_plan_named_directory_lacks_bound_authority() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        let plan = plan_digest(0x43);
        let plan_hex = plan.to_string();
        fs::create_dir_all(root.join("transactions").join(&plan_hex)).unwrap();
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::Ambiguous);
        assert_eq!(
            outcome_for_classified_apply_failure(state),
            "recovery_still_required"
        );
    }

    #[test]
    fn parent_replaced_between_observations_is_ambiguous() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(root.join("transactions")).unwrap();
        let plan = plan_digest(0x44);
        let _guard = classify_hooks::lock_classify_hooks();
        classify_hooks::set_between_absence_probes(Some(
            classify_hooks::BetweenAbsenceRace::ReplaceTransactionsEmpty,
        ));
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::Ambiguous);
    }

    #[test]
    fn parent_removed_between_observations_is_ambiguous() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(root.join("transactions")).unwrap();
        let plan = plan_digest(0x45);
        let _guard = classify_hooks::lock_classify_hooks();
        classify_hooks::set_between_absence_probes(Some(
            classify_hooks::BetweenAbsenceRace::RemoveTransactions,
        ));
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::Ambiguous);
    }

    #[test]
    fn plan_child_inserted_between_observations_never_not_published() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(root.join("transactions")).unwrap();
        let plan = plan_digest(0x46);
        let _guard = classify_hooks::lock_classify_hooks();
        classify_hooks::set_between_absence_probes(Some(
            classify_hooks::BetweenAbsenceRace::InsertPlanChild,
        ));
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_ne!(state, ApplyFailurePublicationState::ProvenNotPublished);
        assert!(matches!(
            state,
            ApplyFailurePublicationState::Published | ApplyFailurePublicationState::Ambiguous
        ));
    }

    #[test]
    fn plan_child_recreated_between_observations_never_not_published() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(root.join("transactions")).unwrap();
        let plan = plan_digest(0x47);
        let _guard = classify_hooks::lock_classify_hooks();
        classify_hooks::set_between_absence_probes(Some(
            classify_hooks::BetweenAbsenceRace::RecreatePlanChild,
        ));
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_ne!(state, ApplyFailurePublicationState::ProvenNotPublished);
    }

    #[test]
    fn transactions_removed_before_open_is_ambiguous() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(root.join("transactions")).unwrap();
        let plan = plan_digest(0x48);
        let _guard = classify_hooks::lock_classify_hooks();
        classify_hooks::set_before_parent_open(Some(
            classify_hooks::BetweenAbsenceRace::RemoveTransactions,
        ));
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::Ambiguous);
    }

    #[test]
    fn unsafe_file_at_plan_name_is_ambiguous_not_absent() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        let plan = plan_digest(0x49);
        let plan_hex = plan.to_string();
        fs::create_dir_all(root.join("transactions")).unwrap();
        fs::write(root.join("transactions").join(&plan_hex), b"not-a-dir").unwrap();
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::Ambiguous);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_transactions_parent_is_ambiguous() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        let real = temp.path().join("real-transactions");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.join("transactions")).unwrap();
        let plan = plan_digest(0x4b);
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::Ambiguous);
        assert_ne!(
            outcome_for_classified_apply_failure(state),
            "safe_failure_before_publication"
        );
    }

    #[test]
    fn safe_failure_requires_proven_not_published() {
        assert_eq!(
            outcome_for_classified_apply_failure(ApplyFailurePublicationState::ProvenNotPublished),
            "safe_failure_before_publication"
        );
        for state in [
            ApplyFailurePublicationState::Published,
            ApplyFailurePublicationState::Ambiguous,
        ] {
            assert_ne!(
                outcome_for_classified_apply_failure(state),
                "safe_failure_before_publication"
            );
            assert_eq!(
                outcome_for_classified_apply_failure(state),
                match state {
                    ApplyFailurePublicationState::Published => "published_recovery_unsealed",
                    ApplyFailurePublicationState::Ambiguous => "recovery_still_required",
                    ApplyFailurePublicationState::ProvenNotPublished => unreachable!(),
                }
            );
        }
    }

    #[test]
    fn outcome_invariant_safe_failure_implies_stable_double_absence() {
        // SafeFailureBeforePublication may only follow ProvenNotPublished, which itself
        // requires an existing stable transactions/ parent and two ProvenAbsent probes.
        let temp = tempdir().unwrap();
        let root = temp.path().join("txn");
        fs::create_dir_all(root.join("transactions")).unwrap();
        let plan = plan_digest(0x4a);
        let state = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(state, ApplyFailurePublicationState::ProvenNotPublished);
        assert!(root.join("transactions").is_dir());
        assert!(!root.join("transactions").join(plan.to_string()).exists());
        assert_eq!(
            outcome_for_classified_apply_failure(state),
            "safe_failure_before_publication"
        );

        // Any instability must not yield safe-prepublication.
        let _guard = classify_hooks::lock_classify_hooks();
        classify_hooks::set_between_absence_probes(Some(
            classify_hooks::BetweenAbsenceRace::ReplaceTransactionsEmpty,
        ));
        let unstable = classify_apply_failure_publication_state(
            &root,
            &plan,
            &TrustedCliUpdateOptions::default(),
        );
        assert_eq!(
            outcome_for_classified_apply_failure(unstable),
            "recovery_still_required"
        );
    }
}
