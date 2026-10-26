//! Retained published-transaction capability binding for Task 24 recovery.

use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{dir_identity, open_child_dir, try_open_child_dir};
use crate::file_identity::StableFileIdentity;
use crate::trusted_transactional_apply_execution::locks::{self, HeldTransactionLocks};
use crate::trusted_transactional_apply_execution::TrustedTransactionRoot;
use crate::{GkrmError, Result, Sha256Digest};

/// One retained, identity-verified published transaction under held locks.
pub(crate) struct VerifiedPublishedTransaction {
    pub(crate) transactions_parent: CapDir,
    pub(crate) transactions_parent_identity: StableFileIdentity,
    pub(crate) txn_dir: CapDir,
    pub(crate) txn_identity: StableFileIdentity,
    pub(crate) plan_hex: String,
    pub(crate) journal_dir: CapDir,
    pub(crate) journal_identity: StableFileIdentity,
    pub(crate) _locks: HeldTransactionLocks,
}

impl VerifiedPublishedTransaction {
    /// Acquire resource lock, open candidate, lock transaction, reopen+bind identity.
    pub(crate) fn acquire(
        root: &TrustedTransactionRoot,
        resource_key: &str,
        plan_id: &Sha256Digest,
    ) -> Result<Self> {
        Self::acquire_inner(root, resource_key, plan_id, None)
    }

    pub(crate) fn acquire_with_expected_namespace(
        root: &TrustedTransactionRoot,
        resource_key: &str,
        plan_id: &Sha256Digest,
        expected_parent: &StableFileIdentity,
        expected_txn: &StableFileIdentity,
        expected_journal: &StableFileIdentity,
    ) -> Result<Self> {
        Self::acquire_inner(
            root,
            resource_key,
            plan_id,
            Some((expected_parent, expected_txn, expected_journal)),
        )
    }

    fn acquire_inner(
        root: &TrustedTransactionRoot,
        resource_key: &str,
        plan_id: &Sha256Digest,
        expected: Option<(
            &StableFileIdentity,
            &StableFileIdentity,
            &StableFileIdentity,
        )>,
    ) -> Result<Self> {
        let plan_hex = plan_id.to_string();
        let resource_lock = locks::acquire_resource_lock(root.dir(), resource_key)?;

        let transactions_parent = try_open_child_dir(root.dir(), "transactions")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?
            .ok_or(GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
        let parent_identity = dir_identity(&transactions_parent, "transactions")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;

        let opened = open_child_dir(&transactions_parent, &plan_hex)
            .map_err(|_| GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
        let txn_identity = dir_identity(&opened, "transaction")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if expected
            .is_some_and(|(parent, txn, _)| parent != &parent_identity || txn != &txn_identity)
        {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        let transaction_lock = locks::acquire_transaction_lock(&opened, plan_id)?;
        let _locks = locks::HeldSplitLocks {
            resource: resource_lock,
            transaction: transaction_lock,
        }
        .into_held();

        // Reopen published name through parent; require exact identity equality.
        let reopened = open_child_dir(&transactions_parent, &plan_hex)
            .map_err(|_| GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
        let reopened_id = dir_identity(&reopened, "transaction")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if reopened_id != txn_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }
        let retained_id = dir_identity(&opened, "transaction")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if retained_id != txn_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        // Rebind parent through the root under locks and require identity equality.
        let parent_rebound = try_open_child_dir(root.dir(), "transactions")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?
            .ok_or(GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        let parent_rebound_id = dir_identity(&parent_rebound, "transactions")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if parent_rebound_id != parent_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        let txn_through_rebound = open_child_dir(&parent_rebound, &plan_hex)
            .map_err(|_| GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
        let txn_through_rebound_id = dir_identity(&txn_through_rebound, "transaction")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if txn_through_rebound_id != txn_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        let journal_dir = try_open_child_dir(&txn_through_rebound, "journal")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?
            .ok_or(GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        let journal_identity = dir_identity(&journal_dir, "journal")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if expected.is_some_and(|(_, _, journal)| journal != &journal_identity) {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        Ok(Self {
            transactions_parent: parent_rebound,
            transactions_parent_identity: parent_identity,
            txn_dir: txn_through_rebound,
            txn_identity,
            plan_hex,
            journal_dir,
            journal_identity,
            _locks,
        })
    }

    /// Rebind root → transactions → txn → journal and require retained identities.
    pub(crate) fn reassert(&self, root: &TrustedTransactionRoot) -> Result<()> {
        root.revalidate_identity()
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;

        let parent = try_open_child_dir(root.dir(), "transactions")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?
            .ok_or(GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        let parent_id = dir_identity(&parent, "transactions")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if parent_id != self.transactions_parent_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }
        let retained_parent_id = dir_identity(&self.transactions_parent, "transactions")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if retained_parent_id != self.transactions_parent_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        let txn = open_child_dir(&parent, &self.plan_hex)
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        let txn_id = dir_identity(&txn, "transaction")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if txn_id != self.txn_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }
        let retained_txn_id = dir_identity(&self.txn_dir, "transaction")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if retained_txn_id != self.txn_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        let journal = try_open_child_dir(&txn, "journal")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?
            .ok_or(GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        let journal_id = dir_identity(&journal, "journal")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if journal_id != self.journal_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }
        let retained_journal_id = dir_identity(&self.journal_dir, "journal")
            .map_err(|_| GkrmError::TrustedTransactionRecoveryRevalidationFailed)?;
        if retained_journal_id != self.journal_identity {
            return Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed);
        }

        Ok(())
    }
}
