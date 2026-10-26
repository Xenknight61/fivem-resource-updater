#![cfg(all(feature = "desktop-test-support", debug_assertions))]

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Mutex;
use std::time::Duration;

use crate::trusted_transactional_apply_execution::hooks::{
    lock_execution_hooks, set_forward_op_fault, set_journal_fault, set_publication_hook,
    ForwardOpFault, JournalFault, PublicationPoint,
};

static SEALED_SNAPSHOT_BARRIER: Mutex<Option<SealedSnapshotBarrierState>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopTransactionFault {
    PanicBeforeBackup,
    JournalForwardStepCompleted,
    ForwardReplace,
    PanicAfterFilePublish,
}

pub fn with_transaction_fault<T>(fault: DesktopTransactionFault, run: impl FnOnce() -> T) -> T {
    let _guard = lock_execution_hooks();
    match fault {
        DesktopTransactionFault::PanicBeforeBackup => {
            set_publication_hook(PublicationPoint::BeforeBackup, || {
                panic!("desktop test crash before backup")
            });
        }
        DesktopTransactionFault::JournalForwardStepCompleted => {
            set_journal_fault(Some(JournalFault::ForwardStepCompleted));
        }
        DesktopTransactionFault::ForwardReplace => {
            set_forward_op_fault(Some(ForwardOpFault::ReplaceFile));
        }
        DesktopTransactionFault::PanicAfterFilePublish => {
            set_publication_hook(PublicationPoint::AfterFilePublish, || {
                panic!("desktop test crash after file publication")
            });
        }
    }
    run()
}

/// Re-seal a published v2 fixture around a deliberately unsupported but
/// internally consistent recovery derivation version.
pub fn make_unsupported_recovery_derivation(
    workspace: &crate::TrustedUpdateWorkspace,
) -> crate::Result<()> {
    crate::trusted_cli_update_artifact::make_unsupported_derivation_for_desktop_test(workspace)
}

struct SealedSnapshotBarrierState {
    transaction_root: PathBuf,
    artifact_root: PathBuf,
    sealed_tx: SyncSender<PathBuf>,
    resume_rx: Receiver<()>,
    skip_before_signal: usize,
}

pub struct SealedSnapshotBarrier {
    sealed_rx: Receiver<PathBuf>,
    resume_tx: SyncSender<()>,
}

impl SealedSnapshotBarrier {
    pub fn wait_for_snapshot_sealed(&self) -> PathBuf {
        self.sealed_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("SNAPSHOT_SEALED barrier was not reached")
    }

    pub fn resume_after_tamper(&self) {
        self.resume_tx
            .send(())
            .expect("TAMPER_COMPLETE barrier receiver was dropped")
    }
}

impl Drop for SealedSnapshotBarrier {
    fn drop(&mut self) {
        let mut barrier = SEALED_SNAPSHOT_BARRIER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        barrier.take();
    }
}

pub fn install_sealed_snapshot_barrier_for_transaction_root(
    transaction_root: &Path,
    artifact_root: &Path,
) -> SealedSnapshotBarrier {
    install_sealed_snapshot_barrier_for_transaction_root_after_skipping(
        transaction_root,
        artifact_root,
        0,
    )
}

pub fn install_sealed_snapshot_barrier_for_transaction_root_after_skipping(
    transaction_root: &Path,
    artifact_root: &Path,
    skip_before_signal: usize,
) -> SealedSnapshotBarrier {
    let (sealed_tx, sealed_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let mut barrier = SEALED_SNAPSHOT_BARRIER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        barrier.is_none(),
        "sealed snapshot barrier already installed"
    );
    *barrier = Some(SealedSnapshotBarrierState {
        transaction_root: transaction_root.to_path_buf(),
        artifact_root: artifact_root.to_path_buf(),
        sealed_tx,
        resume_rx,
        skip_before_signal,
    });
    SealedSnapshotBarrier {
        sealed_rx,
        resume_tx,
    }
}

pub(crate) fn sealed_snapshot_verified_before_staging(
    snapshot_root: &Path,
    transaction_root: &Path,
    artifact_out: &Path,
) {
    let state = {
        let mut barrier = SEALED_SNAPSHOT_BARRIER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(state) = barrier.as_mut() {
            if state.transaction_root != transaction_root
                || !artifact_out.starts_with(&state.artifact_root)
            {
                return;
            }
            if state.skip_before_signal > 0 {
                state.skip_before_signal -= 1;
                return;
            }
        }
        barrier.take()
    };
    let Some(state) = state else {
        return;
    };
    state
        .sealed_tx
        .send(snapshot_root.to_path_buf())
        .expect("SNAPSHOT_SEALED barrier receiver was dropped");
    state
        .resume_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("TAMPER_COMPLETE barrier was not reached");
}
