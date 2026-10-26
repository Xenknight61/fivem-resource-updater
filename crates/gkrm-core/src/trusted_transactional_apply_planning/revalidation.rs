//! Read-only staging/installed revalidation for Task 22.

use crate::trusted_apply_planning::{ApplyFileState, InstalledApplyTreeSnapshot};
use crate::trusted_staging::verify_published_bundle_readonly;
use crate::{
    ApplyPlanningIoOperation, GkrmError, ResourceRelativePath, Result,
    TransactionalApplyPlanningIoOperation, TrustedApplyOperation, TrustedApplyOperationKind,
};

use super::TrustedTransactionalApplyPlanningRequest;

pub(super) struct RevalidatedTrees {
    pub(super) installed_tree_snapshot_fp: crate::Sha256Digest,
    pub(super) file_fp: crate::Sha256Digest,
}

pub(super) fn staging_verify(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    note_staging_read();
    request
        .bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningStagingRevalidationFailed)?;
    verify_published_bundle_readonly(
        request.bundle.published_dir_for_apply_planning(),
        request.bundle.resource_dir_for_apply_planning(),
        request.bundle.manifest(),
    )
    .map_err(map_staging_verify)?;
    if let crate::trusted_apply_planning::ApplyPlanningSource::Undo { staged } = request.source {
        staged.verify_directories().map_err(map_staging_verify)?;
    }
    Ok(())
}

pub(super) fn capture_and_check_preconditions(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<RevalidatedTrees> {
    let snapshot = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(map_installed)?;
    validate_undo_snapshot(request, &snapshot)?;
    let file_fp = snapshot
        .file_only_plan_fingerprint(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningInstalledStale)?;
    if &file_fp != request.source.installed_fingerprint() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningInstalledStale);
    }

    for op in request.apply_plan.operations() {
        verify_operation_precondition(op, &snapshot)?;
    }

    Ok(RevalidatedTrees {
        installed_tree_snapshot_fp: snapshot.fingerprint,
        file_fp,
    })
}

pub(super) fn capture_snapshot_b(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
    expected: &RevalidatedTrees,
) -> Result<()> {
    let snapshot = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(map_installed)?;
    if snapshot.fingerprint != expected.installed_tree_snapshot_fp {
        return Err(GkrmError::TrustedTransactionalApplyPlanningInstalledStale);
    }
    let file_fp = snapshot
        .file_only_plan_fingerprint(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningInstalledStale)?;
    if file_fp != expected.file_fp || &file_fp != request.source.installed_fingerprint() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningInstalledStale);
    }
    Ok(())
}

pub(super) fn validate_persisted_snapshot_preconditions(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
    snapshot: &InstalledApplyTreeSnapshot,
) -> Result<RevalidatedTrees> {
    validate_undo_snapshot(request, snapshot)?;
    let file_fp = snapshot
        .file_only_plan_fingerprint(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningInstalledStale)?;
    if &file_fp != request.source.installed_fingerprint() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningInstalledStale);
    }
    for operation in request.apply_plan.operations() {
        verify_operation_precondition(operation, snapshot)?;
    }
    Ok(RevalidatedTrees {
        installed_tree_snapshot_fp: snapshot.fingerprint,
        file_fp,
    })
}

fn validate_undo_snapshot(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
    snapshot: &InstalledApplyTreeSnapshot,
) -> Result<()> {
    if let crate::trusted_apply_planning::ApplyPlanningSource::Undo { staged } = request.source {
        staged
            .validate_installed_binding(request.installed_source)
            .map_err(map_installed)?;
        if &snapshot.fingerprint != staged.current_tree_fingerprint() {
            return Err(GkrmError::TrustedTransactionalApplyPlanningInstalledStale);
        }
    }
    Ok(())
}

fn verify_operation_precondition(
    op: &TrustedApplyOperation,
    snapshot: &InstalledApplyTreeSnapshot,
) -> Result<()> {
    match op.kind() {
        TrustedApplyOperationKind::DeleteFile | TrustedApplyOperationKind::ReplaceFile => {
            match op.pre_state() {
                ApplyFileState::Present {
                    digest,
                    byte_length,
                } => match snapshot.files.get(op.destination()) {
                    Some(ApplyFileState::Present {
                        digest: got_d,
                        byte_length: got_l,
                    }) if got_d == digest && got_l == byte_length => Ok(()),
                    _ => Err(GkrmError::TrustedTransactionalApplyPlanningPreconditionMismatch),
                },
                ApplyFileState::Absent => {
                    Err(GkrmError::TrustedTransactionalApplyPlanningPreconditionMismatch)
                }
            }
        }
        TrustedApplyOperationKind::InstallFile => match op.pre_state() {
            ApplyFileState::Absent => {
                if snapshot.files.contains_key(op.destination()) {
                    return Err(GkrmError::TrustedTransactionalApplyPlanningPreconditionMismatch);
                }
                // Directory currently at path is OK for dir→file (removed in earlier phase).
                Ok(())
            }
            ApplyFileState::Present { .. } => {
                Err(GkrmError::TrustedTransactionalApplyPlanningPreconditionMismatch)
            }
        },
        TrustedApplyOperationKind::CreateDirectory => {
            // Task 21 plans create when dir missing or file occupies path.
            let _ = op.destination();
            Ok(())
        }
        TrustedApplyOperationKind::RemoveDirectory => {
            if snapshot.directories.contains(op.destination()) {
                Ok(())
            } else {
                Err(GkrmError::TrustedTransactionalApplyPlanningPreconditionMismatch)
            }
        }
    }
}

fn map_staging_verify(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::TrustedStagingUnsafeFilesystemObject
        | GkrmError::TrustedStagingManifestTreeMismatch
        | GkrmError::TrustedStagingDigestLengthMismatch
        | GkrmError::TrustedStagingRootReplaced
        | GkrmError::TrustedApplyPlanningStagingRevalidationFailed
        | GkrmError::TrustedTransactionalApplyPlanningStagingRevalidationFailed => {
            GkrmError::TrustedTransactionalApplyPlanningStagingRevalidationFailed
        }
        GkrmError::TrustedStagingIo { operation: _, kind }
        | GkrmError::TrustedApplyPlanningIo { operation: _, kind } => {
            GkrmError::TrustedTransactionalApplyPlanningIo {
                operation: TransactionalApplyPlanningIoOperation::ReadManifest,
                kind,
            }
        }
        other => {
            let _ = other;
            GkrmError::TrustedTransactionalApplyPlanningStagingRevalidationFailed
        }
    }
}

fn map_installed(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::TrustedApplyPlanningInstalledStale
        | GkrmError::TrustedTransactionalApplyPlanningInstalledStale => {
            GkrmError::TrustedTransactionalApplyPlanningInstalledStale
        }
        GkrmError::TrustedApplyPlanningIo { operation, kind } => {
            GkrmError::TrustedTransactionalApplyPlanningIo {
                operation: map_io_op(operation),
                kind,
            }
        }
        other => {
            let _ = other;
            GkrmError::TrustedTransactionalApplyPlanningInstalledStale
        }
    }
}

fn map_io_op(operation: ApplyPlanningIoOperation) -> TransactionalApplyPlanningIoOperation {
    match operation {
        ApplyPlanningIoOperation::OpenInstalledRoot => {
            TransactionalApplyPlanningIoOperation::OpenInstalledRoot
        }
        ApplyPlanningIoOperation::OpenInstalledResource => {
            TransactionalApplyPlanningIoOperation::OpenInstalledResource
        }
        ApplyPlanningIoOperation::ScanInstalled => {
            TransactionalApplyPlanningIoOperation::ScanInstalled
        }
        ApplyPlanningIoOperation::EnumerateInstalled => {
            TransactionalApplyPlanningIoOperation::EnumerateInstalled
        }
        ApplyPlanningIoOperation::OpenStagingPublished => {
            TransactionalApplyPlanningIoOperation::OpenStagingPublished
        }
        ApplyPlanningIoOperation::OpenStagingResource => {
            TransactionalApplyPlanningIoOperation::OpenStagingResource
        }
        ApplyPlanningIoOperation::ReadManifest => {
            TransactionalApplyPlanningIoOperation::ReadManifest
        }
        ApplyPlanningIoOperation::HashFile => TransactionalApplyPlanningIoOperation::HashFile,
        ApplyPlanningIoOperation::VerifyRegularFile => {
            TransactionalApplyPlanningIoOperation::VerifyRegularFile
        }
        ApplyPlanningIoOperation::RevalidateIdentity => {
            TransactionalApplyPlanningIoOperation::RevalidateIdentity
        }
    }
}

fn note_staging_read() {
    #[cfg(test)]
    super::note_staging_read_count();
}

#[allow(dead_code)]
fn _path_type(_path: &ResourceRelativePath) {}
