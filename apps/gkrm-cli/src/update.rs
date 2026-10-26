//! Thin CLI adapter for Task 25 trusted update orchestration.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use gkrm_core::{
    apply_trusted_cli_update_in_workspace,
    open_existing_trusted_update_workspace_from_explicit_roots,
    plan_trusted_cli_update_in_workspace, recover_trusted_cli_update_in_workspace,
    resolve_trusted_update_workspace_from_explicit_roots, retire_trusted_terminal_update_evidence,
    status_trusted_cli_update, status_trusted_cli_update_in_workspace, BaselineId,
    ExistingExplicitTrustedUpdateWorkspaceRequest, ExplicitTrustedUpdateWorkspaceRequest,
    GkrmError, OfficialBaselineSelector, SafeResourceKey, TrustedCliApplyRequest,
    TrustedCliPlanRequest, TrustedCliRecoverRequest, TrustedCliReport, TrustedCliStatusRequest,
    TrustedCliUpdateOptions, TrustedTerminalEvidenceRetirementOptions, TrustedUpdateWorkspace,
};
use serde::Serialize;

use crate::{CliFailure, EXIT_UNEXPECTED};

pub const EXIT_PENDING: i32 = 10;
pub const EXIT_MANUAL: i32 = 11;
pub const EXIT_ROLLED_BACK: i32 = 12;
pub const EXIT_RECOVERY: i32 = 13;
pub const EXIT_INVALID: i32 = 20;
pub const EXIT_REBIND: i32 = 21;
pub const EXIT_LOCK: i32 = 22;
pub const EXIT_SECURITY: i32 = 23;
pub const EXIT_INTERNAL: i32 = 30;

#[derive(Debug, Subcommand)]
pub enum UpdateCommand {
    Plan(UpdatePlanArgs),
    Apply(UpdateApplyArgs),
    Status(UpdateStatusArgs),
    Recover(UpdateRecoverArgs),
    Finalize(UpdateFinalizeArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Human,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct UpdatePlanArgs {
    #[arg(long)]
    pub package: PathBuf,
    #[arg(long)]
    pub installed: PathBuf,
    #[arg(long)]
    pub baseline_store: PathBuf,
    #[arg(long)]
    pub baseline_id: Option<String>,
    #[arg(long)]
    pub baseline_auto_single: bool,
    #[arg(long)]
    pub resource: Option<String>,
    #[arg(long)]
    pub staging_root: PathBuf,
    #[arg(long)]
    pub transaction_root: PathBuf,
    #[arg(long)]
    pub decisions: Option<PathBuf>,
    #[arg(long)]
    pub decisions_out: Option<PathBuf>,
    #[arg(long)]
    pub operator_merge_root: Option<PathBuf>,
    #[arg(long)]
    pub artifact_out: PathBuf,
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct UpdateApplyArgs {
    #[arg(long)]
    pub artifact: PathBuf,
    #[arg(long)]
    pub package: PathBuf,
    #[arg(long)]
    pub installed: PathBuf,
    #[arg(long)]
    pub baseline_store: PathBuf,
    #[arg(long)]
    pub baseline_id: Option<String>,
    #[arg(long)]
    pub baseline_auto_single: bool,
    #[arg(long)]
    pub resource: Option<String>,
    #[arg(long)]
    pub staging_root: PathBuf,
    #[arg(long)]
    pub transaction_root: PathBuf,
    #[arg(long)]
    pub decisions: Option<PathBuf>,
    #[arg(long)]
    pub operator_merge_root: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct UpdateStatusArgs {
    #[arg(long)]
    pub transaction_root: PathBuf,
    #[arg(long)]
    pub baseline_store: Option<PathBuf>,
    #[arg(long)]
    pub staging_root: Option<PathBuf>,
    #[arg(long)]
    pub artifact_root: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct UpdateFinalizeArgs {
    #[arg(long)]
    pub baseline_store: PathBuf,
    #[arg(long)]
    pub staging_root: PathBuf,
    #[arg(long)]
    pub transaction_root: PathBuf,
    #[arg(long)]
    pub artifact_root: PathBuf,
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct UpdateRecoverArgs {
    #[arg(long)]
    pub candidate: String,
    #[arg(long)]
    pub artifact: PathBuf,
    #[arg(long)]
    pub package: PathBuf,
    #[arg(long)]
    pub installed: PathBuf,
    #[arg(long)]
    pub baseline_store: PathBuf,
    #[arg(long)]
    pub baseline_id: Option<String>,
    #[arg(long)]
    pub baseline_auto_single: bool,
    #[arg(long)]
    pub resource: Option<String>,
    #[arg(long)]
    pub staging_root: PathBuf,
    #[arg(long)]
    pub transaction_root: PathBuf,
    #[arg(long)]
    pub decisions: Option<PathBuf>,
    #[arg(long)]
    pub operator_merge_root: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Serialize)]
struct ReportJson {
    schema_version: u8,
    outcome: &'static str,
    pending_paths: Vec<String>,
    artifact_id: Option<String>,
    candidate_selectors: Vec<String>,
    bound_candidates: usize,
    malformed_candidates: usize,
}

#[derive(Serialize)]
struct FinalizeReportJson {
    schema_version: u8,
    outcome: &'static str,
    finalized_terminal_evidence: usize,
    already_finalized_terminal_evidence: usize,
}

fn baseline_selector(
    baseline_id: Option<&str>,
    auto_single: bool,
) -> Result<OfficialBaselineSelector, CliFailure> {
    match (baseline_id, auto_single) {
        (Some(id), false) => {
            let parsed = BaselineId::parse(id).map_err(|_| CliFailure {
                exit_code: EXIT_INVALID,
                code: "invalid_baseline_id",
                message: "Baseline ID is invalid.",
            })?;
            Ok(OfficialBaselineSelector::Exact(parsed))
        }
        (None, true) => Ok(OfficialBaselineSelector::AutoSingle),
        _ => Err(CliFailure {
            exit_code: EXIT_INVALID,
            code: "invalid_baseline_selector",
            message: "Provide exactly one of --baseline-id or --baseline-auto-single.",
        }),
    }
}

fn parse_resource(value: Option<&str>) -> Result<Option<SafeResourceKey>, CliFailure> {
    match value {
        None => Ok(None),
        Some(v) => SafeResourceKey::parse(v).map(Some).map_err(|_| CliFailure {
            exit_code: EXIT_INVALID,
            code: "invalid_resource",
            message: "Resource key is invalid.",
        }),
    }
}

fn managed_artifact_root(path: &std::path::Path) -> Result<&std::path::Path, CliFailure> {
    let name = path.file_name().and_then(|name| name.to_str());
    if !matches!(name, Some(name) if name.starts_with("plan-") && name.ends_with(".bin")) {
        return Err(CliFailure {
            exit_code: EXIT_INVALID,
            code: "invalid_artifact_name",
            message: "Managed update artifacts must use a plan-*.bin filename.",
        });
    }
    path.parent().ok_or(CliFailure {
        exit_code: EXIT_INVALID,
        code: "invalid_input",
        message: "Invalid update input.",
    })
}

fn render(report: &TrustedCliReport, format: Format) -> Result<String, CliFailure> {
    match format {
        Format::Human => {
            let mut out = format!("outcome: {}\n", report.outcome);
            if report.outcome == "published_recovery_unsealed" {
                out.push_str(
                    "A published transaction requires recovery inspection.\nRun gkrm update status, then gkrm update recover with an exact candidate selector.\n",
                );
            }
            if report.outcome == "published_recovery_failed" {
                out.push_str(
                    "Automatic rollback/recovery completion failed for a published transaction.\nRun gkrm update status, then gkrm update recover with an exact candidate selector.\n",
                );
            }
            if !report.pending_paths.is_empty() {
                out.push_str("pending:\n");
                for p in &report.pending_paths {
                    out.push_str(&format!("  {p}\n"));
                }
            }
            if let Some(id) = &report.artifact_id_hex {
                out.push_str(&format!("artifact: {id}\n"));
            }
            if !report.candidate_selectors.is_empty() {
                out.push_str("candidates:\n");
                for c in &report.candidate_selectors {
                    out.push_str(&format!("  {c}\n"));
                }
            }
            Ok(out)
        }
        Format::Json => {
            let dto = ReportJson {
                schema_version: 1,
                outcome: report.outcome,
                pending_paths: report.pending_paths.clone(),
                artifact_id: report.artifact_id_hex.clone(),
                candidate_selectors: report.candidate_selectors.clone(),
                bound_candidates: report.bound_candidates,
                malformed_candidates: report.malformed_candidates,
            };
            serde_json::to_string_pretty(&dto)
                .map(|mut s| {
                    s.push('\n');
                    s
                })
                .map_err(|_| CliFailure {
                    exit_code: EXIT_UNEXPECTED,
                    code: "render_failed",
                    message: "Failed to render JSON output.",
                })
        }
    }
}

/// Report what this invocation actually did. A pass that publishes no new
/// retirement record must not claim it finalized evidence.
fn finalize_outcome(retired: usize, already_retired: usize) -> &'static str {
    match (retired, already_retired) {
        (0, 0) => "nothing_to_finalize",
        (0, _) => "already_finalized",
        _ => "finalized",
    }
}

fn render_finalize(
    retired: usize,
    already_retired: usize,
    format: Format,
) -> Result<String, CliFailure> {
    let outcome = finalize_outcome(retired, already_retired);
    match format {
        Format::Human => Ok(format!(
            "outcome: {outcome}\nfinalized terminal evidence: {retired}\nalready finalized terminal evidence: {already_retired}\n"
        )),
        Format::Json => serde_json::to_string_pretty(&FinalizeReportJson {
            schema_version: 1,
            outcome,
            finalized_terminal_evidence: retired,
            already_finalized_terminal_evidence: already_retired,
        })
        .map(|mut output| {
            output.push('\n');
            output
        })
        .map_err(|_| CliFailure {
            exit_code: EXIT_UNEXPECTED,
            code: "render_failed",
            message: "Failed to render JSON output.",
        }),
    }
}

fn open_status_workspace(
    args: &UpdateStatusArgs,
) -> Result<Option<TrustedUpdateWorkspace>, CliFailure> {
    match (
        args.baseline_store.as_deref(),
        args.staging_root.as_deref(),
        args.artifact_root.as_deref(),
    ) {
        (None, None, None) => Ok(None),
        (Some(baseline_store), Some(staging_root), Some(artifact_root)) => {
            open_existing_trusted_update_workspace_from_explicit_roots(
                ExistingExplicitTrustedUpdateWorkspaceRequest {
                    baseline_store,
                    staging_root,
                    transaction_root: &args.transaction_root,
                    artifact_root,
                },
            )
            .map(Some)
            .map_err(map_update_error)
        }
        _ => Err(CliFailure {
            exit_code: EXIT_INVALID,
            code: "invalid_workspace_roots",
            message: "Provide all managed workspace roots or only --transaction-root for compatibility status.",
        }),
    }
}

pub fn map_update_error(error: GkrmError) -> CliFailure {
    match error {
        GkrmError::TrustedCliUpdateOptionsInvalid { .. }
        | GkrmError::TrustedCliUpdateResourceSelectionRequired
        | GkrmError::TrustedCliUpdateResourceNotFound
        | GkrmError::TrustedCliUpdateResourceAmbiguous
        | GkrmError::TrustedCliUpdateDecisionsInvalid
        | GkrmError::TrustedCliUpdateDecisionsPlanMismatch
        | GkrmError::TrustedCliUpdateDestinationExists
        | GkrmError::TrustedCliUpdateCandidateNotFound
        | GkrmError::TrustedCliUpdateCandidateAmbiguous => CliFailure {
            exit_code: EXIT_INVALID,
            code: "invalid_input",
            message: "Invalid update input.",
        },
        GkrmError::TrustedCliUpdateBindingMismatch
        | GkrmError::TrustedCliUpdateArtifactInvalid
        | GkrmError::TrustedCliUpdateArtifactVersionUnsupported => CliFailure {
            exit_code: EXIT_REBIND,
            code: "rebinding_mismatch",
            message: "Trusted bindings did not match.",
        },
        GkrmError::TrustedTransactionalApplyExecutionLockContention => CliFailure {
            exit_code: EXIT_LOCK,
            code: "lock_contention",
            message: "Resource or transaction lock contention.",
        },
        GkrmError::TrustedCliUpdateSecurityRejection
        | GkrmError::TrustedCliUpdatePathOverlap
        | GkrmError::TrustedCliUpdateOperatorMergeInvalid
        | GkrmError::TrustedUpdateWorkspaceInvalid => CliFailure {
            exit_code: EXIT_SECURITY,
            code: "security_rejection",
            message: "Security rejection.",
        },
        // Same refusal and same exit code as any other withheld authority, but named so the
        // operator knows the cause is a recognized pre-release layout rather than damaged
        // evidence. The workspace is never migrated, rewritten, or cleaned up.
        GkrmError::TrustedUpdateWorkspaceLegacyUnsupported => CliFailure {
            exit_code: EXIT_SECURITY,
            code: "legacy_workspace_unsupported",
            message: "Managed workspace uses an unsupported pre-release layout. \
                      Recreate the managed workspace at a new trusted parent and keep the \
                      existing evidence for manual attention.",
        },
        GkrmError::TrustedUpdateWorkspaceCapacityReached => CliFailure {
            exit_code: EXIT_INVALID,
            code: "workspace_capacity_reached",
            message: "Workspace capacity has been reached.",
        },
        GkrmError::TrustedCliUpdateRecoveryRequired
        | GkrmError::TrustedCliUpdateTransactionAlreadyPublished
        | GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery { .. }
        | GkrmError::TrustedTransactionalApplyExecutionFailedCompound { .. } => CliFailure {
            exit_code: EXIT_RECOVERY,
            code: "recovery_required",
            message: "Recovery is required before continuing. Run gkrm update status.",
        },
        GkrmError::TrustedTerminalEvidenceRetirementBlocked => CliFailure {
            exit_code: EXIT_RECOVERY,
            code: "finalization_blocked",
            message: "Terminal finalization is blocked by unresolved recovery evidence.",
        },
        GkrmError::TrustedTerminalEvidenceRetirementAcknowledgementRequired
        | GkrmError::TrustedTerminalEvidenceRetirementInvalid
        | GkrmError::TrustedTerminalEvidenceRetirementVersionUnsupported
        | GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded { .. } => CliFailure {
            exit_code: EXIT_SECURITY,
            code: "finalization_rejected",
            message: "Terminal finalization evidence was rejected.",
        },
        _ => CliFailure {
            exit_code: EXIT_INTERNAL,
            code: "update_failed",
            message: "Trusted update orchestration failed.",
        },
    }
}

pub fn exit_for_outcome(outcome: &str) -> i32 {
    match outcome {
        "ready_to_apply"
        | "committed"
        | "status"
        | "safe_restart"
        | "recovered_committed"
        | "recovered_rolled_back" => crate::EXIT_SUCCESS,
        "pending_decisions" => EXIT_PENDING,
        "manual_merge_required" => EXIT_MANUAL,
        "rolled_back" => EXIT_ROLLED_BACK,
        "recovery_required"
        | "recovery_still_required"
        | "published_recovery_unsealed"
        | "published_recovery_failed" => EXIT_RECOVERY,
        "safe_failure_before_publication" => EXIT_INTERNAL,
        _ => EXIT_UNEXPECTED,
    }
}

pub fn run_update(command: UpdateCommand) -> Result<(String, i32), CliFailure> {
    match command {
        UpdateCommand::Plan(args) => {
            let selector =
                baseline_selector(args.baseline_id.as_deref(), args.baseline_auto_single)?;
            let resource = parse_resource(args.resource.as_deref())?;
            let artifact_root = managed_artifact_root(&args.artifact_out)?;
            let workspace = resolve_trusted_update_workspace_from_explicit_roots(
                ExplicitTrustedUpdateWorkspaceRequest {
                    baseline_store: &args.baseline_store,
                    staging_root: &args.staging_root,
                    transaction_root: &args.transaction_root,
                    artifact_root,
                    artifact_out: &args.artifact_out,
                    installed_root: &args.installed,
                    package_file: &args.package,
                },
            )
            .map_err(map_update_error)?;
            let report = plan_trusted_cli_update_in_workspace(TrustedCliPlanRequest {
                package: &args.package,
                installed: &args.installed,
                baseline_store: &args.baseline_store,
                baseline_selector: selector,
                resource: resource.as_ref(),
                staging_root: &args.staging_root,
                transaction_root: &args.transaction_root,
                decisions_path: args.decisions.as_deref(),
                decisions_out: args.decisions_out.as_deref(),
                operator_merge_root: args.operator_merge_root.as_deref(),
                artifact_out: &args.artifact_out,
                workspace: Some(&workspace),
                workspace_options: gkrm_core::TrustedUpdateWorkspaceOptions::default(),
                options: TrustedCliUpdateOptions::default(),
            })
            .map_err(map_update_error)?;
            let text = render(&report, args.format)?;
            Ok((text, exit_for_outcome(report.outcome)))
        }
        UpdateCommand::Apply(args) => {
            let selector =
                baseline_selector(args.baseline_id.as_deref(), args.baseline_auto_single)?;
            let resource = parse_resource(args.resource.as_deref())?;
            let artifact_root = managed_artifact_root(&args.artifact)?;
            let workspace = resolve_trusted_update_workspace_from_explicit_roots(
                ExplicitTrustedUpdateWorkspaceRequest {
                    baseline_store: &args.baseline_store,
                    staging_root: &args.staging_root,
                    transaction_root: &args.transaction_root,
                    artifact_root,
                    artifact_out: &args.artifact,
                    installed_root: &args.installed,
                    package_file: &args.package,
                },
            )
            .map_err(map_update_error)?;
            let report = apply_trusted_cli_update_in_workspace(
                TrustedCliApplyRequest {
                    artifact: &args.artifact,
                    package: &args.package,
                    installed: &args.installed,
                    baseline_store: &args.baseline_store,
                    baseline_selector: selector,
                    resource: resource.as_ref(),
                    staging_root: &args.staging_root,
                    transaction_root: &args.transaction_root,
                    decisions_path: args.decisions.as_deref(),
                    operator_merge_root: args.operator_merge_root.as_deref(),
                    options: TrustedCliUpdateOptions::default(),
                },
                &workspace,
            )
            .map_err(map_update_error)?;
            let text = render(&report, args.format)?;
            Ok((text, exit_for_outcome(report.outcome)))
        }
        UpdateCommand::Status(args) => {
            let workspace = open_status_workspace(&args)?;
            let request = TrustedCliStatusRequest {
                transaction_root: &args.transaction_root,
                options: TrustedCliUpdateOptions::default(),
            };
            let report = match workspace.as_ref() {
                Some(workspace) => status_trusted_cli_update_in_workspace(request, workspace),
                None => status_trusted_cli_update(request),
            }
            .map_err(map_update_error)?;
            let text = render(&report, args.format)?;
            Ok((text, exit_for_outcome(report.outcome)))
        }
        UpdateCommand::Recover(args) => {
            let selector =
                baseline_selector(args.baseline_id.as_deref(), args.baseline_auto_single)?;
            let resource = parse_resource(args.resource.as_deref())?;
            let artifact_root = managed_artifact_root(&args.artifact)?;
            let workspace = resolve_trusted_update_workspace_from_explicit_roots(
                ExplicitTrustedUpdateWorkspaceRequest {
                    baseline_store: &args.baseline_store,
                    staging_root: &args.staging_root,
                    transaction_root: &args.transaction_root,
                    artifact_root,
                    artifact_out: &args.artifact,
                    installed_root: &args.installed,
                    package_file: &args.package,
                },
            )
            .map_err(map_update_error)?;
            let report = recover_trusted_cli_update_in_workspace(
                TrustedCliRecoverRequest {
                    candidate: &args.candidate,
                    artifact: &args.artifact,
                    package: &args.package,
                    installed: &args.installed,
                    baseline_store: &args.baseline_store,
                    baseline_selector: selector,
                    resource: resource.as_ref(),
                    staging_root: &args.staging_root,
                    transaction_root: &args.transaction_root,
                    decisions_path: args.decisions.as_deref(),
                    operator_merge_root: args.operator_merge_root.as_deref(),
                    options: TrustedCliUpdateOptions::default(),
                },
                &workspace,
            )
            .map_err(map_update_error)?;
            let text = render(&report, args.format)?;
            Ok((text, exit_for_outcome(report.outcome)))
        }
        UpdateCommand::Finalize(args) => {
            let workspace = open_existing_trusted_update_workspace_from_explicit_roots(
                ExistingExplicitTrustedUpdateWorkspaceRequest {
                    baseline_store: &args.baseline_store,
                    staging_root: &args.staging_root,
                    transaction_root: &args.transaction_root,
                    artifact_root: &args.artifact_root,
                },
            )
            .map_err(map_update_error)?;
            let outcome = retire_trusted_terminal_update_evidence(
                &workspace,
                TrustedTerminalEvidenceRetirementOptions {
                    acknowledged: true,
                    ..TrustedTerminalEvidenceRetirementOptions::default()
                },
            )
            .map_err(map_update_error)?;
            let text = render_finalize(
                outcome.retired_count(),
                outcome.already_retired_count(),
                args.format,
            )?;
            Ok((text, crate::EXIT_SUCCESS))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_reports_only_what_the_invocation_did() {
        assert_eq!(finalize_outcome(0, 0), "nothing_to_finalize");
        assert_eq!(finalize_outcome(0, 3), "already_finalized");
        assert_eq!(finalize_outcome(2, 0), "finalized");
        assert_eq!(finalize_outcome(2, 3), "finalized");
    }

    #[test]
    fn finalize_rendering_omits_uninformative_state() {
        let human = render_finalize(0, 0, Format::Human).expect("human output");
        assert!(human.starts_with("outcome: nothing_to_finalize\n"));
        assert!(!human.contains("blocking"));

        let json = render_finalize(1, 2, Format::Json).expect("json output");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["outcome"], "finalized");
        assert_eq!(value["finalized_terminal_evidence"], 1);
        assert_eq!(value["already_finalized_terminal_evidence"], 2);
        assert!(value.get("blocking_terminal_evidence_remains").is_none());
    }
}
