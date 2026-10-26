use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use clap::{ColorChoice, Parser, Subcommand, ValueEnum};
use gkrm_core::{
    create_baseline_free_update_plan, inspect_installation_update, validate_cli_installed_argument,
    validate_cli_package_argument, BaselineFreeDisposition, BaselineFreeUpdatePlan,
    ComparisonWarning, EscrowClassificationWarning, EscrowFileClassification, FileComparisonStatus,
    FullInspectionReport, GkrmError, InspectionOptions, InstalledResourceRoot, PlannedFile,
    ResourceMatchKind, ResourceUpdatePlan, Result, UpdatePlanReason, UpdatePlanWarning,
    ZipResourceName, ZipResourceRoot, ZipResourceWarning,
};
use serde::Serialize;

mod update;
pub use update::{
    exit_for_outcome, map_update_error, run_update, UpdateCommand, EXIT_INTERNAL, EXIT_INVALID,
    EXIT_LOCK, EXIT_MANUAL, EXIT_PENDING, EXIT_REBIND, EXIT_RECOVERY, EXIT_ROLLED_BACK,
    EXIT_SECURITY,
};

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_UNEXPECTED: i32 = 1;
/// Legacy unused exit code. The binary returns [`EXIT_INVALID`] (20) for usage/parse failures.
#[allow(dead_code)]
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PIPELINE: i32 = 3;

#[derive(Debug, Parser)]
#[command(name = "gkrm")]
#[command(about = "Resource Manager")]
#[command(version)]
#[command(color = ColorChoice::Never)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Inspect(InspectArgs),
    Plan(PlanArgs),
    #[command(subcommand)]
    Update(Box<UpdateCommand>),
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct InspectArgs {
    #[arg(long, value_name = "directory")]
    pub installed: PathBuf,

    #[arg(long, value_name = "zip-file")]
    pub package: PathBuf,

    #[arg(long, value_enum)]
    pub output: OutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct PlanArgs {
    #[arg(long, value_name = "directory")]
    pub installed: PathBuf,

    #[arg(long, value_name = "zip-file")]
    pub package: PathBuf,

    #[arg(long, value_enum)]
    pub output: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInspectArgs {
    request: ResourceAnalysisRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPlanArgs {
    request: ResourceAnalysisRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResourceAnalysisRequest {
    installed: PathBuf,
    package: PathBuf,
    output: OutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliFailure {
    pub(crate) exit_code: i32,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResourceFileCounts {
    unchanged: usize,
    changed: usize,
    incoming_only: usize,
    installed_only: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AggregateCounts {
    installed_resources: usize,
    incoming_resources: usize,
    matched_resources: usize,
    unmatched_installed_resources: usize,
    unmatched_incoming_resources: usize,
    unchanged_files: usize,
    changed_files: usize,
    incoming_only_files: usize,
    installed_only_files: usize,
    matched_protected_incoming_files: usize,
    matched_ignored_incoming_files: usize,
    matched_unsupported_incoming_files: usize,
    total_warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedResourcePresentation {
    installed_resource: String,
    incoming_resource: String,
    match_kind: &'static str,
    counts: ResourceFileCounts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectionPresentation {
    counts: AggregateCounts,
    warnings: WarningGroupsDto,
    matched_resources: Vec<MatchedResourcePresentation>,
    unmatched_installed_resources: Vec<String>,
    unmatched_incoming_resources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanResourceCounts {
    no_change: usize,
    replace_candidate: usize,
    add_candidate: usize,
    merge_candidate: usize,
    preserve: usize,
    conflict_review: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanPresentation {
    counts: PlanCountsDto,
    warnings: Vec<PlanWarningDto>,
    resources: Vec<PlanResourcePresentation>,
    unmatched_installed_resources: Vec<String>,
    unmatched_incoming_resources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanResourcePresentation {
    installed_resource: String,
    incoming_resource: String,
    match_kind: &'static str,
    counts: PlanResourceCounts,
    files: Vec<PlanFilePresentation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanFilePresentation {
    path: String,
    comparison_status: &'static str,
    disposition: &'static str,
    reason: &'static str,
    incoming_escrow_classification: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InspectJsonDto {
    schema_version: u8,
    installed: InstalledDto,
    incoming: IncomingDto,
    counts: CountsDto,
    warnings: WarningGroupsDto,
    matched_resources: Vec<MatchedResourceDto>,
    unmatched_installed_resources: Vec<ResourceDto>,
    unmatched_incoming_resources: Vec<ResourceDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlanJsonDto {
    schema_version: u8,
    plan_type: &'static str,
    counts: PlanCountsDto,
    warnings: Vec<PlanWarningDto>,
    resources: Vec<PlanResourceDto>,
    unmatched_installed_resources: Vec<ResourceDto>,
    unmatched_incoming_resources: Vec<ResourceDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InstalledDto {
    resource_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IncomingDto {
    entry_count: usize,
    resource_count: usize,
    unassigned_entry_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CountsDto {
    installed_resources: usize,
    incoming_resources: usize,
    matched_resources: usize,
    unmatched_installed_resources: usize,
    unmatched_incoming_resources: usize,
    unchanged_files: usize,
    changed_files: usize,
    incoming_only_files: usize,
    installed_only_files: usize,
    matched_protected_incoming_files: usize,
    matched_ignored_incoming_files: usize,
    matched_unsupported_incoming_files: usize,
    total_warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MatchedResourceDto {
    installed_resource: String,
    incoming_resource: String,
    match_kind: &'static str,
    counts: ResourceCountsDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ResourceCountsDto {
    unchanged_files: usize,
    changed_files: usize,
    incoming_only_files: usize,
    installed_only_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlanCountsDto {
    resources_planned: usize,
    no_change_files: usize,
    replace_candidates: usize,
    add_candidates: usize,
    merge_candidates: usize,
    preserved_files: usize,
    conflict_review_files: usize,
    unmatched_installed_resources: usize,
    unmatched_incoming_resources: usize,
    total_warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlanResourceDto {
    installed_resource: String,
    incoming_resource: String,
    match_kind: &'static str,
    counts: PlanResourceCountsDto,
    files: Vec<PlanFileDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlanResourceCountsDto {
    no_change: usize,
    replace_candidate: usize,
    add_candidate: usize,
    merge_candidate: usize,
    preserve: usize,
    conflict_review: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlanFileDto {
    path: String,
    comparison_status: &'static str,
    disposition: &'static str,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    incoming_escrow_classification: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ResourceDto {
    resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlanWarningDto {
    code: &'static str,
    message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    incoming_resource: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WarningGroupsDto {
    installed: Vec<WarningDto>,
    incoming: Vec<WarningDto>,
    manifest: Vec<WarningDto>,
    escrow: Vec<WarningDto>,
    comparison: Vec<WarningDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WarningDto {
    code: &'static str,
    message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
}

impl InspectArgs {
    pub fn validate(self) -> Result<ValidatedInspectArgs> {
        Ok(ValidatedInspectArgs {
            request: ResourceAnalysisRequest::new(self.installed, self.package, self.output)?,
        })
    }
}

impl PlanArgs {
    pub fn validate(self) -> Result<ValidatedPlanArgs> {
        Ok(ValidatedPlanArgs {
            request: ResourceAnalysisRequest::new(self.installed, self.package, self.output)?,
        })
    }
}

impl ResourceAnalysisRequest {
    fn new(installed: PathBuf, package: PathBuf, output: OutputFormat) -> Result<Self> {
        validate_cli_installed_argument(&installed)?;
        validate_cli_package_argument(&package)?;

        Ok(Self {
            installed,
            package,
            output,
        })
    }
}

impl CliFailure {
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    #[allow(dead_code)]
    pub(crate) fn new(exit_code: i32, code: &'static str, message: &'static str) -> Self {
        Self {
            exit_code,
            code,
            message,
        }
    }
}

impl fmt::Display for CliFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "error[{}]: {}", self.code, self.message)
    }
}

pub fn run(cli: Cli) -> std::result::Result<(String, i32), CliFailure> {
    match cli.command {
        Command::Inspect(args) => Ok((run_inspect(args)?, EXIT_SUCCESS)),
        Command::Plan(args) => Ok((run_plan(args)?, EXIT_SUCCESS)),
        Command::Update(command) => run_update(*command),
    }
}

fn run_inspect(args: InspectArgs) -> std::result::Result<String, CliFailure> {
    let validated = args.validate().map_err(map_argument_validation_error)?;
    let report = inspect_installation_update(
        &validated.request.installed,
        &validated.request.package,
        InspectionOptions::default(),
    )
    .map_err(map_pipeline_error)?;

    match validated.request.output {
        OutputFormat::Text => Ok(render_text(&report)),
        OutputFormat::Json => render_json(&report),
    }
}

fn run_plan(args: PlanArgs) -> std::result::Result<String, CliFailure> {
    let validated = args.validate().map_err(map_argument_validation_error)?;
    let report = inspect_installation_update(
        &validated.request.installed,
        &validated.request.package,
        InspectionOptions::default(),
    )
    .map_err(map_pipeline_error)?;
    let plan = create_baseline_free_update_plan(&report).map_err(map_pipeline_error)?;

    match validated.request.output {
        OutputFormat::Text => Ok(render_plan_text(&report, &plan)),
        OutputFormat::Json => render_plan_json(&report, &plan),
    }
}

fn render_json(report: &FullInspectionReport) -> std::result::Result<String, CliFailure> {
    let presentation = build_presentation(report);
    let dto = InspectJsonDto {
        schema_version: 1,
        installed: InstalledDto {
            resource_count: presentation.counts.installed_resources,
        },
        incoming: IncomingDto {
            entry_count: report.incoming_inspection().entries.len(),
            resource_count: presentation.counts.incoming_resources,
            unassigned_entry_count: report.incoming_discovery().unassigned_entries.len(),
        },
        counts: CountsDto::from_counts(&presentation.counts),
        warnings: presentation.warnings,
        matched_resources: presentation
            .matched_resources
            .into_iter()
            .map(MatchedResourceDto::from_presentation)
            .collect(),
        unmatched_installed_resources: presentation
            .unmatched_installed_resources
            .into_iter()
            .map(|resource| ResourceDto { resource })
            .collect(),
        unmatched_incoming_resources: presentation
            .unmatched_incoming_resources
            .into_iter()
            .map(|resource| ResourceDto { resource })
            .collect(),
    };

    serde_json::to_string_pretty(&dto)
        .map(|mut json| {
            json.push('\n');
            json
        })
        .map_err(|_| CliFailure {
            exit_code: EXIT_UNEXPECTED,
            code: "render_failed",
            message: "Failed to render JSON output.",
        })
}

fn render_plan_json(
    report: &FullInspectionReport,
    plan: &BaselineFreeUpdatePlan,
) -> std::result::Result<String, CliFailure> {
    let presentation = build_plan_presentation(report, plan);
    let dto = PlanJsonDto {
        schema_version: 1,
        plan_type: "baseline_free",
        counts: presentation.counts,
        warnings: presentation.warnings,
        resources: presentation
            .resources
            .into_iter()
            .map(PlanResourceDto::from_presentation)
            .collect(),
        unmatched_installed_resources: presentation
            .unmatched_installed_resources
            .into_iter()
            .map(|resource| ResourceDto { resource })
            .collect(),
        unmatched_incoming_resources: presentation
            .unmatched_incoming_resources
            .into_iter()
            .map(|resource| ResourceDto { resource })
            .collect(),
    };

    serde_json::to_string_pretty(&dto)
        .map(|mut json| {
            json.push('\n');
            json
        })
        .map_err(|_| CliFailure {
            exit_code: EXIT_UNEXPECTED,
            code: "render_failed",
            message: "Failed to render JSON output.",
        })
}

fn render_text(report: &FullInspectionReport) -> String {
    let presentation = build_presentation(report);
    let counts = &presentation.counts;
    let mut output = String::new();

    output.push_str("Resource Manager - Inspection\n\n");
    output.push_str(&format!(
        "Installed resources: {}\n",
        counts.installed_resources
    ));
    output.push_str(&format!(
        "Incoming resources: {}\n",
        counts.incoming_resources
    ));
    output.push_str(&format!(
        "Matched resources: {}\n",
        counts.matched_resources
    ));
    output.push_str(&format!(
        "Unmatched installed resources: {}\n",
        counts.unmatched_installed_resources
    ));
    output.push_str(&format!(
        "Unmatched incoming resources: {}\n\n",
        counts.unmatched_incoming_resources
    ));

    output.push_str("Files\n");
    output.push_str(&format!("  Unchanged: {}\n", counts.unchanged_files));
    output.push_str(&format!("  Changed: {}\n", counts.changed_files));
    output.push_str(&format!(
        "  Incoming only: {}\n",
        counts.incoming_only_files
    ));
    output.push_str(&format!(
        "  Installed only: {}\n\n",
        counts.installed_only_files
    ));

    output.push_str("Escrow - Matched resources only\n");
    output.push_str(&format!(
        "  Protected: {}\n",
        counts.matched_protected_incoming_files
    ));
    output.push_str(&format!(
        "  Ignored/editable: {}\n",
        counts.matched_ignored_incoming_files
    ));
    output.push_str(&format!(
        "  Not supported: {}\n\n",
        counts.matched_unsupported_incoming_files
    ));

    output.push_str(&format!("Warnings: {}\n\n", counts.total_warnings));
    output.push_str("Resources\n");
    for resource in &presentation.matched_resources {
        output.push_str(&format!(
            "  {} -> {} ({})\n",
            resource.installed_resource, resource.incoming_resource, resource.match_kind
        ));
        output.push_str(&format!("    Unchanged: {}\n", resource.counts.unchanged));
        output.push_str(&format!("    Changed: {}\n", resource.counts.changed));
        output.push_str(&format!(
            "    Incoming only: {}\n",
            resource.counts.incoming_only
        ));
        output.push_str(&format!(
            "    Installed only: {}\n",
            resource.counts.installed_only
        ));
    }

    if !presentation.unmatched_installed_resources.is_empty() {
        output.push_str("\nUnmatched installed resources\n");
        for resource in &presentation.unmatched_installed_resources {
            output.push_str(&format!("  {resource}\n"));
        }
    }

    if !presentation.unmatched_incoming_resources.is_empty() {
        output.push_str("\nUnmatched incoming resources\n");
        for resource in &presentation.unmatched_incoming_resources {
            output.push_str(&format!("  {resource}\n"));
        }
    }

    output
}

fn render_plan_text(report: &FullInspectionReport, plan: &BaselineFreeUpdatePlan) -> String {
    let presentation = build_plan_presentation(report, plan);
    let counts = &presentation.counts;
    let mut output = String::new();

    output.push_str("Resource Manager - Baseline-Free Update Plan\n\n");
    output.push_str("These are conservative recommendations only. No files were changed.\n\n");
    output.push_str(&format!(
        "Resources planned: {}\n",
        counts.resources_planned
    ));
    output.push_str(&format!(
        "Unmatched installed resources: {}\n",
        counts.unmatched_installed_resources
    ));
    output.push_str(&format!(
        "Unmatched incoming resources: {}\n\n",
        counts.unmatched_incoming_resources
    ));

    output.push_str("Recommendations\n");
    output.push_str(&format!("  No change: {}\n", counts.no_change_files));
    output.push_str(&format!(
        "  Replace candidates: {}\n",
        counts.replace_candidates
    ));
    output.push_str(&format!("  Add candidates: {}\n", counts.add_candidates));
    output.push_str(&format!(
        "  Merge candidates: {}\n",
        counts.merge_candidates
    ));
    output.push_str(&format!("  Preserve: {}\n", counts.preserved_files));
    output.push_str(&format!(
        "  Conflict review: {}\n\n",
        counts.conflict_review_files
    ));

    output.push_str(&format!("Warnings: {}\n", counts.total_warnings));
    if !presentation.warnings.is_empty() {
        output.push('\n');
        output.push_str("Warnings\n");
        for warning in &presentation.warnings {
            output.push_str(&format!("  [{}] {}", warning.code, warning.message));
            if let (Some(installed), Some(incoming)) =
                (&warning.installed_resource, &warning.incoming_resource)
            {
                output.push_str(&format!(" ({installed} -> {incoming})"));
            }
            output.push('\n');
        }
    }

    output.push_str("\nResources\n");
    for resource in &presentation.resources {
        output.push_str(&format!(
            "  {} -> {} ({})\n",
            resource.installed_resource, resource.incoming_resource, resource.match_kind
        ));
        output.push_str(&format!("    No change: {}\n", resource.counts.no_change));
        output.push_str(&format!(
            "    Replace candidates: {}\n",
            resource.counts.replace_candidate
        ));
        output.push_str(&format!(
            "    Add candidates: {}\n",
            resource.counts.add_candidate
        ));
        output.push_str(&format!(
            "    Merge candidates: {}\n",
            resource.counts.merge_candidate
        ));
        output.push_str(&format!("    Preserve: {}\n", resource.counts.preserve));
        output.push_str(&format!(
            "    Conflict review: {}\n",
            resource.counts.conflict_review
        ));

        for file in &resource.files {
            if file.disposition == "no_change" {
                continue;
            }
            output.push_str(&format!("    [{}] {}\n", file.disposition, file.path));
            output.push_str(&format!("      {}\n", file.reason));
        }
    }

    if !presentation.unmatched_installed_resources.is_empty() {
        output.push_str("\nUnmatched installed resources\n");
        for resource in &presentation.unmatched_installed_resources {
            output.push_str(&format!("  {resource}\n"));
        }
    }

    if !presentation.unmatched_incoming_resources.is_empty() {
        output.push_str("\nUnmatched incoming resources\n");
        for resource in &presentation.unmatched_incoming_resources {
            output.push_str(&format!("  {resource}\n"));
        }
    }

    output
}

fn build_presentation(report: &FullInspectionReport) -> InspectionPresentation {
    let installed_labels = installed_labels(report);
    let incoming_labels = incoming_labels(report);
    let matched_resources =
        matched_resource_presentations(report, &installed_labels, &incoming_labels);
    let warnings = warning_groups(report, &installed_labels, &incoming_labels);
    let counts = aggregate_counts(report, &matched_resources, &warnings);

    InspectionPresentation {
        counts,
        warnings,
        matched_resources,
        unmatched_installed_resources: report
            .comparison()
            .unmatched_installed_resources
            .iter()
            .map(|root| installed_label(&installed_labels, root))
            .collect(),
        unmatched_incoming_resources: report
            .comparison()
            .unmatched_incoming_resources
            .iter()
            .map(|root| incoming_label(&incoming_labels, root))
            .collect(),
    }
}

fn build_plan_presentation(
    report: &FullInspectionReport,
    plan: &BaselineFreeUpdatePlan,
) -> PlanPresentation {
    let installed_labels = installed_labels(report);
    let incoming_labels = incoming_labels(report);
    let resources = plan
        .resources()
        .iter()
        .map(|resource| plan_resource_presentation(resource, &installed_labels, &incoming_labels))
        .collect::<Vec<_>>();
    let counts = plan_counts_dto(plan);
    let warnings = plan
        .warnings()
        .iter()
        .map(|warning| plan_warning_dto(warning, &installed_labels, &incoming_labels))
        .collect();

    PlanPresentation {
        counts,
        warnings,
        resources,
        unmatched_installed_resources: plan
            .unmatched_installed_resources()
            .iter()
            .map(|root| installed_label(&installed_labels, root))
            .collect(),
        unmatched_incoming_resources: plan
            .unmatched_incoming_resources()
            .iter()
            .map(|root| incoming_label(&incoming_labels, root))
            .collect(),
    }
}

fn plan_resource_presentation(
    resource: &ResourceUpdatePlan,
    installed_labels: &BTreeMap<InstalledResourceRoot, String>,
    incoming_labels: &BTreeMap<ZipResourceRoot, String>,
) -> PlanResourcePresentation {
    let counts = plan_resource_counts(resource.files());
    let files = resource
        .files()
        .iter()
        .map(plan_file_presentation)
        .collect::<Vec<_>>();

    PlanResourcePresentation {
        installed_resource: installed_label(
            installed_labels,
            &resource.resource_match().installed_resource,
        ),
        incoming_resource: incoming_label(
            incoming_labels,
            &resource.resource_match().incoming_resource,
        ),
        match_kind: match_kind_label(resource.resource_match().match_kind),
        counts,
        files,
    }
}

fn plan_file_presentation(file: &PlannedFile) -> PlanFilePresentation {
    PlanFilePresentation {
        path: file.relative_path().as_str().to_owned(),
        comparison_status: comparison_status_code(file.comparison_status()),
        disposition: disposition_code(file.disposition()),
        reason: reason_code(file.reason()),
        incoming_escrow_classification: file
            .incoming_escrow_classification()
            .map(escrow_classification_code),
    }
}

fn plan_resource_counts(files: &[PlannedFile]) -> PlanResourceCounts {
    let mut counts = PlanResourceCounts {
        no_change: 0,
        replace_candidate: 0,
        add_candidate: 0,
        merge_candidate: 0,
        preserve: 0,
        conflict_review: 0,
    };

    for file in files {
        match file.disposition() {
            BaselineFreeDisposition::NoChange => counts.no_change += 1,
            BaselineFreeDisposition::ReplaceCandidate => counts.replace_candidate += 1,
            BaselineFreeDisposition::AddCandidate => counts.add_candidate += 1,
            BaselineFreeDisposition::MergeCandidate => counts.merge_candidate += 1,
            BaselineFreeDisposition::Preserve => counts.preserve += 1,
            BaselineFreeDisposition::ConflictReview => counts.conflict_review += 1,
        }
    }

    counts
}

fn plan_counts_dto(plan: &BaselineFreeUpdatePlan) -> PlanCountsDto {
    let counts = plan.counts();
    PlanCountsDto {
        resources_planned: counts.resources_planned(),
        no_change_files: counts.no_change_files(),
        replace_candidates: counts.replace_candidates(),
        add_candidates: counts.add_candidates(),
        merge_candidates: counts.merge_candidates(),
        preserved_files: counts.preserved_files(),
        conflict_review_files: counts.conflict_review_files(),
        unmatched_installed_resources: counts.unmatched_installed_resources(),
        unmatched_incoming_resources: counts.unmatched_incoming_resources(),
        total_warnings: plan.warnings().len(),
    }
}

fn plan_warning_dto(
    warning: &UpdatePlanWarning,
    installed_labels: &BTreeMap<InstalledResourceRoot, String>,
    incoming_labels: &BTreeMap<ZipResourceRoot, String>,
) -> PlanWarningDto {
    match warning {
        UpdatePlanWarning::BaselineUnavailable => PlanWarningDto {
            code: "baseline_unavailable",
            message: "No baseline exists; recommendations are conservative and no update action was executed.",
            installed_resource: None,
            incoming_resource: None,
        },
        UpdatePlanWarning::SingleResourceFallback {
            installed_resource,
            incoming_resource,
        } => PlanWarningDto {
            code: "single_resource_fallback",
            message: "The root ZIP resource was matched using the single-resource fallback.",
            installed_resource: Some(installed_label(installed_labels, installed_resource)),
            incoming_resource: Some(incoming_label(incoming_labels, incoming_resource)),
        },
    }
}

fn installed_labels(report: &FullInspectionReport) -> BTreeMap<InstalledResourceRoot, String> {
    report
        .installed()
        .resources
        .iter()
        .map(|resource| (resource.root.clone(), resource.name.clone()))
        .collect()
}

fn incoming_labels(report: &FullInspectionReport) -> BTreeMap<ZipResourceRoot, String> {
    report
        .incoming_discovery()
        .resources
        .iter()
        .map(|resource| {
            let label = match &resource.name {
                ZipResourceName::Directory(name) => name.clone(),
                ZipResourceName::ZipRoot => "zip_root".to_owned(),
            };
            (resource.root.clone(), label)
        })
        .collect()
}

fn matched_resource_presentations(
    report: &FullInspectionReport,
    installed_labels: &BTreeMap<InstalledResourceRoot, String>,
    incoming_labels: &BTreeMap<ZipResourceRoot, String>,
) -> Vec<MatchedResourcePresentation> {
    report
        .comparison()
        .matched_resources
        .iter()
        .map(|resource| {
            let mut counts = ResourceFileCounts {
                unchanged: 0,
                changed: 0,
                incoming_only: 0,
                installed_only: 0,
            };
            for file in &resource.files {
                match file.status {
                    FileComparisonStatus::Unchanged => counts.unchanged += 1,
                    FileComparisonStatus::Changed => counts.changed += 1,
                    FileComparisonStatus::IncomingOnly => counts.incoming_only += 1,
                    FileComparisonStatus::InstalledOnly => counts.installed_only += 1,
                }
            }

            MatchedResourcePresentation {
                installed_resource: installed_label(
                    installed_labels,
                    &resource.resource_match.installed_resource,
                ),
                incoming_resource: incoming_label(
                    incoming_labels,
                    &resource.resource_match.incoming_resource,
                ),
                match_kind: match_kind_label(resource.resource_match.match_kind),
                counts,
            }
        })
        .collect()
}

fn aggregate_counts(
    report: &FullInspectionReport,
    matched_resources: &[MatchedResourcePresentation],
    warnings: &WarningGroupsDto,
) -> AggregateCounts {
    let mut counts = AggregateCounts {
        installed_resources: report.installed().resources.len(),
        incoming_resources: report.incoming_discovery().resources.len(),
        matched_resources: report.comparison().matched_resources.len(),
        unmatched_installed_resources: report.comparison().unmatched_installed_resources.len(),
        unmatched_incoming_resources: report.comparison().unmatched_incoming_resources.len(),
        unchanged_files: 0,
        changed_files: 0,
        incoming_only_files: 0,
        installed_only_files: 0,
        matched_protected_incoming_files: 0,
        matched_ignored_incoming_files: 0,
        matched_unsupported_incoming_files: 0,
        total_warnings: warnings.installed.len()
            + warnings.incoming.len()
            + warnings.manifest.len()
            + warnings.escrow.len()
            + warnings.comparison.len(),
    };

    for resource in matched_resources {
        counts.unchanged_files += resource.counts.unchanged;
        counts.changed_files += resource.counts.changed;
        counts.incoming_only_files += resource.counts.incoming_only;
        counts.installed_only_files += resource.counts.installed_only;
    }

    for resource in &report.comparison().matched_resources {
        for file in &resource.files {
            let Some(incoming) = &file.incoming else {
                continue;
            };
            match &incoming.escrow_classification {
                EscrowFileClassification::Protected => {
                    counts.matched_protected_incoming_files += 1;
                }
                EscrowFileClassification::Ignored { .. } => {
                    counts.matched_ignored_incoming_files += 1;
                }
                EscrowFileClassification::NotSupported { .. } => {
                    counts.matched_unsupported_incoming_files += 1;
                }
            }
        }
    }

    counts
}

fn warning_groups(
    report: &FullInspectionReport,
    installed_labels: &BTreeMap<InstalledResourceRoot, String>,
    incoming_labels: &BTreeMap<ZipResourceRoot, String>,
) -> WarningGroupsDto {
    WarningGroupsDto {
        installed: report
            .installed()
            .warnings
            .iter()
            .map(|_| WarningDto {
                code: "installed_scan_warning",
                message: "The installed resource scan produced a warning.",
                resource: None,
                path: None,
                pattern: None,
                count: None,
            })
            .collect(),
        incoming: report
            .incoming_discovery()
            .warnings
            .iter()
            .map(incoming_warning_dto)
            .collect(),
        manifest: report
            .manifests()
            .resources
            .iter()
            .flat_map(|resource| {
                resource.warnings.iter().map(|warning| {
                    let (code, message) = match warning {
                        gkrm_core::FxManifestWarning::UnsupportedExpression { .. } => (
                            "unsupported_manifest_expression",
                            "A supported manifest declaration used an unsupported expression.",
                        ),
                        gkrm_core::FxManifestWarning::TableContainsNonStringValue { .. } => (
                            "manifest_table_non_string_value",
                            "A manifest table declaration contained a non-string value.",
                        ),
                        gkrm_core::FxManifestWarning::NestedDeclarationIgnored { .. } => (
                            "nested_manifest_declaration_ignored",
                            "A supported manifest declaration was ignored because it was nested.",
                        ),
                    };
                    WarningDto {
                        code,
                        message,
                        resource: Some(incoming_label(incoming_labels, &resource.resource_root)),
                        path: Some(resource.manifest_path.to_string()),
                        pattern: None,
                        count: None,
                    }
                })
            })
            .collect(),
        escrow: report
            .escrow()
            .resources
            .iter()
            .flat_map(|resource| {
                resource.warnings.iter().map(|warning| match warning {
                    EscrowClassificationWarning::IgnorePatternMatchedNoFiles { pattern } => {
                        WarningDto {
                            code: "ignore_pattern_matched_no_files",
                            message: "An escrow_ignore pattern did not match any incoming files.",
                            resource: Some(incoming_label(incoming_labels, &resource.resource_root)),
                            path: None,
                            pattern: Some(pattern.clone()),
                            count: None,
                        }
                    }
                    EscrowClassificationWarning::IgnorePatternMatchedOnlyUnsupportedFiles {
                        pattern,
                    } => WarningDto {
                        code: "ignore_pattern_matched_only_unsupported_files",
                        message:
                            "An escrow_ignore pattern matched only files not supported by Asset Escrow.",
                        resource: Some(incoming_label(incoming_labels, &resource.resource_root)),
                        path: None,
                        pattern: Some(pattern.clone()),
                        count: None,
                    },
                })
            })
            .collect(),
        comparison: report
            .comparison()
            .warnings
            .iter()
            .map(|warning| comparison_warning_dto(warning, installed_labels, incoming_labels))
            .collect(),
    }
}

fn incoming_warning_dto(warning: &ZipResourceWarning) -> WarningDto {
    match warning {
        ZipResourceWarning::NoFiveMResourcesFound => WarningDto {
            code: "no_incoming_resources_found",
            message: "No FiveM resources were found in the incoming ZIP package.",
            resource: None,
            path: None,
            pattern: None,
            count: None,
        },
        ZipResourceWarning::UnassignedPackageEntries { count } => WarningDto {
            code: "unassigned_package_entries",
            message: "Some incoming ZIP entries were not assigned to a discovered resource.",
            resource: None,
            path: None,
            pattern: None,
            count: Some(*count),
        },
    }
}

fn comparison_warning_dto(
    warning: &ComparisonWarning,
    installed_labels: &BTreeMap<InstalledResourceRoot, String>,
    _incoming_labels: &BTreeMap<ZipResourceRoot, String>,
) -> WarningDto {
    match warning {
        ComparisonWarning::SingleResourceFallback {
            installed_resource,
            incoming_resource: _,
        } => WarningDto {
            code: "single_resource_fallback",
            message: "The root ZIP resource was matched using the single-resource fallback.",
            resource: Some(installed_label(installed_labels, installed_resource)),
            path: None,
            pattern: None,
            count: None,
        },
    }
}

fn installed_label(
    labels: &BTreeMap<InstalledResourceRoot, String>,
    root: &InstalledResourceRoot,
) -> String {
    labels.get(root).cloned().unwrap_or_else(|| match root {
        InstalledResourceRoot::Root => "installed_root".to_owned(),
        InstalledResourceRoot::Path(path) => path.to_string(),
    })
}

fn incoming_label(labels: &BTreeMap<ZipResourceRoot, String>, root: &ZipResourceRoot) -> String {
    labels.get(root).cloned().unwrap_or_else(|| match root {
        ZipResourceRoot::Root => "zip_root".to_owned(),
        ZipResourceRoot::Path(path) => path.to_string(),
    })
}

fn match_kind_label(kind: ResourceMatchKind) -> &'static str {
    match kind {
        ResourceMatchKind::ExactName => "exact_name",
        ResourceMatchKind::SingleResourceFallback => "single_resource_fallback",
    }
}

fn comparison_status_code(status: FileComparisonStatus) -> &'static str {
    match status {
        FileComparisonStatus::Unchanged => "unchanged",
        FileComparisonStatus::Changed => "changed",
        FileComparisonStatus::IncomingOnly => "incoming_only",
        FileComparisonStatus::InstalledOnly => "installed_only",
    }
}

fn disposition_code(disposition: BaselineFreeDisposition) -> &'static str {
    match disposition {
        BaselineFreeDisposition::NoChange => "no_change",
        BaselineFreeDisposition::ReplaceCandidate => "replace_candidate",
        BaselineFreeDisposition::AddCandidate => "add_candidate",
        BaselineFreeDisposition::MergeCandidate => "merge_candidate",
        BaselineFreeDisposition::Preserve => "preserve",
        BaselineFreeDisposition::ConflictReview => "conflict_review",
    }
}

fn reason_code(reason: UpdatePlanReason) -> &'static str {
    match reason {
        UpdatePlanReason::HashesMatch => "hashes_match",
        UpdatePlanReason::ProtectedFileChanged => "protected_file_changed",
        UpdatePlanReason::EditableFileChangedWithoutBaseline => {
            "editable_file_changed_without_baseline"
        }
        UpdatePlanReason::UnsupportedFileChangedWithoutProfile => {
            "unsupported_file_changed_without_profile"
        }
        UpdatePlanReason::IncomingFileHasNoInstalledCounterpart => {
            "incoming_file_has_no_installed_counterpart"
        }
        UpdatePlanReason::InstalledFileHasNoIncomingCounterpart => {
            "installed_file_has_no_incoming_counterpart"
        }
    }
}

fn escrow_classification_code(classification: &EscrowFileClassification) -> &'static str {
    match classification {
        EscrowFileClassification::Protected => "protected",
        EscrowFileClassification::Ignored { .. } => "ignored",
        EscrowFileClassification::NotSupported { .. } => "not_supported",
    }
}

impl CountsDto {
    fn from_counts(counts: &AggregateCounts) -> Self {
        Self {
            installed_resources: counts.installed_resources,
            incoming_resources: counts.incoming_resources,
            matched_resources: counts.matched_resources,
            unmatched_installed_resources: counts.unmatched_installed_resources,
            unmatched_incoming_resources: counts.unmatched_incoming_resources,
            unchanged_files: counts.unchanged_files,
            changed_files: counts.changed_files,
            incoming_only_files: counts.incoming_only_files,
            installed_only_files: counts.installed_only_files,
            matched_protected_incoming_files: counts.matched_protected_incoming_files,
            matched_ignored_incoming_files: counts.matched_ignored_incoming_files,
            matched_unsupported_incoming_files: counts.matched_unsupported_incoming_files,
            total_warnings: counts.total_warnings,
        }
    }
}

impl PlanResourceCountsDto {
    fn from_counts(counts: &PlanResourceCounts) -> Self {
        Self {
            no_change: counts.no_change,
            replace_candidate: counts.replace_candidate,
            add_candidate: counts.add_candidate,
            merge_candidate: counts.merge_candidate,
            preserve: counts.preserve,
            conflict_review: counts.conflict_review,
        }
    }
}

impl PlanResourceDto {
    fn from_presentation(resource: PlanResourcePresentation) -> Self {
        Self {
            installed_resource: resource.installed_resource,
            incoming_resource: resource.incoming_resource,
            match_kind: resource.match_kind,
            counts: PlanResourceCountsDto::from_counts(&resource.counts),
            files: resource
                .files
                .into_iter()
                .map(PlanFileDto::from_presentation)
                .collect(),
        }
    }
}

impl PlanFileDto {
    fn from_presentation(file: PlanFilePresentation) -> Self {
        Self {
            path: file.path,
            comparison_status: file.comparison_status,
            disposition: file.disposition,
            reason: file.reason,
            incoming_escrow_classification: file.incoming_escrow_classification,
        }
    }
}

impl MatchedResourceDto {
    fn from_presentation(resource: MatchedResourcePresentation) -> Self {
        Self {
            installed_resource: resource.installed_resource,
            incoming_resource: resource.incoming_resource,
            match_kind: resource.match_kind,
            counts: ResourceCountsDto {
                unchanged_files: resource.counts.unchanged,
                changed_files: resource.counts.changed,
                incoming_only_files: resource.counts.incoming_only,
                installed_only_files: resource.counts.installed_only,
            },
        }
    }
}

fn map_argument_validation_error(error: GkrmError) -> CliFailure {
    let (code, message) = match error {
        GkrmError::InstalledPathMissing { .. }
        | GkrmError::InstalledPathMetadata { .. }
        | GkrmError::InstalledPathNotDirectory { .. } => (
            "invalid_installed_path",
            "Installed path must be an existing directory.",
        ),
        GkrmError::PackagePathMissing { .. }
        | GkrmError::PackagePathMetadata { .. }
        | GkrmError::PackagePathNotFile { .. }
        | GkrmError::PackagePathNotZip { .. } => (
            "invalid_package_path",
            "Package path must be an existing .zip file.",
        ),
        _ => ("invalid_arguments", "Invalid inspect arguments."),
    };

    CliFailure {
        exit_code: EXIT_INVALID,
        code,
        message,
    }
}

fn map_pipeline_error(error: GkrmError) -> CliFailure {
    let (code, message) = match error {
        GkrmError::ZipEntryParentTraversal { .. }
        | GkrmError::ZipEntryUnixAbsolutePath { .. }
        | GkrmError::ZipEntryWindowsDrivePath { .. }
        | GkrmError::ZipEntryUncPath { .. }
        | GkrmError::ZipEntryWindowsRootPath { .. }
        | GkrmError::ZipEntryControlCharacter { .. }
        | GkrmError::ZipEntryEmptyComponent { .. }
        | GkrmError::ZipEntryCurrentDirectory { .. }
        | GkrmError::ZipEntryWindowsInvalidCharacter { .. }
        | GkrmError::ZipEntryWindowsTrailingDotOrSpace { .. }
        | GkrmError::ZipEntryWindowsReservedName { .. }
        | GkrmError::ZipEntrySymlink { .. } => ("unsafe_zip_entry", "ZIP contains an unsafe path."),
        GkrmError::ZipPackageOpen { .. }
        | GkrmError::ZipArchiveRead { .. }
        | GkrmError::ZipEntryRead { .. }
        | GkrmError::ZipEntryStream { .. }
        | GkrmError::ZipEntryNameInvalidUtf8 { .. }
        | GkrmError::ZipEntryEncrypted { .. }
        | GkrmError::ZipEntryUnsupportedCompression { .. }
        | GkrmError::ZipDirectoryEntryNonZeroSize { .. }
        | GkrmError::ZipEntryDuplicatePath { .. }
        | GkrmError::ZipEntryCaseInsensitiveCollision { .. }
        | GkrmError::ZipEntryCountLimitExceeded { .. }
        | GkrmError::ZipEntrySizeLimitExceeded { .. }
        | GkrmError::ZipEntryStreamSizeMismatch { .. }
        | GkrmError::ZipTotalSizeLimitExceeded { .. }
        | GkrmError::ZipCompressionRatioLimitExceeded { .. }
        | GkrmError::ZipResourceDuplicateManifest { .. }
        | GkrmError::ComparisonArchiveSizeLimitExceeded { .. }
        | GkrmError::ComparisonPackageOpen { .. }
        | GkrmError::ComparisonPackageMetadata { .. }
        | GkrmError::ComparisonPackageNotFile { .. }
        | GkrmError::ComparisonPackageSymlink { .. }
        | GkrmError::ComparisonPackageReparsePoint { .. }
        | GkrmError::ComparisonPackageTimestampUnavailable { .. }
        | GkrmError::ComparisonPackageIdentityUnavailable { .. }
        | GkrmError::ComparisonPackageHashRead { .. }
        | GkrmError::ComparisonPackageArchiveSizeMismatch { .. }
        | GkrmError::ComparisonPackageChanged { .. } => (
            "package_inspection_failed",
            "Incoming ZIP package could not be inspected.",
        ),
        GkrmError::ManifestEntryMissing { .. }
        | GkrmError::ManifestEntryNotFile { .. }
        | GkrmError::ManifestSizeLimitExceeded { .. }
        | GkrmError::ManifestZipOpen { .. }
        | GkrmError::ManifestZipArchiveRead { .. }
        | GkrmError::ManifestZipEntryChanged { .. }
        | GkrmError::ManifestZipEntryRead { .. }
        | GkrmError::ManifestRead { .. }
        | GkrmError::ManifestInvalidUtf8 { .. }
        | GkrmError::ManifestInvalidStringEscape { .. }
        | GkrmError::ManifestLuaSyntax { .. }
        | GkrmError::ManifestTokenLimitExceeded { .. }
        | GkrmError::ManifestParserPanic { .. } => (
            "manifest_parse_failed",
            "Incoming resource manifest could not be parsed.",
        ),
        GkrmError::EscrowManifestMissing { .. }
        | GkrmError::EscrowManifestDuplicate { .. }
        | GkrmError::EscrowManifestRootMismatch { .. }
        | GkrmError::EscrowManifestPathMismatch { .. }
        | GkrmError::EscrowDiscoveryEntryMismatch { .. }
        | GkrmError::EscrowGlobUnsafe { .. }
        | GkrmError::EscrowGlobTrailingSlash { .. }
        | GkrmError::EscrowGlobMalformed { .. }
        | GkrmError::EscrowResourceRelativePath { .. } => (
            "escrow_classification_failed",
            "Incoming Asset Escrow files could not be classified.",
        ),
        GkrmError::InstalledPathMetadata { .. }
        | GkrmError::InstalledPathMissing { .. }
        | GkrmError::InstalledPathNotDirectory { .. }
        | GkrmError::InstalledScanZeroLimit { .. }
        | GkrmError::InstalledRootCanonicalize { .. }
        | GkrmError::InstalledRootUnsupportedPrefix { .. }
        | GkrmError::InstalledRootSymlink { .. }
        | GkrmError::InstalledRootNameNonUtf8 { .. }
        | GkrmError::InstalledNoResourcesFound
        | GkrmError::InstalledDirectoryRead { .. }
        | GkrmError::InstalledDirectoryEntryRead { .. }
        | GkrmError::InstalledDirectoryDisappeared { .. }
        | GkrmError::InstalledFileDisappeared { .. }
        | GkrmError::InstalledEntryMetadata { .. }
        | GkrmError::InstalledEntrySymlink { .. }
        | GkrmError::InstalledFxManifestSymlink { .. }
        | GkrmError::InstalledEntryReparsePoint { .. }
        | GkrmError::InstalledUnsupportedEntryType { .. }
        | GkrmError::InstalledPathEmpty { .. }
        | GkrmError::InstalledPathAbsolute { .. }
        | GkrmError::InstalledPathNonUtf8 { .. }
        | GkrmError::InstalledPathControlCharacter { .. }
        | GkrmError::InstalledPathEmptyComponent { .. }
        | GkrmError::InstalledPathCurrentDirectory { .. }
        | GkrmError::InstalledPathParentTraversal { .. }
        | GkrmError::InstalledPathWindowsInvalidCharacter { .. }
        | GkrmError::InstalledPathWindowsTrailingDotOrSpace { .. }
        | GkrmError::InstalledPathWindowsReservedName { .. }
        | GkrmError::InstalledPathDuplicate { .. }
        | GkrmError::InstalledPathCaseInsensitiveCollision { .. }
        | GkrmError::InstalledResourceCountLimitExceeded { .. }
        | GkrmError::InstalledFilesPerResourceLimitExceeded { .. }
        | GkrmError::InstalledTotalFilesLimitExceeded { .. }
        | GkrmError::InstalledTotalEntriesLimitExceeded { .. }
        | GkrmError::InstalledDirectoryCountLimitExceeded { .. }
        | GkrmError::InstalledFileSizeLimitExceeded { .. }
        | GkrmError::InstalledTotalSizeLimitExceeded { .. }
        | GkrmError::InstalledDirectoryDepthLimitExceeded { .. }
        | GkrmError::InstalledFileOutsideResource { .. }
        | GkrmError::InstalledResourceRelativePath { .. }
        | GkrmError::InstalledContainmentViolation { .. }
        | GkrmError::InstalledFileOpen { .. }
        | GkrmError::InstalledFileMetadata { .. }
        | GkrmError::InstalledFileTimestampUnavailable { .. }
        | GkrmError::InstalledFileIdentityUnavailable { .. }
        | GkrmError::InstalledOpenedFileNotRegular { .. }
        | GkrmError::InstalledFileChanged { .. }
        | GkrmError::InstalledFileContentChanged { .. }
        | GkrmError::InstalledFileHashRead { .. }
        | GkrmError::InstalledFileSizeMismatch { .. } => (
            "installed_scan_failed",
            "Installed resources could not be scanned.",
        ),
        GkrmError::UpdatePlanInvalidFileSides { .. }
        | GkrmError::UpdatePlanMissingIncomingClassification { .. }
        | GkrmError::UpdatePlanUnexpectedIncomingClassification { .. }
        | GkrmError::UpdatePlanDuplicateFilePath { .. }
        | GkrmError::UpdatePlanDuplicateInstalledResourceMatch { .. }
        | GkrmError::UpdatePlanDuplicateIncomingResourceMatch { .. }
        | GkrmError::UpdatePlanCountMismatch { .. } => (
            "planning_failed",
            "Baseline-free update plan could not be created.",
        ),
        _ => (
            "comparison_failed",
            "Installed and incoming resources could not be compared.",
        ),
    };

    CliFailure {
        exit_code: EXIT_PIPELINE,
        code,
        message,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;
    use gkrm_core::GkrmError;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn parses_valid_inspect_arguments() {
        let cli = Cli::parse_from([
            "gkrm",
            "inspect",
            "--installed",
            "installed-resource",
            "--package",
            "update.zip",
            "--output",
            "json",
        ]);

        let Command::Inspect(args) = cli.command else {
            panic!("inspect command should parse");
        };
        assert_eq!(args.installed, PathBuf::from("installed-resource"));
        assert_eq!(args.package, PathBuf::from("update.zip"));
        assert_eq!(args.output, OutputFormat::Json);
    }

    #[test]
    fn parses_valid_plan_arguments() {
        let cli = Cli::parse_from([
            "gkrm",
            "plan",
            "--installed",
            "installed-resource",
            "--package",
            "update.zip",
            "--output",
            "json",
        ]);

        let Command::Plan(args) = cli.command else {
            panic!("plan command should parse");
        };
        assert_eq!(args.installed, PathBuf::from("installed-resource"));
        assert_eq!(args.package, PathBuf::from("update.zip"));
        assert_eq!(args.output, OutputFormat::Json);
    }

    #[test]
    fn rejects_unsupported_output_argument() {
        let err = Cli::try_parse_from([
            "gkrm",
            "inspect",
            "--installed",
            "installed-resource",
            "--package",
            "update.zip",
            "--output",
            "xml",
        ])
        .expect_err("xml output should be rejected by clap");

        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn rejects_unsupported_plan_output_argument() {
        let err = Cli::try_parse_from([
            "gkrm",
            "plan",
            "--installed",
            "installed-resource",
            "--package",
            "update.zip",
            "--output",
            "xml",
        ])
        .expect_err("xml output should be rejected by clap");

        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn validates_existing_installed_directory_and_zip_package() {
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).expect("installed dir should be created");
        let package = temp.path().join("update.zip");
        fs::write(&package, b"synthetic zip placeholder").expect("package should be created");

        let args = InspectArgs {
            installed: installed.clone(),
            package: package.clone(),
            output: OutputFormat::Text,
        };

        let validated = args.validate().expect("paths should validate");
        assert_eq!(validated.request.installed, installed);
        assert_eq!(validated.request.package, package);
        assert_eq!(validated.request.output, OutputFormat::Text);
    }

    #[test]
    fn rejects_missing_installed_path() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("update.zip");
        fs::write(&package, b"synthetic zip placeholder").expect("package should be created");

        let args = InspectArgs {
            installed: temp.path().join("missing"),
            package,
            output: OutputFormat::Json,
        };

        let err = args
            .validate()
            .expect_err("missing installed path should fail");
        assert!(matches!(err, GkrmError::InstalledPathMissing { .. }));
    }

    #[test]
    fn rejects_installed_path_that_is_not_directory() {
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("installed.txt");
        fs::write(&installed, b"not a directory").expect("installed file should be created");
        let package = temp.path().join("update.zip");
        fs::write(&package, b"synthetic zip placeholder").expect("package should be created");

        let args = InspectArgs {
            installed,
            package,
            output: OutputFormat::Json,
        };

        let err = args
            .validate()
            .expect_err("installed file path should fail");
        assert!(matches!(err, GkrmError::InstalledPathNotDirectory { .. }));
    }

    #[test]
    fn rejects_missing_package_path() {
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).expect("installed dir should be created");

        let args = InspectArgs {
            installed,
            package: temp.path().join("missing.zip"),
            output: OutputFormat::Json,
        };

        let err = args
            .validate()
            .expect_err("missing package path should fail");
        assert!(matches!(err, GkrmError::PackagePathMissing { .. }));
    }

    #[test]
    fn rejects_package_path_that_is_not_file() {
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).expect("installed dir should be created");
        let package = temp.path().join("package-dir.zip");
        fs::create_dir(&package).expect("package dir should be created");

        let args = InspectArgs {
            installed,
            package,
            output: OutputFormat::Json,
        };

        let err = args.validate().expect_err("package directory should fail");
        assert!(matches!(err, GkrmError::PackagePathNotFile { .. }));
    }

    #[test]
    fn rejects_package_without_zip_extension() {
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).expect("installed dir should be created");
        let package = temp.path().join("update.txt");
        fs::write(&package, b"not a zip").expect("package should be created");

        let args = InspectArgs {
            installed,
            package,
            output: OutputFormat::Json,
        };

        let err = args
            .validate()
            .expect_err("package without .zip should fail");
        assert!(matches!(err, GkrmError::PackagePathNotZip { .. }));
    }

    #[test]
    fn planning_failures_map_to_exit_three() {
        let failure = map_pipeline_error(GkrmError::UpdatePlanInvalidFileSides {
            status: FileComparisonStatus::Changed,
            has_installed: true,
            has_incoming: false,
        });

        assert_eq!(failure.exit_code(), EXIT_PIPELINE);
        assert_eq!(
            failure.to_string(),
            "error[planning_failed]: Baseline-free update plan could not be created."
        );
    }

    #[test]
    fn cli_human_and_json_mapping_do_not_leak_core_sentinels() {
        const WIN: &str = r"C:\Users\sentinel\leak\pkg.zip";
        const UNIX: &str = "/tmp/sentinel/leak/pkg.zip";
        const ENTRY: &str = "SENTINEL_ENTRY_res/config.lua";
        const PARSER: &str = "SENTINEL_PARSER unexpected token";
        const DEP: &str = "SENTINEL_DEP_Permission denied";
        const BASELINE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let failures = [
            map_pipeline_error(GkrmError::ManifestLuaSyntax {
                entry: ENTRY.to_owned(),
                errors: PARSER.to_owned(),
            }),
            map_pipeline_error(GkrmError::ZipEntryParentTraversal {
                index: 3,
                entry: ENTRY.to_owned(),
            }),
            map_pipeline_error(GkrmError::ZipPackageOpen {
                path: PathBuf::from(WIN),
                cause: std::io::Error::other(DEP),
            }),
            map_argument_validation_error(GkrmError::InstalledPathMetadata {
                path: PathBuf::from(UNIX),
                cause: std::io::Error::other(DEP),
            }),
            map_update_error(GkrmError::BaselineExistingConflict {
                resource_key: "res".to_owned(),
                baseline_id: BASELINE.to_owned(),
            }),
        ];

        for failure in failures {
            let human = failure.to_string();
            let json = serde_json::json!({
                "code": failure.code,
                "message": failure.message,
                "exit_code": failure.exit_code(),
            })
            .to_string();
            for text in [&human, &json] {
                for needle in [
                    WIN,
                    UNIX,
                    ENTRY,
                    PARSER,
                    DEP,
                    BASELINE,
                    "config.lua",
                    "Permission denied",
                ] {
                    assert!(
                        !text.contains(needle),
                        "CLI surface leaked {needle}: {text}"
                    );
                }
            }
        }
    }
}
