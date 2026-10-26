use std::collections::BTreeSet;

use crate::{
    ComparedFile, ComparedFileSide, ComparedIncomingFile, ComparisonWarning,
    EscrowFileClassification, FileComparisonStatus, FullInspectionReport, GkrmError,
    InstalledResourceRoot, ResourceMatch, ResourceRelativePath, Result, Sha256Digest,
    ZipResourceRoot,
};

/// Trusted, read-only, baseline-free update plan.
///
/// A `BaselineFreeUpdatePlan` is created only from a trusted
/// `FullInspectionReport`. Future apply APIs must accept this trusted plan type
/// rather than caller-built DTOs or arbitrary report combinations. CLI and
/// serialization representations must remain separate from this core model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineFreeUpdatePlan {
    resources: Vec<ResourceUpdatePlan>,
    unmatched_installed_resources: Vec<InstalledResourceRoot>,
    unmatched_incoming_resources: Vec<ZipResourceRoot>,
    warnings: Vec<UpdatePlanWarning>,
    counts: UpdatePlanCounts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUpdatePlan {
    resource_match: ResourceMatch,
    files: Vec<PlannedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    relative_path: ResourceRelativePath,
    comparison_status: FileComparisonStatus,
    disposition: BaselineFreeDisposition,
    reason: UpdatePlanReason,
    expected_installed: Option<ExpectedFileState>,
    expected_incoming: Option<ExpectedFileState>,
    incoming_escrow_classification: Option<EscrowFileClassification>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedFileState {
    size: u64,
    sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlanCounts {
    resources_planned: usize,
    no_change_files: usize,
    replace_candidates: usize,
    add_candidates: usize,
    merge_candidates: usize,
    preserved_files: usize,
    conflict_review_files: usize,
    unmatched_installed_resources: usize,
    unmatched_incoming_resources: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineFreeDisposition {
    NoChange,
    ReplaceCandidate,
    AddCandidate,
    MergeCandidate,
    Preserve,
    ConflictReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePlanReason {
    HashesMatch,
    ProtectedFileChanged,
    EditableFileChangedWithoutBaseline,
    UnsupportedFileChangedWithoutProfile,
    IncomingFileHasNoInstalledCounterpart,
    InstalledFileHasNoIncomingCounterpart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdatePlanWarning {
    BaselineUnavailable,
    SingleResourceFallback {
        installed_resource: InstalledResourceRoot,
        incoming_resource: ZipResourceRoot,
    },
}

impl BaselineFreeUpdatePlan {
    pub fn resources(&self) -> &[ResourceUpdatePlan] {
        &self.resources
    }

    pub fn unmatched_installed_resources(&self) -> &[InstalledResourceRoot] {
        &self.unmatched_installed_resources
    }

    pub fn unmatched_incoming_resources(&self) -> &[ZipResourceRoot] {
        &self.unmatched_incoming_resources
    }

    pub fn warnings(&self) -> &[UpdatePlanWarning] {
        &self.warnings
    }

    pub fn counts(&self) -> &UpdatePlanCounts {
        &self.counts
    }
}

impl ResourceUpdatePlan {
    pub fn resource_match(&self) -> &ResourceMatch {
        &self.resource_match
    }

    pub fn files(&self) -> &[PlannedFile] {
        &self.files
    }
}

impl PlannedFile {
    pub fn relative_path(&self) -> &ResourceRelativePath {
        &self.relative_path
    }

    pub fn comparison_status(&self) -> FileComparisonStatus {
        self.comparison_status
    }

    pub fn disposition(&self) -> BaselineFreeDisposition {
        self.disposition
    }

    pub fn reason(&self) -> UpdatePlanReason {
        self.reason
    }

    pub fn expected_installed(&self) -> Option<&ExpectedFileState> {
        self.expected_installed.as_ref()
    }

    pub fn expected_incoming(&self) -> Option<&ExpectedFileState> {
        self.expected_incoming.as_ref()
    }

    pub fn incoming_escrow_classification(&self) -> Option<&EscrowFileClassification> {
        self.incoming_escrow_classification.as_ref()
    }
}

impl ExpectedFileState {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

impl UpdatePlanCounts {
    pub fn resources_planned(&self) -> usize {
        self.resources_planned
    }

    pub fn no_change_files(&self) -> usize {
        self.no_change_files
    }

    pub fn replace_candidates(&self) -> usize {
        self.replace_candidates
    }

    pub fn add_candidates(&self) -> usize {
        self.add_candidates
    }

    pub fn merge_candidates(&self) -> usize {
        self.merge_candidates
    }

    pub fn preserved_files(&self) -> usize {
        self.preserved_files
    }

    pub fn conflict_review_files(&self) -> usize {
        self.conflict_review_files
    }

    pub fn unmatched_installed_resources(&self) -> usize {
        self.unmatched_installed_resources
    }

    pub fn unmatched_incoming_resources(&self) -> usize {
        self.unmatched_incoming_resources
    }
}

/// Create a trusted, read-only, baseline-free update plan.
///
/// The plan is created only from a trusted `FullInspectionReport`. Future apply
/// APIs must accept this trusted plan type rather than caller-built DTOs or
/// arbitrary report combinations. CLI and serialization representations must
/// remain separate from this core plan model.
pub fn create_baseline_free_update_plan(
    inspection: &FullInspectionReport,
) -> Result<BaselineFreeUpdatePlan> {
    let comparison = inspection.comparison();
    let mut matched_installed = BTreeSet::new();
    let mut matched_incoming = BTreeSet::new();
    let mut resources = Vec::with_capacity(comparison.matched_resources.len());

    for resource in &comparison.matched_resources {
        if !matched_installed.insert(resource.resource_match.installed_resource.clone()) {
            return Err(GkrmError::UpdatePlanDuplicateInstalledResourceMatch {
                resource: installed_resource_key(&resource.resource_match.installed_resource),
            });
        }
        if !matched_incoming.insert(resource.resource_match.incoming_resource.clone()) {
            return Err(GkrmError::UpdatePlanDuplicateIncomingResourceMatch {
                resource: incoming_resource_key(&resource.resource_match.incoming_resource),
            });
        }

        let mut paths = BTreeSet::new();
        let mut files = Vec::with_capacity(resource.files.len());
        let resource_key = resource_plan_key(&resource.resource_match);
        for file in &resource.files {
            if !paths.insert(file.relative_path.clone()) {
                return Err(GkrmError::UpdatePlanDuplicateFilePath {
                    resource: resource_key.clone(),
                    path: file.relative_path.to_string(),
                });
            }
            files.push(plan_file(&resource_key, file)?);
        }

        resources.push(ResourceUpdatePlan {
            resource_match: resource.resource_match.clone(),
            files,
        });
    }

    let mut warnings = Vec::with_capacity(comparison.warnings.len() + 1);
    warnings.push(UpdatePlanWarning::BaselineUnavailable);
    warnings.extend(comparison.warnings.iter().map(convert_warning));

    let mut plan = BaselineFreeUpdatePlan {
        resources,
        unmatched_installed_resources: comparison.unmatched_installed_resources.clone(),
        unmatched_incoming_resources: comparison.unmatched_incoming_resources.clone(),
        warnings,
        counts: UpdatePlanCounts::zero(),
    };
    plan.counts = calculate_counts(&plan);
    verify_counts(&plan)?;

    Ok(plan)
}

fn plan_file(resource: &str, file: &ComparedFile) -> Result<PlannedFile> {
    if matches!(file.status, FileComparisonStatus::InstalledOnly) && file.incoming.is_some() {
        return Err(GkrmError::UpdatePlanUnexpectedIncomingClassification {
            resource: resource.to_owned(),
            path: file.relative_path.to_string(),
        });
    }
    if !matches!(file.status, FileComparisonStatus::InstalledOnly) && file.incoming.is_none() {
        return Err(GkrmError::UpdatePlanMissingIncomingClassification {
            resource: resource.to_owned(),
            path: file.relative_path.to_string(),
        });
    }
    validate_file_sides(
        file.status,
        file.installed.is_some(),
        file.incoming.is_some(),
    )?;

    let expected_installed = file.installed.as_ref().map(expected_from_installed);
    let expected_incoming = file.incoming.as_ref().map(expected_from_incoming);
    let incoming_escrow_classification = match (&file.incoming, file.status) {
        (Some(incoming), _) => Some(incoming.escrow_classification.clone()),
        (None, FileComparisonStatus::InstalledOnly) => None,
        (None, _) => {
            return Err(GkrmError::UpdatePlanMissingIncomingClassification {
                resource: resource.to_owned(),
                path: file.relative_path.to_string(),
            });
        }
    };

    let (disposition, reason) = disposition_and_reason(
        file.status,
        incoming_escrow_classification.as_ref(),
        resource,
        &file.relative_path,
    )?;

    Ok(PlannedFile {
        relative_path: file.relative_path.clone(),
        comparison_status: file.status,
        disposition,
        reason,
        expected_installed,
        expected_incoming,
        incoming_escrow_classification,
    })
}

fn validate_file_sides(
    status: FileComparisonStatus,
    has_installed: bool,
    has_incoming: bool,
) -> Result<()> {
    let valid = match status {
        FileComparisonStatus::Unchanged | FileComparisonStatus::Changed => {
            has_installed && has_incoming
        }
        FileComparisonStatus::IncomingOnly => !has_installed && has_incoming,
        FileComparisonStatus::InstalledOnly => has_installed && !has_incoming,
    };

    if valid {
        Ok(())
    } else {
        Err(GkrmError::UpdatePlanInvalidFileSides {
            status,
            has_installed,
            has_incoming,
        })
    }
}

fn disposition_and_reason(
    status: FileComparisonStatus,
    incoming: Option<&EscrowFileClassification>,
    resource: &str,
    path: &ResourceRelativePath,
) -> Result<(BaselineFreeDisposition, UpdatePlanReason)> {
    match status {
        FileComparisonStatus::Unchanged => Ok((
            BaselineFreeDisposition::NoChange,
            UpdatePlanReason::HashesMatch,
        )),
        FileComparisonStatus::Changed => match incoming {
            Some(EscrowFileClassification::Protected) => Ok((
                BaselineFreeDisposition::ReplaceCandidate,
                UpdatePlanReason::ProtectedFileChanged,
            )),
            Some(EscrowFileClassification::Ignored { .. }) => Ok((
                BaselineFreeDisposition::MergeCandidate,
                UpdatePlanReason::EditableFileChangedWithoutBaseline,
            )),
            Some(EscrowFileClassification::NotSupported { .. }) => Ok((
                BaselineFreeDisposition::ConflictReview,
                UpdatePlanReason::UnsupportedFileChangedWithoutProfile,
            )),
            None => Err(GkrmError::UpdatePlanMissingIncomingClassification {
                resource: resource.to_owned(),
                path: path.to_string(),
            }),
        },
        FileComparisonStatus::IncomingOnly => Ok((
            BaselineFreeDisposition::AddCandidate,
            UpdatePlanReason::IncomingFileHasNoInstalledCounterpart,
        )),
        FileComparisonStatus::InstalledOnly => Ok((
            BaselineFreeDisposition::Preserve,
            UpdatePlanReason::InstalledFileHasNoIncomingCounterpart,
        )),
    }
}

fn expected_from_installed(side: &ComparedFileSide) -> ExpectedFileState {
    ExpectedFileState {
        size: side.size,
        sha256: side.sha256,
    }
}

fn expected_from_incoming(side: &ComparedIncomingFile) -> ExpectedFileState {
    ExpectedFileState {
        size: side.size,
        sha256: side.sha256,
    }
}

fn convert_warning(warning: &ComparisonWarning) -> UpdatePlanWarning {
    match warning {
        ComparisonWarning::SingleResourceFallback {
            installed_resource,
            incoming_resource,
        } => UpdatePlanWarning::SingleResourceFallback {
            installed_resource: installed_resource.clone(),
            incoming_resource: incoming_resource.clone(),
        },
    }
}

fn calculate_counts(plan: &BaselineFreeUpdatePlan) -> UpdatePlanCounts {
    let mut counts = UpdatePlanCounts {
        resources_planned: plan.resources.len(),
        unmatched_installed_resources: plan.unmatched_installed_resources.len(),
        unmatched_incoming_resources: plan.unmatched_incoming_resources.len(),
        ..UpdatePlanCounts::zero()
    };

    for resource in &plan.resources {
        for file in &resource.files {
            match file.disposition {
                BaselineFreeDisposition::NoChange => counts.no_change_files += 1,
                BaselineFreeDisposition::ReplaceCandidate => counts.replace_candidates += 1,
                BaselineFreeDisposition::AddCandidate => counts.add_candidates += 1,
                BaselineFreeDisposition::MergeCandidate => counts.merge_candidates += 1,
                BaselineFreeDisposition::Preserve => counts.preserved_files += 1,
                BaselineFreeDisposition::ConflictReview => counts.conflict_review_files += 1,
            }
        }
    }

    counts
}

fn verify_counts(plan: &BaselineFreeUpdatePlan) -> Result<()> {
    let counted = calculate_counts(plan);
    compare_count(
        "resources_planned",
        plan.counts.resources_planned,
        counted.resources_planned,
    )?;
    compare_count(
        "no_change_files",
        plan.counts.no_change_files,
        counted.no_change_files,
    )?;
    compare_count(
        "replace_candidates",
        plan.counts.replace_candidates,
        counted.replace_candidates,
    )?;
    compare_count(
        "add_candidates",
        plan.counts.add_candidates,
        counted.add_candidates,
    )?;
    compare_count(
        "merge_candidates",
        plan.counts.merge_candidates,
        counted.merge_candidates,
    )?;
    compare_count(
        "preserved_files",
        plan.counts.preserved_files,
        counted.preserved_files,
    )?;
    compare_count(
        "conflict_review_files",
        plan.counts.conflict_review_files,
        counted.conflict_review_files,
    )?;
    compare_count(
        "unmatched_installed_resources",
        plan.counts.unmatched_installed_resources,
        counted.unmatched_installed_resources,
    )?;
    compare_count(
        "unmatched_incoming_resources",
        plan.counts.unmatched_incoming_resources,
        counted.unmatched_incoming_resources,
    )
}

fn compare_count(expected: &'static str, actual: usize, counted: usize) -> Result<()> {
    if actual == counted {
        Ok(())
    } else {
        Err(GkrmError::UpdatePlanCountMismatch {
            expected,
            actual,
            counted,
        })
    }
}

impl UpdatePlanCounts {
    fn zero() -> Self {
        Self {
            resources_planned: 0,
            no_change_files: 0,
            replace_candidates: 0,
            add_candidates: 0,
            merge_candidates: 0,
            preserved_files: 0,
            conflict_review_files: 0,
            unmatched_installed_resources: 0,
            unmatched_incoming_resources: 0,
        }
    }
}

fn resource_plan_key(resource_match: &ResourceMatch) -> String {
    format!(
        "installed={} incoming={}",
        installed_resource_key(&resource_match.installed_resource),
        incoming_resource_key(&resource_match.incoming_resource)
    )
}

fn installed_resource_key(root: &InstalledResourceRoot) -> String {
    match root {
        InstalledResourceRoot::Root => ".".to_owned(),
        InstalledResourceRoot::Path(path) => path.to_string(),
    }
}

fn incoming_resource_key(root: &ZipResourceRoot) -> String {
    match root {
        ZipResourceRoot::Root => ".".to_owned(),
        ZipResourceRoot::Path(path) => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        create_baseline_free_update_plan, ComparedFile, ComparedFileSide, ComparedIncomingFile,
        EscrowFileClassification, FileComparisonStatus, FullInspectionReport, GkrmError,
        InstallationComparisonReport, InstallationRelativePath, InstalledInstallationScan,
        InstalledResourceRoot, ResourceComparison, ResourceMatch, ResourceMatchKind,
        ResourceRelativePath, Sha256Digest, ZipInspection, ZipManifestParseReport,
        ZipResourceDiscovery, ZipResourceRoot,
    };

    use super::BaselineFreeDisposition;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn rel(path: &str) -> ResourceRelativePath {
        ResourceRelativePath::from_safe_slash_path(
            InstallationRelativePath::from_path(Path::new(path))
                .expect("test path should be valid")
                .to_string(),
        )
    }

    fn side(size: u64, byte: u8) -> ComparedFileSide {
        ComparedFileSide {
            size,
            sha256: digest(byte),
        }
    }

    fn incoming(
        size: u64,
        byte: u8,
        escrow_classification: EscrowFileClassification,
    ) -> ComparedIncomingFile {
        ComparedIncomingFile {
            size,
            sha256: digest(byte),
            escrow_classification,
        }
    }

    fn file(
        path: &str,
        status: FileComparisonStatus,
        installed: Option<ComparedFileSide>,
        incoming: Option<ComparedIncomingFile>,
    ) -> ComparedFile {
        ComparedFile {
            relative_path: rel(path),
            status,
            installed,
            incoming,
        }
    }

    fn report(files: Vec<ComparedFile>) -> FullInspectionReport {
        report_with_matches(vec![ResourceComparison {
            resource_match: ResourceMatch {
                installed_resource: InstalledResourceRoot::Root,
                incoming_resource: ZipResourceRoot::Root,
                match_kind: ResourceMatchKind::ExactName,
            },
            files,
        }])
    }

    fn report_with_matches(matches: Vec<ResourceComparison>) -> FullInspectionReport {
        FullInspectionReport::from_parts_for_test(
            InstalledInstallationScan {
                root: "installed".into(),
                resources: Vec::new(),
                warnings: Vec::new(),
            },
            Sha256Digest::new([0x42; 32]),
            ZipInspection {
                path: "package.zip".into(),
                entries: Vec::new(),
            },
            ZipResourceDiscovery {
                resources: Vec::new(),
                unassigned_entries: Vec::new(),
                warnings: Vec::new(),
            },
            ZipManifestParseReport {
                resources: Vec::new(),
            },
            crate::EscrowClassificationReport {
                resources: Vec::new(),
            },
            InstallationComparisonReport {
                matched_resources: matches,
                unmatched_installed_resources: Vec::new(),
                unmatched_incoming_resources: Vec::new(),
                warnings: Vec::new(),
            },
        )
    }

    #[test]
    fn rejects_invalid_status_side_combinations() {
        let err = create_baseline_free_update_plan(&report(vec![file(
            "bad.lua",
            FileComparisonStatus::IncomingOnly,
            Some(side(1, 1)),
            Some(incoming(2, 2, EscrowFileClassification::Protected)),
        )]))
        .expect_err("invalid sides should fail");

        assert!(matches!(
            err,
            GkrmError::UpdatePlanInvalidFileSides {
                status: FileComparisonStatus::IncomingOnly,
                has_installed: true,
                has_incoming: true
            }
        ));
    }

    #[test]
    fn rejects_missing_incoming_classification() {
        let err = create_baseline_free_update_plan(&report(vec![file(
            "bad.lua",
            FileComparisonStatus::Changed,
            Some(side(1, 1)),
            None,
        )]))
        .expect_err("missing incoming classification should fail");

        assert!(matches!(
            err,
            GkrmError::UpdatePlanMissingIncomingClassification { .. }
        ));
    }

    #[test]
    fn rejects_unexpected_incoming_classification_on_installed_only() {
        let err = create_baseline_free_update_plan(&report(vec![file(
            "bad.lua",
            FileComparisonStatus::InstalledOnly,
            Some(side(1, 1)),
            Some(incoming(2, 2, EscrowFileClassification::Protected)),
        )]))
        .expect_err("unexpected incoming classification should fail");

        assert!(matches!(
            err,
            GkrmError::UpdatePlanUnexpectedIncomingClassification { .. }
        ));
    }

    #[test]
    fn rejects_duplicate_file_paths() {
        let err = create_baseline_free_update_plan(&report(vec![
            file(
                "dup.lua",
                FileComparisonStatus::InstalledOnly,
                Some(side(1, 1)),
                None,
            ),
            file(
                "dup.lua",
                FileComparisonStatus::InstalledOnly,
                Some(side(2, 2)),
                None,
            ),
        ]))
        .expect_err("duplicate path should fail");

        assert!(matches!(err, GkrmError::UpdatePlanDuplicateFilePath { .. }));
    }

    #[test]
    fn rejects_one_installed_resource_used_in_multiple_matches() {
        let matches = vec![
            ResourceComparison {
                resource_match: ResourceMatch {
                    installed_resource: InstalledResourceRoot::Root,
                    incoming_resource: ZipResourceRoot::Path(
                        crate::ZipRelativePath::new(0, b"a").expect("path should be valid"),
                    ),
                    match_kind: ResourceMatchKind::ExactName,
                },
                files: Vec::new(),
            },
            ResourceComparison {
                resource_match: ResourceMatch {
                    installed_resource: InstalledResourceRoot::Root,
                    incoming_resource: ZipResourceRoot::Path(
                        crate::ZipRelativePath::new(0, b"b").expect("path should be valid"),
                    ),
                    match_kind: ResourceMatchKind::ExactName,
                },
                files: Vec::new(),
            },
        ];

        let err = create_baseline_free_update_plan(&report_with_matches(matches))
            .expect_err("duplicate installed resource should fail");

        assert!(matches!(
            err,
            GkrmError::UpdatePlanDuplicateInstalledResourceMatch { .. }
        ));
    }

    #[test]
    fn rejects_one_incoming_resource_used_in_multiple_matches() {
        let matches = vec![
            ResourceComparison {
                resource_match: ResourceMatch {
                    installed_resource: InstalledResourceRoot::Path(
                        InstallationRelativePath::from_path(Path::new("a"))
                            .expect("path should be valid"),
                    ),
                    incoming_resource: ZipResourceRoot::Root,
                    match_kind: ResourceMatchKind::ExactName,
                },
                files: Vec::new(),
            },
            ResourceComparison {
                resource_match: ResourceMatch {
                    installed_resource: InstalledResourceRoot::Path(
                        InstallationRelativePath::from_path(Path::new("b"))
                            .expect("path should be valid"),
                    ),
                    incoming_resource: ZipResourceRoot::Root,
                    match_kind: ResourceMatchKind::ExactName,
                },
                files: Vec::new(),
            },
        ];

        let err = create_baseline_free_update_plan(&report_with_matches(matches))
            .expect_err("duplicate incoming resource should fail");

        assert!(matches!(
            err,
            GkrmError::UpdatePlanDuplicateIncomingResourceMatch { .. }
        ));
    }

    #[test]
    fn installed_only_has_no_incoming_classification() {
        let plan = create_baseline_free_update_plan(&report(vec![file(
            "old.lua",
            FileComparisonStatus::InstalledOnly,
            Some(side(7, 7)),
            None,
        )]))
        .expect("plan should be created");

        let planned = &plan.resources()[0].files()[0];
        assert_eq!(planned.disposition(), BaselineFreeDisposition::Preserve);
        assert!(planned.incoming_escrow_classification().is_none());
    }
}
