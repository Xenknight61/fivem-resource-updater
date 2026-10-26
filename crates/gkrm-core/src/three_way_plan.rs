use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::three_way_fingerprint::{self, IncomingFingerprintFile, InstalledFingerprintFile};
use crate::{
    BaselineEscrowClass, BaselineId, DiscoveredZipResource, EscrowFileClassification,
    FullInspectionReport, GkrmError, InstalledResourceRoot, ResolvedOfficialBaseline,
    ResourceRelativePath, Result, SafeResourceKey, Sha256Digest, StoredBaseline, ZipEntryKind,
    ZipRelativePath, ZipResourceName, ZipResourceRoot,
};

const DEFAULT_MAX_PLAN_ENTRIES: usize = 100_000;
const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug)]
pub struct ThreeWayUpdatePlanRequest<'a> {
    baseline: &'a ResolvedOfficialBaseline,
    installed: &'a InstalledResourceSnapshot,
    incoming: &'a IncomingOfficialResourceSnapshot,
    options: ThreeWayPlannerOptions,
}

impl<'a> ThreeWayUpdatePlanRequest<'a> {
    pub fn try_new(
        baseline: &'a ResolvedOfficialBaseline,
        installed: &'a InstalledResourceSnapshot,
        incoming: &'a IncomingOfficialResourceSnapshot,
        options: ThreeWayPlannerOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            baseline,
            installed,
            incoming,
            options,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreeWayPlannerOptions {
    max_plan_entries: usize,
}

impl Default for ThreeWayPlannerOptions {
    fn default() -> Self {
        Self {
            max_plan_entries: DEFAULT_MAX_PLAN_ENTRIES,
        }
    }
}

impl ThreeWayPlannerOptions {
    pub fn try_new(max_plan_entries: usize) -> Result<Self> {
        let options = Self { max_plan_entries };
        options.validate()?;
        Ok(options)
    }

    pub fn max_plan_entries(&self) -> usize {
        self.max_plan_entries
    }

    fn validate(self) -> Result<()> {
        if self.max_plan_entries == 0 {
            return Err(GkrmError::ThreeWayPlannerOptionsInvalid {
                limit: "max_plan_entries",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledResourceSnapshot {
    version: u32,
    resource_key: SafeResourceKey,
    resource_root: InstalledResourceRoot,
    matched_incoming_resource: ZipResourceRoot,
    files: Vec<InstalledSnapshotFile>,
    fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledSnapshotFile {
    path: ResourceRelativePath,
    sha256: Sha256Digest,
}

impl InstalledResourceSnapshot {
    pub fn try_from_inspection(
        inspection: &FullInspectionReport,
        selected_root: &InstalledResourceRoot,
        expected_key: &SafeResourceKey,
    ) -> Result<Self> {
        let resources = inspection
            .installed()
            .resources
            .iter()
            .filter(|resource| &resource.root == selected_root)
            .collect::<Vec<_>>();
        let resource = exactly_one_installed_resource(resources)?;

        let resource_key = SafeResourceKey::parse(&resource.name)
            .map_err(|_| GkrmError::ThreeWayBaselineInstalledResourceMismatch)?;
        if &resource_key != expected_key {
            return Err(GkrmError::ThreeWayBaselineInstalledResourceMismatch);
        }

        let comparisons = inspection
            .comparison()
            .matched_resources
            .iter()
            .filter(|comparison| &comparison.resource_match.installed_resource == selected_root)
            .collect::<Vec<_>>();
        let comparison = exactly_one_installed_comparison(comparisons)?;

        let mut seen = BTreeSet::new();
        let mut files = Vec::with_capacity(resource.files.len());
        for file in &resource.files {
            if !seen.insert(file.relative_path.clone()) {
                return Err(GkrmError::ThreeWayDuplicateInstalledPath);
            }
            files.push(InstalledSnapshotFile {
                path: file.relative_path.clone(),
                sha256: file.sha256,
            });
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));

        let fingerprint = installed_snapshot_fingerprint(&resource_key, &files)?;
        Ok(Self {
            version: SNAPSHOT_VERSION,
            resource_key,
            resource_root: selected_root.clone(),
            matched_incoming_resource: comparison.resource_match.incoming_resource.clone(),
            files,
            fingerprint,
        })
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn resource_root(&self) -> &InstalledResourceRoot {
        &self.resource_root
    }

    pub fn fingerprint(&self) -> &Sha256Digest {
        &self.fingerprint
    }

    /// Path and content digest for every installed file, so planners can read the file set
    /// without reaching into the private snapshot representation.
    pub(crate) fn file_states(
        &self,
    ) -> impl Iterator<Item = (&ResourceRelativePath, &Sha256Digest)> {
        self.files.iter().map(|file| (&file.path, &file.sha256))
    }

    pub(crate) fn matched_incoming_resource(&self) -> &ZipResourceRoot {
        &self.matched_incoming_resource
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        resource_key: SafeResourceKey,
        files: Vec<(ResourceRelativePath, Sha256Digest)>,
    ) -> Self {
        let mut files = files
            .into_iter()
            .map(|(path, sha256)| InstalledSnapshotFile { path, sha256 })
            .collect::<Vec<_>>();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let fingerprint = installed_snapshot_fingerprint(&resource_key, &files)
            .expect("test installed snapshot fingerprint should encode");
        Self {
            version: SNAPSHOT_VERSION,
            resource_key,
            resource_root: InstalledResourceRoot::Root,
            matched_incoming_resource: ZipResourceRoot::Root,
            files,
            fingerprint,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_version_for_test(mut self, version: u32) -> Self {
        self.version = version;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingOfficialResourceSnapshot {
    version: u32,
    resource_key: SafeResourceKey,
    resource_root: ZipResourceRoot,
    matched_installed_resource: InstalledResourceRoot,
    package_fingerprint: Sha256Digest,
    resource_fingerprint: Sha256Digest,
    files: Vec<IncomingSnapshotFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncomingSnapshotFile {
    path: ResourceRelativePath,
    sha256: Sha256Digest,
    escrow_class: BaselineEscrowClass,
}

impl IncomingOfficialResourceSnapshot {
    pub fn try_from_inspection(
        inspection: &FullInspectionReport,
        selected_root: &ZipResourceRoot,
        expected_key: &SafeResourceKey,
    ) -> Result<Self> {
        let package_fingerprint = *inspection.incoming_package_fingerprint();
        let resources = inspection
            .incoming_discovery()
            .resources
            .iter()
            .filter(|resource| &resource.root == selected_root)
            .collect::<Vec<_>>();
        let resource = exactly_one_incoming_resource(resources)?;

        let resource_key = trusted_incoming_resource_key(resource)?;
        if &resource_key != expected_key {
            return Err(GkrmError::ThreeWayBaselineIncomingResourceMismatch);
        }

        let comparisons = inspection
            .comparison()
            .matched_resources
            .iter()
            .filter(|comparison| &comparison.resource_match.incoming_resource == selected_root)
            .collect::<Vec<_>>();
        let comparison = exactly_one_incoming_comparison(comparisons)?;

        let escrow_resources = inspection
            .escrow()
            .resources
            .iter()
            .filter(|classified| &classified.resource_root == selected_root)
            .collect::<Vec<_>>();
        let escrow_resource = exactly_one_incoming_escrow(escrow_resources)?;

        let mut comparison_hashes = BTreeMap::new();
        for compared in &comparison.files {
            if let Some(incoming) = compared.incoming.as_ref() {
                if comparison_hashes
                    .insert(
                        compared.relative_path.clone(),
                        (
                            incoming.sha256,
                            escrow_class_to_baseline(&incoming.escrow_classification),
                        ),
                    )
                    .is_some()
                {
                    return Err(GkrmError::ThreeWayDuplicateIncomingPath);
                }
            }
        }

        let mut escrow_classes = BTreeMap::new();
        for classified in &escrow_resource.files {
            let path =
                ResourceRelativePath::try_from_slash_str(&classified.resource_relative_path)?;
            if escrow_classes
                .insert(path, escrow_class_to_baseline(&classified.classification))
                .is_some()
            {
                return Err(GkrmError::ThreeWayDuplicateIncomingPath);
            }
        }

        let mut seen = BTreeSet::new();
        let mut files = Vec::new();
        for entry in &resource.entries {
            if entry.kind != ZipEntryKind::File {
                continue;
            }
            let path = zip_resource_relative_path(selected_root, &entry.path)?;
            if !seen.insert(path.clone()) {
                return Err(GkrmError::ThreeWayDuplicateIncomingPath);
            }
            let (sha256, comparison_class) = comparison_hashes
                .get(&path)
                .copied()
                .ok_or(GkrmError::ThreeWayMissingRequiredDigest)?;
            let escrow_class = *escrow_classes
                .get(&path)
                .ok_or(GkrmError::ThreeWaySnapshotFingerprintFailure)?;
            if comparison_class != escrow_class {
                return Err(GkrmError::ThreeWaySnapshotFingerprintFailure);
            }
            files.push(IncomingSnapshotFile {
                path,
                sha256,
                escrow_class,
            });
        }
        if comparison_hashes.keys().any(|path| !seen.contains(path))
            || escrow_classes.keys().any(|path| !seen.contains(path))
        {
            return Err(GkrmError::ThreeWaySnapshotFingerprintFailure);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));

        let resource_fingerprint = incoming_resource_fingerprint(
            &package_fingerprint,
            &resource_key,
            selected_root,
            &files,
        )?;
        Ok(Self {
            version: SNAPSHOT_VERSION,
            resource_key,
            resource_root: selected_root.clone(),
            matched_installed_resource: comparison.resource_match.installed_resource.clone(),
            package_fingerprint,
            resource_fingerprint,
            files,
        })
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn resource_root(&self) -> &ZipResourceRoot {
        &self.resource_root
    }

    pub fn package_fingerprint(&self) -> &Sha256Digest {
        &self.package_fingerprint
    }

    pub fn resource_fingerprint(&self) -> &Sha256Digest {
        &self.resource_fingerprint
    }

    /// Path, content digest, and declared escrow class for every incoming file.
    pub(crate) fn incoming_file_states(
        &self,
    ) -> impl Iterator<Item = (&ResourceRelativePath, &Sha256Digest, BaselineEscrowClass)> {
        self.files
            .iter()
            .map(|file| (&file.path, &file.sha256, file.escrow_class))
    }

    pub(crate) fn matched_installed_resource(&self) -> &InstalledResourceRoot {
        &self.matched_installed_resource
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        resource_key: SafeResourceKey,
        package_fingerprint: Sha256Digest,
        files: Vec<(ResourceRelativePath, Sha256Digest, BaselineEscrowClass)>,
    ) -> Self {
        let mut files = files
            .into_iter()
            .map(|(path, sha256, escrow_class)| IncomingSnapshotFile {
                path,
                sha256,
                escrow_class,
            })
            .collect::<Vec<_>>();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let resource_fingerprint = incoming_resource_fingerprint(
            &package_fingerprint,
            &resource_key,
            &ZipResourceRoot::Root,
            &files,
        )
        .expect("test incoming snapshot fingerprint should encode");
        Self {
            version: SNAPSHOT_VERSION,
            resource_key,
            resource_root: ZipResourceRoot::Root,
            matched_installed_resource: InstalledResourceRoot::Root,
            package_fingerprint,
            resource_fingerprint,
            files,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_version_for_test(mut self, version: u32) -> Self {
        self.version = version;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayUpdatePlan {
    resource_key: SafeResourceKey,
    baseline_id: BaselineId,
    plan_id: ThreeWayPlanId,
    installed_snapshot_fingerprint: Sha256Digest,
    incoming_package_fingerprint: Sha256Digest,
    incoming_resource_fingerprint: Sha256Digest,
    entries: Vec<ThreeWayPlanEntry>,
    summary: ThreeWayPlanSummary,
    readiness: ThreeWayPlanReadiness,
}

impl ThreeWayUpdatePlan {
    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn baseline_id(&self) -> &BaselineId {
        &self.baseline_id
    }

    pub fn plan_id(&self) -> &ThreeWayPlanId {
        &self.plan_id
    }

    pub fn installed_snapshot_fingerprint(&self) -> &Sha256Digest {
        &self.installed_snapshot_fingerprint
    }

    pub fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_package_fingerprint
    }

    pub fn incoming_resource_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_resource_fingerprint
    }

    pub fn entries(&self) -> &[ThreeWayPlanEntry] {
        &self.entries
    }

    pub fn summary(&self) -> &ThreeWayPlanSummary {
        &self.summary
    }

    pub fn readiness(&self) -> ThreeWayPlanReadiness {
        self.readiness
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPlanEntry {
    path: ResourceRelativePath,
    baseline_state: ThreeWayFileState,
    installed_state: ThreeWayFileState,
    incoming_state: ThreeWayFileState,
    local_delta: ThreeWayDelta,
    incoming_delta: ThreeWayDelta,
    disposition: ThreeWayPlanDisposition,
    policy_transition: EscrowPolicyTransition,
}

impl ThreeWayPlanEntry {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }

    pub fn baseline_state(&self) -> &ThreeWayFileState {
        &self.baseline_state
    }

    pub fn installed_state(&self) -> &ThreeWayFileState {
        &self.installed_state
    }

    pub fn incoming_state(&self) -> &ThreeWayFileState {
        &self.incoming_state
    }

    pub fn local_delta(&self) -> ThreeWayDelta {
        self.local_delta
    }

    pub fn incoming_delta(&self) -> ThreeWayDelta {
        self.incoming_delta
    }

    pub fn disposition(&self) -> ThreeWayPlanDisposition {
        self.disposition
    }

    pub fn policy_transition(&self) -> EscrowPolicyTransition {
        self.policy_transition
    }

    pub fn blocks_automatic_application(&self) -> bool {
        matches!(
            self.disposition,
            ThreeWayPlanDisposition::MergeCandidate
                | ThreeWayPlanDisposition::ConflictReview
                | ThreeWayPlanDisposition::DeleteVsModifyConflict
                | ThreeWayPlanDisposition::ModifyVsDeleteConflict
                | ThreeWayPlanDisposition::AddVsAddConflict
                | ThreeWayPlanDisposition::PolicyReview
                | ThreeWayPlanDisposition::PolicyConflictReview
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPlanSummary {
    total: u64,
    no_change: u64,
    incoming_actions: u64,
    preserved_local: u64,
    converged: u64,
    merge_candidates: u64,
    conflicts: u64,
    policy_reviews: u64,
}

impl ThreeWayPlanSummary {
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn no_change(&self) -> u64 {
        self.no_change
    }

    pub fn incoming_actions(&self) -> u64 {
        self.incoming_actions
    }

    pub fn preserved_local(&self) -> u64 {
        self.preserved_local
    }

    pub fn converged(&self) -> u64 {
        self.converged
    }

    pub fn merge_candidates(&self) -> u64 {
        self.merge_candidates
    }

    pub fn conflicts(&self) -> u64 {
        self.conflicts
    }

    pub fn policy_reviews(&self) -> u64 {
        self.policy_reviews
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayPlanReadiness {
    ReviewRequired,
    HasBlockingEntries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreeWayPlanId(Sha256Digest);

impl ThreeWayPlanId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayFileState {
    Absent,
    Present {
        sha256: Sha256Digest,
        escrow_class: Option<BaselineEscrowClass>,
        trusted_baseline_blob_available: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayDelta {
    Unchanged,
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowPolicyTransition {
    None,
    Changed {
        baseline: BaselineEscrowClass,
        incoming: BaselineEscrowClass,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayPlanDisposition {
    NoChange,
    UseIncoming,
    RemoveForIncoming,
    PreserveInstalled,
    PreserveInstalledDeletion,
    AddIncoming,
    PreserveInstalledAddition,
    Converged,
    ConvergedAddition,
    ConvergedDeletion,
    MergeCandidate,
    ConflictReview,
    DeleteVsModifyConflict,
    ModifyVsDeleteConflict,
    AddVsAddConflict,
    PolicyReview,
    PolicyConflictReview,
}

impl ThreeWayUpdatePlan {
    pub(crate) fn from_desktop_apply_descriptor(
        resource_key: SafeResourceKey,
        baseline_id: BaselineId,
        plan_id: Sha256Digest,
        installed_snapshot_fingerprint: Sha256Digest,
        incoming_package_fingerprint: Sha256Digest,
        incoming_resource_fingerprint: Sha256Digest,
        entries: Vec<ThreeWayPlanEntry>,
    ) -> Self {
        let summary = summarize_entries_for_descriptor(&entries);
        Self {
            resource_key,
            baseline_id,
            plan_id: ThreeWayPlanId::from_digest(plan_id),
            installed_snapshot_fingerprint,
            incoming_package_fingerprint,
            incoming_resource_fingerprint,
            entries,
            summary,
            readiness: ThreeWayPlanReadiness::ReviewRequired,
        }
    }
}

impl ThreeWayPlanEntry {
    pub(crate) fn from_desktop_apply_descriptor_exact(
        path: ResourceRelativePath,
        baseline_state: ThreeWayFileState,
        installed_state: ThreeWayFileState,
        incoming_state: ThreeWayFileState,
        local_delta: ThreeWayDelta,
        incoming_delta: ThreeWayDelta,
        disposition: ThreeWayPlanDisposition,
    ) -> Self {
        Self {
            path,
            baseline_state,
            installed_state,
            incoming_state,
            local_delta,
            incoming_delta,
            disposition,
            policy_transition: EscrowPolicyTransition::None,
        }
    }
}

fn summarize_entries_for_descriptor(entries: &[ThreeWayPlanEntry]) -> ThreeWayPlanSummary {
    let mut summary = ThreeWayPlanSummary {
        total: entries.len() as u64,
        no_change: 0,
        incoming_actions: 0,
        preserved_local: 0,
        converged: 0,
        merge_candidates: 0,
        conflicts: 0,
        policy_reviews: 0,
    };
    for entry in entries {
        match entry.disposition {
            ThreeWayPlanDisposition::NoChange => summary.no_change += 1,
            ThreeWayPlanDisposition::UseIncoming
            | ThreeWayPlanDisposition::RemoveForIncoming
            | ThreeWayPlanDisposition::AddIncoming => summary.incoming_actions += 1,
            ThreeWayPlanDisposition::PreserveInstalled
            | ThreeWayPlanDisposition::PreserveInstalledDeletion
            | ThreeWayPlanDisposition::PreserveInstalledAddition => summary.preserved_local += 1,
            ThreeWayPlanDisposition::Converged
            | ThreeWayPlanDisposition::ConvergedAddition
            | ThreeWayPlanDisposition::ConvergedDeletion => summary.converged += 1,
            ThreeWayPlanDisposition::MergeCandidate => summary.merge_candidates += 1,
            ThreeWayPlanDisposition::PolicyReview
            | ThreeWayPlanDisposition::PolicyConflictReview => summary.policy_reviews += 1,
            ThreeWayPlanDisposition::ConflictReview
            | ThreeWayPlanDisposition::DeleteVsModifyConflict
            | ThreeWayPlanDisposition::ModifyVsDeleteConflict
            | ThreeWayPlanDisposition::AddVsAddConflict => summary.conflicts += 1,
        }
    }
    summary
}

pub fn create_three_way_update_plan(
    request: ThreeWayUpdatePlanRequest<'_>,
) -> Result<ThreeWayUpdatePlan> {
    request.options.validate()?;
    validate_resource_binding(request.baseline, request.installed, request.incoming)?;

    let baseline_files = baseline_file_map(request.baseline.stored_baseline())?;
    let installed_files = installed_file_map(request.installed)?;
    let incoming_files = incoming_file_map(request.incoming)?;
    let union = path_union(
        baseline_files.keys(),
        installed_files.keys(),
        incoming_files.keys(),
        request.options.max_plan_entries,
    )?;

    let mut entries = Vec::with_capacity(union.len());
    for path in union {
        let baseline = baseline_files.get(&path);
        let installed = installed_files.get(&path);
        let incoming = incoming_files.get(&path);
        if baseline.is_none() && installed.is_none() && incoming.is_none() {
            return Err(GkrmError::ThreeWayInternalInvariant);
        }

        let baseline_state = baseline_state(baseline)?;
        let installed_state = installed_state(installed);
        let incoming_state = incoming_state(incoming);
        let local_delta = calculate_delta(&baseline_state, &installed_state);
        let incoming_delta = calculate_delta(&baseline_state, &incoming_state);
        let policy_transition = policy_transition(baseline, incoming);
        let disposition = disposition(
            &baseline_state,
            &installed_state,
            &incoming_state,
            local_delta,
            incoming_delta,
            policy_transition,
        )?;

        entries.push(ThreeWayPlanEntry {
            path,
            baseline_state,
            installed_state,
            incoming_state,
            local_delta,
            incoming_delta,
            disposition,
            policy_transition,
        });
    }

    let summary = summarize(&entries)?;
    let readiness = if entries
        .iter()
        .any(ThreeWayPlanEntry::blocks_automatic_application)
    {
        ThreeWayPlanReadiness::HasBlockingEntries
    } else {
        ThreeWayPlanReadiness::ReviewRequired
    };
    let plan_id = plan_id(
        request.baseline,
        request.installed,
        request.incoming,
        &entries,
    )?;

    Ok(ThreeWayUpdatePlan {
        resource_key: request.baseline.resource_key().clone(),
        baseline_id: request.baseline.baseline_id().clone(),
        plan_id,
        installed_snapshot_fingerprint: *request.installed.fingerprint(),
        incoming_package_fingerprint: *request.incoming.package_fingerprint(),
        incoming_resource_fingerprint: *request.incoming.resource_fingerprint(),
        entries,
        summary,
        readiness,
    })
}

fn validate_resource_binding(
    baseline: &ResolvedOfficialBaseline,
    installed: &InstalledResourceSnapshot,
    incoming: &IncomingOfficialResourceSnapshot,
) -> Result<()> {
    if installed.version != SNAPSHOT_VERSION || incoming.version != SNAPSHOT_VERSION {
        return Err(GkrmError::ThreeWayUnsupportedTrustedSnapshotVersion);
    }
    if baseline.resource_key() != installed.resource_key() {
        return Err(GkrmError::ThreeWayBaselineInstalledResourceMismatch);
    }
    if baseline.resource_key() != incoming.resource_key() {
        return Err(GkrmError::ThreeWayBaselineIncomingResourceMismatch);
    }
    if installed.resource_key() != incoming.resource_key() {
        return Err(GkrmError::ThreeWayInstalledIncomingResourceMismatch);
    }
    if installed.matched_incoming_resource != incoming.resource_root
        || incoming.matched_installed_resource != installed.resource_root
    {
        return Err(GkrmError::ThreeWaySelectedIncomingResourceAmbiguous);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct BaselineFileState {
    sha256: Sha256Digest,
    escrow_class: BaselineEscrowClass,
    trusted_blob_available: bool,
}

#[derive(Clone, Copy)]
struct InstalledFileState {
    sha256: Sha256Digest,
}

#[derive(Clone, Copy)]
struct IncomingFileState {
    sha256: Sha256Digest,
    escrow_class: BaselineEscrowClass,
}

fn baseline_file_map(
    baseline: &StoredBaseline,
) -> Result<BTreeMap<ResourceRelativePath, BaselineFileState>> {
    let mut files = BTreeMap::new();
    for file in baseline.files() {
        let trusted_blob_available = file.blob_sha256().is_some();
        if file.escrow_class() == BaselineEscrowClass::Ignored && !trusted_blob_available {
            return Err(GkrmError::ThreeWayInconsistentIgnoredBaselineBlobPolicy);
        }
        if files
            .insert(
                file.relative_path().clone(),
                BaselineFileState {
                    sha256: *file.sha256(),
                    escrow_class: file.escrow_class(),
                    trusted_blob_available,
                },
            )
            .is_some()
        {
            return Err(GkrmError::ThreeWayDuplicateBaselinePath);
        }
    }
    Ok(files)
}

fn installed_file_map(
    snapshot: &InstalledResourceSnapshot,
) -> Result<BTreeMap<ResourceRelativePath, InstalledFileState>> {
    let mut files = BTreeMap::new();
    for file in &snapshot.files {
        if files
            .insert(
                file.path.clone(),
                InstalledFileState {
                    sha256: file.sha256,
                },
            )
            .is_some()
        {
            return Err(GkrmError::ThreeWayDuplicateInstalledPath);
        }
    }
    Ok(files)
}

fn incoming_file_map(
    snapshot: &IncomingOfficialResourceSnapshot,
) -> Result<BTreeMap<ResourceRelativePath, IncomingFileState>> {
    let mut files = BTreeMap::new();
    for file in &snapshot.files {
        if files
            .insert(
                file.path.clone(),
                IncomingFileState {
                    sha256: file.sha256,
                    escrow_class: file.escrow_class,
                },
            )
            .is_some()
        {
            return Err(GkrmError::ThreeWayDuplicateIncomingPath);
        }
    }
    Ok(files)
}

fn path_union<'a>(
    baseline: impl Iterator<Item = &'a ResourceRelativePath>,
    installed: impl Iterator<Item = &'a ResourceRelativePath>,
    incoming: impl Iterator<Item = &'a ResourceRelativePath>,
    limit: usize,
) -> Result<BTreeSet<ResourceRelativePath>> {
    let mut union = BTreeSet::new();
    for path in baseline.chain(installed).chain(incoming) {
        if union.insert(path.clone()) {
            let actual = union
                .len()
                .checked_add(0)
                .ok_or(GkrmError::ThreeWayArithmeticOverflow)?;
            if actual > limit {
                return Err(GkrmError::ThreeWayPlanEntryLimitExceeded { limit, actual });
            }
        }
    }
    Ok(union)
}

fn baseline_state(file: Option<&BaselineFileState>) -> Result<ThreeWayFileState> {
    Ok(match file {
        Some(file) => ThreeWayFileState::Present {
            sha256: file.sha256,
            escrow_class: Some(file.escrow_class),
            trusted_baseline_blob_available: file.trusted_blob_available,
        },
        None => ThreeWayFileState::Absent,
    })
}

fn installed_state(file: Option<&InstalledFileState>) -> ThreeWayFileState {
    match file {
        Some(file) => ThreeWayFileState::Present {
            sha256: file.sha256,
            escrow_class: None,
            trusted_baseline_blob_available: false,
        },
        None => ThreeWayFileState::Absent,
    }
}

fn incoming_state(file: Option<&IncomingFileState>) -> ThreeWayFileState {
    match file {
        Some(file) => ThreeWayFileState::Present {
            sha256: file.sha256,
            escrow_class: Some(file.escrow_class),
            trusted_baseline_blob_available: false,
        },
        None => ThreeWayFileState::Absent,
    }
}

fn calculate_delta(baseline: &ThreeWayFileState, side: &ThreeWayFileState) -> ThreeWayDelta {
    match (baseline, side) {
        (ThreeWayFileState::Absent, ThreeWayFileState::Absent) => ThreeWayDelta::Unchanged,
        (ThreeWayFileState::Absent, ThreeWayFileState::Present { .. }) => ThreeWayDelta::Added,
        (ThreeWayFileState::Present { .. }, ThreeWayFileState::Absent) => ThreeWayDelta::Deleted,
        (
            ThreeWayFileState::Present {
                sha256: baseline, ..
            },
            ThreeWayFileState::Present { sha256: side, .. },
        ) if baseline == side => ThreeWayDelta::Unchanged,
        (ThreeWayFileState::Present { .. }, ThreeWayFileState::Present { .. }) => {
            ThreeWayDelta::Modified
        }
    }
}

fn policy_transition(
    baseline: Option<&BaselineFileState>,
    incoming: Option<&IncomingFileState>,
) -> EscrowPolicyTransition {
    match (baseline, incoming) {
        (Some(baseline), Some(incoming)) if baseline.escrow_class != incoming.escrow_class => {
            EscrowPolicyTransition::Changed {
                baseline: baseline.escrow_class,
                incoming: incoming.escrow_class,
            }
        }
        _ => EscrowPolicyTransition::None,
    }
}

fn disposition(
    baseline: &ThreeWayFileState,
    installed: &ThreeWayFileState,
    incoming: &ThreeWayFileState,
    local_delta: ThreeWayDelta,
    incoming_delta: ThreeWayDelta,
    policy_transition: EscrowPolicyTransition,
) -> Result<ThreeWayPlanDisposition> {
    if policy_transition != EscrowPolicyTransition::None {
        return Ok(
            if local_delta == ThreeWayDelta::Unchanged && incoming_delta == ThreeWayDelta::Unchanged
            {
                ThreeWayPlanDisposition::PolicyReview
            } else {
                ThreeWayPlanDisposition::PolicyConflictReview
            },
        );
    }

    match baseline {
        ThreeWayFileState::Present { .. } => match (local_delta, incoming_delta) {
            (ThreeWayDelta::Unchanged, ThreeWayDelta::Unchanged) => {
                Ok(ThreeWayPlanDisposition::NoChange)
            }
            (ThreeWayDelta::Unchanged, ThreeWayDelta::Modified) => {
                Ok(ThreeWayPlanDisposition::UseIncoming)
            }
            (ThreeWayDelta::Unchanged, ThreeWayDelta::Deleted) => {
                Ok(ThreeWayPlanDisposition::RemoveForIncoming)
            }
            (ThreeWayDelta::Modified, ThreeWayDelta::Unchanged) => {
                Ok(ThreeWayPlanDisposition::PreserveInstalled)
            }
            (ThreeWayDelta::Deleted, ThreeWayDelta::Unchanged) => {
                Ok(ThreeWayPlanDisposition::PreserveInstalledDeletion)
            }
            (ThreeWayDelta::Modified, ThreeWayDelta::Modified) => {
                if same_present_hash(installed, incoming)? {
                    Ok(ThreeWayPlanDisposition::Converged)
                } else if merge_candidate_eligible(baseline, installed, incoming) {
                    Ok(ThreeWayPlanDisposition::MergeCandidate)
                } else {
                    Ok(ThreeWayPlanDisposition::ConflictReview)
                }
            }
            (ThreeWayDelta::Deleted, ThreeWayDelta::Deleted) => {
                Ok(ThreeWayPlanDisposition::ConvergedDeletion)
            }
            (ThreeWayDelta::Deleted, ThreeWayDelta::Modified) => {
                Ok(ThreeWayPlanDisposition::DeleteVsModifyConflict)
            }
            (ThreeWayDelta::Modified, ThreeWayDelta::Deleted) => {
                Ok(ThreeWayPlanDisposition::ModifyVsDeleteConflict)
            }
            (ThreeWayDelta::Added, _) | (_, ThreeWayDelta::Added) => {
                Err(GkrmError::ThreeWayInternalInvariant)
            }
        },
        ThreeWayFileState::Absent => match (local_delta, incoming_delta) {
            (ThreeWayDelta::Unchanged, ThreeWayDelta::Added) => {
                Ok(ThreeWayPlanDisposition::AddIncoming)
            }
            (ThreeWayDelta::Added, ThreeWayDelta::Unchanged) => {
                Ok(ThreeWayPlanDisposition::PreserveInstalledAddition)
            }
            (ThreeWayDelta::Added, ThreeWayDelta::Added) => {
                if same_present_hash(installed, incoming)? {
                    Ok(ThreeWayPlanDisposition::ConvergedAddition)
                } else {
                    Ok(ThreeWayPlanDisposition::AddVsAddConflict)
                }
            }
            (ThreeWayDelta::Unchanged, ThreeWayDelta::Unchanged) => {
                Err(GkrmError::ThreeWayInternalInvariant)
            }
            (ThreeWayDelta::Modified, _)
            | (ThreeWayDelta::Deleted, _)
            | (_, ThreeWayDelta::Modified)
            | (_, ThreeWayDelta::Deleted) => Err(GkrmError::ThreeWayInternalInvariant),
        },
    }
}

fn same_present_hash(left: &ThreeWayFileState, right: &ThreeWayFileState) -> Result<bool> {
    match (left, right) {
        (
            ThreeWayFileState::Present { sha256: left, .. },
            ThreeWayFileState::Present { sha256: right, .. },
        ) => Ok(left == right),
        _ => Err(GkrmError::ThreeWayInternalInvariant),
    }
}

fn merge_candidate_eligible(
    baseline: &ThreeWayFileState,
    installed: &ThreeWayFileState,
    incoming: &ThreeWayFileState,
) -> bool {
    match (baseline, installed, incoming) {
        (
            ThreeWayFileState::Present {
                sha256: baseline_hash,
                escrow_class: Some(BaselineEscrowClass::Ignored),
                trusted_baseline_blob_available: true,
            },
            ThreeWayFileState::Present {
                sha256: installed_hash,
                escrow_class: None,
                ..
            },
            ThreeWayFileState::Present {
                sha256: incoming_hash,
                escrow_class: Some(BaselineEscrowClass::Ignored),
                ..
            },
        ) => {
            baseline_hash != installed_hash
                && baseline_hash != incoming_hash
                && installed_hash != incoming_hash
        }
        _ => false,
    }
}

fn summarize(entries: &[ThreeWayPlanEntry]) -> Result<ThreeWayPlanSummary> {
    let mut summary = ThreeWayPlanSummary {
        total: 0,
        no_change: 0,
        incoming_actions: 0,
        preserved_local: 0,
        converged: 0,
        merge_candidates: 0,
        conflicts: 0,
        policy_reviews: 0,
    };

    for entry in entries {
        increment(&mut summary.total)?;
        match entry.disposition {
            ThreeWayPlanDisposition::NoChange => increment(&mut summary.no_change)?,
            ThreeWayPlanDisposition::UseIncoming
            | ThreeWayPlanDisposition::RemoveForIncoming
            | ThreeWayPlanDisposition::AddIncoming => increment(&mut summary.incoming_actions)?,
            ThreeWayPlanDisposition::PreserveInstalled
            | ThreeWayPlanDisposition::PreserveInstalledDeletion
            | ThreeWayPlanDisposition::PreserveInstalledAddition => {
                increment(&mut summary.preserved_local)?
            }
            ThreeWayPlanDisposition::Converged
            | ThreeWayPlanDisposition::ConvergedAddition
            | ThreeWayPlanDisposition::ConvergedDeletion => increment(&mut summary.converged)?,
            ThreeWayPlanDisposition::MergeCandidate => increment(&mut summary.merge_candidates)?,
            ThreeWayPlanDisposition::ConflictReview
            | ThreeWayPlanDisposition::DeleteVsModifyConflict
            | ThreeWayPlanDisposition::ModifyVsDeleteConflict
            | ThreeWayPlanDisposition::AddVsAddConflict => increment(&mut summary.conflicts)?,
            ThreeWayPlanDisposition::PolicyReview
            | ThreeWayPlanDisposition::PolicyConflictReview => {
                increment(&mut summary.policy_reviews)?
            }
        }
    }

    Ok(summary)
}

fn increment(value: &mut u64) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or(GkrmError::ThreeWayArithmeticOverflow)?;
    Ok(())
}

fn plan_id(
    baseline: &ResolvedOfficialBaseline,
    installed: &InstalledResourceSnapshot,
    incoming: &IncomingOfficialResourceSnapshot,
    entries: &[ThreeWayPlanEntry],
) -> Result<ThreeWayPlanId> {
    let mut encoder = CanonicalEncoder::new("gkrm-three-way-plan-v1");
    encoder.string(baseline.resource_key().as_str());
    encoder.string(baseline.baseline_id().as_str());
    encoder.digest(incoming.package_fingerprint());
    encoder.digest(installed.fingerprint());
    encoder.digest(incoming.resource_fingerprint());
    encoder.usize(entries.len());
    for entry in entries {
        encoder.path(&entry.path);
        encoder.file_state(&entry.baseline_state);
        encoder.file_state(&entry.installed_state);
        encoder.file_state(&entry.incoming_state);
        encoder.u8(delta_code(entry.local_delta));
        encoder.u8(delta_code(entry.incoming_delta));
        encoder.policy_transition(entry.policy_transition);
        encoder.u8(disposition_code(entry.disposition));
    }
    Ok(ThreeWayPlanId(encoder.finish()))
}

fn installed_snapshot_fingerprint(
    resource_key: &SafeResourceKey,
    files: &[InstalledSnapshotFile],
) -> Result<Sha256Digest> {
    let files = files
        .iter()
        .map(|file| InstalledFingerprintFile {
            path: &file.path,
            sha256: &file.sha256,
        })
        .collect::<Vec<_>>();
    three_way_fingerprint::installed_resource_fingerprint(resource_key, &files)
}

fn incoming_resource_fingerprint(
    package_fingerprint: &Sha256Digest,
    resource_key: &SafeResourceKey,
    root: &ZipResourceRoot,
    files: &[IncomingSnapshotFile],
) -> Result<Sha256Digest> {
    let files = files
        .iter()
        .map(|file| IncomingFingerprintFile {
            path: &file.path,
            sha256: &file.sha256,
            escrow_class: file.escrow_class,
        })
        .collect::<Vec<_>>();
    three_way_fingerprint::incoming_resource_fingerprint(
        package_fingerprint,
        resource_key,
        zip_root_stable_identity(root),
        &files,
    )
}

struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn new(domain: &'static str) -> Self {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.string(domain);
        encoder
    }

    fn string(&mut self, value: &str) {
        self.usize(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn path(&mut self, path: &ResourceRelativePath) {
        self.string(path.as_str());
    }

    fn digest(&mut self, digest: &Sha256Digest) {
        self.bytes.extend_from_slice(digest.as_bytes());
    }

    fn usize(&mut self, value: usize) {
        self.bytes.extend_from_slice(&(value as u64).to_le_bytes());
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn escrow_class(&mut self, value: Option<BaselineEscrowClass>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u8(value.as_stable_code());
            }
            None => self.u8(0),
        }
    }

    fn file_state(&mut self, state: &ThreeWayFileState) {
        match state {
            ThreeWayFileState::Absent => self.u8(0),
            ThreeWayFileState::Present {
                sha256,
                escrow_class,
                trusted_baseline_blob_available,
            } => {
                self.u8(1);
                self.digest(sha256);
                self.escrow_class(*escrow_class);
                self.u8(u8::from(*trusted_baseline_blob_available));
            }
        }
    }

    fn policy_transition(&mut self, transition: EscrowPolicyTransition) {
        match transition {
            EscrowPolicyTransition::None => self.u8(0),
            EscrowPolicyTransition::Changed { baseline, incoming } => {
                self.u8(1);
                self.u8(baseline.as_stable_code());
                self.u8(incoming.as_stable_code());
            }
        }
    }

    fn finish(self) -> Sha256Digest {
        Sha256Digest::new(Sha256::digest(self.bytes).into())
    }
}

fn exactly_one_installed_resource<T>(resources: Vec<T>) -> Result<T> {
    exactly_one(
        resources,
        GkrmError::ThreeWaySelectedInstalledResourceMissing,
        GkrmError::ThreeWaySelectedInstalledResourceAmbiguous,
    )
}

fn exactly_one_installed_comparison<T>(comparisons: Vec<T>) -> Result<T> {
    exactly_one(
        comparisons,
        GkrmError::ThreeWaySelectedInstalledResourceMissing,
        GkrmError::ThreeWaySelectedInstalledResourceAmbiguous,
    )
}

fn exactly_one_incoming_resource<T>(resources: Vec<T>) -> Result<T> {
    exactly_one(
        resources,
        GkrmError::ThreeWaySelectedIncomingResourceMissing,
        GkrmError::ThreeWaySelectedIncomingResourceAmbiguous,
    )
}

fn exactly_one_incoming_comparison<T>(comparisons: Vec<T>) -> Result<T> {
    exactly_one(
        comparisons,
        GkrmError::ThreeWaySelectedIncomingResourceMissing,
        GkrmError::ThreeWaySelectedIncomingResourceAmbiguous,
    )
}

fn exactly_one_incoming_escrow<T>(resources: Vec<T>) -> Result<T> {
    exactly_one(
        resources,
        GkrmError::ThreeWaySelectedIncomingResourceMissing,
        GkrmError::ThreeWaySelectedIncomingResourceAmbiguous,
    )
}

fn exactly_one<T>(mut values: Vec<T>, missing: GkrmError, ambiguous: GkrmError) -> Result<T> {
    match values.len() {
        0 => Err(missing),
        1 => Ok(values.remove(0)),
        _ => Err(ambiguous),
    }
}

fn trusted_incoming_resource_key(resource: &DiscoveredZipResource) -> Result<SafeResourceKey> {
    match (&resource.root, &resource.name) {
        (ZipResourceRoot::Root, ZipResourceName::ZipRoot) => {
            Err(GkrmError::ThreeWayIncomingRootIdentityUnavailable)
        }
        (ZipResourceRoot::Path(path), ZipResourceName::Directory(discovered_name)) => {
            let final_component = path
                .as_str()
                .rsplit_once('/')
                .map_or(path.as_str(), |(_, name)| name);
            if discovered_name != final_component {
                return Err(GkrmError::ThreeWayIncomingResourceIdentityInconsistent);
            }
            SafeResourceKey::parse(final_component)
                .map_err(|_| GkrmError::ThreeWayBaselineIncomingResourceMismatch)
        }
        _ => Err(GkrmError::ThreeWayIncomingResourceIdentityInconsistent),
    }
}

fn zip_resource_relative_path(
    root: &ZipResourceRoot,
    path: &ZipRelativePath,
) -> Result<ResourceRelativePath> {
    match root {
        ZipResourceRoot::Root => ResourceRelativePath::try_from_slash_str(path.as_str()),
        ZipResourceRoot::Path(root) => {
            let suffix = path
                .as_str()
                .strip_prefix(root.as_str())
                .and_then(|suffix| suffix.strip_prefix('/'))
                .ok_or(GkrmError::ThreeWaySnapshotFingerprintFailure)?;
            ResourceRelativePath::try_from_slash_str(suffix)
        }
    }
}

fn zip_root_stable_identity(root: &ZipResourceRoot) -> &str {
    match root {
        ZipResourceRoot::Root => ".",
        ZipResourceRoot::Path(path) => path.as_str(),
    }
}

fn escrow_class_to_baseline(classification: &EscrowFileClassification) -> BaselineEscrowClass {
    match classification {
        EscrowFileClassification::Protected => BaselineEscrowClass::Protected,
        EscrowFileClassification::Ignored { .. } => BaselineEscrowClass::Ignored,
        EscrowFileClassification::NotSupported { .. } => BaselineEscrowClass::NotSupported,
    }
}

fn delta_code(delta: ThreeWayDelta) -> u8 {
    match delta {
        ThreeWayDelta::Unchanged => 0,
        ThreeWayDelta::Added => 1,
        ThreeWayDelta::Modified => 2,
        ThreeWayDelta::Deleted => 3,
    }
}

fn disposition_code(disposition: ThreeWayPlanDisposition) -> u8 {
    match disposition {
        ThreeWayPlanDisposition::NoChange => 0,
        ThreeWayPlanDisposition::UseIncoming => 1,
        ThreeWayPlanDisposition::RemoveForIncoming => 2,
        ThreeWayPlanDisposition::PreserveInstalled => 3,
        ThreeWayPlanDisposition::PreserveInstalledDeletion => 4,
        ThreeWayPlanDisposition::AddIncoming => 5,
        ThreeWayPlanDisposition::PreserveInstalledAddition => 6,
        ThreeWayPlanDisposition::Converged => 7,
        ThreeWayPlanDisposition::ConvergedAddition => 8,
        ThreeWayPlanDisposition::ConvergedDeletion => 9,
        ThreeWayPlanDisposition::MergeCandidate => 10,
        ThreeWayPlanDisposition::ConflictReview => 11,
        ThreeWayPlanDisposition::DeleteVsModifyConflict => 12,
        ThreeWayPlanDisposition::ModifyVsDeleteConflict => 13,
        ThreeWayPlanDisposition::AddVsAddConflict => 14,
        ThreeWayPlanDisposition::PolicyReview => 15,
        ThreeWayPlanDisposition::PolicyConflictReview => 16,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use zip::CompressionMethod;

    use super::*;
    use crate::baseline::make_file_record;
    use crate::{
        BaselineCounts, ClassifiedResourceFile, ClassifiedZipResource, ComparedFile,
        ComparedFileSide, ComparedIncomingFile, DiscoveredZipResource, EscrowClassificationReport,
        FileComparisonStatus, InstallationComparisonReport, InstallationRelativePath,
        InstalledFileInfo, InstalledInstallationScan, InstalledResourceScan,
        ParsedZipResourceManifest, ResourceComparison, ResourceMatch, ResourceMatchKind,
        ZipEntryInfo, ZipInspection, ZipManifestParseReport, ZipResourceDiscovery, ZipResourceName,
    };

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn rel(path: &str) -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str(path).expect("test path")
    }

    fn key() -> SafeResourceKey {
        SafeResourceKey::parse("gksphone").expect("resource key")
    }

    fn baseline_id() -> BaselineId {
        BaselineId::from_digest(digest(0x77))
    }

    fn resolved_baseline(
        files: Vec<(&str, u8, BaselineEscrowClass, bool)>,
    ) -> ResolvedOfficialBaseline {
        let records = files
            .into_iter()
            .map(|(path, byte, class, blob)| {
                make_file_record(
                    rel(path),
                    1,
                    digest(byte),
                    class,
                    blob.then(|| digest(byte)),
                )
            })
            .collect::<Vec<_>>();
        let counts = BaselineCounts::from_parts_for_test(records.len() as u64, 0, 0, 0, 0, 0);
        let stored = StoredBaseline::from_parts_for_test(
            baseline_id(),
            key(),
            "gksphone".to_owned(),
            Some("1.0.0".to_owned()),
            Some(digest(0x44)),
            records,
            counts,
        );
        ResolvedOfficialBaseline::from_stored_baseline_for_test(stored)
    }

    fn installed(files: Vec<(&str, u8)>) -> InstalledResourceSnapshot {
        InstalledResourceSnapshot::from_parts_for_test(
            key(),
            files
                .into_iter()
                .map(|(path, byte)| (rel(path), digest(byte)))
                .collect(),
        )
    }

    fn incoming(files: Vec<(&str, u8, BaselineEscrowClass)>) -> IncomingOfficialResourceSnapshot {
        IncomingOfficialResourceSnapshot::from_parts_for_test(
            key(),
            digest(0x55),
            files
                .into_iter()
                .map(|(path, byte, class)| (rel(path), digest(byte), class))
                .collect(),
        )
    }

    fn create_plan(
        baseline: &ResolvedOfficialBaseline,
        installed: &InstalledResourceSnapshot,
        incoming: &IncomingOfficialResourceSnapshot,
    ) -> Result<ThreeWayUpdatePlan> {
        create_three_way_update_plan(ThreeWayUpdatePlanRequest::try_new(
            baseline,
            installed,
            incoming,
            ThreeWayPlannerOptions::default(),
        )?)
    }

    fn single_disposition(
        baseline: Vec<(&str, u8, BaselineEscrowClass, bool)>,
        installed_files: Vec<(&str, u8)>,
        incoming_files: Vec<(&str, u8, BaselineEscrowClass)>,
    ) -> ThreeWayPlanDisposition {
        let baseline = resolved_baseline(baseline);
        let installed = installed(installed_files);
        let incoming = incoming(incoming_files);
        let plan = create_plan(&baseline, &installed, &incoming).expect("plan");
        assert_eq!(plan.entries().len(), 1);
        plan.entries()[0].disposition()
    }

    #[test]
    fn truth_table_baseline_present_dispositions() {
        use BaselineEscrowClass::{Ignored, Protected};
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 1)],
                vec![("a.lua", 1, Protected)]
            ),
            ThreeWayPlanDisposition::NoChange
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 1)],
                vec![("a.lua", 2, Protected)]
            ),
            ThreeWayPlanDisposition::UseIncoming
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 1)],
                vec![]
            ),
            ThreeWayPlanDisposition::RemoveForIncoming
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 1, Protected)]
            ),
            ThreeWayPlanDisposition::PreserveInstalled
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![],
                vec![("a.lua", 1, Protected)]
            ),
            ThreeWayPlanDisposition::PreserveInstalledDeletion
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 2, Protected)]
            ),
            ThreeWayPlanDisposition::Converged
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 3, Protected)]
            ),
            ThreeWayPlanDisposition::ConflictReview
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Ignored, true)],
                vec![("a.lua", 2)],
                vec![("a.lua", 3, Ignored)]
            ),
            ThreeWayPlanDisposition::MergeCandidate
        );
        assert_eq!(
            single_disposition(vec![("a.lua", 1, Protected, false)], vec![], vec![]),
            ThreeWayPlanDisposition::ConvergedDeletion
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![],
                vec![("a.lua", 2, Protected)]
            ),
            ThreeWayPlanDisposition::DeleteVsModifyConflict
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![]
            ),
            ThreeWayPlanDisposition::ModifyVsDeleteConflict
        );
    }

    #[test]
    fn truth_table_baseline_absent_dispositions() {
        use BaselineEscrowClass::Protected;
        assert_eq!(
            single_disposition(vec![], vec![], vec![("a.lua", 1, Protected)]),
            ThreeWayPlanDisposition::AddIncoming
        );
        assert_eq!(
            single_disposition(vec![], vec![("a.lua", 1)], vec![]),
            ThreeWayPlanDisposition::PreserveInstalledAddition
        );
        assert_eq!(
            single_disposition(vec![], vec![("a.lua", 1)], vec![("a.lua", 1, Protected)]),
            ThreeWayPlanDisposition::ConvergedAddition
        );
        assert_eq!(
            single_disposition(vec![], vec![("a.lua", 1)], vec![("a.lua", 2, Protected)]),
            ThreeWayPlanDisposition::AddVsAddConflict
        );
    }

    #[test]
    fn policy_transitions_have_precedence_for_every_class_pair() {
        use BaselineEscrowClass::{Ignored, NotSupported, Protected};
        let classes = [Protected, Ignored, NotSupported];
        for baseline_class in classes {
            for incoming_class in classes {
                if baseline_class == incoming_class {
                    continue;
                }
                assert_eq!(
                    single_disposition(
                        vec![("a.lua", 1, baseline_class, baseline_class == Ignored)],
                        vec![("a.lua", 1)],
                        vec![("a.lua", 1, incoming_class)]
                    ),
                    ThreeWayPlanDisposition::PolicyReview
                );
            }
        }
    }

    #[test]
    fn policy_transition_content_changes_are_policy_conflicts() {
        use BaselineEscrowClass::{Ignored, Protected};
        let cases = [
            (vec![("a.lua", 2)], vec![("a.lua", 1, Protected)]),
            (vec![("a.lua", 1)], vec![("a.lua", 2, Protected)]),
            (vec![("a.lua", 2)], vec![("a.lua", 3, Protected)]),
            (vec![], vec![("a.lua", 1, Protected)]),
            (vec![("a.lua", 2)], vec![("a.lua", 2, Protected)]),
        ];
        for (local, incoming_files) in cases {
            assert_eq!(
                single_disposition(vec![("a.lua", 1, Ignored, true)], local, incoming_files),
                ThreeWayPlanDisposition::PolicyConflictReview
            );
        }
    }

    #[test]
    fn merge_policy_requires_ignored_classes_and_trusted_blob() {
        use BaselineEscrowClass::{Ignored, NotSupported, Protected};
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Ignored, true)],
                vec![("a.lua", 2)],
                vec![("a.lua", 3, Ignored)]
            ),
            ThreeWayPlanDisposition::MergeCandidate
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 3, Protected)]
            ),
            ThreeWayPlanDisposition::ConflictReview
        );
        assert_eq!(
            single_disposition(
                vec![("a.lua", 1, NotSupported, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 3, NotSupported)]
            ),
            ThreeWayPlanDisposition::ConflictReview
        );
        assert_eq!(
            single_disposition(vec![], vec![("a.lua", 2)], vec![("a.lua", 3, Ignored)]),
            ThreeWayPlanDisposition::AddVsAddConflict
        );
    }

    #[test]
    fn deterministic_order_and_plan_id_ignore_input_order() {
        use BaselineEscrowClass::Protected;
        let baseline_a = resolved_baseline(vec![
            ("b.lua", 2, Protected, false),
            ("a.lua", 1, Protected, false),
        ]);
        let baseline_b = resolved_baseline(vec![
            ("a.lua", 1, Protected, false),
            ("b.lua", 2, Protected, false),
        ]);
        let installed_a = installed(vec![("b.lua", 2), ("a.lua", 1)]);
        let installed_b = installed(vec![("a.lua", 1), ("b.lua", 2)]);
        let incoming_a = incoming(vec![("b.lua", 3, Protected), ("a.lua", 1, Protected)]);
        let incoming_b = incoming(vec![("a.lua", 1, Protected), ("b.lua", 3, Protected)]);

        let first = create_plan(&baseline_a, &installed_a, &incoming_a).expect("first plan");
        let second = create_plan(&baseline_b, &installed_b, &incoming_b).expect("second plan");

        assert_eq!(
            first
                .entries()
                .iter()
                .map(|entry| entry.path().as_str())
                .collect::<Vec<_>>(),
            vec!["a.lua", "b.lua"]
        );
        assert_eq!(first.entries(), second.entries());
        assert_eq!(first.plan_id(), second.plan_id());

        let changed_incoming = incoming(vec![("a.lua", 1, Protected), ("b.lua", 4, Protected)]);
        let changed = create_plan(&baseline_b, &installed_b, &changed_incoming).expect("changed");
        assert_ne!(first.plan_id(), changed.plan_id());
    }

    #[test]
    fn fixed_fingerprint_and_plan_id_vectors_match_pre_task16_encoding() {
        use BaselineEscrowClass::{Ignored, NotSupported, Protected};

        let installed_vector = installed(vec![("b.lua", 2), ("dir/c.lua", 3), ("a.lua", 1)]);
        assert_eq!(
            installed_vector.fingerprint().to_string(),
            "b9eba1e9288c82262ad2356355948628e73b30182f9e07677032782292a49796"
        );

        let incoming_vector = IncomingOfficialResourceSnapshot::from_parts_for_test(
            key(),
            digest(0x55),
            vec![
                (rel("b.lua"), digest(2), Ignored),
                (rel("dir/c.lua"), digest(3), NotSupported),
                (rel("a.lua"), digest(1), Protected),
            ],
        );
        assert_eq!(
            incoming_vector.resource_fingerprint().to_string(),
            "426eb8e7fba2d1f31089c6b7df82d833b9f9bca633b6927aeca6752ecd0739d0"
        );

        let baseline = resolved_baseline(vec![
            ("b.lua", 2, Ignored, true),
            ("a.lua", 1, Protected, false),
            ("policy.lua", 5, Ignored, true),
        ]);
        let installed = installed(vec![("local.lua", 3), ("b.lua", 3), ("a.lua", 1)]);
        let incoming = IncomingOfficialResourceSnapshot::from_parts_for_test(
            key(),
            digest(0x55),
            vec![
                (rel("new.lua"), digest(6), Ignored),
                (rel("b.lua"), digest(4), Ignored),
                (rel("policy.lua"), digest(5), Protected),
                (rel("a.lua"), digest(1), Protected),
            ],
        );
        let plan = create_plan(&baseline, &installed, &incoming).expect("plan");
        assert_eq!(
            plan.plan_id().digest().to_string(),
            "fa04e854f9651c5e3179f48c7f1b06e7e08c4834d92345c686dd648b17be3fae"
        );
    }

    #[test]
    fn rejects_limits_duplicates_and_unsupported_snapshot_version() {
        use BaselineEscrowClass::Protected;
        assert!(matches!(
            ThreeWayPlannerOptions::try_new(0),
            Err(GkrmError::ThreeWayPlannerOptionsInvalid { .. })
        ));

        let baseline = resolved_baseline(vec![]);
        let installed_snapshot = installed(vec![("a.lua", 1)]);
        let incoming_snapshot = incoming(vec![("b.lua", 1, Protected)]);
        let err = create_three_way_update_plan(
            ThreeWayUpdatePlanRequest::try_new(
                &baseline,
                &installed_snapshot,
                &incoming_snapshot,
                ThreeWayPlannerOptions::try_new(1).expect("options"),
            )
            .expect("request"),
        )
        .expect_err("union limit");
        assert!(matches!(
            err,
            GkrmError::ThreeWayPlanEntryLimitExceeded { .. }
        ));

        let duplicated_installed = InstalledResourceSnapshot::from_parts_for_test(
            key(),
            vec![(rel("a.lua"), digest(1)), (rel("a.lua"), digest(2))],
        );
        let empty_incoming = incoming(vec![]);
        let err = create_plan(
            &resolved_baseline(vec![]),
            &duplicated_installed,
            &empty_incoming,
        )
        .expect_err("duplicate installed");
        assert!(matches!(err, GkrmError::ThreeWayDuplicateInstalledPath));

        let unsupported = installed(vec![]).with_version_for_test(999);
        let empty_incoming = incoming(vec![]);
        let err = create_plan(&resolved_baseline(vec![]), &unsupported, &empty_incoming)
            .expect_err("unsupported version");
        assert!(matches!(
            err,
            GkrmError::ThreeWayUnsupportedTrustedSnapshotVersion
        ));

        let unsupported_incoming = incoming(vec![]).with_version_for_test(999);
        let err = create_plan(
            &resolved_baseline(vec![]),
            &installed(vec![]),
            &unsupported_incoming,
        )
        .expect_err("unsupported incoming version");
        assert!(matches!(
            err,
            GkrmError::ThreeWayUnsupportedTrustedSnapshotVersion
        ));
    }

    #[test]
    fn ignored_baseline_without_blob_is_rejected() {
        let baseline = resolved_baseline(vec![("a.lua", 1, BaselineEscrowClass::Ignored, false)]);
        let err = create_plan(&baseline, &installed(vec![("a.lua", 2)]), &incoming(vec![]))
            .expect_err("ignored baseline without blob");
        assert!(matches!(
            err,
            GkrmError::ThreeWayInconsistentIgnoredBaselineBlobPolicy
        ));
    }

    #[test]
    fn snapshot_construction_uses_complete_trusted_inventories() {
        let report = inspection_report_fixture();
        let installed_root = InstalledResourceRoot::Path(
            InstallationRelativePath::from_path(Path::new("gksphone")).unwrap(),
        );
        let incoming_root =
            ZipResourceRoot::Path(ZipRelativePath::parse_canonical("gksphone").unwrap());
        let expected = key();

        let installed_snapshot =
            InstalledResourceSnapshot::try_from_inspection(&report, &installed_root, &expected)
                .expect("installed snapshot");
        let incoming_snapshot = IncomingOfficialResourceSnapshot::try_from_inspection(
            &report,
            &incoming_root,
            &expected,
        )
        .expect("incoming snapshot");

        assert_eq!(installed_snapshot.file_count(), 2);
        assert_eq!(incoming_snapshot.file_count(), 3);
        assert_eq!(incoming_snapshot.package_fingerprint(), &digest(0x91));
        assert_ne!(
            installed_snapshot.fingerprint(),
            incoming_snapshot.resource_fingerprint()
        );
    }

    #[test]
    fn snapshot_construction_rejects_mismatched_resource_key() {
        let report = inspection_report_fixture();
        let installed_root = InstalledResourceRoot::Path(
            InstallationRelativePath::from_path(Path::new("gksphone")).unwrap(),
        );
        let wrong = SafeResourceKey::parse("other").unwrap();
        let err = InstalledResourceSnapshot::try_from_inspection(&report, &installed_root, &wrong)
            .expect_err("mismatch");
        assert!(matches!(
            err,
            GkrmError::ThreeWayBaselineInstalledResourceMismatch
        ));
    }

    fn inspection_report_fixture() -> FullInspectionReport {
        let installed_root = InstalledResourceRoot::Path(
            InstallationRelativePath::from_path(Path::new("gksphone")).unwrap(),
        );
        let incoming_root =
            ZipResourceRoot::Path(ZipRelativePath::parse_canonical("gksphone").unwrap());
        let installed_scan = InstalledInstallationScan {
            root: Path::new("installed").to_path_buf(),
            resources: vec![InstalledResourceScan {
                name: "gksphone".to_owned(),
                root: installed_root.clone(),
                manifest_relative_path: InstallationRelativePath::from_path(Path::new(
                    "gksphone/fxmanifest.lua",
                ))
                .unwrap(),
                files: vec![
                    InstalledFileInfo {
                        relative_path: rel("shared.lua"),
                        size: 1,
                        sha256: digest(1),
                    },
                    InstalledFileInfo {
                        relative_path: rel("installed-only.lua"),
                        size: 1,
                        sha256: digest(2),
                    },
                ],
            }],
            warnings: Vec::new(),
        };
        let entries = vec![
            zip_file(0, "gksphone/fxmanifest.lua"),
            zip_file(1, "gksphone/shared.lua"),
            zip_file(2, "gksphone/incoming-only.lua"),
        ];
        let discovery = ZipResourceDiscovery {
            resources: vec![DiscoveredZipResource {
                name: ZipResourceName::Directory("gksphone".to_owned()),
                root: incoming_root.clone(),
                manifest_path: ZipRelativePath::parse_canonical("gksphone/fxmanifest.lua").unwrap(),
                entries: entries.clone(),
            }],
            unassigned_entries: Vec::new(),
            warnings: Vec::new(),
        };
        let escrow = EscrowClassificationReport {
            resources: vec![ClassifiedZipResource {
                resource_root: incoming_root.clone(),
                files: vec![
                    classified("gksphone/fxmanifest.lua", "fxmanifest.lua"),
                    classified("gksphone/shared.lua", "shared.lua"),
                    classified("gksphone/incoming-only.lua", "incoming-only.lua"),
                ],
                warnings: Vec::new(),
            }],
        };
        let comparison = InstallationComparisonReport {
            matched_resources: vec![ResourceComparison {
                resource_match: ResourceMatch {
                    installed_resource: installed_root,
                    incoming_resource: incoming_root,
                    match_kind: ResourceMatchKind::ExactName,
                },
                files: vec![
                    compared_incoming("fxmanifest.lua", 9),
                    compared_incoming("shared.lua", 1),
                    compared_incoming("incoming-only.lua", 3),
                ],
            }],
            unmatched_installed_resources: Vec::new(),
            unmatched_incoming_resources: Vec::new(),
            warnings: Vec::new(),
        };

        FullInspectionReport::from_parts_for_test(
            installed_scan,
            digest(0x91),
            ZipInspection {
                path: Path::new("package.zip").to_path_buf(),
                entries,
            },
            discovery,
            ZipManifestParseReport {
                resources: Vec::<ParsedZipResourceManifest>::new(),
            },
            escrow,
            comparison,
        )
    }

    fn zip_file(index: usize, path: &str) -> ZipEntryInfo {
        ZipEntryInfo {
            archive_index: index,
            path: ZipRelativePath::parse_canonical(path).unwrap(),
            compressed_size: 1,
            uncompressed_size: 1,
            crc32: 0,
            compression_method: CompressionMethod::Stored,
            encrypted: false,
            unix_mode: None,
            kind: ZipEntryKind::File,
        }
    }

    fn classified(package_path: &str, resource_relative_path: &str) -> ClassifiedResourceFile {
        ClassifiedResourceFile {
            package_path: ZipRelativePath::parse_canonical(package_path).unwrap(),
            resource_relative_path: resource_relative_path.to_owned(),
            classification: EscrowFileClassification::Protected,
        }
    }

    fn compared_incoming(path: &str, byte: u8) -> ComparedFile {
        ComparedFile {
            relative_path: rel(path),
            status: FileComparisonStatus::IncomingOnly,
            installed: Some(ComparedFileSide {
                size: 1,
                sha256: digest(byte),
            }),
            incoming: Some(ComparedIncomingFile {
                size: 1,
                sha256: digest(byte),
                escrow_classification: EscrowFileClassification::Protected,
            }),
        }
    }
}
