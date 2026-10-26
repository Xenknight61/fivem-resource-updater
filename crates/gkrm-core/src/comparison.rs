use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};
use std::path::Path;

use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::{
    classify_zip_resource_escrow, package_source::PackageSnapshot, EscrowClassificationReport,
    EscrowFileClassification, GkrmError, InstalledInstallationScan, InstalledResourceRoot,
    InstalledResourceScan, ResourceRelativePath, Result, Sha256Digest, ZipEntryInfo, ZipEntryKind,
    ZipInspection, ZipManifestParseReport, ZipRelativePath, ZipResourceDiscovery, ZipResourceName,
    ZipResourceRoot,
};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
type AfterArchiveOpenedHook = Box<dyn FnOnce() + Send>;

#[cfg(test)]
thread_local! {
    static AFTER_ARCHIVE_OPENED_HOOK: RefCell<Option<AfterArchiveOpenedHook>> =
        const { RefCell::new(None) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonLimits {
    pub max_incoming_files_hashed: usize,
    pub max_incoming_file_size: u64,
    pub max_total_incoming_uncompressed_size: u64,
    pub max_archive_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMatch {
    pub installed_resource: InstalledResourceRoot,
    pub incoming_resource: ZipResourceRoot,
    pub match_kind: ResourceMatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceMatchKind {
    ExactName,
    SingleResourceFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileComparisonStatus {
    Unchanged,
    Changed,
    IncomingOnly,
    InstalledOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparedFileSide {
    pub size: u64,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparedIncomingFile {
    pub size: u64,
    pub sha256: Sha256Digest,
    pub escrow_classification: EscrowFileClassification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparedFile {
    pub relative_path: ResourceRelativePath,
    pub status: FileComparisonStatus,
    pub installed: Option<ComparedFileSide>,
    pub incoming: Option<ComparedIncomingFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceComparison {
    pub resource_match: ResourceMatch,
    pub files: Vec<ComparedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationComparisonReport {
    pub matched_resources: Vec<ResourceComparison>,
    pub unmatched_installed_resources: Vec<InstalledResourceRoot>,
    pub unmatched_incoming_resources: Vec<ZipResourceRoot>,
    pub warnings: Vec<ComparisonWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonWarning {
    SingleResourceFallback {
        installed_resource: InstalledResourceRoot,
        incoming_resource: ZipResourceRoot,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncomingFileToHash {
    resource_root: ZipResourceRoot,
    relative_path: ResourceRelativePath,
    entry: ZipEntryInfo,
    escrow_classification: EscrowFileClassification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HashedIncomingFile {
    size: u64,
    sha256: Sha256Digest,
    escrow_classification: EscrowFileClassification,
}

#[derive(Debug)]
struct ResourceMatchReport {
    matches: Vec<ResourceMatch>,
    unmatched_installed_resources: Vec<InstalledResourceRoot>,
    unmatched_incoming_resources: Vec<ZipResourceRoot>,
    warnings: Vec<ComparisonWarning>,
}

impl ComparisonLimits {
    pub(crate) fn validate(self) -> Result<()> {
        if self.max_incoming_files_hashed == 0 {
            return Err(GkrmError::ComparisonZeroLimit {
                limit: "max_incoming_files_hashed",
            });
        }
        if self.max_incoming_file_size == 0 {
            return Err(GkrmError::ComparisonZeroLimit {
                limit: "max_incoming_file_size",
            });
        }
        if self.max_total_incoming_uncompressed_size == 0 {
            return Err(GkrmError::ComparisonZeroLimit {
                limit: "max_total_incoming_uncompressed_size",
            });
        }
        if self.max_archive_size == 0 {
            return Err(GkrmError::ComparisonZeroLimit {
                limit: "max_archive_size",
            });
        }

        Ok(())
    }
}

impl Default for ComparisonLimits {
    fn default() -> Self {
        Self {
            max_incoming_files_hashed: 10_000,
            max_incoming_file_size: 512 * 1024 * 1024,
            max_total_incoming_uncompressed_size: 2 * 1024 * 1024 * 1024,
            max_archive_size: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Compare an installed scan with discovered incoming ZIP resources without
/// modifying the installation or extracting ZIP entries.
///
/// Incoming package stability is checked by opening the package without
/// following the final path component, capturing stable file identity, size,
/// modification time, and a full archive SHA-256 before and after hashing the
/// matched entries. This is strong practical live-file change detection, not a
/// filesystem snapshot guarantee.
pub fn compare_installation_to_zip(
    installed: &InstalledInstallationScan,
    inspection: &ZipInspection,
    discovery: &ZipResourceDiscovery,
    manifests: &ZipManifestParseReport,
    escrow: &EscrowClassificationReport,
    limits: ComparisonLimits,
) -> Result<InstallationComparisonReport> {
    limits.validate()?;
    let snapshot = PackageSnapshot::create(&inspection.path, limits.max_archive_size)?;
    compare_installation_to_zip_snapshot(
        installed, &snapshot, inspection, discovery, manifests, escrow, limits,
    )
}

pub(crate) fn compare_installation_to_zip_snapshot(
    installed: &InstalledInstallationScan,
    snapshot: &PackageSnapshot,
    inspection: &ZipInspection,
    discovery: &ZipResourceDiscovery,
    manifests: &ZipManifestParseReport,
    escrow: &EscrowClassificationReport,
    limits: ComparisonLimits,
) -> Result<InstallationComparisonReport> {
    limits.validate()?;
    let installed_by_root = validate_installed_scan(installed)?;
    let discovery_by_root = validate_incoming_reports(inspection, discovery, manifests)?;
    let trusted_escrow = classify_zip_resource_escrow(inspection, discovery, manifests)?;
    validate_escrow_report(inspection, discovery, &trusted_escrow)?;
    if &trusted_escrow != escrow {
        return Err(GkrmError::ComparisonInconsistentReport {
            message:
                "caller-provided escrow classification does not match canonical classification"
                    .to_owned(),
        });
    }

    let match_report = match_resources(installed, discovery)?;
    let incoming_to_hash = incoming_files_to_hash(
        &match_report.matches,
        &discovery_by_root,
        &trusted_escrow,
        limits,
    )?;
    let hashed_incoming = hash_matched_incoming_files(snapshot, &incoming_to_hash)?;

    let mut matched_resources = Vec::with_capacity(match_report.matches.len());
    for resource_match in match_report.matches {
        let installed_resource = installed_by_root
            .get(&resource_match.installed_resource)
            .ok_or_else(|| GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "matched installed resource root is missing: {:?}",
                    installed_root_key(&resource_match.installed_resource)
                ),
            })?;
        let incoming_files = hashed_incoming
            .get(&resource_match.incoming_resource)
            .cloned()
            .unwrap_or_default();

        matched_resources.push(ResourceComparison {
            files: compare_resource_files(installed_resource, incoming_files)?,
            resource_match,
        });
    }

    Ok(InstallationComparisonReport {
        matched_resources,
        unmatched_installed_resources: match_report.unmatched_installed_resources,
        unmatched_incoming_resources: match_report.unmatched_incoming_resources,
        warnings: match_report.warnings,
    })
}

fn validate_installed_scan(
    installed: &InstalledInstallationScan,
) -> Result<BTreeMap<InstalledResourceRoot, &InstalledResourceScan>> {
    let mut by_root = BTreeMap::new();
    let mut by_name = BTreeMap::<&str, ()>::new();

    for resource in &installed.resources {
        let expected_name = expected_installed_resource_name(&installed.root, &resource.root)?;
        if resource.name != expected_name {
            return Err(GkrmError::ComparisonInstalledNameMismatch {
                root: installed_root_key(&resource.root),
                expected: expected_name,
                actual: resource.name.clone(),
            });
        }
        if by_root.insert(resource.root.clone(), resource).is_some() {
            return Err(GkrmError::ComparisonDuplicateInstalledRoot {
                root: installed_root_key(&resource.root),
            });
        }
        if by_name.insert(resource.name.as_str(), ()).is_some() {
            return Err(GkrmError::ComparisonDuplicateInstalledName {
                name: resource.name.clone(),
            });
        }

        let mut files = BTreeSet::new();
        for file in &resource.files {
            if !files.insert(file.relative_path.clone()) {
                return Err(GkrmError::ComparisonDuplicateInstalledFile {
                    resource: installed_root_key(&resource.root),
                    path: file.relative_path.to_string(),
                });
            }
        }
    }

    Ok(by_root)
}

fn validate_incoming_reports<'a>(
    inspection: &'a ZipInspection,
    discovery: &'a ZipResourceDiscovery,
    manifests: &ZipManifestParseReport,
) -> Result<BTreeMap<ZipResourceRoot, &'a crate::DiscoveredZipResource>> {
    let inspection_by_path = validate_inspection_entries(inspection)?;
    let mut discovery_by_root = BTreeMap::new();
    let mut incoming_names = BTreeMap::<&str, ()>::new();
    let mut assigned_package_paths = BTreeSet::new();
    let mut assigned_archive_indices = BTreeSet::new();

    for resource in &discovery.resources {
        validate_incoming_resource_name(resource)?;
        let mut resource_relative_paths = BTreeSet::new();
        if discovery_by_root
            .insert(resource.root.clone(), resource)
            .is_some()
        {
            return Err(GkrmError::ComparisonDuplicateIncomingRoot {
                root: incoming_root_key(&resource.root),
            });
        }
        if let ZipResourceName::Directory(name) = &resource.name {
            if incoming_names.insert(name.as_str(), ()).is_some() {
                return Err(GkrmError::ComparisonDuplicateIncomingName { name: name.clone() });
            }
        }
        let expected_manifest = expected_manifest_path(&resource.root);
        if resource.manifest_path != expected_manifest {
            return Err(GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "discovered manifest path for root {:?} is {:?}, expected {:?}",
                    incoming_root_key(&resource.root),
                    resource.manifest_path,
                    expected_manifest
                ),
            });
        }
        for entry in &resource.entries {
            if !assigned_package_paths.insert(entry.path.clone()) {
                return Err(GkrmError::ComparisonDuplicateIncomingPackagePath {
                    path: entry.path.to_string(),
                });
            }
            if !assigned_archive_indices.insert(entry.archive_index) {
                return Err(GkrmError::ComparisonDuplicateIncomingArchiveIndex {
                    index: entry.archive_index,
                });
            }
            let inspected = inspection_by_path.get(entry.path.as_str()).ok_or_else(|| {
                GkrmError::ComparisonInconsistentReport {
                    message: format!(
                        "discovered entry is missing from inspection: {}",
                        entry.path
                    ),
                }
            })?;
            verify_entry_metadata(inspected, entry)?;
            if !zip_root_contains(&resource.root, &entry.path) {
                return Err(GkrmError::ComparisonInconsistentReport {
                    message: format!(
                        "discovered entry {} is outside resource root {:?}",
                        entry.path,
                        incoming_root_key(&resource.root)
                    ),
                });
            }
            if entry.kind == ZipEntryKind::File {
                let relative_path = zip_resource_relative_path(&resource.root, entry)?;
                if !resource_relative_paths.insert(relative_path.clone()) {
                    return Err(GkrmError::ComparisonDuplicateIncomingRelativePath {
                        resource: incoming_root_key(&resource.root),
                        path: relative_path.to_string(),
                    });
                }
            }
        }
    }

    validate_nested_resource_assignment(discovery)?;
    validate_manifest_report(discovery, manifests)?;

    Ok(discovery_by_root)
}

fn validate_inspection_entries(
    inspection: &ZipInspection,
) -> Result<BTreeMap<&str, &ZipEntryInfo>> {
    let mut by_path = BTreeMap::new();
    let mut archive_indices = BTreeSet::new();

    for entry in &inspection.entries {
        if by_path.insert(entry.path.as_str(), entry).is_some() {
            return Err(GkrmError::ComparisonDuplicateIncomingPackagePath {
                path: entry.path.to_string(),
            });
        }
        if !archive_indices.insert(entry.archive_index) {
            return Err(GkrmError::ComparisonDuplicateIncomingArchiveIndex {
                index: entry.archive_index,
            });
        }
    }

    Ok(by_path)
}

fn validate_nested_resource_assignment(discovery: &ZipResourceDiscovery) -> Result<()> {
    let roots = discovery
        .resources
        .iter()
        .map(|resource| &resource.root)
        .collect::<Vec<_>>();

    for resource in &discovery.resources {
        for entry in &resource.entries {
            let deepest = roots
                .iter()
                .filter(|root| zip_root_contains(root, &entry.path))
                .max_by_key(|root| zip_root_depth(root));
            if deepest != Some(&&resource.root) {
                return Err(GkrmError::ComparisonInconsistentReport {
                    message: format!(
                        "discovered entry {} is assigned to {:?} instead of deepest matching resource",
                        entry.path,
                        incoming_root_key(&resource.root)
                    ),
                });
            }
        }
    }

    Ok(())
}

fn validate_manifest_report(
    discovery: &ZipResourceDiscovery,
    manifests: &ZipManifestParseReport,
) -> Result<()> {
    let discovered = discovery
        .resources
        .iter()
        .map(|resource| (&resource.root, resource))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();

    for manifest in &manifests.resources {
        if !seen.insert(manifest.resource_root.clone()) {
            return Err(GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "multiple parsed manifests exist for root {:?}",
                    incoming_root_key(&manifest.resource_root)
                ),
            });
        }
        let resource = discovered.get(&manifest.resource_root).ok_or_else(|| {
            GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "parsed manifest does not match a discovered root: {:?}",
                    incoming_root_key(&manifest.resource_root)
                ),
            }
        })?;
        if manifest.manifest_path != resource.manifest_path {
            return Err(GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "parsed manifest path mismatch for root {:?}",
                    incoming_root_key(&manifest.resource_root)
                ),
            });
        }
    }

    if seen.len() != discovery.resources.len() {
        return Err(GkrmError::ComparisonInconsistentReport {
            message: "parsed manifest report is missing a discovered resource".to_owned(),
        });
    }

    Ok(())
}

fn validate_escrow_report(
    inspection: &ZipInspection,
    discovery: &ZipResourceDiscovery,
    escrow: &EscrowClassificationReport,
) -> Result<()> {
    let inspection_by_path = inspection
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let discovered = discovery
        .resources
        .iter()
        .map(|resource| (&resource.root, resource))
        .collect::<BTreeMap<_, _>>();
    let mut seen_roots = BTreeSet::new();

    for classified_resource in &escrow.resources {
        if !seen_roots.insert(classified_resource.resource_root.clone()) {
            return Err(GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "multiple escrow classifications exist for root {:?}",
                    incoming_root_key(&classified_resource.resource_root)
                ),
            });
        }
        let discovered_resource = discovered
            .get(&classified_resource.resource_root)
            .ok_or_else(|| GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "escrow classification does not match a discovered root: {:?}",
                    incoming_root_key(&classified_resource.resource_root)
                ),
            })?;
        let discovered_files = discovered_resource
            .entries
            .iter()
            .filter(|entry| entry.kind == ZipEntryKind::File)
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut seen_files = BTreeSet::new();

        for file in &classified_resource.files {
            if !seen_files.insert(file.package_path.clone()) {
                return Err(GkrmError::ComparisonInconsistentReport {
                    message: format!("duplicate escrow-classified file: {}", file.package_path),
                });
            }
            let discovered_entry = discovered_files
                .get(file.package_path.as_str())
                .ok_or_else(|| GkrmError::ComparisonInconsistentReport {
                    message: format!(
                        "escrow-classified file is not assigned to its resource: {}",
                        file.package_path
                    ),
                })?;
            let inspected_entry = inspection_by_path
                .get(file.package_path.as_str())
                .ok_or_else(|| GkrmError::ComparisonInconsistentReport {
                    message: format!(
                        "escrow-classified file is missing from inspection: {}",
                        file.package_path
                    ),
                })?;
            verify_entry_metadata(inspected_entry, discovered_entry)?;
            let expected_relative =
                zip_resource_relative_path(&classified_resource.resource_root, discovered_entry)?;
            if file.resource_relative_path != expected_relative.as_str() {
                return Err(GkrmError::ComparisonInconsistentReport {
                    message: format!(
                        "escrow-classified relative path mismatch for {}",
                        file.package_path
                    ),
                });
            }
            if !zip_root_contains(&classified_resource.resource_root, &file.package_path) {
                return Err(GkrmError::ComparisonInconsistentReport {
                    message: format!(
                        "escrow-classified file {} is outside its resource root",
                        file.package_path
                    ),
                });
            }
        }

        if seen_files.len() != discovered_files.len() {
            return Err(GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "escrow classification is missing files for root {:?}",
                    incoming_root_key(&classified_resource.resource_root)
                ),
            });
        }
    }

    if seen_roots.len() != discovery.resources.len() {
        return Err(GkrmError::ComparisonInconsistentReport {
            message: "escrow classification report is missing a discovered resource".to_owned(),
        });
    }

    Ok(())
}

fn match_resources(
    installed: &InstalledInstallationScan,
    discovery: &ZipResourceDiscovery,
) -> Result<ResourceMatchReport> {
    let mut installed_by_name = BTreeMap::<String, &InstalledResourceScan>::new();
    for resource in &installed.resources {
        let name = trusted_installed_match_name(&installed.root, resource)?;
        if installed_by_name.insert(name.clone(), resource).is_some() {
            return Err(GkrmError::ComparisonDuplicateInstalledName { name });
        }
    }

    let mut incoming_by_name = BTreeMap::<String, &crate::DiscoveredZipResource>::new();
    for resource in &discovery.resources {
        if let Some(name) = trusted_incoming_match_name(resource) {
            if incoming_by_name.insert(name.clone(), resource).is_some() {
                return Err(GkrmError::ComparisonDuplicateIncomingName { name });
            }
        }
    }

    let mut matches = Vec::new();
    let mut matched_installed = BTreeSet::new();
    let mut matched_incoming = BTreeSet::new();

    for (name, installed_resource) in &installed_by_name {
        if let Some(incoming_resource) = incoming_by_name.get(name.as_str()) {
            matches.push(ResourceMatch {
                installed_resource: installed_resource.root.clone(),
                incoming_resource: incoming_resource.root.clone(),
                match_kind: ResourceMatchKind::ExactName,
            });
            matched_installed.insert(installed_resource.root.clone());
            matched_incoming.insert(incoming_resource.root.clone());
        }
    }

    let mut unmatched_installed = installed
        .resources
        .iter()
        .filter(|resource| !matched_installed.contains(&resource.root))
        .map(|resource| resource.root.clone())
        .collect::<Vec<_>>();
    let mut unmatched_incoming = discovery
        .resources
        .iter()
        .filter(|resource| !matched_incoming.contains(&resource.root))
        .map(|resource| resource.root.clone())
        .collect::<Vec<_>>();

    sort_installed_roots(&mut unmatched_installed);
    sort_incoming_roots(&mut unmatched_incoming);

    let mut warnings = Vec::new();
    if unmatched_installed.len() == 1
        && unmatched_incoming.len() == 1
        && unmatched_incoming[0] == ZipResourceRoot::Root
    {
        let installed_resource = unmatched_installed.remove(0);
        let incoming_resource = unmatched_incoming.remove(0);
        matches.push(ResourceMatch {
            installed_resource: installed_resource.clone(),
            incoming_resource: incoming_resource.clone(),
            match_kind: ResourceMatchKind::SingleResourceFallback,
        });
        warnings.push(ComparisonWarning::SingleResourceFallback {
            installed_resource,
            incoming_resource,
        });
    }

    matches.sort_by(|left, right| {
        installed_root_key(&left.installed_resource)
            .cmp(&installed_root_key(&right.installed_resource))
            .then_with(|| {
                incoming_root_key(&left.incoming_resource)
                    .cmp(&incoming_root_key(&right.incoming_resource))
            })
    });

    Ok(ResourceMatchReport {
        matches,
        unmatched_installed_resources: unmatched_installed,
        unmatched_incoming_resources: unmatched_incoming,
        warnings,
    })
}

fn trusted_installed_match_name(
    selected_root: &Path,
    resource: &InstalledResourceScan,
) -> Result<String> {
    expected_installed_resource_name(selected_root, &resource.root)
}

fn trusted_incoming_match_name(resource: &crate::DiscoveredZipResource) -> Option<String> {
    match &resource.root {
        ZipResourceRoot::Root => None,
        ZipResourceRoot::Path(path) => Some(final_zip_component(path).to_owned()),
    }
}

fn incoming_files_to_hash(
    matches: &[ResourceMatch],
    discovery_by_root: &BTreeMap<ZipResourceRoot, &crate::DiscoveredZipResource>,
    escrow: &EscrowClassificationReport,
    limits: ComparisonLimits,
) -> Result<Vec<IncomingFileToHash>> {
    let escrow_by_root = escrow
        .resources
        .iter()
        .map(|resource| (&resource.resource_root, resource))
        .collect::<BTreeMap<_, _>>();
    let mut files = Vec::new();
    let mut total_size = 0_u64;

    for resource_match in matches {
        let resource = discovery_by_root
            .get(&resource_match.incoming_resource)
            .ok_or_else(|| GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "matched incoming resource root is missing: {:?}",
                    incoming_root_key(&resource_match.incoming_resource)
                ),
            })?;
        let classifications = escrow_by_root
            .get(&resource_match.incoming_resource)
            .ok_or_else(|| GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "matched incoming resource root has no escrow classification: {:?}",
                    incoming_root_key(&resource_match.incoming_resource)
                ),
            })?
            .files
            .iter()
            .map(|file| (file.package_path.as_str(), file))
            .collect::<BTreeMap<_, _>>();

        for entry in &resource.entries {
            if entry.kind != ZipEntryKind::File {
                continue;
            }
            if files.len() == limits.max_incoming_files_hashed {
                return Err(GkrmError::ComparisonIncomingFileCountLimitExceeded {
                    limit: limits.max_incoming_files_hashed,
                    actual: files.len() + 1,
                });
            }
            if entry.uncompressed_size > limits.max_incoming_file_size {
                return Err(GkrmError::ComparisonIncomingFileSizeLimitExceeded {
                    entry: entry.path.to_string(),
                    limit: limits.max_incoming_file_size,
                    actual: entry.uncompressed_size,
                });
            }
            total_size = total_size.checked_add(entry.uncompressed_size).ok_or(
                GkrmError::ComparisonIncomingTotalSizeLimitExceeded {
                    limit: limits.max_total_incoming_uncompressed_size,
                    actual: u64::MAX,
                },
            )?;
            if total_size > limits.max_total_incoming_uncompressed_size {
                return Err(GkrmError::ComparisonIncomingTotalSizeLimitExceeded {
                    limit: limits.max_total_incoming_uncompressed_size,
                    actual: total_size,
                });
            }

            let classified = classifications.get(entry.path.as_str()).ok_or_else(|| {
                GkrmError::ComparisonInconsistentReport {
                    message: format!("incoming file has no escrow classification: {}", entry.path),
                }
            })?;
            files.push(IncomingFileToHash {
                resource_root: resource.root.clone(),
                relative_path: zip_resource_relative_path(&resource.root, entry)?,
                entry: entry.clone(),
                escrow_classification: classified.classification.clone(),
            });
        }
    }

    files.sort_by(|left, right| {
        incoming_root_key(&left.resource_root)
            .cmp(&incoming_root_key(&right.resource_root))
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });

    Ok(files)
}

fn hash_matched_incoming_files(
    snapshot: &PackageSnapshot,
    files: &[IncomingFileToHash],
) -> Result<BTreeMap<ZipResourceRoot, BTreeMap<ResourceRelativePath, HashedIncomingFile>>> {
    let mut archive = snapshot.open_zip_archive().map_err(|source| match source {
        GkrmError::ZipPackageOpen {
            path,
            cause: source,
        } => GkrmError::ComparisonPackageOpen {
            path,
            cause: source,
        },
        GkrmError::ZipArchiveRead {
            path,
            cause: source,
        } => GkrmError::ComparisonZipArchiveRead {
            path,
            cause: source,
        },
        other => other,
    })?;

    run_after_archive_opened_hook();

    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    let mut hashed =
        BTreeMap::<ZipResourceRoot, BTreeMap<ResourceRelativePath, HashedIncomingFile>>::new();
    for file in files {
        let digest = hash_zip_entry_exact(&mut archive, &file.entry, &mut buffer)?;
        let previous = hashed
            .entry(file.resource_root.clone())
            .or_default()
            .insert(
                file.relative_path.clone(),
                HashedIncomingFile {
                    size: file.entry.uncompressed_size,
                    sha256: digest,
                    escrow_classification: file.escrow_classification.clone(),
                },
            );
        if previous.is_some() {
            return Err(GkrmError::ComparisonDuplicateIncomingRelativePath {
                resource: incoming_root_key(&file.resource_root),
                path: file.relative_path.to_string(),
            });
        }
    }

    Ok(hashed)
}

fn hash_zip_entry_exact<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    expected: &ZipEntryInfo,
    buffer: &mut [u8],
) -> Result<Sha256Digest> {
    {
        let entry = archive
            .by_index_raw(expected.archive_index)
            .map_err(|source| GkrmError::ComparisonZipEntryChanged {
                entry: expected.path.to_string(),
                reason: source.to_string(),
            })?;
        let actual_path =
            ZipRelativePath::new(expected.archive_index, entry.name_raw()).map_err(|source| {
                GkrmError::ComparisonZipEntryChanged {
                    entry: expected.path.to_string(),
                    reason: source.to_string(),
                }
            })?;
        let actual_kind = if entry.is_dir() {
            ZipEntryKind::Directory
        } else {
            ZipEntryKind::File
        };
        let actual = ZipEntryInfo {
            archive_index: expected.archive_index,
            path: actual_path,
            compressed_size: entry.compressed_size(),
            uncompressed_size: entry.size(),
            crc32: entry.crc32(),
            compression_method: entry.compression(),
            encrypted: entry.encrypted(),
            unix_mode: entry.unix_mode(),
            kind: actual_kind,
        };
        verify_entry_metadata(expected, &actual).map_err(|source| {
            GkrmError::ComparisonZipEntryChanged {
                entry: expected.path.to_string(),
                reason: source.to_string(),
            }
        })?;
    }

    let mut entry = archive.by_index(expected.archive_index).map_err(|source| {
        GkrmError::ComparisonZipEntryRead {
            entry: expected.path.to_string(),
            cause: source,
        }
    })?;
    hash_reader_exact(
        &mut entry,
        expected.uncompressed_size,
        buffer,
        expected.path.as_str(),
    )
}

fn hash_reader_exact<R: Read>(
    reader: &mut R,
    expected_size: u64,
    buffer: &mut [u8],
    entry: &str,
) -> Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;

    loop {
        let read = reader
            .read(buffer)
            .map_err(|source| GkrmError::ComparisonZipEntryStream {
                entry: entry.to_owned(),
                cause: source,
            })?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.checked_add(read as u64).ok_or_else(|| {
            GkrmError::ComparisonZipEntryStreamSizeMismatch {
                entry: entry.to_owned(),
                expected: expected_size,
                actual: u64::MAX,
            }
        })?;
        if bytes_read > expected_size {
            return Err(GkrmError::ComparisonZipEntryStreamSizeMismatch {
                entry: entry.to_owned(),
                expected: expected_size,
                actual: bytes_read,
            });
        }
        hasher.update(&buffer[..read]);
    }

    if bytes_read != expected_size {
        return Err(GkrmError::ComparisonZipEntryStreamSizeMismatch {
            entry: entry.to_owned(),
            expected: expected_size,
            actual: bytes_read,
        });
    }

    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn compare_resource_files(
    installed: &InstalledResourceScan,
    incoming: BTreeMap<ResourceRelativePath, HashedIncomingFile>,
) -> Result<Vec<ComparedFile>> {
    let installed_files = installed
        .files
        .iter()
        .map(|file| (file.relative_path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    let mut paths = BTreeSet::new();
    paths.extend(installed_files.keys().cloned());
    paths.extend(incoming.keys().cloned());

    let mut files = Vec::with_capacity(paths.len());
    for relative_path in paths {
        let installed_side = installed_files
            .get(&relative_path)
            .map(|file| ComparedFileSide {
                size: file.size,
                sha256: file.sha256,
            });
        let incoming_side = incoming
            .get(&relative_path)
            .map(|file| ComparedIncomingFile {
                size: file.size,
                sha256: file.sha256,
                escrow_classification: file.escrow_classification.clone(),
            });
        let status = match (&installed_side, &incoming_side) {
            (Some(installed), Some(incoming)) if installed.sha256 == incoming.sha256 => {
                FileComparisonStatus::Unchanged
            }
            (Some(_), Some(_)) => FileComparisonStatus::Changed,
            (None, Some(_)) => FileComparisonStatus::IncomingOnly,
            (Some(_), None) => FileComparisonStatus::InstalledOnly,
            (None, None) => {
                return Err(GkrmError::ComparisonInconsistentReport {
                    message: "compared path has neither installed nor incoming side".to_owned(),
                });
            }
        };
        files.push(ComparedFile {
            relative_path,
            status,
            installed: installed_side,
            incoming: incoming_side,
        });
    }

    Ok(files)
}

fn verify_entry_metadata(expected: &ZipEntryInfo, actual: &ZipEntryInfo) -> Result<()> {
    if expected.path != actual.path
        || expected.kind != actual.kind
        || expected.archive_index != actual.archive_index
        || expected.compressed_size != actual.compressed_size
        || expected.uncompressed_size != actual.uncompressed_size
        || expected.crc32 != actual.crc32
        || expected.compression_method != actual.compression_method
        || expected.encrypted != actual.encrypted
        || expected.unix_mode != actual.unix_mode
    {
        return Err(GkrmError::ComparisonInconsistentReport {
            message: format!(
                "zip entry metadata mismatch for {}: path, kind, archive index, size, CRC32, compression, encryption, or Unix mode differs",
                actual.path
            ),
        });
    }

    Ok(())
}

fn zip_resource_relative_path(
    root: &ZipResourceRoot,
    entry: &ZipEntryInfo,
) -> Result<ResourceRelativePath> {
    let relative = match root {
        ZipResourceRoot::Root => entry.path.as_str().to_owned(),
        ZipResourceRoot::Path(root_path) => entry
            .path
            .as_str()
            .strip_prefix(root_path.as_str())
            .and_then(|suffix| suffix.strip_prefix('/'))
            .filter(|suffix| !suffix.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| GkrmError::ComparisonInconsistentReport {
                message: format!(
                    "failed to derive resource-relative path for root {:?}, entry {}",
                    incoming_root_key(root),
                    entry.path
                ),
            })?,
    };

    Ok(ResourceRelativePath::from_safe_slash_path(relative))
}

fn expected_installed_resource_name(
    selected_root: &Path,
    root: &InstalledResourceRoot,
) -> Result<String> {
    match root {
        InstalledResourceRoot::Root => selected_root
            .file_name()
            .map(|name| {
                name.to_str().map(str::to_owned).ok_or_else(|| {
                    GkrmError::InstalledRootNameNonUtf8 {
                        path: selected_root.to_path_buf(),
                    }
                })
            })
            .unwrap_or_else(|| Ok("root".to_owned())),
        InstalledResourceRoot::Path(path) => Ok(path.file_name().to_owned()),
    }
}

fn validate_incoming_resource_name(resource: &crate::DiscoveredZipResource) -> Result<()> {
    match (&resource.root, &resource.name) {
        (ZipResourceRoot::Root, ZipResourceName::ZipRoot) => Ok(()),
        (ZipResourceRoot::Root, actual) => Err(GkrmError::ComparisonIncomingNameMismatch {
            root: incoming_root_key(&resource.root),
            expected: "ZipRoot".to_owned(),
            actual: incoming_name_label(actual),
        }),
        (ZipResourceRoot::Path(root), ZipResourceName::Directory(actual))
            if actual == final_zip_component(root) =>
        {
            Ok(())
        }
        (ZipResourceRoot::Path(root), actual) => Err(GkrmError::ComparisonIncomingNameMismatch {
            root: incoming_root_key(&resource.root),
            expected: format!("Directory({:?})", final_zip_component(root)),
            actual: incoming_name_label(actual),
        }),
    }
}

fn incoming_name_label(name: &ZipResourceName) -> String {
    match name {
        ZipResourceName::ZipRoot => "ZipRoot".to_owned(),
        ZipResourceName::Directory(name) => format!("Directory({name:?})"),
    }
}

fn final_zip_component(path: &ZipRelativePath) -> &str {
    path.as_str()
        .rsplit_once('/')
        .map_or(path.as_str(), |(_, name)| name)
}

fn expected_manifest_path(root: &ZipResourceRoot) -> ZipRelativePath {
    match root {
        ZipResourceRoot::Root => {
            ZipRelativePath::new(0, b"fxmanifest.lua").expect("static path should be valid")
        }
        ZipResourceRoot::Path(root) => {
            ZipRelativePath::new(0, format!("{}/fxmanifest.lua", root.as_str()).as_bytes())
                .expect("root-derived path should be valid")
        }
    }
}

fn zip_root_contains(root: &ZipResourceRoot, path: &ZipRelativePath) -> bool {
    match root {
        ZipResourceRoot::Root => true,
        ZipResourceRoot::Path(root) => {
            path == root
                || path
                    .as_str()
                    .strip_prefix(root.as_str())
                    .is_some_and(|suffix| suffix.as_bytes().first() == Some(&b'/'))
        }
    }
}

fn zip_root_depth(root: &ZipResourceRoot) -> usize {
    match root {
        ZipResourceRoot::Root => 0,
        ZipResourceRoot::Path(root) => root.as_str().split('/').count(),
    }
}

fn installed_root_key(root: &InstalledResourceRoot) -> String {
    match root {
        InstalledResourceRoot::Root => ".".to_owned(),
        InstalledResourceRoot::Path(path) => path.to_string(),
    }
}

fn incoming_root_key(root: &ZipResourceRoot) -> String {
    match root {
        ZipResourceRoot::Root => "/".to_owned(),
        ZipResourceRoot::Path(path) => path.to_string(),
    }
}

fn sort_installed_roots(roots: &mut [InstalledResourceRoot]) {
    roots.sort_by_key(installed_root_key);
}

fn sort_incoming_roots(roots: &mut [ZipResourceRoot]) {
    roots.sort_by_key(incoming_root_key);
}

#[cfg(test)]
struct AfterArchiveOpenedHookGuard;

#[cfg(test)]
impl Drop for AfterArchiveOpenedHookGuard {
    fn drop(&mut self) {
        AFTER_ARCHIVE_OPENED_HOOK.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

#[cfg(test)]
fn set_after_archive_opened_hook(
    hook: impl FnOnce() + Send + 'static,
) -> AfterArchiveOpenedHookGuard {
    AFTER_ARCHIVE_OPENED_HOOK.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(hook));
    });
    AfterArchiveOpenedHookGuard
}

#[cfg(test)]
fn run_after_archive_opened_hook() {
    let hook = AFTER_ARCHIVE_OPENED_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_after_archive_opened_hook() {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::io::Write;
    use std::path::Path;

    use super::*;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("zip should be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

        for (name, contents) in entries {
            writer
                .start_file(*name, options)
                .expect("file should start");
            writer
                .write_all(contents)
                .expect("file contents should be written");
        }

        writer.finish().expect("zip should finish");
    }

    #[test]
    fn hash_reader_exact_hashes_known_value() {
        let mut reader = Cursor::new(b"abc");
        let mut buffer = [0_u8; 2];
        let digest =
            hash_reader_exact(&mut reader, 3, &mut buffer, "entry").expect("hash should succeed");

        assert_eq!(
            digest.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_reader_exact_rejects_short_stream() {
        let mut reader = Cursor::new(b"ab");
        let mut buffer = [0_u8; 2];
        let err = hash_reader_exact(&mut reader, 3, &mut buffer, "entry")
            .expect_err("short stream should fail");

        assert!(matches!(
            err,
            GkrmError::ComparisonZipEntryStreamSizeMismatch {
                expected: 3,
                actual: 2,
                ..
            }
        ));
    }

    #[test]
    fn hash_reader_exact_rejects_long_stream() {
        let mut reader = Cursor::new(b"abc");
        let mut buffer = [0_u8; 2];
        let err = hash_reader_exact(&mut reader, 2, &mut buffer, "entry")
            .expect_err("long stream should fail");

        assert!(matches!(
            err,
            GkrmError::ComparisonZipEntryStreamSizeMismatch {
                expected: 2,
                actual: 3,
                ..
            }
        ));
    }

    #[test]
    fn live_archive_change_after_snapshot_does_not_change_hashing() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(&package, &[("resource/fxmanifest.lua", b"manifest")]);
        let snapshot =
            PackageSnapshot::create(&package, ComparisonLimits::default().max_archive_size)
                .expect("snapshot should be created");
        let package_for_hook = package.clone();
        let _hook_guard = set_after_archive_opened_hook(move || {
            write_zip(
                &package_for_hook,
                &[("resource/fxmanifest.lua", b"changed!")],
            );
        });

        let hashed = hash_matched_incoming_files(&snapshot, &[]).expect("snapshot should hash");

        assert!(hashed.is_empty());
    }

    #[test]
    fn private_archive_snapshot_is_used_for_entry_hashing() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                ("resource/fxmanifest.lua", b"fx_version 'cerulean'"),
                ("resource/file.lua", b"old"),
            ],
        );
        let inspection = crate::inspect_zip_package(&package, crate::PackageLimits::default())
            .expect("zip should inspect");
        let file_entry = inspection
            .entries
            .iter()
            .find(|entry| entry.path.as_str() == "resource/file.lua")
            .expect("file entry should exist")
            .clone();
        let snapshot =
            PackageSnapshot::create(&package, ComparisonLimits::default().max_archive_size)
                .expect("snapshot should be created");

        write_zip(
            &package,
            &[
                ("resource/fxmanifest.lua", b"fx_version 'cerulean'"),
                ("resource/file.lua", b"new"),
            ],
        );

        let mut archive = snapshot
            .open_zip_archive()
            .expect("snapshot zip should parse");
        let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
        let digest = hash_zip_entry_exact(&mut archive, &file_entry, &mut buffer)
            .expect("snapshot entry should hash");

        assert_eq!(
            digest.to_string(),
            "cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4"
        );
    }

    #[test]
    fn duplicate_hash_map_relative_path_insert_is_rejected() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                ("resource/fxmanifest.lua", b"fx_version 'cerulean'"),
                ("resource/a.lua", b"a"),
                ("resource/b.lua", b"b"),
            ],
        );
        let inspection = crate::inspect_zip_package(&package, crate::PackageLimits::default())
            .expect("zip should inspect");
        let root = ZipResourceRoot::Path(
            ZipRelativePath::new(0, b"resource").expect("root path should be valid"),
        );
        let entries = ["resource/a.lua", "resource/b.lua"]
            .into_iter()
            .map(|path| {
                inspection
                    .entries
                    .iter()
                    .find(|entry| entry.path.as_str() == path)
                    .expect("entry should exist")
                    .clone()
            })
            .collect::<Vec<_>>();
        let files = entries
            .into_iter()
            .map(|entry| IncomingFileToHash {
                resource_root: root.clone(),
                relative_path: ResourceRelativePath::from_safe_slash_path("same.lua".to_owned()),
                entry,
                escrow_classification: EscrowFileClassification::Protected,
            })
            .collect::<Vec<_>>();

        let snapshot =
            PackageSnapshot::create(&package, ComparisonLimits::default().max_archive_size)
                .expect("snapshot should be created");
        let err = hash_matched_incoming_files(&snapshot, &files)
            .expect_err("duplicate relative path insert should fail");

        assert!(matches!(
            err,
            GkrmError::ComparisonDuplicateIncomingRelativePath { .. }
        ));
    }
}
