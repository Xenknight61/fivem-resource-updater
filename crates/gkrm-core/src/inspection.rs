use std::path::Path;

use crate::{
    classify_zip_resource_escrow, comparison::compare_installation_to_zip_snapshot,
    discover_zip_resources, manifest::parse_zip_resource_manifests_from_snapshot,
    package_source::PackageSnapshot, scan_installed_resources, three_way_fingerprint,
    zip_package::inspect_zip_snapshot, ComparisonLimits, EscrowClassificationReport,
    InstallationComparisonReport, InstalledInstallationScan, InstalledScanLimits, ManifestLimits,
    PackageLimits, Result, SafeResourceKey, Sha256Digest, ZipInspection, ZipManifestParseReport,
    ZipResourceDiscovery,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InspectionOptions {
    pub package_limits: PackageLimits,
    pub manifest_limits: ManifestLimits,
    pub installed_scan_limits: InstalledScanLimits,
    pub comparison_limits: ComparisonLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullInspectionReport {
    installed: InstalledInstallationScan,
    incoming_package_fingerprint: Sha256Digest,
    incoming_inspection: ZipInspection,
    incoming_discovery: ZipResourceDiscovery,
    manifests: ZipManifestParseReport,
    escrow: EscrowClassificationReport,
    comparison: InstallationComparisonReport,
}

pub const PACKAGE_RESOURCE_INSPECTION_MAX_PACKAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageResourceInspectionOptions {
    pub max_package_bytes: u64,
    pub package_limits: PackageLimits,
    pub manifest_limits: ManifestLimits,
}

impl Default for PackageResourceInspectionOptions {
    fn default() -> Self {
        Self {
            max_package_bytes: PACKAGE_RESOURCE_INSPECTION_MAX_PACKAGE_BYTES,
            package_limits: PackageLimits::default(),
            manifest_limits: ManifestLimits::default(),
        }
    }
}

impl PackageResourceInspectionOptions {
    fn validate(&self) -> Result<()> {
        if self.max_package_bytes == 0 {
            return Err(crate::GkrmError::ComparisonZeroLimit {
                limit: "max_package_bytes",
            });
        }
        if self.max_package_bytes > PACKAGE_RESOURCE_INSPECTION_MAX_PACKAGE_BYTES {
            return Err(crate::GkrmError::ComparisonArchiveSizeLimitExceeded {
                path: Path::new("package").to_path_buf(),
                limit: PACKAGE_RESOURCE_INSPECTION_MAX_PACKAGE_BYTES,
                actual: self.max_package_bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageResourceInspectionReport {
    package_commitment: PackageSourceCommitment,
    resource_count: usize,
    warning_count: usize,
    total_file_count: usize,
    total_bytes: u64,
    resources: Vec<PackageResourceInspectionResource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledResourceSourceCommitment {
    fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageSourceCommitment {
    fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageResourceInspectionResource {
    resource_key: Option<SafeResourceKey>,
    display_name: String,
    file_count: usize,
    total_bytes: u64,
    manifest: PackageResourceManifestSummary,
    escrow: PackageResourceEscrowSummary,
    warning_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageResourceManifestSummary {
    pub client_script_count: usize,
    pub server_script_count: usize,
    pub shared_script_count: usize,
    pub data_file_count: usize,
    pub has_ui_page: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageResourceEscrowSummary {
    pub protected_file_count: usize,
    pub ignored_file_count: usize,
    pub unsupported_file_count: usize,
}

impl PackageResourceInspectionReport {
    pub fn package_commitment(&self) -> PackageSourceCommitment {
        self.package_commitment
    }

    pub fn resource_count(&self) -> usize {
        self.resource_count
    }

    pub fn warning_count(&self) -> usize {
        self.warning_count
    }

    pub fn total_file_count(&self) -> usize {
        self.total_file_count
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn resources(&self) -> &[PackageResourceInspectionResource] {
        &self.resources
    }
}

impl InstalledResourceSourceCommitment {
    pub fn fingerprint(&self) -> &Sha256Digest {
        &self.fingerprint
    }
}

impl PackageSourceCommitment {
    pub fn from_package_fingerprint(fingerprint: Sha256Digest) -> Self {
        Self { fingerprint }
    }

    pub fn fingerprint(&self) -> &Sha256Digest {
        &self.fingerprint
    }
}

impl PackageResourceInspectionResource {
    pub fn resource_key(&self) -> Option<&SafeResourceKey> {
        self.resource_key.as_ref()
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn file_count(&self) -> usize {
        self.file_count
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn manifest(&self) -> PackageResourceManifestSummary {
        self.manifest
    }

    pub fn escrow(&self) -> PackageResourceEscrowSummary {
        self.escrow
    }

    pub fn warning_count(&self) -> usize {
        self.warning_count
    }
}

pub fn installed_resource_source_commitment(
    resource: &crate::InstalledResourceScan,
    expected_key: &SafeResourceKey,
) -> Result<InstalledResourceSourceCommitment> {
    let resource_key = SafeResourceKey::parse(&resource.name)
        .map_err(|_| crate::GkrmError::ThreeWayBaselineInstalledResourceMismatch)?;
    if &resource_key != expected_key {
        return Err(crate::GkrmError::ThreeWayBaselineInstalledResourceMismatch);
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut files = Vec::with_capacity(resource.files.len());
    for file in &resource.files {
        if !seen.insert(file.relative_path.clone()) {
            return Err(crate::GkrmError::ThreeWayDuplicateInstalledPath);
        }
        files.push((file.relative_path.clone(), file.size, file.sha256));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let fingerprint_files = files
        .iter()
        .map(
            |(path, size, sha256)| three_way_fingerprint::InstalledSourceCommitmentFile {
                path,
                size: *size,
                sha256,
            },
        )
        .collect::<Vec<_>>();
    Ok(InstalledResourceSourceCommitment {
        fingerprint: three_way_fingerprint::installed_resource_source_commitment(
            &resource_key,
            &fingerprint_files,
        )?,
    })
}

/// A complete, internally consistent read-only inspection result.
///
/// Future mutating APIs must accept this whole report rather than arbitrary
/// caller-assembled combinations of package inspection, discovery, manifest,
/// escrow, and comparison reports.
impl FullInspectionReport {
    pub fn installed(&self) -> &InstalledInstallationScan {
        &self.installed
    }

    pub fn incoming_inspection(&self) -> &ZipInspection {
        &self.incoming_inspection
    }

    pub fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_package_fingerprint
    }

    pub fn incoming_discovery(&self) -> &ZipResourceDiscovery {
        &self.incoming_discovery
    }

    pub fn manifests(&self) -> &ZipManifestParseReport {
        &self.manifests
    }

    pub fn escrow(&self) -> &EscrowClassificationReport {
        &self.escrow
    }

    pub fn comparison(&self) -> &InstallationComparisonReport {
        &self.comparison
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        installed: InstalledInstallationScan,
        incoming_package_fingerprint: Sha256Digest,
        incoming_inspection: ZipInspection,
        incoming_discovery: ZipResourceDiscovery,
        manifests: ZipManifestParseReport,
        escrow: EscrowClassificationReport,
        comparison: InstallationComparisonReport,
    ) -> Self {
        Self {
            installed,
            incoming_package_fingerprint,
            incoming_inspection,
            incoming_discovery,
            manifests,
            escrow,
            comparison,
        }
    }
}

pub fn inspect_installation_update(
    installed_path: &Path,
    package_path: &Path,
    options: InspectionOptions,
) -> Result<FullInspectionReport> {
    options.comparison_limits.validate()?;
    let package_snapshot =
        PackageSnapshot::create(package_path, options.comparison_limits.max_archive_size)?;
    inspect_installation_update_from_package_snapshot(installed_path, &package_snapshot, options)
}

pub(crate) fn inspect_installation_update_from_package_snapshot(
    installed_path: &Path,
    package_snapshot: &PackageSnapshot,
    options: InspectionOptions,
) -> Result<FullInspectionReport> {
    options.comparison_limits.validate()?;
    let incoming_package_fingerprint = *package_snapshot.fingerprint();
    let incoming_inspection = inspect_zip_snapshot(package_snapshot, options.package_limits)?;
    let incoming_discovery = discover_zip_resources(&incoming_inspection)?;
    let manifests = parse_zip_resource_manifests_from_snapshot(
        package_snapshot,
        &incoming_inspection,
        &incoming_discovery,
        options.manifest_limits,
    )?;
    let escrow =
        classify_zip_resource_escrow(&incoming_inspection, &incoming_discovery, &manifests)?;
    let installed = scan_installed_resources(installed_path, options.installed_scan_limits)?;
    let comparison = compare_installation_to_zip_snapshot(
        &installed,
        package_snapshot,
        &incoming_inspection,
        &incoming_discovery,
        &manifests,
        &escrow,
        options.comparison_limits,
    )?;

    Ok(FullInspectionReport {
        installed,
        incoming_package_fingerprint,
        incoming_inspection,
        incoming_discovery,
        manifests,
        escrow,
        comparison,
    })
}

pub fn inspect_package_resources(
    package_path: &Path,
    options: PackageResourceInspectionOptions,
) -> Result<PackageResourceInspectionReport> {
    options.validate()?;
    let package_snapshot = PackageSnapshot::create(package_path, options.max_package_bytes)?;
    let inspection = inspect_zip_snapshot(&package_snapshot, options.package_limits)?;
    let discovery = discover_zip_resources(&inspection)?;
    let manifests = parse_zip_resource_manifests_from_snapshot(
        &package_snapshot,
        &inspection,
        &discovery,
        options.manifest_limits,
    )?;
    let escrow = classify_zip_resource_escrow(&inspection, &discovery, &manifests)?;

    let mut resources = Vec::with_capacity(discovery.resources.len());
    let mut total_file_count = 0usize;
    let mut total_bytes = 0u64;
    let mut warning_count = discovery.warnings.len();

    for discovered in &discovery.resources {
        let file_count = discovered
            .entries
            .iter()
            .filter(|entry| entry.kind == crate::ZipEntryKind::File)
            .count();
        let resource_bytes = discovered
            .entries
            .iter()
            .filter(|entry| entry.kind == crate::ZipEntryKind::File)
            .try_fold(0u64, |acc, entry| {
                acc.checked_add(entry.uncompressed_size).ok_or(
                    crate::GkrmError::ZipTotalSizeLimitExceeded {
                        limit: u64::MAX,
                        actual: u64::MAX,
                    },
                )
            })?;
        total_file_count = total_file_count.checked_add(file_count).ok_or(
            crate::GkrmError::ZipEntryCountLimitExceeded {
                limit: usize::MAX,
                actual: usize::MAX,
            },
        )?;
        total_bytes = total_bytes.checked_add(resource_bytes).ok_or(
            crate::GkrmError::ZipTotalSizeLimitExceeded {
                limit: u64::MAX,
                actual: u64::MAX,
            },
        )?;

        let parsed_manifest = manifests
            .resources
            .iter()
            .find(|manifest| manifest.resource_root == discovered.root)
            .ok_or(crate::GkrmError::EscrowManifestMissing {
                root: "package resource".to_owned(),
            })?;
        let classified = escrow
            .resources
            .iter()
            .find(|resource| resource.resource_root == discovered.root)
            .ok_or(crate::GkrmError::EscrowManifestMissing {
                root: "package resource".to_owned(),
            })?;
        warning_count = warning_count
            .checked_add(parsed_manifest.warnings.len())
            .and_then(|count| count.checked_add(classified.warnings.len()))
            .ok_or(crate::GkrmError::ZipEntryCountLimitExceeded {
                limit: usize::MAX,
                actual: usize::MAX,
            })?;

        let mut protected_file_count = 0usize;
        let mut ignored_file_count = 0usize;
        let mut unsupported_file_count = 0usize;
        for file in &classified.files {
            match file.classification {
                crate::EscrowFileClassification::Protected => protected_file_count += 1,
                crate::EscrowFileClassification::Ignored { .. } => ignored_file_count += 1,
                crate::EscrowFileClassification::NotSupported { .. } => unsupported_file_count += 1,
            }
        }

        resources.push(PackageResourceInspectionResource {
            resource_key: match &discovered.name {
                crate::ZipResourceName::Directory(name) => SafeResourceKey::parse(name).ok(),
                crate::ZipResourceName::ZipRoot => None,
            },
            display_name: match &discovered.name {
                crate::ZipResourceName::Directory(name) => name.clone(),
                crate::ZipResourceName::ZipRoot => "Package root".to_owned(),
            },
            file_count,
            total_bytes: resource_bytes,
            manifest: PackageResourceManifestSummary {
                client_script_count: parsed_manifest.manifest.client_scripts.len(),
                server_script_count: parsed_manifest.manifest.server_scripts.len(),
                shared_script_count: parsed_manifest.manifest.shared_scripts.len(),
                data_file_count: parsed_manifest.manifest.files.len(),
                has_ui_page: !parsed_manifest.manifest.ui_pages.is_empty(),
            },
            escrow: PackageResourceEscrowSummary {
                protected_file_count,
                ignored_file_count,
                unsupported_file_count,
            },
            warning_count: parsed_manifest.warnings.len() + classified.warnings.len(),
        });
    }

    Ok(PackageResourceInspectionReport {
        package_commitment: PackageSourceCommitment::from_package_fingerprint(
            *package_snapshot.fingerprint(),
        ),
        resource_count: resources.len(),
        warning_count,
        total_file_count,
        total_bytes,
        resources,
    })
}

#[cfg(test)]
mod package_resource_inspection_tests {
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("zip should be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, contents) in entries {
            writer.start_file(*name, options).expect("file start");
            writer.write_all(contents).expect("file write");
        }
        writer.finish().expect("zip finish");
    }

    #[test]
    fn package_resource_adapter_reports_safe_resource_facts() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                (
                    "alpha/fxmanifest.lua",
                    b"fx_version 'cerulean'\ngame 'gta5'\nclient_script 'client.lua'\nserver_script 'server.lua'\nfiles { 'html/index.html' }\nui_page 'html/index.html'\nescrow_ignore { 'config.lua' }\n",
                ),
                ("alpha/client.lua", b"client"),
                ("alpha/server.lua", b"server"),
                ("alpha/config.lua", b"config"),
                ("alpha/html/index.html", b"html"),
                ("beta/fxmanifest.lua", b"fx_version 'cerulean'\ngame 'gta5'\n"),
            ],
        );

        let report =
            inspect_package_resources(&package, PackageResourceInspectionOptions::default())
                .unwrap();
        assert_eq!(report.resource_count(), 2);
        assert_eq!(report.resources()[0].display_name(), "alpha");
        assert_eq!(report.resources()[0].manifest().client_script_count, 1);
        assert_eq!(report.resources()[0].manifest().server_script_count, 1);
        assert_eq!(report.resources()[0].manifest().data_file_count, 1);
        assert!(report.resources()[0].manifest().has_ui_page);
        assert!(report.total_file_count() >= 6);
    }

    #[test]
    fn package_commitment_changes_for_same_length_package_replacement() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                ("gksphone/fxmanifest.lua", b"fx_version 'cerulean'\n"),
                ("gksphone/client.lua", b"base\n"),
            ],
        );
        let before =
            inspect_package_resources(&package, PackageResourceInspectionOptions::default())
                .unwrap();
        let before_len = fs::metadata(&package).unwrap().len();
        write_zip(
            &package,
            &[
                ("gksphone/fxmanifest.lua", b"fx_version 'cerulean'\n"),
                ("gksphone/client.lua", b"bAse\n"),
            ],
        );
        assert_eq!(fs::metadata(&package).unwrap().len(), before_len);
        let after =
            inspect_package_resources(&package, PackageResourceInspectionOptions::default())
                .unwrap();
        assert_ne!(before.package_commitment(), after.package_commitment());
    }

    #[test]
    fn package_resource_adapter_does_not_extract_or_format_paths() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("private-package.zip");
        write_zip(
            &package,
            &[(
                "resource/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            )],
        );

        let report =
            inspect_package_resources(&package, PackageResourceInspectionOptions::default())
                .unwrap();
        let debug = format!("{report:?}");
        assert!(!debug.contains(temp.path().to_string_lossy().as_ref()));
        assert!(!temp.path().join("resource").exists());
    }

    #[test]
    fn package_resource_adapter_rejects_unsafe_zip() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("unsafe.zip");
        write_zip(&package, &[("../fxmanifest.lua", b"fx_version 'cerulean'")]);

        assert!(
            inspect_package_resources(&package, PackageResourceInspectionOptions::default())
                .is_err()
        );
    }

    #[test]
    fn package_resource_inspection_enforces_configured_archive_size() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[(
                "resource/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            )],
        );
        let package_size = fs::metadata(&package).unwrap().len();

        let below_limit = PackageResourceInspectionOptions {
            max_package_bytes: package_size + 1,
            ..PackageResourceInspectionOptions::default()
        };
        assert!(inspect_package_resources(&package, below_limit).is_ok());

        let exact_limit = PackageResourceInspectionOptions {
            max_package_bytes: package_size,
            ..PackageResourceInspectionOptions::default()
        };
        assert!(inspect_package_resources(&package, exact_limit).is_ok());

        let too_small = PackageResourceInspectionOptions {
            max_package_bytes: package_size - 1,
            ..PackageResourceInspectionOptions::default()
        };
        assert!(matches!(
            inspect_package_resources(&package, too_small),
            Err(crate::GkrmError::ComparisonArchiveSizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn package_resource_inspection_rejects_zero_and_above_hard_archive_limit() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[(
                "resource/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            )],
        );

        let zero = PackageResourceInspectionOptions {
            max_package_bytes: 0,
            ..PackageResourceInspectionOptions::default()
        };
        assert!(matches!(
            inspect_package_resources(&package, zero),
            Err(crate::GkrmError::ComparisonZeroLimit {
                limit: "max_package_bytes"
            })
        ));

        let above_hard = PackageResourceInspectionOptions {
            max_package_bytes: PACKAGE_RESOURCE_INSPECTION_MAX_PACKAGE_BYTES + 1,
            ..PackageResourceInspectionOptions::default()
        };
        assert!(matches!(
            inspect_package_resources(&package, above_hard),
            Err(crate::GkrmError::ComparisonArchiveSizeLimitExceeded { .. })
        ));
    }
}
