use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    classify_zip_resource_escrow, compare_installation_to_zip, discover_zip_resources,
    inspect_zip_package, parse_zip_resource_manifests, ComparisonLimits, ComparisonWarning,
    EscrowFileClassification, FileComparisonStatus, GkrmError, InstallationRelativePath,
    InstalledInstallationScan, InstalledResourceRoot, InstalledResourceScan, ManifestLimits,
    PackageLimits, ResourceMatchKind, ZipInspection, ZipManifestParseReport, ZipResourceDiscovery,
    ZipResourceName, ZipResourceRoot,
};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'";

fn package_limits() -> PackageLimits {
    PackageLimits {
        max_entries: 50,
        max_entry_uncompressed_size: 4096,
        max_total_uncompressed_size: 32 * 1024,
        max_compression_ratio: 200,
    }
}

fn manifest_limits() -> ManifestLimits {
    ManifestLimits {
        max_manifest_size: 2048,
        max_tokens: 1024,
    }
}

fn comparison_limits() -> ComparisonLimits {
    ComparisonLimits {
        max_incoming_files_hashed: 50,
        max_incoming_file_size: 4096,
        max_total_incoming_uncompressed_size: 32 * 1024,
        max_archive_size: 32 * 1024,
    }
}

fn installed_limits() -> gkrm_core::InstalledScanLimits {
    gkrm_core::InstalledScanLimits {
        max_resources: 20,
        max_files_per_resource: 50,
        max_total_files: 200,
        max_total_entries: 250,
        max_directories: 100,
        max_file_size: 4096,
        max_total_size: 32 * 1024,
        max_directory_depth: 16,
    }
}

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("test path should have parent"))
        .expect("parent directory should be created");
    fs::write(path, contents).expect("file should be written");
}

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

struct IncomingReports {
    inspection: ZipInspection,
    discovery: ZipResourceDiscovery,
    manifests: ZipManifestParseReport,
    escrow: gkrm_core::EscrowClassificationReport,
}

fn incoming_reports(package: &Path) -> IncomingReports {
    let inspection = inspect_zip_package(package, package_limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    let manifests = parse_zip_resource_manifests(&inspection, &discovery, manifest_limits())
        .expect("manifests should parse");
    let escrow = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
        .expect("escrow should classify");

    IncomingReports {
        inspection,
        discovery,
        manifests,
        escrow,
    }
}

fn scan_installed(root: &Path) -> InstalledInstallationScan {
    gkrm_core::scan_installed_resources(root, installed_limits()).expect("installed should scan")
}

fn rel(path: &str) -> InstallationRelativePath {
    InstallationRelativePath::from_path(Path::new(path)).expect("test path should be valid")
}

fn compare(
    installed: &InstalledInstallationScan,
    reports: &IncomingReports,
) -> gkrm_core::InstallationComparisonReport {
    compare_installation_to_zip(
        installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect("comparison should succeed")
}

fn statuses(report: &gkrm_core::InstallationComparisonReport) -> Vec<(&str, FileComparisonStatus)> {
    report.matched_resources[0]
        .files
        .iter()
        .map(|file| (file.relative_path.as_str(), file.status))
        .collect()
}

#[test]
fn exact_name_matching_and_file_statuses_are_reported() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(
        &installed_root.join("fxmanifest.lua"),
        b"fx_version 'cerulean'",
    );
    write_file(&installed_root.join("same.lua"), b"same");
    write_file(&installed_root.join("changed.lua"), b"installed");
    write_file(&installed_root.join("old.lua"), b"old");
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", b"fx_version 'cerulean'"),
            ("gksphone/same.lua", b"same"),
            ("gksphone/changed.lua", b"incoming"),
            ("gksphone/new.lua", b"new"),
        ],
    );
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);

    assert_eq!(report.matched_resources.len(), 1);
    assert_eq!(
        report.matched_resources[0].resource_match.match_kind,
        ResourceMatchKind::ExactName
    );
    assert_eq!(
        statuses(&report),
        vec![
            ("changed.lua", FileComparisonStatus::Changed),
            ("fxmanifest.lua", FileComparisonStatus::Unchanged),
            ("new.lua", FileComparisonStatus::IncomingOnly),
            ("old.lua", FileComparisonStatus::InstalledOnly),
            ("same.lua", FileComparisonStatus::Unchanged),
        ]
    );
    let incoming_same = report.matched_resources[0]
        .files
        .iter()
        .find(|file| file.relative_path.as_str() == "same.lua")
        .and_then(|file| file.incoming.as_ref())
        .expect("incoming side should exist");
    assert_eq!(
        incoming_same.sha256.to_string(),
        "0967115f2813a3541eaef77de9d9d5773f1c0c04314b0bbfe4ff3b3b1c55b5d5"
    );
    assert!(!temp.path().join("gksphone").join("new.lua").exists());
}

#[test]
fn multiple_sibling_resources_match_deterministically() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("[gks]");
    write_file(&installed_root.join("gksphone/fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("gksphone/client.lua"), b"phone");
    write_file(&installed_root.join("tablet/fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("tablet/client.lua"), b"tablet");
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("tablet/fxmanifest.lua", MANIFEST),
            ("tablet/client.lua", b"tablet"),
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/client.lua", b"phone"),
        ],
    );
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);

    assert_eq!(
        report
            .matched_resources
            .iter()
            .map(
                |resource| match &resource.resource_match.installed_resource {
                    InstalledResourceRoot::Root => ".".to_owned(),
                    InstalledResourceRoot::Path(path) => path.to_string(),
                }
            )
            .collect::<Vec<_>>(),
        vec!["gksphone", "tablet"]
    );
    assert!(report.unmatched_installed_resources.is_empty());
    assert!(report.unmatched_incoming_resources.is_empty());
}

#[test]
fn duplicate_installed_names_are_hard_errors() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(&package, &[]);
    let installed = InstalledInstallationScan {
        root: PathBuf::from("installed"),
        resources: vec![
            InstalledResourceScan {
                name: "same".to_owned(),
                root: InstalledResourceRoot::Path(rel("a/same")),
                manifest_relative_path: rel("a/same/fxmanifest.lua"),
                files: Vec::new(),
            },
            InstalledResourceScan {
                name: "same".to_owned(),
                root: InstalledResourceRoot::Path(rel("b/same")),
                manifest_relative_path: rel("b/same/fxmanifest.lua"),
                files: Vec::new(),
            },
        ],
        warnings: Vec::new(),
    };
    let empty_inspection = ZipInspection {
        path: package,
        entries: Vec::new(),
    };
    let empty_discovery = ZipResourceDiscovery {
        resources: Vec::new(),
        unassigned_entries: Vec::new(),
        warnings: Vec::new(),
    };
    let empty_manifests = ZipManifestParseReport {
        resources: Vec::new(),
    };
    let empty_escrow = gkrm_core::EscrowClassificationReport {
        resources: Vec::new(),
    };

    let err = compare_installation_to_zip(
        &installed,
        &empty_inspection,
        &empty_discovery,
        &empty_manifests,
        &empty_escrow,
        comparison_limits(),
    )
    .expect_err("duplicate installed names should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonDuplicateInstalledName { .. }
    ));
}

#[test]
fn mutated_installed_name_is_rejected() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let mut installed = scan_installed(&installed_root);
    installed.resources[0].name = "other".to_owned();

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&package);

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("mutated installed name should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonInstalledNameMismatch { .. }
    ));
}

#[test]
fn duplicate_incoming_names_are_hard_errors() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(&package, &[]);
    let installed = InstalledInstallationScan {
        root: PathBuf::from("installed"),
        resources: Vec::new(),
        warnings: Vec::new(),
    };
    let inspection = ZipInspection {
        path: package,
        entries: Vec::new(),
    };
    let discovery = ZipResourceDiscovery {
        resources: vec![
            gkrm_core::DiscoveredZipResource {
                name: ZipResourceName::Directory("same".to_owned()),
                root: ZipResourceRoot::Path(gkrm_core::ZipRelativePath::new(0, b"a/same").unwrap()),
                manifest_path: gkrm_core::ZipRelativePath::new(0, b"a/same/fxmanifest.lua")
                    .unwrap(),
                entries: Vec::new(),
            },
            gkrm_core::DiscoveredZipResource {
                name: ZipResourceName::Directory("same".to_owned()),
                root: ZipResourceRoot::Path(gkrm_core::ZipRelativePath::new(0, b"b/same").unwrap()),
                manifest_path: gkrm_core::ZipRelativePath::new(0, b"b/same/fxmanifest.lua")
                    .unwrap(),
                entries: Vec::new(),
            },
        ],
        unassigned_entries: Vec::new(),
        warnings: Vec::new(),
    };

    let err = compare_installation_to_zip(
        &installed,
        &inspection,
        &discovery,
        &ZipManifestParseReport {
            resources: Vec::new(),
        },
        &gkrm_core::EscrowClassificationReport {
            resources: Vec::new(),
        },
        comparison_limits(),
    )
    .expect_err("duplicate incoming names should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonDuplicateIncomingName { .. }
    ));
}

#[test]
fn mutated_incoming_name_is_rejected() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let mut reports = incoming_reports(&package);
    reports.discovery.resources[0].name = ZipResourceName::Directory("other".to_owned());

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("mutated incoming name should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonIncomingNameMismatch { .. }
    ));
}

#[test]
fn root_incoming_resource_cannot_be_relabelled_for_exact_matching() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("fxmanifest.lua", MANIFEST)]);
    let mut reports = incoming_reports(&package);
    reports.discovery.resources[0].name = ZipResourceName::Directory("gksphone".to_owned());

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("relabelled root incoming name should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonIncomingNameMismatch { .. }
    ));
}

#[test]
fn unmatched_resources_remain_visible_without_guessing() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("other/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);

    assert!(report.matched_resources.is_empty());
    assert_eq!(
        report.unmatched_installed_resources,
        vec![InstalledResourceRoot::Root]
    );
    assert_eq!(
        report.unmatched_incoming_resources,
        vec![ZipResourceRoot::Path(
            gkrm_core::ZipRelativePath::new(0, b"other").unwrap()
        )]
    );
}

#[test]
fn single_root_resource_fallback_warns() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("client.lua"), b"client");
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[("fxmanifest.lua", MANIFEST), ("client.lua", b"client")],
    );
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);

    assert_eq!(
        report.matched_resources[0].resource_match.match_kind,
        ResourceMatchKind::SingleResourceFallback
    );
    assert_eq!(
        report.warnings,
        vec![ComparisonWarning::SingleResourceFallback {
            installed_resource: InstalledResourceRoot::Root,
            incoming_resource: ZipResourceRoot::Root,
        }]
    );
}

#[test]
fn invalid_root_fallback_conditions_leave_resources_unmatched() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("[gks]");
    write_file(&installed_root.join("one/fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("two/fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);

    assert!(report.matched_resources.is_empty());
    assert_eq!(report.unmatched_installed_resources.len(), 2);
    assert_eq!(
        report.unmatched_incoming_resources,
        vec![ZipResourceRoot::Root]
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn nested_resources_compare_independently() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("package");
    write_file(
        &installed_root.join("bundle/phone/fxmanifest.lua"),
        MANIFEST,
    );
    write_file(&installed_root.join("bundle/phone/client.lua"), b"parent");
    write_file(
        &installed_root.join("bundle/phone/plugins/example/fxmanifest.lua"),
        MANIFEST,
    );
    write_file(
        &installed_root.join("bundle/phone/plugins/example/client.lua"),
        b"nested",
    );
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("bundle/phone/fxmanifest.lua", MANIFEST),
            ("bundle/phone/client.lua", b"parent"),
            ("bundle/phone/plugins/example/fxmanifest.lua", MANIFEST),
            ("bundle/phone/plugins/example/client.lua", b"nested-changed"),
        ],
    );
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);

    assert_eq!(report.matched_resources.len(), 2);
    assert_eq!(
        report
            .matched_resources
            .iter()
            .map(|resource| {
                resource
                    .files
                    .iter()
                    .map(|file| file.relative_path.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        vec![
            vec!["client.lua", "fxmanifest.lua"],
            vec!["client.lua", "fxmanifest.lua"]
        ]
    );
    assert_eq!(
        report.matched_resources[1].files[0].status,
        FileComparisonStatus::Changed
    );
}

#[test]
fn sibling_prefix_resources_do_not_leak_files() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("client.lua"), b"phone");
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/client.lua", b"phone"),
            ("gksphone-extra/fxmanifest.lua", MANIFEST),
            ("gksphone-extra/client.lua", b"extra"),
        ],
    );
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);

    assert_eq!(report.matched_resources.len(), 1);
    assert_eq!(
        statuses(&report),
        vec![
            ("client.lua", FileComparisonStatus::Unchanged),
            ("fxmanifest.lua", FileComparisonStatus::Unchanged),
        ]
    );
    assert_eq!(report.unmatched_incoming_resources.len(), 1);
}

#[test]
fn package_change_after_inspection_is_rejected() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&package);
    write_zip(
        &package,
        &[("gksphone/fxmanifest.lua", b"manifest changed")],
    );

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("changed package should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonPackageChanged { .. }
            | GkrmError::ComparisonZipEntryChanged { .. }
            | GkrmError::ComparisonZipEntryRead { .. }
            | GkrmError::ComparisonZipEntryStream { .. }
    ));
}

#[test]
fn matched_resource_only_hashing_ignores_unmatched_large_files() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let large = vec![b'x'; 2048];
    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("other/fxmanifest.lua", MANIFEST),
            ("other/large.bin", &large),
        ],
    );
    let reports = incoming_reports(&package);
    let limits = ComparisonLimits {
        max_incoming_file_size: 64,
        max_total_incoming_uncompressed_size: 128,
        ..comparison_limits()
    };

    compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        limits,
    )
    .expect("unmatched large file should not be hashed or limited");
}

#[test]
fn compressed_archive_size_limit_is_enforced() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&package);

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        ComparisonLimits {
            max_archive_size: 1,
            ..comparison_limits()
        },
    )
    .expect_err("archive size limit should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonArchiveSizeLimitExceeded { .. }
    ));
}

#[test]
fn aggregate_limits_fail_before_hashing() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("client.lua"), b"client");
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/client.lua", b"client"),
        ],
    );
    let reports = incoming_reports(&package);
    fs::write(&package, b"not a zip anymore").expect("package should be replaced");

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        ComparisonLimits {
            max_total_incoming_uncompressed_size: 1,
            ..comparison_limits()
        },
    )
    .expect_err("aggregate limit should fail before package hashing");

    assert!(matches!(
        err,
        GkrmError::ComparisonIncomingTotalSizeLimitExceeded { .. }
    ));
}

#[test]
fn escrow_classification_is_attached_to_incoming_files() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(
        &installed_root.join("fxmanifest.lua"),
        b"escrow_ignore 'config.lua'",
    );
    write_file(&installed_root.join("config.lua"), b"installed");
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", b"escrow_ignore 'config.lua'"),
            ("gksphone/config.lua", b"incoming"),
        ],
    );
    let reports = incoming_reports(&package);

    let report = compare(&installed, &reports);
    let config = report.matched_resources[0]
        .files
        .iter()
        .find(|file| file.relative_path.as_str() == "config.lua")
        .and_then(|file| file.incoming.as_ref())
        .expect("config incoming side should exist");

    assert_eq!(
        config.escrow_classification,
        EscrowFileClassification::Ignored {
            matching_patterns: vec!["config.lua".to_owned()]
        }
    );
}

#[test]
fn mutated_escrow_classification_is_rejected() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(
        &installed_root.join("fxmanifest.lua"),
        b"escrow_ignore 'config.lua'",
    );
    write_file(&installed_root.join("config.lua"), b"installed");
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", b"escrow_ignore 'config.lua'"),
            ("gksphone/config.lua", b"incoming"),
        ],
    );
    let mut reports = incoming_reports(&package);
    reports.escrow.resources[0].files[0].classification = EscrowFileClassification::Protected;

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("mutated escrow classification should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonInconsistentReport { .. }
    ));
}

#[test]
fn duplicate_package_path_is_rejected() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let mut reports = incoming_reports(&package);
    let duplicate = reports.discovery.resources[0].entries[0].clone();
    reports.discovery.resources[0].entries.push(duplicate);

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("duplicate package path should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonDuplicateIncomingPackagePath { .. }
    ));
}

#[test]
fn one_package_entry_assigned_to_multiple_resources_is_rejected() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("[gks]");
    write_file(&installed_root.join("gksphone/fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("other/fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("other/fxmanifest.lua", MANIFEST),
        ],
    );
    let mut reports = incoming_reports(&package);
    let duplicate = reports.discovery.resources[0].entries[0].clone();
    reports.discovery.resources[1].entries.push(duplicate);

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("same package entry assigned to multiple resources should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonDuplicateIncomingPackagePath { .. }
            | GkrmError::ComparisonDuplicateIncomingArchiveIndex { .. }
    ));
}

#[test]
fn inconsistent_reports_are_rejected() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let mut reports = incoming_reports(&package);
    reports.discovery.resources[0].entries[0].uncompressed_size += 1;

    let err = compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("inconsistent discovery should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonInconsistentReport { .. }
    ));
}

#[test]
fn comparison_does_not_modify_installed_files() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_root.join("config.lua"), b"installed");
    let installed_before = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/config.lua", b"incoming"),
        ],
    );
    let reports = incoming_reports(&package);

    compare(&installed_before, &reports);
    let installed_after = scan_installed(&installed_root);

    assert_eq!(installed_before.resources, installed_after.resources);
    assert_eq!(
        fs::read(installed_root.join("config.lua")).expect("config should be readable"),
        b"installed"
    );
}

#[test]
fn private_snapshot_does_not_create_files_in_source_directories_after_success() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&package);

    let before = fs::read_dir(temp.path())
        .expect("temp dir should be readable")
        .count();
    compare(&installed, &reports);
    let after = fs::read_dir(temp.path())
        .expect("temp dir should be readable")
        .count();

    assert_eq!(before, after);
    assert!(!installed_root.join("resource").exists());
}

#[test]
fn private_snapshot_does_not_create_files_in_source_directories_after_error() {
    let temp = tempdir().expect("temp dir should be created");
    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&package);

    let before = fs::read_dir(temp.path())
        .expect("temp dir should be readable")
        .count();
    compare_installation_to_zip(
        &installed,
        &reports.inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        ComparisonLimits {
            max_archive_size: 1,
            ..comparison_limits()
        },
    )
    .expect_err("comparison should fail");
    let after = fs::read_dir(temp.path())
        .expect("temp dir should be readable")
        .count();

    assert_eq!(before, after);
}

#[cfg(unix)]
#[test]
fn symlinked_zip_parent_component_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temp dir should be created");
    let real_parent = temp.path().join("real");
    let link_parent = temp.path().join("link");
    fs::create_dir(&real_parent).expect("real parent should be created");
    symlink(&real_parent, &link_parent).expect("parent symlink should be created");

    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let real_package = real_parent.join("update.zip");
    write_zip(&real_package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&real_package);
    let mut inspection = reports.inspection.clone();
    inspection.path = link_parent.join("update.zip");

    let err = compare_installation_to_zip(
        &installed,
        &inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("symlinked parent component should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonPackageOpen { .. } | GkrmError::ComparisonPackageSymlink { .. }
    ));
}

#[cfg(windows)]
#[test]
fn junction_zip_parent_component_is_rejected_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let real_parent = temp.path().join("real");
    let junction_parent = temp.path().join("junction");
    fs::create_dir(&real_parent).expect("real parent should be created");

    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            junction_parent
                .to_str()
                .expect("junction path should be UTF-8"),
            real_parent.to_str().expect("real path should be UTF-8"),
        ])
        .status()
        .expect("mklink should run");
    if !status.success() {
        eprintln!("skipping junction test because mklink /J failed");
        return;
    }

    let installed_root = temp.path().join("gksphone");
    write_file(&installed_root.join("fxmanifest.lua"), MANIFEST);
    let installed = scan_installed(&installed_root);

    let real_package = real_parent.join("update.zip");
    write_zip(&real_package, &[("gksphone/fxmanifest.lua", MANIFEST)]);
    let reports = incoming_reports(&real_package);
    let mut inspection = reports.inspection.clone();
    inspection.path = junction_parent.join("update.zip");

    let err = compare_installation_to_zip(
        &installed,
        &inspection,
        &reports.discovery,
        &reports.manifests,
        &reports.escrow,
        comparison_limits(),
    )
    .expect_err("junction parent component should fail");

    assert!(matches!(
        err,
        GkrmError::ComparisonPackageOpen { .. } | GkrmError::ComparisonPackageReparsePoint { .. }
    ));
}
