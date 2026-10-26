use std::fs::File;
use std::io::Write;
use std::path::Path;

use gkrm_core::{
    classify_zip_resource_escrow, discover_zip_resources, inspect_zip_package,
    parse_zip_resource_manifests, EscrowClassificationWarning, EscrowFileClassification, GkrmError,
    ManifestLimits, PackageLimits, ZipEntryKind, ZipResourceName, ZipResourceWarning,
};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

fn limits() -> PackageLimits {
    PackageLimits {
        max_entries: 10,
        max_entry_uncompressed_size: 1024,
        max_total_uncompressed_size: 4096,
        max_compression_ratio: 200,
    }
}

fn large_limits() -> PackageLimits {
    PackageLimits {
        max_entries: 20,
        max_entry_uncompressed_size: 2048,
        max_total_uncompressed_size: 8192,
        max_compression_ratio: 200,
    }
}

fn manifest_limits() -> ManifestLimits {
    ManifestLimits {
        max_manifest_size: 1024,
        max_tokens: 512,
    }
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).expect("zip file should be created");
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
fn public_zip_inspector_returns_deterministic_entries_without_extracting() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(
        &package,
        &[
            ("resource/server.lua", b"server"),
            ("resource/client.lua", b"client"),
            ("resource/config.lua", b"config"),
        ],
    );

    let inspection = inspect_zip_package(&package, limits()).expect("zip should inspect");

    let paths = inspection
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        paths,
        vec![
            "resource/client.lua",
            "resource/config.lua",
            "resource/server.lua"
        ]
    );
    assert_eq!(
        inspection
            .entries
            .iter()
            .map(|entry| entry.archive_index)
            .collect::<Vec<_>>(),
        vec![1, 2, 0]
    );
    assert!(inspection
        .entries
        .iter()
        .all(|entry| entry.kind == ZipEntryKind::File));
    assert!(!temp.path().join("resource").exists());
}

#[test]
fn public_zip_inspector_rejects_parent_traversal_as_hard_error() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(&package, &[("../evil.lua", b"evil")]);

    let err = inspect_zip_package(&package, limits()).expect_err("traversal should fail");

    assert!(matches!(err, GkrmError::ZipEntryParentTraversal { .. }));
    assert!(!temp.path().join("evil.lua").exists());
}

#[test]
fn public_zip_inspector_enforces_total_size_limit() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(&package, &[("a.lua", b"aaa"), ("b.lua", b"bbb")]);
    let small_limits = PackageLimits {
        max_total_uncompressed_size: 5,
        ..limits()
    };

    let err = inspect_zip_package(&package, small_limits).expect_err("total size should fail");

    assert!(matches!(err, GkrmError::ZipTotalSizeLimitExceeded { .. }));
}

#[test]
fn public_zip_discovery_uses_inspected_zip_inventory() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(
        &package,
        &[
            ("bundle/readme.txt", b"readme"),
            ("bundle/gksphone/fxmanifest.lua", b"manifest"),
            ("bundle/gksphone/client/main.lua", b"client"),
            ("bundle/gksphone/plugins/example/fxmanifest.lua", b"nested"),
            (
                "bundle/gksphone/plugins/example/client.lua",
                b"nested client",
            ),
        ],
    );

    let inspection = inspect_zip_package(&package, limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");

    assert_eq!(discovery.resources.len(), 2);
    assert_eq!(
        discovery.resources[0].name,
        ZipResourceName::Directory("gksphone".to_owned())
    );
    assert_eq!(
        discovery.resources[1].name,
        ZipResourceName::Directory("example".to_owned())
    );
    assert_eq!(
        discovery
            .resources
            .iter()
            .map(|resource| {
                resource
                    .entries
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        vec![
            vec![
                "bundle/gksphone/client/main.lua",
                "bundle/gksphone/fxmanifest.lua"
            ],
            vec![
                "bundle/gksphone/plugins/example/client.lua",
                "bundle/gksphone/plugins/example/fxmanifest.lua"
            ],
        ]
    );
    assert_eq!(
        discovery
            .unassigned_entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["bundle/readme.txt"]
    );
    assert_eq!(
        discovery.warnings,
        vec![ZipResourceWarning::UnassignedPackageEntries { count: 1 }]
    );
}

#[test]
fn public_manifest_parser_reads_discovered_manifests_deterministically() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(
        &package,
        &[
            (
                "bundle/gksphone/fxmanifest.lua",
                br#"
                fx_version 'cerulean'
                game 'gta5'
                client_script 'client/main.lua'
                files({
                    'html/index.html',
                    'html/assets/*',
                })
                "#,
            ),
            ("bundle/gksphone/client/main.lua", b"client"),
            (
                "bundle/gksphone/plugins/example/fxmanifest.lua",
                br#"
                fx_version "cerulean"
                games { 'gta5', 'rdr3', }
                dependency 'qb-core'
                "#,
            ),
            (
                "bundle/gksphone/plugins/example/client.lua",
                b"nested client",
            ),
        ],
    );

    let inspection = inspect_zip_package(&package, large_limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    let report = parse_zip_resource_manifests(&inspection, &discovery, manifest_limits())
        .expect("manifests should parse");

    assert_eq!(report.resources.len(), 2);
    assert!(report
        .resources
        .iter()
        .all(|resource| resource.warnings.is_empty()));
    assert_eq!(
        report
            .resources
            .iter()
            .map(|resource| resource.manifest_path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "bundle/gksphone/fxmanifest.lua",
            "bundle/gksphone/plugins/example/fxmanifest.lua"
        ]
    );
    assert_eq!(
        report.resources[0]
            .manifest
            .client_scripts
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["client/main.lua"]
    );
    assert_eq!(
        report.resources[0]
            .manifest
            .files
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["html/index.html", "html/assets/*"]
    );
    assert_eq!(
        report.resources[1]
            .manifest
            .games
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["gta5", "rdr3"]
    );
}

#[test]
fn public_manifest_parser_rejects_invalid_utf8_manifest() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(&package, &[("resource/fxmanifest.lua", &[0xff, 0xfe])]);

    let inspection = inspect_zip_package(&package, limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    let err = parse_zip_resource_manifests(&inspection, &discovery, manifest_limits())
        .expect_err("invalid UTF-8 should fail");

    assert!(matches!(err, GkrmError::ManifestInvalidUtf8 { .. }));
}

#[test]
fn public_manifest_parser_enforces_manifest_size_limit() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(
        &package,
        &[(
            "resource/fxmanifest.lua",
            b"client_script 'client/main.lua'",
        )],
    );

    let inspection = inspect_zip_package(&package, limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    let small_manifest_limits = ManifestLimits {
        max_manifest_size: 4,
        ..manifest_limits()
    };
    let err = parse_zip_resource_manifests(&inspection, &discovery, small_manifest_limits)
        .expect_err("manifest size should fail");

    assert!(matches!(err, GkrmError::ManifestSizeLimitExceeded { .. }));
}

#[test]
fn public_manifest_parser_rejects_changed_zip_entry_metadata_after_inspection() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(
        &package,
        &[("resource/fxmanifest.lua", b"client_script 'a.lua'")],
    );

    let inspection = inspect_zip_package(&package, limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    write_zip(
        &package,
        &[(
            "resource/fxmanifest.lua",
            b"client_script 'a.lua'\nclient_script 'b.lua'",
        )],
    );

    let err = parse_zip_resource_manifests(&inspection, &discovery, manifest_limits())
        .expect_err("changed ZIP entry should fail");

    assert!(matches!(err, GkrmError::ManifestZipEntryChanged { .. }));
}

#[test]
fn public_manifest_parser_rejects_same_size_changed_manifest_after_inspection() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(
        &package,
        &[("resource/fxmanifest.lua", b"client_script 'a.lua'")],
    );

    let inspection = inspect_zip_package(&package, limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    write_zip(
        &package,
        &[("resource/fxmanifest.lua", b"client_script 'b.lua'")],
    );

    let err = parse_zip_resource_manifests(&inspection, &discovery, manifest_limits())
        .expect_err("same-size changed ZIP entry should fail");

    assert!(matches!(err, GkrmError::ManifestZipEntryChanged { .. }));
}

#[test]
fn public_manifest_parser_reads_only_discovered_manifest_entries() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    let large_entry = vec![b'x'; 1500];
    write_zip(
        &package,
        &[
            (
                "resource/fxmanifest.lua",
                b"client_script 'client/main.lua'",
            ),
            ("resource/client/main.lua", b"client"),
            ("resource/large.bin", &large_entry),
        ],
    );

    let inspection = inspect_zip_package(&package, large_limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    let small_manifest_limits = ManifestLimits {
        max_manifest_size: 64,
        ..manifest_limits()
    };
    let report = parse_zip_resource_manifests(&inspection, &discovery, small_manifest_limits)
        .expect("non-manifest entry size should not affect manifest parsing");

    assert_eq!(report.resources.len(), 1);
    assert_eq!(
        report.resources[0]
            .manifest
            .client_scripts
            .iter()
            .map(|value| value.value.as_str())
            .collect::<Vec<_>>(),
        vec!["client/main.lua"]
    );
}

#[test]
fn public_escrow_classifier_uses_discovered_resources_and_parsed_manifests() {
    let temp = tempdir().expect("temp dir should be created");
    let package = temp.path().join("package.zip");
    write_zip(
        &package,
        &[
            (
                "bundle/gksphone/fxmanifest.lua",
                br#"
                fx_version 'cerulean'
                game 'gta5'
                escrow_ignore {
                    'config/*.lua',
                    'stream/*.yft',
                    'html/*',
                }
                "#,
            ),
            ("bundle/gksphone/client/main.lua", b"client"),
            ("bundle/gksphone/config/config.lua", b"config"),
            ("bundle/gksphone/stream/car.yft", b"stream"),
            ("bundle/gksphone/html/index.html", b"html"),
            (
                "bundle/gksphone/plugins/example/fxmanifest.lua",
                br#"
                fx_version 'cerulean'
                game 'gta5'
                escrow_ignore 'config.lua'
                "#,
            ),
            (
                "bundle/gksphone/plugins/example/client.lua",
                b"nested client",
            ),
            (
                "bundle/gksphone/plugins/example/config.lua",
                b"nested config",
            ),
        ],
    );

    let inspection = inspect_zip_package(&package, large_limits()).expect("zip should inspect");
    let discovery = discover_zip_resources(&inspection).expect("resources should discover");
    let manifests = parse_zip_resource_manifests(&inspection, &discovery, manifest_limits())
        .expect("manifests should parse");
    let report = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
        .expect("files should classify");

    assert_eq!(report.resources.len(), 2);
    assert_eq!(
        report.resources[0]
            .files
            .iter()
            .map(|file| { (file.resource_relative_path.as_str(), &file.classification,) })
            .collect::<Vec<_>>(),
        vec![
            ("client/main.lua", &EscrowFileClassification::Protected),
            (
                "config/config.lua",
                &EscrowFileClassification::Ignored {
                    matching_patterns: vec!["config/*.lua".to_owned()]
                }
            ),
            ("fxmanifest.lua", &EscrowFileClassification::Protected),
            (
                "html/index.html",
                &EscrowFileClassification::NotSupported {
                    matching_ignore_patterns: vec!["html/*".to_owned()]
                }
            ),
            (
                "stream/car.yft",
                &EscrowFileClassification::Ignored {
                    matching_patterns: vec!["stream/*.yft".to_owned()]
                }
            ),
        ]
    );
    assert_eq!(
        report.resources[0].warnings,
        vec![
            EscrowClassificationWarning::IgnorePatternMatchedOnlyUnsupportedFiles {
                pattern: "html/*".to_owned()
            }
        ]
    );
    assert_eq!(
        report.resources[1]
            .files
            .iter()
            .map(|file| { (file.resource_relative_path.as_str(), &file.classification,) })
            .collect::<Vec<_>>(),
        vec![
            ("client.lua", &EscrowFileClassification::Protected),
            (
                "config.lua",
                &EscrowFileClassification::Ignored {
                    matching_patterns: vec!["config.lua".to_owned()]
                }
            ),
            ("fxmanifest.lua", &EscrowFileClassification::Protected),
        ]
    );
    assert!(report.resources[1].warnings.is_empty());
}
