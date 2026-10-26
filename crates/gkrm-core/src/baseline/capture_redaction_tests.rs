//! Task 12 capture public-error Display redaction and ZIP failure coverage.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::baseline::capture::test_seams::{
    hook_lock, list_capture_spools, set_before_partial_spool_create_hook,
};
use crate::baseline::capture::{
    capture_official_baseline_in_standalone_store, redact_capture_error_for_tests,
    reject_duplicate_selected_archive_indexes_for_tests, BaselineCaptureOptions,
    BaselineCaptureRequest, IncomingResourceSelector,
};
use crate::baseline::key::SafeResourceKey;
use crate::baseline::model::BaselineStoreLimits;
use crate::manifest::ManifestLimits;
use crate::package_limits::PackageLimits;
use crate::zip_package::{ZipEntryInfo, ZipEntryKind};
use crate::zip_path::ZipRelativePath;
use crate::{
    BaselineCaptureArchiveLimitKind, BaselineCaptureBlobSpoolStage, BaselineCaptureUnsafeEntryKind,
    GkrmError, Sha256Digest,
};
use sha2::{Digest, Sha256};
use zip::result::ZipError;

const SENTINEL_INDEX: usize = 424_242;
const SENTINEL_PARTIAL_NAME: &str = ".p-deadbeefcafebabe";

struct AuditPaths {
    package: PathBuf,
    store: PathBuf,
    installed: PathBuf,
    snapshot_marker: String,
}

impl AuditPaths {
    fn from_roots(installed: &Path, store: &Path, package: &Path) -> Self {
        Self {
            package: package.to_path_buf(),
            store: store.to_path_buf(),
            installed: installed.to_path_buf(),
            snapshot_marker: "snapshot".to_owned(),
        }
    }
}

fn assert_capture_display_safe(error: &GkrmError, paths: &AuditPaths) {
    let text = error.to_string();
    let lowered = text.to_ascii_lowercase();

    assert!(
        !text.contains(&format!("at index {SENTINEL_INDEX}")),
        "sentinel archive index leaked: {text}"
    );
    assert!(
        !lowered.contains("at index "),
        "archive-index wording leaked: {text}"
    );
    assert!(
        !text.contains(".partial-"),
        "legacy partial spool name leaked: {text}"
    );
    assert!(
        !text.contains(".p-"),
        "private partial spool name leaked: {text}"
    );
    assert!(
        !text.contains(SENTINEL_PARTIAL_NAME),
        "sentinel private spool name leaked: {text}"
    );
    assert!(
        !text.contains("entry id") && !text.contains("entry_id"),
        "internal entry id leaked: {text}"
    );

    for absolute in [
        paths.package.as_path(),
        paths.store.as_path(),
        paths.installed.as_path(),
    ] {
        let display = absolute.display().to_string();
        if !display.is_empty() {
            assert!(
                !text.contains(&display),
                "absolute path leaked ({display}): {text}"
            );
        }
        if let Ok(canonical) = absolute.canonicalize() {
            let canonical_display = canonical.display().to_string();
            assert!(
                !text.contains(&canonical_display),
                "canonical path leaked ({canonical_display}): {text}"
            );
        }
    }

    let _ = &paths.snapshot_marker;
}

fn zip_err() -> ZipError {
    ZipError::InvalidArchive(std::borrow::Cow::Borrowed("forced"))
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    let store = temp.path().join("store");
    let package = temp.path().join("pkg.zip");
    fs::create_dir_all(&installed).unwrap();
    fs::create_dir_all(&store).unwrap();
    fs::write(installed.join("customer.lua"), b"preserve-me").unwrap();
    (temp, installed, store, package)
}

fn assert_no_baseline(store: &Path) {
    let baselines = store.join("baselines");
    if baselines.exists() {
        let mut any = false;
        for key in fs::read_dir(&baselines).unwrap().flatten() {
            if key.path().is_dir() {
                for child in fs::read_dir(key.path()).unwrap().flatten() {
                    any = true;
                    let _ = child;
                }
            }
        }
        assert!(!any, "baseline was published under {baselines:?}");
    }
}

fn assert_spool_cleaned(store: &Path) {
    assert!(
        list_capture_spools(store).is_empty(),
        "capture spool left behind"
    );
}

fn assert_installed_unchanged(installed: &Path) {
    let bytes = fs::read(installed.join("customer.lua")).expect("customer file");
    assert_eq!(bytes, b"preserve-me");
}

fn capture_with_limits(
    installed: &Path,
    store: &Path,
    package: &Path,
    package_limits: PackageLimits,
) -> Result<crate::baseline::capture::BaselineCaptureResult, GkrmError> {
    let options = BaselineCaptureOptions::try_new(
        package_limits,
        ManifestLimits::default(),
        BaselineStoreLimits::default(),
        10_000,
        1024 * 1024,
        1024 * 1024 * 1024,
    )
    .unwrap();
    let request = BaselineCaptureRequest::try_new(
        installed,
        store,
        package,
        SafeResourceKey::parse("res").unwrap(),
        IncomingResourceSelector::AutoSingle,
        options,
    )?;
    let store = crate::resolve_standalone_baseline_store(store)?;
    capture_official_baseline_in_standalone_store(&store, request)
}

fn capture_default(
    installed: &Path,
    store: &Path,
    package: &Path,
) -> Result<crate::baseline::capture::BaselineCaptureResult, GkrmError> {
    capture_with_limits(installed, store, package, PackageLimits::default())
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("start");
        writer.write_all(bytes).expect("write");
    }
    writer.finish().expect("finish");
}

fn write_resource_plus(path: &Path, extra: &[(&str, &[u8])]) {
    let mut entries = vec![(
        "res/fxmanifest.lua",
        b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'config.lua'\n}\n" as &[u8],
    )];
    entries.extend_from_slice(extra);
    write_zip(path, &entries);
}

struct ManualZipEntry<'a> {
    name: &'a str,
    flags: u16,
    compression_method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    external_attributes: u32,
    contents: &'a [u8],
}

fn write_manual_single_entry_zip(path: &Path, entry: ManualZipEntry<'_>) {
    let mut file = File::create(path).expect("zip");
    let name = entry.name.as_bytes();

    write_u32(&mut file, 0x0403_4b50);
    write_u16(&mut file, 20);
    write_u16(&mut file, entry.flags);
    write_u16(&mut file, entry.compression_method);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u32(&mut file, 0);
    write_u32(&mut file, entry.compressed_size);
    write_u32(&mut file, entry.uncompressed_size);
    write_u16(&mut file, name.len() as u16);
    write_u16(&mut file, 0);
    file.write_all(name).unwrap();
    file.write_all(entry.contents).unwrap();

    let central_directory_offset = 30_u32
        .checked_add(name.len() as u32)
        .and_then(|offset| offset.checked_add(entry.contents.len() as u32))
        .unwrap();

    write_u32(&mut file, 0x0201_4b50);
    write_u16(&mut file, 0x0314);
    write_u16(&mut file, 20);
    write_u16(&mut file, entry.flags);
    write_u16(&mut file, entry.compression_method);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u32(&mut file, 0);
    write_u32(&mut file, entry.compressed_size);
    write_u32(&mut file, entry.uncompressed_size);
    write_u16(&mut file, name.len() as u16);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u32(&mut file, entry.external_attributes);
    write_u32(&mut file, 0);
    file.write_all(name).unwrap();

    let central_directory_size = 46_u32.checked_add(name.len() as u32).unwrap();
    write_u32(&mut file, 0x0605_4b50);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 1);
    write_u16(&mut file, 1);
    write_u32(&mut file, central_directory_size);
    write_u32(&mut file, central_directory_offset);
    write_u16(&mut file, 0);
}

fn write_u16(file: &mut File, value: u16) {
    file.write_all(&value.to_le_bytes()).unwrap();
}

fn write_u32(file: &mut File, value: u32) {
    file.write_all(&value.to_le_bytes()).unwrap();
}

fn assert_failure_cleanup(err: &GkrmError, paths: &AuditPaths, installed: &Path, store: &Path) {
    assert_capture_display_safe(err, paths);
    assert_no_baseline(store);
    assert_spool_cleaned(store);
    assert_installed_unchanged(installed);
}

#[test]
fn redact_maps_all_index_bearing_zip_errors() {
    let paths = AuditPaths {
        package: PathBuf::from("/tmp/sentinel-package.zip"),
        store: PathBuf::from("/tmp/sentinel-store"),
        installed: PathBuf::from("/tmp/sentinel-installed"),
        snapshot_marker: "snapshot".into(),
    };
    let package = paths.package.clone();
    let entry = "res/link.lua".to_owned();

    let cases = vec![
        GkrmError::ZipEntrySymlink {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
        },
        GkrmError::ZipEntryEncrypted {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
        },
        GkrmError::ZipEntryUnsupportedCompression {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
            method: "Unsupported(12)".into(),
        },
        GkrmError::ZipEntryParentTraversal {
            index: SENTINEL_INDEX,
            entry: "../evil.lua".into(),
        },
        GkrmError::ZipEntryUnixAbsolutePath {
            index: SENTINEL_INDEX,
            entry: "/abs/x.lua".into(),
        },
        GkrmError::ZipEntryWindowsDrivePath {
            index: SENTINEL_INDEX,
            entry: "C:/abs/x.lua".into(),
        },
        GkrmError::ZipEntryUncPath {
            index: SENTINEL_INDEX,
            entry: "//server/share".into(),
        },
        GkrmError::ZipEntryWindowsRootPath {
            index: SENTINEL_INDEX,
            entry: "/rooted.lua".into(),
        },
        GkrmError::ZipEntryControlCharacter {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
            codepoint: 1,
        },
        GkrmError::ZipEntryEmptyComponent {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
        },
        GkrmError::ZipEntryCurrentDirectory {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
        },
        GkrmError::ZipEntryWindowsInvalidCharacter {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
            character: '|',
        },
        GkrmError::ZipEntryWindowsTrailingDotOrSpace {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
            component: "x.".into(),
        },
        GkrmError::ZipEntryWindowsReservedName {
            index: SENTINEL_INDEX,
            entry: entry.clone(),
            component: "CON".into(),
        },
        GkrmError::ZipEntryNameInvalidUtf8 {
            index: SENTINEL_INDEX,
        },
        GkrmError::ZipEntryPathEmpty {
            index: SENTINEL_INDEX,
        },
        GkrmError::ZipDirectoryEntryNonZeroSize {
            index: SENTINEL_INDEX,
            entry: "dir/".into(),
            compressed_size: 1,
            uncompressed_size: 1,
        },
        GkrmError::ZipEntryDuplicatePath {
            entry: entry.clone(),
        },
        GkrmError::ZipEntryCaseInsensitiveCollision {
            first: "A.lua".into(),
            second: "a.lua".into(),
        },
        GkrmError::ZipEntryCountLimitExceeded {
            limit: 1,
            actual: 2,
        },
        GkrmError::ZipEntrySizeLimitExceeded {
            entry: entry.clone(),
            limit: 1,
            actual: 9,
        },
        GkrmError::ZipTotalSizeLimitExceeded {
            limit: 1,
            actual: 9,
        },
        GkrmError::ZipCompressionRatioLimitExceeded {
            entry: entry.clone(),
            limit: 1,
            compressed_size: 1,
            uncompressed_size: 100,
        },
        GkrmError::ZipEntryStreamSizeMismatch {
            entry: entry.clone(),
            expected: 1,
            actual: 2,
        },
        GkrmError::ZipEntryRead {
            path: package.clone(),
            index: SENTINEL_INDEX,
            cause: zip_err(),
        },
        GkrmError::ZipArchiveRead {
            path: package.clone(),
            cause: zip_err(),
        },
        GkrmError::ZipEntryStream {
            entry: entry.clone(),
            cause: std::io::Error::other("stream"),
        },
        GkrmError::ManifestZipEntryRead {
            entry: entry.clone(),
            cause: zip_err(),
        },
        GkrmError::ComparisonZipEntryRead {
            entry: entry.clone(),
            cause: zip_err(),
        },
        GkrmError::ComparisonZipArchiveRead {
            path: package,
            cause: zip_err(),
        },
        GkrmError::ComparisonZipEntryStream {
            entry: entry.clone(),
            cause: std::io::Error::other("forced"),
        },
        GkrmError::ComparisonDuplicateIncomingArchiveIndex {
            index: SENTINEL_INDEX,
        },
        GkrmError::ComparisonZipEntryChanged {
            entry: entry.clone(),
            reason: format!("archive index {SENTINEL_INDEX}"),
        },
        GkrmError::ManifestZipEntryChanged {
            entry: entry.clone(),
            reason: format!("at index {SENTINEL_INDEX}"),
        },
        GkrmError::EscrowDiscoveryEntryMismatch {
            entry,
            reason: format!("archive index {SENTINEL_INDEX}"),
        },
    ];

    for original in cases {
        let original_text = original.to_string();
        assert!(
            original_text.contains(&SENTINEL_INDEX.to_string())
                || original_text.contains("index")
                || matches!(
                    original,
                    GkrmError::ZipEntryDuplicatePath { .. }
                        | GkrmError::ZipEntryCaseInsensitiveCollision { .. }
                        | GkrmError::ZipEntryCountLimitExceeded { .. }
                        | GkrmError::ZipEntrySizeLimitExceeded { .. }
                        | GkrmError::ZipTotalSizeLimitExceeded { .. }
                        | GkrmError::ZipCompressionRatioLimitExceeded { .. }
                        | GkrmError::ZipEntryStreamSizeMismatch { .. }
                        | GkrmError::ZipEntryStream { .. }
                        | GkrmError::ZipArchiveRead { .. }
                        | GkrmError::ManifestZipEntryRead { .. }
                        | GkrmError::ComparisonZipEntryRead { .. }
                        | GkrmError::ComparisonZipArchiveRead { .. }
                        | GkrmError::ComparisonZipEntryStream { .. }
                        | GkrmError::ComparisonZipEntryChanged { .. }
                        | GkrmError::ManifestZipEntryChanged { .. }
                        | GkrmError::EscrowDiscoveryEntryMismatch { .. }
                ),
            "fixture should exercise redaction: {original_text}"
        );
        let redacted = redact_capture_error_for_tests(original);
        assert_capture_display_safe(&redacted, &paths);
        assert!(
            !matches!(
                redacted,
                GkrmError::ZipEntrySymlink { .. }
                    | GkrmError::ZipEntryRead { .. }
                    | GkrmError::ZipArchiveRead { .. }
                    | GkrmError::ComparisonDuplicateIncomingArchiveIndex { .. }
            ),
            "index-bearing ZIP error must not remain public: {redacted}"
        );
    }
}

#[test]
fn symlink_zip_entry_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_manual_single_entry_zip(
        &package,
        ManualZipEntry {
            name: "res/link.lua",
            flags: 0,
            compression_method: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            external_attributes: (0o120777_u32) << 16,
            contents: b"",
        },
    );
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("symlink");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: BaselineCaptureUnsafeEntryKind::Symlink,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn parent_traversal_zip_entry_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_zip(&package, &[("../evil.lua", b"evil")]);
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("traversal");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: BaselineCaptureUnsafeEntryKind::ParentTraversal,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn absolute_zip_entry_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_zip(&package, &[("/abs/evil.lua", b"evil")]);
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("absolute");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: BaselineCaptureUnsafeEntryKind::AbsoluteOrDrivePath,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn directory_nonzero_size_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_manual_single_entry_zip(
        &package,
        ManualZipEntry {
            name: "res/",
            flags: 0,
            compression_method: 0,
            compressed_size: 1,
            uncompressed_size: 1,
            external_attributes: 0,
            contents: b"x",
        },
    );
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("dir size");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: BaselineCaptureUnsafeEntryKind::DirectoryNonZeroSize,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn duplicate_canonical_path_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"one"),
            ("res\\a.lua", b"two"),
        ],
    );
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("duplicate");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: BaselineCaptureUnsafeEntryKind::DuplicatePath,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn unsupported_zip_entry_type_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_manual_single_entry_zip(
        &package,
        ManualZipEntry {
            name: "res/unsupported.lua",
            flags: 0,
            compression_method: 12,
            compressed_size: 0,
            uncompressed_size: 0,
            external_attributes: 0,
            contents: b"",
        },
    );
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("unsupported");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: BaselineCaptureUnsafeEntryKind::UnsupportedCompression,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn archive_entry_count_limit_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_resource_plus(
        &package,
        &[("res/config.lua", b"cfg"), ("res/client.lua", b"c")],
    );
    let limits = PackageLimits {
        max_entries: 1,
        ..PackageLimits::default()
    };
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_with_limits(&installed, &store, &package, limits).expect_err("count");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureArchiveLimitExceeded {
            kind: BaselineCaptureArchiveLimitKind::EntryCount,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn per_entry_size_limit_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_resource_plus(&package, &[("res/config.lua", b"too-large")]);
    let limits = PackageLimits {
        max_entry_uncompressed_size: 4,
        ..PackageLimits::default()
    };
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_with_limits(&installed, &store, &package, limits).expect_err("entry size");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureArchiveEntryLimitExceeded {
            kind: BaselineCaptureArchiveLimitKind::EntryUncompressedSize,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn total_uncompressed_size_limit_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_resource_plus(
        &package,
        &[("res/config.lua", b"aaaa"), ("res/client.lua", b"bbbb")],
    );
    let limits = PackageLimits {
        max_total_uncompressed_size: 40,
        ..PackageLimits::default()
    };
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_with_limits(&installed, &store, &package, limits).expect_err("total");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureArchiveLimitExceeded {
            kind: BaselineCaptureArchiveLimitKind::TotalUncompressedSize,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn compression_ratio_limit_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    let file = File::create(&package).unwrap();
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    writer.start_file("res/fxmanifest.lua", options).unwrap();
    writer
        .write_all(b"fx_version 'cerulean'\ngame 'gta5'\n")
        .unwrap();
    writer.start_file("res/config.lua", options).unwrap();
    writer.write_all(&vec![b'a'; 2048]).unwrap();
    writer.finish().unwrap();
    let limits = PackageLimits {
        max_compression_ratio: 1,
        ..PackageLimits::default()
    };
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_with_limits(&installed, &store, &package, limits).expect_err("ratio");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureArchiveEntryLimitExceeded {
            kind: BaselineCaptureArchiveLimitKind::CompressionRatio,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn malformed_archive_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    fs::write(&package, b"not-a-zip").unwrap();
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("malformed");
    assert!(matches!(err, GkrmError::BaselineCaptureArchiveInvalid));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn decompression_failure_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    // Deflated local entry with garbage payload that still advertises safe ratio.
    write_manual_single_entry_zip(
        &package,
        ManualZipEntry {
            name: "res/fxmanifest.lua",
            flags: 0,
            compression_method: 8,
            compressed_size: 8,
            uncompressed_size: 32,
            external_attributes: 0,
            contents: b"notdefl!",
        },
    );
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("decompress");
    assert!(
        matches!(
            err,
            GkrmError::BaselineCaptureEntryReadFailure { .. }
                | GkrmError::BaselineCaptureArchiveEntryRead
                | GkrmError::BaselineCaptureArchiveEntryStream { .. }
                | GkrmError::BaselineCaptureArchiveEntrySizeMismatch { .. }
                | GkrmError::BaselineCaptureEntrySizeMismatch { .. }
        ),
        "unexpected category: {err}"
    );
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

#[test]
fn duplicate_selected_archive_association_is_index_free() {
    let paths = AuditPaths {
        package: PathBuf::from("C:\\sentinel\\pkg.zip"),
        store: PathBuf::from("C:\\sentinel\\store"),
        installed: PathBuf::from("C:\\sentinel\\installed"),
        snapshot_marker: "snapshot".into(),
    };
    let entry = |path: &str, index: usize| ZipEntryInfo {
        archive_index: index,
        path: ZipRelativePath::parse_canonical(path).unwrap(),
        compressed_size: 1,
        uncompressed_size: 1,
        crc32: 0,
        compression_method: CompressionMethod::Stored,
        encrypted: false,
        unix_mode: None,
        kind: ZipEntryKind::File,
    };
    let err = reject_duplicate_selected_archive_indexes_for_tests(&[
        entry("res/a.lua", SENTINEL_INDEX),
        entry("res/b.lua", SENTINEL_INDEX),
    ])
    .expect_err("duplicate association");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureDuplicateArchiveEntry
    ));
    assert_capture_display_safe(&err, &paths);
}

#[test]
fn spool_creation_failure_is_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_resource_plus(&package, &[("res/config.lua", b"cfg-body")]);
    set_before_partial_spool_create_hook(|| {
        Err(GkrmError::BaselineCaptureBlobSpoolFailure {
            stage: BaselineCaptureBlobSpoolStage::Create,
            kind: std::io::ErrorKind::PermissionDenied,
        })
    });
    let paths = AuditPaths::from_roots(&installed, &store, &package);
    let err = capture_default(&installed, &store, &package).expect_err("spool create");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureBlobSpoolFailure {
            stage: BaselineCaptureBlobSpoolStage::Create,
            ..
        }
    ));
    assert_failure_cleanup(&err, &paths, &installed, &store);
}

fn assert_source_chain_present(error: &GkrmError) {
    // Compound capture failures expose nested GkrmError via source(); raw io/zip causes do not.
    match error {
        GkrmError::BaselineCaptureSpoolCleanupFailed { .. }
        | GkrmError::BaselineCaptureFailedWithCleanupFailure { .. }
        | GkrmError::BaselineCaptureBundleConstruction { .. } => {
            assert!(
                std::error::Error::source(error).is_some(),
                "expected nested GkrmError source for {error}"
            );
        }
        _ => {
            assert!(
                std::error::Error::source(error).is_none(),
                "raw dependency cause must not appear via Error::source(): {error}"
            );
        }
    }
}

#[test]
fn private_spool_store_errors_are_redacted() {
    let paths = AuditPaths {
        package: PathBuf::from("C:\\sentinel\\pkg.zip"),
        store: PathBuf::from("C:\\sentinel\\store"),
        installed: PathBuf::from("C:\\sentinel\\installed"),
        snapshot_marker: "snapshot".into(),
    };
    let cases = vec![
        GkrmError::BaselineStoreUnexpectedType {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreHardLink {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreSymlink {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreReparsePoint {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreUnsafeComponent {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreMissing {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreIo {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
            cause: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "create denied"),
        },
        GkrmError::BaselineStoreIo {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
            cause: std::io::Error::other("rename failed"),
        },
        GkrmError::BaselineStoreIo {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
            cause: std::io::Error::other("cleanup failed"),
        },
        GkrmError::BaselineStoreUnexpectedType {
            component: ".partial-9".to_owned(),
        },
        GkrmError::BaselineStoreIo {
            component: "capture-deadbeefcafebabe".to_owned(),
            cause: std::io::Error::other("allocate failed"),
        },
    ];

    for original in cases {
        let leaks_private_name = match &original {
            GkrmError::BaselineStoreUnexpectedType { component }
            | GkrmError::BaselineStoreHardLink { component }
            | GkrmError::BaselineStoreSymlink { component }
            | GkrmError::BaselineStoreReparsePoint { component }
            | GkrmError::BaselineStoreUnsafeComponent { component }
            | GkrmError::BaselineStoreMissing { component }
            | GkrmError::BaselineStoreIo { component, .. } => {
                component.contains(".p-")
                    || component.contains(".partial-")
                    || component.contains("capture-")
            }
            _ => false,
        };
        assert!(
            leaks_private_name,
            "fixture should carry private spool component before redaction: {original:?}"
        );
        let redacted = redact_capture_error_for_tests(original);
        assert!(
            matches!(
                redacted,
                GkrmError::BaselineCaptureBlobSpoolFailure {
                    stage: BaselineCaptureBlobSpoolStage::Create,
                    ..
                }
            ),
            "unexpected category: {redacted}"
        );
        assert_capture_display_safe(&redacted, &paths);
        assert_source_chain_present(&redacted);
    }
}

#[test]
fn private_spool_store_errors_via_create_hook_are_redacted() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_resource_plus(&package, &[("res/config.lua", b"cfg-body")]);
    let paths = AuditPaths::from_roots(&installed, &store, &package);

    let injected = [
        GkrmError::BaselineStoreUnexpectedType {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreHardLink {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreSymlink {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreUnsafeComponent {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
        },
        GkrmError::BaselineStoreIo {
            component: SENTINEL_PARTIAL_NAME.to_owned(),
            cause: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "open failed"),
        },
    ];

    for error in injected {
        set_before_partial_spool_create_hook(move || Err(error));
        let err = capture_default(&installed, &store, &package).expect_err("spool store");
        assert!(matches!(
            err,
            GkrmError::BaselineCaptureBlobSpoolFailure { .. }
        ));
        assert_failure_cleanup(&err, &paths, &installed, &store);
        assert_source_chain_present(&err);
    }
}

#[test]
fn successful_capture_does_not_leave_partial_spool_names() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_resource_plus(&package, &[("res/config.lua", b"cfg-body")]);
    let result = capture_default(&installed, &store, &package).expect("capture");
    assert_spool_cleaned(&store);
    let digest = Sha256Digest::new(Sha256::digest(b"cfg-body").into());
    assert_eq!(result.counts().blobs(), 1);
    let _ = digest;
}

const SENTINEL_WIN_PATH: &str = r"C:\Users\sentinel\leak\pkg.zip";
const SENTINEL_UNIX_PATH: &str = "/tmp/sentinel/leak/pkg.zip";
const SENTINEL_ENTRY: &str = "SENTINEL_ENTRY_res/config.lua";
const SENTINEL_LABELS: &str = "SENTINEL_LABELS_res-a,res-b";
const SENTINEL_VALUE: &str = "SENTINEL_UNSAFE_IDENTITY_../x";
const SENTINEL_BASELINE_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SENTINEL_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SENTINEL_PARSER: &str = "SENTINEL_PARSER unexpected token near 'fx_version'";
const SENTINEL_GLOB: &str = "SENTINEL_GLOB_**/*.lua";
const SENTINEL_REASON: &str = "SENTINEL_REASON_full archive digest changed";
const SENTINEL_DEP: &str = "SENTINEL_DEP_Permission denied (os error 13)";
const SENTINEL_JOURNAL: &str = "SENTINEL_JOURNAL_.gkrm-txn-deadbeef.json";
const SENTINEL_TXN: &str = "SENTINEL_TXN_plan-id-cafebabe01234567";

fn public_error_surfaces(error: &GkrmError) -> String {
    let mut out = format!("{error} | {error:?} | {error:#?}");
    let mut cur: Option<&dyn std::error::Error> = Some(error);
    while let Some(err) = cur {
        out.push_str(" | ");
        out.push_str(&err.to_string());
        out.push_str(" | ");
        out.push_str(&format!("{err:?}"));
        cur = err.source();
    }
    out
}

fn assert_public_surface_clean(error: &GkrmError) {
    let text = public_error_surfaces(error);
    for needle in [
        SENTINEL_WIN_PATH,
        SENTINEL_UNIX_PATH,
        SENTINEL_ENTRY,
        SENTINEL_LABELS,
        SENTINEL_VALUE,
        SENTINEL_BASELINE_ID,
        SENTINEL_DIGEST,
        SENTINEL_PARSER,
        SENTINEL_GLOB,
        SENTINEL_REASON,
        SENTINEL_DEP,
        SENTINEL_JOURNAL,
        SENTINEL_TXN,
        r"C:\Users\sentinel",
        "/tmp/sentinel",
        "config.lua",
        "res-a,res-b",
        "fx_version",
        "Permission denied",
        ".gkrm-txn-",
        "plan-id-",
        "aaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbb",
    ] {
        assert!(
            !text.contains(needle),
            "sentinel leaked through public formatting/source chain ({needle}): {text}"
        );
    }
    // No long hex internal IDs in public surfaces.
    let hex_runs = regex_long_hex(&text);
    assert!(
        hex_runs.is_empty(),
        "long hexadecimal identity leaked: {hex_runs:?} in {text}"
    );
}

fn regex_long_hex(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start >= 32 {
                out.push(text[start..i].to_owned());
            }
        } else {
            i += 1;
        }
    }
    out
}

fn assert_raw_source_unreachable(error: &GkrmError) {
    let mut cur: Option<&dyn std::error::Error> = Some(error);
    while let Some(err) = cur {
        let text = format!("{err} | {err:?}");
        assert!(
            !text.contains(SENTINEL_DEP)
                && !text.contains("Permission denied")
                && !text.contains(SENTINEL_WIN_PATH)
                && !text.contains(SENTINEL_UNIX_PATH),
            "raw dependency/path text reachable via source chain: {text}"
        );
        cur = err.source();
    }
}

#[test]
fn public_gkrm_error_surfaces_and_source_policy_are_redacted() {
    let cases = vec![
        GkrmError::ManifestLuaSyntax {
            entry: SENTINEL_ENTRY.to_owned(),
            errors: SENTINEL_PARSER.to_owned(),
        },
        GkrmError::ManifestInvalidStringEscape {
            entry: SENTINEL_ENTRY.to_owned(),
            message: SENTINEL_PARSER.to_owned(),
        },
        GkrmError::BaselineExistingConflict {
            resource_key: SENTINEL_LABELS.to_owned(),
            baseline_id: SENTINEL_BASELINE_ID.to_owned(),
        },
        GkrmError::BaselineSelectedBaselineNotFound {
            baseline_id: SENTINEL_BASELINE_ID.to_owned(),
        },
        GkrmError::EscrowGlobUnsafe {
            pattern: SENTINEL_GLOB.to_owned(),
            reason: SENTINEL_REASON.to_owned(),
        },
        GkrmError::ManifestZipEntryChanged {
            entry: SENTINEL_ENTRY.to_owned(),
            reason: SENTINEL_REASON.to_owned(),
        },
        GkrmError::ComparisonPackageChanged {
            path: PathBuf::from(SENTINEL_WIN_PATH),
            reason: SENTINEL_REASON.to_owned(),
        },
        GkrmError::BaselineCaptureAmbiguousResources,
        GkrmError::BaselineCaptureUnsafeResourceIdentity,
        GkrmError::BaselineCaptureEntryReadFailure {
            kind: std::io::ErrorKind::PermissionDenied,
        },
        GkrmError::BaselineCaptureBlobSpoolFailure {
            stage: BaselineCaptureBlobSpoolStage::Create,
            kind: std::io::ErrorKind::PermissionDenied,
        },
        GkrmError::BaselineStoreIo {
            component: SENTINEL_JOURNAL.to_owned(),
            cause: std::io::Error::other(SENTINEL_DEP),
        },
        GkrmError::ZipPackageOpen {
            path: PathBuf::from(SENTINEL_WIN_PATH),
            cause: std::io::Error::other(SENTINEL_DEP),
        },
        GkrmError::EscrowGlobMalformed {
            pattern: SENTINEL_GLOB.to_owned(),
            cause: globset::Glob::new("[").expect_err("invalid glob for sentinel"),
        },
        GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: BaselineCaptureUnsafeEntryKind::ParentTraversal,
        },
        GkrmError::BaselineCaptureIgnoredBlobDigestMismatch,
    ];

    for original in cases {
        assert_public_surface_clean(&original);
        assert_raw_source_unreachable(&original);
        assert!(
            std::error::Error::source(&original).is_none()
                || matches!(
                    original,
                    GkrmError::BaselineCaptureSpoolCleanupFailed { .. }
                        | GkrmError::BaselineCaptureFailedWithCleanupFailure { .. }
                        | GkrmError::BaselineCaptureBundleConstruction { .. }
                ),
            "unexpected public source on {original}"
        );
    }
}

#[test]
fn redact_capture_error_clears_identity_fields_and_is_idempotent() {
    let zip_mapped = redact_capture_error_for_tests(GkrmError::ZipEntryStream {
        entry: SENTINEL_ENTRY.to_owned(),
        cause: std::io::Error::other(SENTINEL_DEP),
    });
    match &zip_mapped {
        GkrmError::BaselineCaptureArchiveEntryStream { kind } => {
            assert_eq!(*kind, std::io::ErrorKind::Other);
        }
        other => panic!("unexpected mapping: {other}"),
    }
    assert_public_surface_clean(&zip_mapped);
    assert_raw_source_unreachable(&zip_mapped);
    assert!(std::error::Error::source(&zip_mapped).is_none());

    let again = redact_capture_error_for_tests(GkrmError::BaselineCaptureArchiveEntryStream {
        kind: std::io::ErrorKind::Other,
    });
    assert_eq!(format!("{zip_mapped}"), format!("{again}"));
    match again {
        GkrmError::BaselineCaptureArchiveEntryStream { kind } => {
            assert_eq!(kind, std::io::ErrorKind::Other);
        }
        other => panic!("unexpected: {other}"),
    }

    let ambiguous = redact_capture_error_for_tests(GkrmError::BaselineCaptureAmbiguousResources);
    assert!(matches!(
        ambiguous,
        GkrmError::BaselineCaptureAmbiguousResources
    ));

    let unsafe_id =
        redact_capture_error_for_tests(GkrmError::BaselineCaptureUnsafeResourceIdentity);
    assert!(matches!(
        unsafe_id,
        GkrmError::BaselineCaptureUnsafeResourceIdentity
    ));

    let digest =
        redact_capture_error_for_tests(GkrmError::BaselineCaptureIgnoredBlobDigestMismatch);
    assert!(matches!(
        digest,
        GkrmError::BaselineCaptureIgnoredBlobDigestMismatch
    ));

    let primary = GkrmError::ZipEntryParentTraversal {
        index: 7,
        entry: SENTINEL_ENTRY.to_owned(),
    };
    let cleanup = GkrmError::BaselineCaptureEntryReadFailure {
        kind: std::io::ErrorKind::PermissionDenied,
    };
    let compound =
        redact_capture_error_for_tests(GkrmError::BaselineCaptureFailedWithCleanupFailure {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        });
    assert_public_surface_clean(&compound);
    assert_raw_source_unreachable(&compound);
    match &compound {
        GkrmError::BaselineCaptureFailedWithCleanupFailure { primary, cleanup } => {
            match primary.as_ref() {
                GkrmError::BaselineCaptureUnsafeZipEntry { kind } => {
                    assert_eq!(*kind, BaselineCaptureUnsafeEntryKind::ParentTraversal);
                }
                other => panic!("primary not cleared: {other}"),
            }
            match cleanup.as_ref() {
                GkrmError::BaselineCaptureEntryReadFailure { kind } => {
                    assert_eq!(*kind, std::io::ErrorKind::PermissionDenied);
                }
                other => panic!("cleanup not cleared: {other}"),
            }
        }
        other => panic!("unexpected compound: {other}"),
    }

    // Field-level proof: raw dependency causes are discarded, not merely hidden.
    let io_mapped = redact_capture_error_for_tests(GkrmError::ZipPackageOpen {
        path: PathBuf::from(SENTINEL_WIN_PATH),
        cause: std::io::Error::new(std::io::ErrorKind::PermissionDenied, SENTINEL_DEP),
    });
    match io_mapped {
        GkrmError::BaselineCapturePackageOpen { kind } => {
            assert_eq!(kind, std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("unexpected package open mapping: {other}"),
    }

    let zip_invalid = redact_capture_error_for_tests(GkrmError::ZipArchiveRead {
        path: PathBuf::from(SENTINEL_WIN_PATH),
        cause: ZipError::InvalidArchive(std::borrow::Cow::Borrowed(SENTINEL_DEP)),
    });
    assert!(matches!(
        zip_invalid,
        GkrmError::BaselineCaptureArchiveInvalid
    ));

    let manifest = redact_capture_error_for_tests(GkrmError::ManifestLuaSyntax {
        entry: SENTINEL_ENTRY.to_owned(),
        errors: SENTINEL_PARSER.to_owned(),
    });
    assert!(matches!(
        manifest,
        GkrmError::BaselineCaptureManifestInvalid
    ));

    let escape = redact_capture_error_for_tests(GkrmError::ManifestInvalidStringEscape {
        entry: SENTINEL_ENTRY.to_owned(),
        message: SENTINEL_PARSER.to_owned(),
    });
    assert!(matches!(escape, GkrmError::BaselineCaptureManifestInvalid));

    let glob = redact_capture_error_for_tests(GkrmError::EscrowGlobUnsafe {
        pattern: SENTINEL_GLOB.to_owned(),
        reason: SENTINEL_REASON.to_owned(),
    });
    assert!(matches!(glob, GkrmError::BaselineCaptureEscrowGlobInvalid));

    let conflict = redact_capture_error_for_tests(GkrmError::BaselineExistingConflict {
        resource_key: SENTINEL_LABELS.to_owned(),
        baseline_id: SENTINEL_BASELINE_ID.to_owned(),
    });
    assert!(matches!(
        conflict,
        GkrmError::BaselineCaptureBaselineConflict
    ));

    let missing = redact_capture_error_for_tests(GkrmError::BaselineSelectedBaselineNotFound {
        baseline_id: SENTINEL_BASELINE_ID.to_owned(),
    });
    assert!(matches!(
        missing,
        GkrmError::BaselineCaptureBaselineConflict
    ));

    let blob = redact_capture_error_for_tests(GkrmError::BaselineBlobDigestMismatch {
        digest: SENTINEL_DIGEST.to_owned(),
    });
    assert!(matches!(
        blob,
        GkrmError::BaselineCaptureBlobVerificationFailed
    ));

    let changed = redact_capture_error_for_tests(GkrmError::ComparisonPackageChanged {
        path: PathBuf::from(SENTINEL_WIN_PATH),
        reason: SENTINEL_REASON.to_owned(),
    });
    assert!(matches!(changed, GkrmError::BaselineCapturePackageChanged));
}

#[test]
fn redact_capture_error_sanitizes_previously_bypassed_escrow_and_bundle_variants() {
    fn assert_redacted(original: GkrmError, expected: GkrmError) {
        let redacted = redact_capture_error_for_tests(original);
        assert_eq!(format!("{redacted}"), format!("{expected}"));
        match (&redacted, &expected) {
            (
                GkrmError::BaselineCaptureEscrowManifestInvalid,
                GkrmError::BaselineCaptureEscrowManifestInvalid,
            )
            | (
                GkrmError::BaselineCaptureEscrowResourcePathInvalid,
                GkrmError::BaselineCaptureEscrowResourcePathInvalid,
            )
            | (
                GkrmError::BaselineCaptureBundlePathInvalid,
                GkrmError::BaselineCaptureBundlePathInvalid,
            )
            | (
                GkrmError::BaselineCaptureBundleOrderingInvalid,
                GkrmError::BaselineCaptureBundleOrderingInvalid,
            )
            | (
                GkrmError::BaselineCaptureBundleBlobInvalid,
                GkrmError::BaselineCaptureBundleBlobInvalid,
            )
            | (
                GkrmError::BaselineCaptureBundleIdentityMismatch,
                GkrmError::BaselineCaptureBundleIdentityMismatch,
            ) => {}
            (
                GkrmError::BaselineCapturePublicationFailed { kind: left },
                GkrmError::BaselineCapturePublicationFailed { kind: right },
            ) => assert_eq!(left, right),
            (got, want) => panic!("unexpected redacted shape: got={got} want={want}"),
        }
        assert_public_surface_clean(&redacted);
        assert_raw_source_unreachable(&redacted);
        assert!(std::error::Error::source(&redacted).is_none());
        let second = redact_capture_error_for_tests(match &redacted {
            GkrmError::BaselineCaptureEscrowManifestInvalid => {
                GkrmError::BaselineCaptureEscrowManifestInvalid
            }
            GkrmError::BaselineCaptureEscrowResourcePathInvalid => {
                GkrmError::BaselineCaptureEscrowResourcePathInvalid
            }
            GkrmError::BaselineCaptureBundlePathInvalid => {
                GkrmError::BaselineCaptureBundlePathInvalid
            }
            GkrmError::BaselineCaptureBundleOrderingInvalid => {
                GkrmError::BaselineCaptureBundleOrderingInvalid
            }
            GkrmError::BaselineCaptureBundleBlobInvalid => {
                GkrmError::BaselineCaptureBundleBlobInvalid
            }
            GkrmError::BaselineCaptureBundleIdentityMismatch => {
                GkrmError::BaselineCaptureBundleIdentityMismatch
            }
            GkrmError::BaselineCapturePublicationFailed { kind } => {
                GkrmError::BaselineCapturePublicationFailed { kind: *kind }
            }
            other => panic!("unexpected: {other}"),
        });
        assert_eq!(format!("{redacted}"), format!("{second}"));
    }

    assert_redacted(
        GkrmError::EscrowManifestMissing {
            root: SENTINEL_ENTRY.to_owned(),
        },
        GkrmError::BaselineCaptureEscrowManifestInvalid,
    );
    assert_redacted(
        GkrmError::EscrowManifestDuplicate {
            root: SENTINEL_ENTRY.to_owned(),
        },
        GkrmError::BaselineCaptureEscrowManifestInvalid,
    );
    assert_redacted(
        GkrmError::EscrowManifestRootMismatch {
            root: SENTINEL_ENTRY.to_owned(),
        },
        GkrmError::BaselineCaptureEscrowManifestInvalid,
    );
    assert_redacted(
        GkrmError::EscrowManifestPathMismatch {
            root: SENTINEL_ENTRY.to_owned(),
            expected: SENTINEL_UNIX_PATH.to_owned(),
            actual: SENTINEL_WIN_PATH.to_owned(),
        },
        GkrmError::BaselineCaptureEscrowManifestInvalid,
    );
    assert_redacted(
        GkrmError::EscrowResourceRelativePath {
            root: SENTINEL_ENTRY.to_owned(),
            entry: SENTINEL_UNIX_PATH.to_owned(),
        },
        GkrmError::BaselineCaptureEscrowResourcePathInvalid,
    );
    assert_redacted(
        GkrmError::BaselineUnsafeRelativePath {
            path: SENTINEL_UNIX_PATH.to_owned(),
        },
        GkrmError::BaselineCaptureBundlePathInvalid,
    );
    assert_redacted(
        GkrmError::BaselineDuplicateFilePath {
            path: SENTINEL_WIN_PATH.to_owned(),
        },
        GkrmError::BaselineCaptureBundlePathInvalid,
    );
    assert_redacted(
        GkrmError::BaselineInvalidOrdering {
            path: SENTINEL_ENTRY.to_owned(),
        },
        GkrmError::BaselineCaptureBundleOrderingInvalid,
    );
    assert_redacted(
        GkrmError::BaselineUnexpectedBlob {
            name: SENTINEL_DIGEST.to_owned(),
        },
        GkrmError::BaselineCaptureBundleBlobInvalid,
    );
    assert_redacted(
        GkrmError::BaselineBlobLimitExceeded {
            digest: SENTINEL_DIGEST.to_owned(),
            limit: 1,
            actual: 9,
        },
        GkrmError::BaselineCaptureBundleBlobInvalid,
    );
    assert_redacted(
        GkrmError::BaselineResourceKeyMismatch {
            requested: SENTINEL_LABELS.to_owned(),
            stored: SENTINEL_VALUE.to_owned(),
        },
        GkrmError::BaselineCaptureBundleIdentityMismatch,
    );
    assert_redacted(
        GkrmError::BaselineRequestedIdMismatch {
            requested: SENTINEL_BASELINE_ID.to_owned(),
            stored: SENTINEL_DIGEST.to_owned(),
        },
        GkrmError::BaselineCaptureBundleIdentityMismatch,
    );
    assert_redacted(
        GkrmError::BaselineIdMismatch {
            stored: SENTINEL_BASELINE_ID.to_owned(),
            computed: SENTINEL_DIGEST.to_owned(),
        },
        GkrmError::BaselineCaptureBundleIdentityMismatch,
    );
    assert_redacted(
        GkrmError::BaselineAtomicPublishFailure {
            cause: std::io::Error::new(std::io::ErrorKind::PermissionDenied, SENTINEL_DEP),
        },
        GkrmError::BaselineCapturePublicationFailed {
            kind: std::io::ErrorKind::PermissionDenied,
        },
    );
}

#[test]
fn redact_capture_error_recursively_sanitizes_bundle_construction() {
    let nested = GkrmError::BaselineUnsafeRelativePath {
        path: SENTINEL_UNIX_PATH.to_owned(),
    };
    let wrapped = GkrmError::BaselineCaptureBundleConstruction {
        source: Box::new(nested),
    };
    let redacted = redact_capture_error_for_tests(wrapped);
    match redacted {
        GkrmError::BaselineCaptureBundleConstruction { source } => {
            assert!(matches!(
                source.as_ref(),
                GkrmError::BaselineCaptureBundlePathInvalid
            ));
            assert_public_surface_clean(source.as_ref());
            assert!(std::error::Error::source(source.as_ref()).is_none());
        }
        other => panic!("unexpected: {other}"),
    }
}

#[test]
fn redact_capture_error_has_no_wildcard_fallback_in_source() {
    let source = include_str!("capture.rs");
    let start = source
        .find("fn redact_capture_error(error: GkrmError)")
        .expect("redact_capture_error");
    let end = source[start..]
        .find("\nfn note_production_blob_map_shape")
        .expect("end of redact")
        + start;
    let body = &source[start..end];
    assert!(
        !body.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("other =>") || trimmed.starts_with("_ =>")
        }),
        "redact_capture_error must not contain a wildcard fallback"
    );
    assert!(
        body.contains("intentionally uses an exhaustive match"),
        "maintenance comment missing"
    );
}

#[test]
fn production_classify_selected_path_redacts_escrow_failures() {
    use crate::escrow_classification::classify_selected_zip_resource_escrow;
    use crate::manifest::{FxManifest, ParsedZipResourceManifest};
    use crate::zip_package::{ZipEntryInfo, ZipEntryKind, ZipInspection};
    use crate::zip_path::ZipRelativePath;
    use crate::{DiscoveredZipResource, ZipResourceName, ZipResourceRoot};

    fn zip_path(value: &str) -> ZipRelativePath {
        ZipRelativePath::parse_canonical(value).expect("path")
    }

    fn file_entry(path: &str, index: usize) -> ZipEntryInfo {
        ZipEntryInfo {
            archive_index: index,
            path: zip_path(path),
            kind: ZipEntryKind::File,
            compressed_size: 1,
            uncompressed_size: 1,
            crc32: 0,
            compression_method: zip::CompressionMethod::Stored,
            encrypted: false,
            unix_mode: None,
        }
    }

    fn resource(root: &str, entries: Vec<ZipEntryInfo>) -> DiscoveredZipResource {
        let root_path = zip_path(root);
        DiscoveredZipResource {
            name: ZipResourceName::Directory(root.to_owned()),
            root: ZipResourceRoot::Path(root_path.clone()),
            manifest_path: zip_path(&format!("{root}/fxmanifest.lua")),
            entries,
        }
    }

    fn parsed(root: &str, manifest_path: &str) -> ParsedZipResourceManifest {
        ParsedZipResourceManifest {
            resource_root: ZipResourceRoot::Path(zip_path(root)),
            manifest_path: zip_path(manifest_path),
            manifest: FxManifest::default(),
            warnings: Vec::new(),
        }
    }

    let root = SENTINEL_ENTRY;
    let manifest_ok = format!("{root}/fxmanifest.lua");
    let sibling = format!("{root}-extra/client.lua");

    // Path mismatch through the same classify_selected + redact composition capture uses.
    {
        let entries = vec![file_entry(&manifest_ok, 0)];
        let inspection = ZipInspection {
            path: PathBuf::from("package.zip"),
            entries: entries.clone(),
        };
        let selected = resource(root, entries);
        let bad = parsed(root, &format!("{root}/other.lua"));
        let redacted = classify_selected_zip_resource_escrow(&inspection, &selected, &bad)
            .map_err(redact_capture_error_for_tests)
            .expect_err("path mismatch");
        assert!(matches!(
            redacted,
            GkrmError::BaselineCaptureEscrowManifestInvalid
        ));
        assert_public_surface_clean(&redacted);
        assert!(std::error::Error::source(&redacted).is_none());
    }

    // Root mismatch surfaces as path mismatch on classify_selected.
    {
        let entries = vec![file_entry(&manifest_ok, 0)];
        let inspection = ZipInspection {
            path: PathBuf::from("package.zip"),
            entries: entries.clone(),
        };
        let selected = resource(root, entries);
        let bad = ParsedZipResourceManifest {
            resource_root: ZipResourceRoot::Path(zip_path("other-root")),
            manifest_path: zip_path(&manifest_ok),
            manifest: FxManifest::default(),
            warnings: Vec::new(),
        };
        let redacted = classify_selected_zip_resource_escrow(&inspection, &selected, &bad)
            .map_err(redact_capture_error_for_tests)
            .expect_err("root mismatch");
        assert!(matches!(
            redacted,
            GkrmError::BaselineCaptureEscrowManifestInvalid
        ));
        assert_public_surface_clean(&redacted);
    }

    // Resource-relative path violation (sibling prefix entry).
    {
        let entries = vec![file_entry(&manifest_ok, 0), file_entry(&sibling, 1)];
        let inspection = ZipInspection {
            path: PathBuf::from("package.zip"),
            entries: entries.clone(),
        };
        let selected = resource(root, entries);
        let good = parsed(root, &manifest_ok);
        let redacted = classify_selected_zip_resource_escrow(&inspection, &selected, &good)
            .map_err(redact_capture_error_for_tests)
            .expect_err("relative path");
        assert!(matches!(
            redacted,
            GkrmError::BaselineCaptureEscrowResourcePathInvalid
        ));
        assert_public_surface_clean(&redacted);
        assert!(std::error::Error::source(&redacted).is_none());
    }

    // Missing / duplicate / root-mismatch are produced by the full escrow classifier;
    // apply the same capture redaction composition used at the classify_selected call site.
    use crate::escrow_classification::classify_zip_resource_escrow;
    use crate::manifest::ZipManifestParseReport;
    use crate::ZipResourceDiscovery;

    let entries = vec![file_entry("fxmanifest.lua", 0)];
    let inspection = ZipInspection {
        path: PathBuf::from("package.zip"),
        entries: entries.clone(),
    };
    let discovery = ZipResourceDiscovery {
        resources: vec![DiscoveredZipResource {
            name: ZipResourceName::ZipRoot,
            root: ZipResourceRoot::Root,
            manifest_path: zip_path("fxmanifest.lua"),
            entries: entries.clone(),
        }],
        unassigned_entries: Vec::new(),
        warnings: Vec::new(),
    };
    let missing = ZipManifestParseReport {
        resources: Vec::new(),
    };
    let redacted = classify_zip_resource_escrow(&inspection, &discovery, &missing)
        .map_err(redact_capture_error_for_tests)
        .expect_err("missing");
    assert!(matches!(
        redacted,
        GkrmError::BaselineCaptureEscrowManifestInvalid
    ));
    assert_public_surface_clean(&redacted);

    let duplicate = ZipManifestParseReport {
        resources: vec![
            ParsedZipResourceManifest {
                resource_root: ZipResourceRoot::Root,
                manifest_path: zip_path("fxmanifest.lua"),
                manifest: FxManifest::default(),
                warnings: Vec::new(),
            },
            ParsedZipResourceManifest {
                resource_root: ZipResourceRoot::Root,
                manifest_path: zip_path("fxmanifest.lua"),
                manifest: FxManifest::default(),
                warnings: Vec::new(),
            },
        ],
    };
    let redacted = classify_zip_resource_escrow(&inspection, &discovery, &duplicate)
        .map_err(redact_capture_error_for_tests)
        .expect_err("duplicate");
    assert!(matches!(
        redacted,
        GkrmError::BaselineCaptureEscrowManifestInvalid
    ));
    assert_public_surface_clean(&redacted);

    let root_mismatch = ZipManifestParseReport {
        resources: vec![ParsedZipResourceManifest {
            resource_root: ZipResourceRoot::Path(zip_path("other")),
            manifest_path: zip_path("other/fxmanifest.lua"),
            manifest: FxManifest::default(),
            warnings: Vec::new(),
        }],
    };
    let redacted = classify_zip_resource_escrow(&inspection, &discovery, &root_mismatch)
        .map_err(redact_capture_error_for_tests)
        .expect_err("root mismatch");
    assert!(matches!(
        redacted,
        GkrmError::BaselineCaptureEscrowManifestInvalid
    ));
    assert_public_surface_clean(&redacted);
}

#[test]
fn production_bundle_and_store_helpers_redact_sensitive_variants() {
    use std::collections::BTreeMap;

    use crate::baseline::key::SafeResourceKey;
    use crate::baseline::model::{
        make_file_record, BaselineEscrowClass, BaselineStoreLimits, ValidatedBaselineBundle,
    };
    use crate::baseline::store::{load_baseline_bundle, write_baseline_bundle};
    use crate::baseline::InMemoryBlobProvider;
    use crate::installed_path::ResourceRelativePath;

    fn digest_of(bytes: &[u8]) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Sha256Digest::new(hasher.finalize().into())
    }

    fn wrap_bundle_construction(source: GkrmError) -> GkrmError {
        // Mirror capture_with_spool composition (including immediate redaction).
        redact_capture_error_for_tests(GkrmError::BaselineCaptureBundleConstruction {
            source: Box::new(source),
        })
    }

    let key = SafeResourceKey::parse("phone").unwrap();
    let path_a = ResourceRelativePath::try_from_slash_str("a.lua").unwrap();
    let digest = digest_of(b"body");

    // Unsafe relative path / control in resource name.
    let err = ValidatedBaselineBundle::try_from_parts(
        key.clone(),
        "bad\nname".into(),
        None,
        None,
        vec![make_file_record(
            path_a.clone(),
            4,
            digest,
            BaselineEscrowClass::Protected,
            None,
        )],
        BTreeMap::new(),
        BaselineStoreLimits::default(),
    )
    .expect_err("unsafe name");
    assert!(matches!(err, GkrmError::BaselineUnsafeRelativePath { .. }));
    let redacted = wrap_bundle_construction(err);
    match redacted {
        GkrmError::BaselineCaptureBundleConstruction { source } => {
            assert!(matches!(
                source.as_ref(),
                GkrmError::BaselineCaptureBundlePathInvalid
            ));
            assert_public_surface_clean(source.as_ref());
        }
        other => panic!("unexpected: {other}"),
    }

    // Duplicate file path.
    let err = ValidatedBaselineBundle::try_from_parts(
        key.clone(),
        "phone".into(),
        None,
        None,
        vec![
            make_file_record(
                path_a.clone(),
                4,
                digest,
                BaselineEscrowClass::Protected,
                None,
            ),
            make_file_record(
                path_a.clone(),
                4,
                digest,
                BaselineEscrowClass::Protected,
                None,
            ),
        ],
        BTreeMap::new(),
        BaselineStoreLimits::default(),
    )
    .expect_err("duplicate");
    assert!(matches!(err, GkrmError::BaselineDuplicateFilePath { .. }));
    let redacted = wrap_bundle_construction(err);
    match redacted {
        GkrmError::BaselineCaptureBundleConstruction { source } => {
            assert!(matches!(
                source.as_ref(),
                GkrmError::BaselineCaptureBundlePathInvalid
            ));
            assert_public_surface_clean(source.as_ref());
        }
        other => panic!("unexpected: {other}"),
    }

    // Unexpected blob.
    let unexpected = digest_of(b"extra");
    let err = ValidatedBaselineBundle::try_from_parts(
        key.clone(),
        "phone".into(),
        None,
        None,
        vec![make_file_record(
            path_a.clone(),
            4,
            digest,
            BaselineEscrowClass::Protected,
            None,
        )],
        BTreeMap::from([(unexpected, 1)]),
        BaselineStoreLimits::default(),
    )
    .expect_err("unexpected blob");
    assert!(matches!(err, GkrmError::BaselineUnexpectedBlob { .. }));
    let redacted = wrap_bundle_construction(err);
    match redacted {
        GkrmError::BaselineCaptureBundleConstruction { source } => {
            assert!(matches!(
                source.as_ref(),
                GkrmError::BaselineCaptureBundleBlobInvalid
            ));
            assert_public_surface_clean(source.as_ref());
        }
        other => panic!("unexpected: {other}"),
    }

    // Blob limit exceeded.
    let limits = BaselineStoreLimits::new(1024 * 1024, 10_000, 1, 1024 * 1024).expect("limits");
    let ignored = digest_of(b"ignored-bytes");
    let err = ValidatedBaselineBundle::try_from_parts(
        key.clone(),
        "phone".into(),
        None,
        None,
        vec![make_file_record(
            path_a.clone(),
            12,
            ignored,
            BaselineEscrowClass::Ignored,
            Some(ignored),
        )],
        BTreeMap::from([(ignored, 12)]),
        limits,
    )
    .expect_err("blob limit");
    assert!(matches!(err, GkrmError::BaselineBlobLimitExceeded { .. }));
    let redacted = wrap_bundle_construction(err);
    match redacted {
        GkrmError::BaselineCaptureBundleConstruction { source } => {
            assert!(matches!(
                source.as_ref(),
                GkrmError::BaselineCaptureBundleBlobInvalid
            ));
            assert_public_surface_clean(source.as_ref());
        }
        other => panic!("unexpected: {other}"),
    }

    // Invalid ordering via DTO decode path is covered field-level; construct directly for store.
    let ordering = GkrmError::BaselineInvalidOrdering {
        path: SENTINEL_ENTRY.to_owned(),
    };
    let redacted = wrap_bundle_construction(ordering);
    match redacted {
        GkrmError::BaselineCaptureBundleConstruction { source } => {
            assert!(matches!(
                source.as_ref(),
                GkrmError::BaselineCaptureBundleOrderingInvalid
            ));
        }
        other => panic!("unexpected: {other}"),
    }

    // Publish a real bundle, then load with mismatched key / id (store helpers + redact).
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let bytes = b"ignored-bytes";
    let blob = digest_of(bytes);
    let bundle = ValidatedBaselineBundle::try_from_parts_with_bytes(
        key.clone(),
        "phone".into(),
        None,
        None,
        vec![
            make_file_record(
                ResourceRelativePath::try_from_slash_str("fxmanifest.lua").unwrap(),
                1,
                digest_of(b"m"),
                BaselineEscrowClass::Protected,
                None,
            ),
            make_file_record(
                ResourceRelativePath::try_from_slash_str("config.lua").unwrap(),
                bytes.len() as u64,
                blob,
                BaselineEscrowClass::Ignored,
                Some(blob),
            ),
        ],
        BTreeMap::from([(blob, bytes.to_vec())]),
        BaselineStoreLimits::default(),
    )
    .expect("bundle");
    let provider = InMemoryBlobProvider::new(BTreeMap::from([(blob, bytes.to_vec())]));
    write_baseline_bundle(&store, &bundle, &provider, BaselineStoreLimits::default())
        .expect("publish");

    let other_key = SafeResourceKey::parse("otherphone").unwrap();
    let key_err = load_baseline_bundle(
        &store,
        &other_key,
        bundle.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect_err("key mismatch");
    // Missing vs mismatch depending on directory layout; force mismatch via constructed error
    // if the store returns not-found for a different key directory.
    let key_mismatch = match key_err {
        GkrmError::BaselineResourceKeyMismatch { .. } => key_err,
        other => {
            let _ = other;
            GkrmError::BaselineResourceKeyMismatch {
                requested: SENTINEL_LABELS.to_owned(),
                stored: SENTINEL_VALUE.to_owned(),
            }
        }
    };
    let redacted = redact_capture_error_for_tests(key_mismatch);
    assert!(matches!(
        redacted,
        GkrmError::BaselineCaptureBundleIdentityMismatch
    ));
    assert_public_surface_clean(&redacted);

    let fake_id = crate::baseline::BaselineId::parse(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let id_err = load_baseline_bundle(&store, &key, &fake_id, BaselineStoreLimits::default())
        .expect_err("id mismatch or missing");
    let id_mismatch = match id_err {
        GkrmError::BaselineRequestedIdMismatch { .. } | GkrmError::BaselineIdMismatch { .. } => {
            id_err
        }
        other => {
            let _ = other;
            GkrmError::BaselineRequestedIdMismatch {
                requested: SENTINEL_BASELINE_ID.to_owned(),
                stored: SENTINEL_DIGEST.to_owned(),
            }
        }
    };
    let redacted = redact_capture_error_for_tests(id_mismatch);
    assert!(matches!(
        redacted,
        GkrmError::BaselineCaptureBundleIdentityMismatch
    ));
    assert_public_surface_clean(&redacted);

    // Atomic publication failure: same mapping write_baseline uses via map_err(redact).
    let publish_err = GkrmError::BaselineAtomicPublishFailure {
        cause: std::io::Error::new(std::io::ErrorKind::PermissionDenied, SENTINEL_DEP),
    };
    let redacted = redact_capture_error_for_tests(publish_err);
    match redacted {
        GkrmError::BaselineCapturePublicationFailed { kind } => {
            assert_eq!(kind, std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("unexpected: {other}"),
    }
    assert_public_surface_clean(&redacted);
    assert_raw_source_unreachable(&redacted);
    assert!(std::error::Error::source(&redacted).is_none());
}

#[test]
fn raw_dependency_errors_are_not_error_sources() {
    for error in [
        redact_capture_error_for_tests(GkrmError::InstalledPathMetadata {
            path: PathBuf::from(SENTINEL_WIN_PATH),
            cause: std::io::Error::other(SENTINEL_DEP),
        }),
        redact_capture_error_for_tests(GkrmError::ZipPackageOpen {
            path: PathBuf::from(SENTINEL_UNIX_PATH),
            cause: std::io::Error::other(SENTINEL_DEP),
        }),
        redact_capture_error_for_tests(GkrmError::ZipArchiveRead {
            path: PathBuf::from(SENTINEL_WIN_PATH),
            cause: ZipError::InvalidArchive(std::borrow::Cow::Borrowed(SENTINEL_DEP)),
        }),
        redact_capture_error_for_tests(GkrmError::ManifestInvalidUtf8 {
            entry: SENTINEL_ENTRY.to_owned(),
            cause: String::from_utf8(vec![0xff, 0xfe]).unwrap_err(),
        }),
        redact_capture_error_for_tests(GkrmError::BaselineAtomicPublishFailure {
            cause: std::io::Error::other(SENTINEL_DEP),
        }),
        redact_capture_error_for_tests(GkrmError::BaselineStoreIo {
            component: SENTINEL_JOURNAL.to_owned(),
            cause: std::io::Error::other(SENTINEL_DEP),
        }),
        GkrmError::BaselineCapturePackageOpen {
            kind: std::io::ErrorKind::PermissionDenied,
        },
    ] {
        assert!(
            std::error::Error::source(&error).is_none(),
            "raw dependency must not be Error::source(): {error}"
        );
        assert_public_surface_clean(&error);
    }
}
