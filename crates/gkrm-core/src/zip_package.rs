use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use zip::CompressionMethod;

use crate::{package_source::PackageSnapshot, GkrmError, PackageLimits, Result, ZipRelativePath};

/// Read-only inventory of a ZIP package after entry validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipInspection {
    pub path: PathBuf,
    pub entries: Vec<ZipEntryInfo>,
}

/// Metadata for one validated ZIP entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntryInfo {
    pub archive_index: usize,
    pub path: ZipRelativePath,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// ZIP CRC32 is revalidated when reading manifests to detect ordinary
    /// package replacement. It is not a cryptographic integrity guarantee.
    pub crc32: u32,
    pub compression_method: CompressionMethod,
    pub encrypted: bool,
    pub unix_mode: Option<u32>,
    pub kind: ZipEntryKind,
}

/// The supported entry kinds for Milestone 1 ZIP inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipEntryKind {
    File,
    Directory,
}

/// Validate and inventory a ZIP package without extracting entries to disk.
pub fn inspect_zip_package(package_path: &Path, limits: PackageLimits) -> Result<ZipInspection> {
    let snapshot = PackageSnapshot::create(package_path, u64::MAX)?;
    inspect_zip_snapshot(&snapshot, limits)
}

pub(crate) fn inspect_zip_snapshot(
    snapshot: &PackageSnapshot,
    limits: PackageLimits,
) -> Result<ZipInspection> {
    let package_path = snapshot.source_path();
    let mut archive = snapshot.open_zip_archive().map_err(|source| match source {
        GkrmError::ZipPackageOpen { cause: source, .. } => GkrmError::ZipPackageOpen {
            path: package_path.to_path_buf(),
            cause: source,
        },
        GkrmError::ZipArchiveRead { cause: source, .. } => GkrmError::ZipArchiveRead {
            path: package_path.to_path_buf(),
            cause: source,
        },
        other => other,
    })?;

    let actual_entries = archive.len();
    if actual_entries > limits.max_entries {
        return Err(GkrmError::ZipEntryCountLimitExceeded {
            limit: limits.max_entries,
            actual: actual_entries,
        });
    }

    let mut entries = Vec::with_capacity(actual_entries);
    let mut exact_paths = BTreeMap::<String, ()>::new();
    let mut case_insensitive_paths = BTreeMap::<String, String>::new();
    let mut total_uncompressed_size = 0_u64;

    for index in 0..actual_entries {
        let (
            normalized_path,
            normalized_path_string,
            uncompressed_size,
            compressed_size,
            crc32,
            compression_method,
            encrypted,
            unix_mode,
            kind,
        ) = {
            let entry = archive
                .by_index_raw(index)
                .map_err(|source| GkrmError::ZipEntryRead {
                    path: package_path.to_path_buf(),
                    index,
                    cause: source,
                })?;

            let normalized_path = ZipRelativePath::new(index, entry.name_raw())?;
            let normalized_path_string = normalized_path.as_str().to_owned();

            if is_symlink(entry.unix_mode()) {
                return Err(GkrmError::ZipEntrySymlink {
                    index,
                    entry: normalized_path_string,
                });
            }

            let encrypted = entry.encrypted();
            if encrypted {
                return Err(GkrmError::ZipEntryEncrypted {
                    index,
                    entry: normalized_path_string,
                });
            }

            let compression_method = entry.compression();
            if !is_supported_compression(compression_method) {
                return Err(GkrmError::ZipEntryUnsupportedCompression {
                    index,
                    entry: normalized_path_string,
                    method: format!("{compression_method:?}"),
                });
            }

            let uncompressed_size = entry.size();
            let compressed_size = entry.compressed_size();
            let crc32 = entry.crc32();
            let unix_mode = entry.unix_mode();
            let kind = if entry.is_dir() {
                if compressed_size != 0 || uncompressed_size != 0 {
                    return Err(GkrmError::ZipDirectoryEntryNonZeroSize {
                        index,
                        entry: normalized_path_string,
                        compressed_size,
                        uncompressed_size,
                    });
                }

                ZipEntryKind::Directory
            } else {
                ZipEntryKind::File
            };

            (
                normalized_path,
                normalized_path_string,
                uncompressed_size,
                compressed_size,
                crc32,
                compression_method,
                encrypted,
                unix_mode,
                kind,
            )
        };

        if exact_paths
            .insert(normalized_path_string.clone(), ())
            .is_some()
        {
            return Err(GkrmError::ZipEntryDuplicatePath {
                entry: normalized_path_string,
            });
        }

        // Deterministic best-effort collision detection. This does not attempt full
        // Windows Unicode filesystem normalization.
        let case_key = normalized_path_string.to_lowercase();
        if let Some(first) = case_insensitive_paths.insert(case_key, normalized_path_string.clone())
        {
            return Err(GkrmError::ZipEntryCaseInsensitiveCollision {
                first,
                second: normalized_path_string,
            });
        }

        if uncompressed_size > limits.max_entry_uncompressed_size {
            return Err(GkrmError::ZipEntrySizeLimitExceeded {
                entry: normalized_path_string,
                limit: limits.max_entry_uncompressed_size,
                actual: uncompressed_size,
            });
        }

        validate_compression_ratio(
            &normalized_path_string,
            compressed_size,
            uncompressed_size,
            limits.max_compression_ratio,
        )?;

        total_uncompressed_size = total_uncompressed_size
            .checked_add(uncompressed_size)
            .ok_or(GkrmError::ZipTotalSizeLimitExceeded {
                limit: limits.max_total_uncompressed_size,
                actual: u64::MAX,
            })?;

        if total_uncompressed_size > limits.max_total_uncompressed_size {
            return Err(GkrmError::ZipTotalSizeLimitExceeded {
                limit: limits.max_total_uncompressed_size,
                actual: total_uncompressed_size,
            });
        }

        if kind == ZipEntryKind::File {
            let mut entry = archive
                .by_index(index)
                .map_err(|source| GkrmError::ZipEntryRead {
                    path: package_path.to_path_buf(),
                    index,
                    cause: source,
                })?;
            stream_entry_to_sink(&mut entry, &normalized_path_string, uncompressed_size)?;
        }

        entries.push(ZipEntryInfo {
            archive_index: index,
            path: normalized_path,
            compressed_size,
            uncompressed_size,
            crc32,
            compression_method,
            encrypted,
            unix_mode,
            kind,
        });
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(ZipInspection {
        path: package_path.to_path_buf(),
        entries,
    })
}

fn is_supported_compression(method: CompressionMethod) -> bool {
    matches!(
        method,
        CompressionMethod::Stored | CompressionMethod::Deflated
    )
}

fn validate_compression_ratio(
    entry: &str,
    compressed_size: u64,
    uncompressed_size: u64,
    limit: u64,
) -> Result<()> {
    if limit == 0 && uncompressed_size > 0 {
        return Err(GkrmError::ZipCompressionRatioLimitExceeded {
            entry: entry.to_owned(),
            limit,
            compressed_size,
            uncompressed_size,
        });
    }

    if uncompressed_size == 0 {
        return Ok(());
    }

    if compressed_size == 0 || uncompressed_size > compressed_size.saturating_mul(limit) {
        return Err(GkrmError::ZipCompressionRatioLimitExceeded {
            entry: entry.to_owned(),
            limit,
            compressed_size,
            uncompressed_size,
        });
    }

    Ok(())
}

fn stream_entry_to_sink<R: Read>(
    reader: &mut R,
    entry: &str,
    expected_uncompressed_size: u64,
) -> Result<()> {
    let mut limited = reader.take(expected_uncompressed_size.saturating_add(1));
    let bytes_read =
        io::copy(&mut limited, &mut io::sink()).map_err(|source| GkrmError::ZipEntryStream {
            entry: entry.to_owned(),
            cause: source,
        })?;

    if bytes_read != expected_uncompressed_size {
        return Err(GkrmError::ZipEntryStreamSizeMismatch {
            entry: entry.to_owned(),
            expected: expected_uncompressed_size,
            actual: bytes_read,
        });
    }

    Ok(())
}

fn is_symlink(unix_mode: Option<u32>) -> bool {
    const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
    const UNIX_SYMLINK_TYPE: u32 = 0o120000;

    unix_mode
        .map(|mode| mode & UNIX_FILE_TYPE_MASK == UNIX_SYMLINK_TYPE)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{Cursor, Write};

    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    fn test_limits() -> PackageLimits {
        PackageLimits {
            max_entries: 10,
            max_entry_uncompressed_size: 1024,
            max_total_uncompressed_size: 4096,
            max_compression_ratio: 200,
        }
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).expect("zip file should be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

        for (name, contents) in entries {
            if name.ends_with('/') {
                writer
                    .add_directory(*name, options)
                    .expect("directory should be added");
            } else {
                writer
                    .start_file(*name, options)
                    .expect("file should start");
                writer
                    .write_all(contents)
                    .expect("file contents should be written");
            }
        }

        writer.finish().expect("zip should finish");
    }

    fn write_symlink_zip(path: &Path, entry_name: &str) {
        write_manual_single_entry_zip(
            path,
            ManualZipEntry {
                name: entry_name,
                flags: 0,
                compression_method: 0,
                compressed_size: 0,
                uncompressed_size: 0,
                external_attributes: (0o120777_u32) << 16,
                contents: b"",
            },
        );
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
        let mut file = File::create(path).expect("zip file should be created");
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
        file.write_all(name).expect("local name should be written");
        file.write_all(entry.contents)
            .expect("local contents should be written");

        let central_directory_offset = 30_u32
            .checked_add(name.len() as u32)
            .and_then(|offset| offset.checked_add(entry.contents.len() as u32))
            .expect("offset should fit");

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
        file.write_all(name)
            .expect("central directory name should be written");

        let central_directory_size = 46_u32
            .checked_add(name.len() as u32)
            .expect("size should fit");

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
        file.write_all(&value.to_le_bytes())
            .expect("u16 should be written");
    }

    fn write_u32(file: &mut File, value: u32) {
        file.write_all(&value.to_le_bytes())
            .expect("u32 should be written");
    }

    #[test]
    fn inventories_valid_zip_without_extracting() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                ("resource/server.lua", b"server"),
                ("resource/", b""),
                ("resource/client.lua", b"client"),
            ],
        );

        let inspection = inspect_zip_package(&package, test_limits()).expect("zip should inspect");

        let paths = inspection
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec!["resource", "resource/client.lua", "resource/server.lua"]
        );
        assert!(!temp.path().join("resource").exists());
    }

    #[test]
    fn rejects_duplicate_normalized_paths() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[("resource/file.lua", b"a"), ("resource\\file.lua", b"b")],
        );

        let err = inspect_zip_package(&package, test_limits()).expect_err("duplicate should fail");

        assert!(matches!(err, GkrmError::ZipEntryDuplicatePath { .. }));
    }

    #[test]
    fn rejects_case_insensitive_path_collisions() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(&package, &[("config.lua", b"a"), ("Config.lua", b"b")]);

        let err = inspect_zip_package(&package, test_limits())
            .expect_err("case-insensitive collision should fail");

        assert!(matches!(
            err,
            GkrmError::ZipEntryCaseInsensitiveCollision { .. }
        ));
    }

    #[test]
    fn rejects_entry_count_above_limit() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(&package, &[("a.lua", b"a"), ("b.lua", b"b")]);
        let limits = PackageLimits {
            max_entries: 1,
            ..test_limits()
        };

        let err = inspect_zip_package(&package, limits).expect_err("entry count should fail");

        assert!(matches!(err, GkrmError::ZipEntryCountLimitExceeded { .. }));
    }

    #[test]
    fn rejects_individual_uncompressed_size_above_limit() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(&package, &[("large.lua", b"large")]);
        let limits = PackageLimits {
            max_entry_uncompressed_size: 4,
            ..test_limits()
        };

        let err = inspect_zip_package(&package, limits).expect_err("entry size should fail");

        assert!(matches!(err, GkrmError::ZipEntrySizeLimitExceeded { .. }));
    }

    #[test]
    fn rejects_total_uncompressed_size_above_limit() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(&package, &[("a.lua", b"aaa"), ("b.lua", b"bbb")]);
        let limits = PackageLimits {
            max_total_uncompressed_size: 5,
            ..test_limits()
        };

        let err = inspect_zip_package(&package, limits).expect_err("total size should fail");

        assert!(matches!(err, GkrmError::ZipTotalSizeLimitExceeded { .. }));
    }

    #[test]
    fn rejects_compression_ratio_above_limit() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        let file = File::create(&package).expect("zip file should be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer
            .start_file("compressed.txt", options)
            .expect("file should start");
        writer
            .write_all(&vec![b'a'; 1024])
            .expect("file contents should be written");
        writer.finish().expect("zip should finish");
        let limits = PackageLimits {
            max_compression_ratio: 1,
            ..test_limits()
        };

        let err = inspect_zip_package(&package, limits).expect_err("ratio should fail");

        assert!(matches!(
            err,
            GkrmError::ZipCompressionRatioLimitExceeded { .. }
        ));
    }

    #[test]
    fn rejects_corrupt_zip() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        fs::write(&package, b"not a zip").expect("corrupt zip should be created");

        let err = inspect_zip_package(&package, test_limits()).expect_err("zip should fail");

        assert!(matches!(err, GkrmError::ZipArchiveRead { .. }));
    }

    #[test]
    fn rejects_symlink_entries() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_symlink_zip(&package, "link.lua");

        let err = inspect_zip_package(&package, test_limits()).expect_err("symlink should fail");

        assert!(matches!(err, GkrmError::ZipEntrySymlink { .. }));
    }

    #[test]
    fn rejects_encrypted_entries_before_streaming() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_manual_single_entry_zip(
            &package,
            ManualZipEntry {
                name: "secret.lua",
                flags: 1,
                compression_method: 0,
                compressed_size: 0,
                uncompressed_size: 0,
                external_attributes: 0,
                contents: b"",
            },
        );

        let err = inspect_zip_package(&package, test_limits()).expect_err("encrypted should fail");

        assert!(matches!(err, GkrmError::ZipEntryEncrypted { .. }));
    }

    #[test]
    fn rejects_unsupported_compression_methods_before_streaming() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_manual_single_entry_zip(
            &package,
            ManualZipEntry {
                name: "unsupported.lua",
                flags: 0,
                compression_method: 12,
                compressed_size: 0,
                uncompressed_size: 0,
                external_attributes: 0,
                contents: b"",
            },
        );

        let err = inspect_zip_package(&package, test_limits())
            .expect_err("unsupported method should fail");

        assert!(matches!(
            err,
            GkrmError::ZipEntryUnsupportedCompression { .. }
        ));
    }

    #[test]
    fn rejects_directory_entries_with_non_zero_size() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_manual_single_entry_zip(
            &package,
            ManualZipEntry {
                name: "resource/",
                flags: 0,
                compression_method: 0,
                compressed_size: 1,
                uncompressed_size: 1,
                external_attributes: 0,
                contents: b"x",
            },
        );

        let err = inspect_zip_package(&package, test_limits())
            .expect_err("non-zero directory should fail");

        assert!(matches!(
            err,
            GkrmError::ZipDirectoryEntryNonZeroSize { .. }
        ));
    }

    #[test]
    fn streams_entry_contents_without_hashing_or_extracting() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(&package, &[("nested/file.lua", b"contents")]);

        inspect_zip_package(&package, test_limits()).expect("zip should inspect");

        assert_eq!(
            fs::read_dir(temp.path())
                .expect("temp dir should be readable")
                .count(),
            1
        );
    }

    #[test]
    fn streaming_rejects_reader_that_exceeds_expected_size() {
        let mut reader = Cursor::new(b"abc");

        let err = stream_entry_to_sink(&mut reader, "entry.txt", 2)
            .expect_err("oversized stream should fail");

        assert!(matches!(
            err,
            GkrmError::ZipEntryStreamSizeMismatch {
                expected: 2,
                actual: 3,
                ..
            }
        ));
    }

    #[test]
    fn streaming_rejects_reader_that_ends_before_declared_size() {
        let mut reader = Cursor::new(b"ab");

        let err = stream_entry_to_sink(&mut reader, "entry.txt", 3)
            .expect_err("undersized stream should fail");

        assert!(matches!(
            err,
            GkrmError::ZipEntryStreamSizeMismatch {
                expected: 3,
                actual: 2,
                ..
            }
        ));
    }
}
