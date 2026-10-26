use std::io;

use cap_std::fs::{Dir as CapDir, File as CapFile, Metadata as CapMetadata};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum StableFileIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },

    #[cfg(windows)]
    Windows { volume_serial: u64, file_index: u64 },
}

#[cfg(unix)]
pub(crate) fn capture_stable_file_identity(file: &CapFile) -> io::Result<StableFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.try_clone()?.into_std().metadata()?;
    Ok(StableFileIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
pub(crate) fn capture_stable_file_identity(file: &CapFile) -> io::Result<StableFileIdentity> {
    let std_file = file.try_clone()?.into_std();
    let handle = winapi_util::Handle::from_file(std_file);
    let info = winapi_util::file::information(&handle)?;

    Ok(StableFileIdentity::Windows {
        volume_serial: info.volume_serial_number(),
        file_index: info.file_index(),
    })
}

#[cfg(unix)]
pub(crate) fn capture_stable_dir_identity(dir: &CapDir) -> io::Result<StableFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = dir.dir_metadata()?;
    Ok(StableFileIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
pub(crate) fn capture_stable_dir_identity(dir: &CapDir) -> io::Result<StableFileIdentity> {
    use std::os::windows::io::AsRawHandle;

    capture_stable_identity_from_raw_handle(dir.as_raw_handle())
}

/// Capture stable identity from an already-open Windows handle without pathname reopen.
#[cfg(windows)]
pub(crate) fn capture_stable_identity_from_raw_handle(
    handle: std::os::windows::io::RawHandle,
) -> io::Result<StableFileIdentity> {
    let handle_ref = unsafe { winapi_util::HandleRef::from_raw_handle(handle) };
    let info = winapi_util::file::information(&handle_ref)?;

    Ok(StableFileIdentity::Windows {
        volume_serial: info.volume_serial_number(),
        file_index: info.file_index(),
    })
}

#[cfg(unix)]
pub(crate) fn file_link_count(metadata: &CapMetadata) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(metadata.nlink())
}

#[cfg(windows)]
pub(crate) fn file_link_count_from_handle(file: &CapFile) -> io::Result<u64> {
    let std_file = file.try_clone()?.into_std();
    let handle = winapi_util::Handle::from_file(std_file);
    let info = winapi_util::file::information(&handle)?;
    Ok(info.number_of_links())
}

#[cfg(windows)]
pub(crate) fn is_windows_reparse_point_cap(metadata: &CapMetadata) -> bool {
    use cap_fs_ext::OsMetadataExt;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
pub(crate) fn is_windows_reparse_point_cap(_metadata: &CapMetadata) -> bool {
    false
}

#[cfg(windows)]
pub(crate) fn is_windows_reparse_point_std(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
pub(crate) fn is_windows_reparse_point_std(_metadata: &std::fs::Metadata) -> bool {
    false
}
