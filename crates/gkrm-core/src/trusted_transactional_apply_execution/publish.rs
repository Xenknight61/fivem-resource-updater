//! Capability-relative same-directory file publication for Task 23.
//!
//! Install uses no-replace rename. Replace uses platform atomic replacement.
//! Delete-then-rename is never used.

use std::io;

use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{open_file_nofollow, try_open_child_dir, verify_regular_file};
use crate::baseline::store::sync_dir;
use crate::{GkrmError, Result, Sha256Digest, TransactionalApplyIoOperation};

use super::journal::{map_baseline_to_io, map_io};
use super::paths::hash_file;

fn validate_component(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains(':')
        || name.len() > 255
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid single path component",
        ));
    }
    Ok(())
}

/// Install: verified same-directory temp → no-replace rename. Destination must be absent.
pub(super) fn publish_install(
    parent: &CapDir,
    temp_name: &str,
    dest_name: &str,
    expected_digest: &Sha256Digest,
    expected_len: u64,
) -> Result<()> {
    validate_component(temp_name)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RenameInstalled, e))?;
    validate_component(dest_name)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RenameInstalled, e))?;

    if try_open_child_dir(parent, dest_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?
        .is_some()
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject);
    }
    // Only NotFound/Missing proves absence; other open outcomes fail closed.
    match open_file_nofollow(parent, dest_name) {
        Ok(_) => return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed),
        Err(GkrmError::BaselineStoreMissing { .. }) => {}
        Err(GkrmError::BaselineStoreIo { cause: source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject);
        }
    }

    #[cfg(test)]
    if super::hooks::interrupt_before_file_publish() {
        let _ = parent.remove_file(temp_name);
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }

    rename_noreplace_component(parent, temp_name, dest_name).map_err(|e| {
        let _ = parent.remove_file(temp_name);
        map_io(TransactionalApplyIoOperation::RenameInstalled, e)
    })?;

    #[cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
    super::hooks::fire_publication_hook(super::hooks::PublicationPoint::AfterFilePublish);

    #[cfg(test)]
    if super::hooks::interrupt_after_file_publish() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }

    finish_publish(parent, dest_name, expected_digest, expected_len)
}

/// Replace: verified same-directory temp → atomic replacement of existing regular file.
pub(super) fn publish_replace(
    parent: &CapDir,
    temp_name: &str,
    dest_name: &str,
    expected_digest: &Sha256Digest,
    expected_len: u64,
) -> Result<()> {
    validate_component(temp_name)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RenameInstalled, e))?;
    validate_component(dest_name)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RenameInstalled, e))?;

    // Reject symlink/reparse/hard-link/special immediately before replacement.
    let existing = open_file_nofollow(parent, dest_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledFile, e))?;
    verify_regular_file(&existing, dest_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e))?;
    drop(existing);

    #[cfg(test)]
    if super::hooks::interrupt_before_file_publish() {
        let _ = parent.remove_file(temp_name);
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }

    rename_replace_component(parent, temp_name, dest_name).map_err(|e| {
        let _ = parent.remove_file(temp_name);
        map_io(TransactionalApplyIoOperation::RenameInstalled, e)
    })?;

    #[cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
    super::hooks::fire_publication_hook(super::hooks::PublicationPoint::AfterFilePublish);

    #[cfg(test)]
    if super::hooks::interrupt_after_file_publish() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }

    finish_publish(parent, dest_name, expected_digest, expected_len)
}

fn finish_publish(
    parent: &CapDir,
    dest_name: &str,
    expected_digest: &Sha256Digest,
    expected_len: u64,
) -> Result<()> {
    #[cfg(test)]
    if super::hooks::force_parent_sync_failure() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
            operation: TransactionalApplyIoOperation::SyncInstalledDirectory,
            kind: io::ErrorKind::Other,
        });
    }
    sync_dir(parent, "parent").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
    })?;
    let published = open_file_nofollow(parent, dest_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledFile, e))?;
    verify_regular_file(&published, dest_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e))?;
    let (got_d, got_l) = hash_file(&published)?;
    if &got_d != expected_digest || got_l != expected_len {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    Ok(())
}

fn rename_noreplace_component(parent: &CapDir, src: &str, dest: &str) -> io::Result<()> {
    #[cfg(test)]
    if super::hooks::force_rename_failure() {
        return Err(io::Error::other("injected rename failure"));
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;
        let from = CString::new(src)?;
        let to = CString::new(dest)?;
        const RENAME_NOREPLACE: libc::c_uint = 1;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;
        let from = CString::new(src)?;
        let to = CString::new(dest)?;
        const RENAME_EXCL: u32 = 0x0000_0004;
        let rc = unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_EXCL,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }
    #[cfg(windows)]
    {
        windows_rename_file(parent, src, dest, false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (parent, src, dest);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no-replace rename unsupported",
        ))
    }
}

fn rename_replace_component(parent: &CapDir, src: &str, dest: &str) -> io::Result<()> {
    #[cfg(test)]
    if super::hooks::force_rename_failure() {
        return Err(io::Error::other("injected rename failure"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;
        let from = CString::new(src)?;
        let to = CString::new(dest)?;
        let rc = unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if rc == 0 {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }
    #[cfg(windows)]
    {
        windows_rename_file(parent, src, dest, true)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (parent, src, dest);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic replace rename unsupported",
        ))
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn windows_rename_file(parent: &CapDir, src: &str, dest: &str, replace: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    use cap_fs_ext::{FollowSymlinks, OpenOptionsExt, OpenOptionsFollowExt};
    use cap_std::fs::OpenOptions;

    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_RENAME_INFORMATION: u32 = 10;
    const FILE_RENAME_INFORMATION_EX: u32 = 65;
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_TRAVERSE: u32 = 0x0020;

    let mut options = OpenOptions::new();
    options.read(true);
    options.write(true);
    options.follow(FollowSymlinks::No);
    options.access_mode(DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES);
    let source = parent.open_with(src, &options)?;
    let meta = source.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source is not a regular file",
        ));
    }

    let dest_root = parent.as_raw_handle();
    if dest_root.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "destination capability handle unavailable",
        ));
    }
    let dest_root_owned =
        open_directory_by_file_id(dest_root, FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE)
            .ok();
    let root_handle = dest_root_owned.as_ref().map(|h| h.0).unwrap_or(dest_root);

    let utf16: Vec<u16> = dest.encode_utf16().collect();
    let name_byte_len = utf16
        .len()
        .checked_mul(2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UTF-16 length overflow"))?;
    let header = 20usize;
    let total = header
        .checked_add(name_byte_len)
        .and_then(|n| n.checked_add(2))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "buffer overflow"))?;
    let mut buffer = vec![0_u8; total];
    let flags: u32 = if replace {
        FILE_RENAME_FLAG_REPLACE_IF_EXISTS
    } else {
        0
    };
    buffer[0..4].copy_from_slice(&flags.to_le_bytes());
    buffer[8..16].copy_from_slice(&(root_handle as u64).to_le_bytes());
    buffer[16..20].copy_from_slice(&(name_byte_len as u32).to_le_bytes());
    let name_bytes =
        unsafe { std::slice::from_raw_parts(utf16.as_ptr().cast::<u8>(), name_byte_len) };
    buffer[20..20 + name_byte_len].copy_from_slice(name_bytes);

    match nt_set_rename(source.as_raw_handle(), FILE_RENAME_INFORMATION_EX, &buffer) {
        Ok(()) => Ok(()),
        Err(err) if is_ex_unsupported(&err) => {
            buffer[0] = u8::from(replace);
            buffer[1] = 0;
            buffer[2] = 0;
            buffer[3] = 0;
            nt_set_rename(source.as_raw_handle(), FILE_RENAME_INFORMATION, &buffer)
        }
        Err(err) => Err(err),
    }
}

#[cfg(all(windows, not(target_pointer_width = "64")))]
fn windows_rename_file(parent: &CapDir, src: &str, dest: &str, replace: bool) -> io::Result<()> {
    let _ = (parent, src, dest, replace);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic file rename requires 64-bit Windows",
    ))
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn is_ex_unsupported(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(1 | 50))
}

#[cfg(all(windows, target_pointer_width = "64"))]
struct OwnedWinHandle(std::os::windows::io::RawHandle);

#[cfg(all(windows, target_pointer_width = "64"))]
impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(h_object: *mut std::ffi::c_void) -> i32;
        }
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn open_directory_by_file_id(
    existing: std::os::windows::io::RawHandle,
    desired_access: u32,
) -> io::Result<OwnedWinHandle> {
    use winapi_util::HandleRef;

    const FILE_SHARE_READ: u32 = 0x0001;
    const FILE_SHARE_WRITE: u32 = 0x0002;
    const FILE_SHARE_DELETE: u32 = 0x0004;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ID_TYPE_FILE_ID: u32 = 0;

    #[repr(C)]
    struct FileIdDescriptor {
        dw_size: u32,
        type_: u32,
        file_id: u64,
        _union_pad: u64,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenFileById(
            h_volume_hint: *mut std::ffi::c_void,
            lp_file_id: *mut FileIdDescriptor,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut std::ffi::c_void,
            dw_flags_and_attributes: u32,
        ) -> *mut std::ffi::c_void;
    }

    let handle_ref = unsafe { HandleRef::from_raw_handle(existing) };
    let info = winapi_util::file::information(&handle_ref)?;
    let mut descriptor = FileIdDescriptor {
        dw_size: std::mem::size_of::<FileIdDescriptor>() as u32,
        type_: FILE_ID_TYPE_FILE_ID,
        file_id: info.file_index(),
        _union_pad: 0,
    };
    let handle = unsafe {
        OpenFileById(
            existing,
            &mut descriptor,
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if handle.is_null() || handle == (-1isize as *mut std::ffi::c_void) {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedWinHandle(handle))
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn nt_set_rename(
    handle: std::os::windows::io::RawHandle,
    info_class: u32,
    buffer: &[u8],
) -> io::Result<()> {
    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }
    #[link(name = "ntdll")]
    extern "system" {
        fn NtSetInformationFile(
            file_handle: *mut std::ffi::c_void,
            io_status_block: *mut IoStatusBlock,
            file_information: *const std::ffi::c_void,
            length: u32,
            file_information_class: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    let mut iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let buf = buffer.to_vec();
    let status = unsafe {
        NtSetInformationFile(
            handle,
            &mut iosb,
            buf.as_ptr().cast(),
            buf.len() as u32,
            info_class,
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        let win32 = unsafe { RtlNtStatusToDosError(status) };
        if win32 == 0 || win32 == 0xFFFF_FFFF {
            Err(io::Error::from_raw_os_error(status))
        } else {
            Err(io::Error::from_raw_os_error(win32 as i32))
        }
    }
}
