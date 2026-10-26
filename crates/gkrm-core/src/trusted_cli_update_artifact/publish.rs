//! Secure no-replace publication for CLI artifacts and decision documents.
//!
//! Uses same-directory file rename (not baseline directory rename).

use std::io::{self, Read, Write};
use std::path::{Component, Path};

use cap_fs_ext::ambient_authority;
use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{
    create_new_file, dir_identity, open_existing_directory, open_file_nofollow,
    validate_single_component, verify_regular_file,
};
use crate::baseline::store::{allocate_temp_name, fsync_file, sync_dir};
use crate::{GkrmError, Result};

#[cfg(test)]
thread_local! {
    static PUBLISH_PARENT_SYNC_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PUBLISH_POST_VERIFY_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_publish_parent_sync_fault(enabled: bool) {
    PUBLISH_PARENT_SYNC_FAULT.with(|c| c.set(enabled));
}

#[cfg(test)]
pub(crate) fn set_publish_post_verify_fault(enabled: bool) {
    PUBLISH_POST_VERIFY_FAULT.with(|c| c.set(enabled));
}

#[cfg(test)]
fn publish_parent_sync_fault_enabled() -> bool {
    PUBLISH_PARENT_SYNC_FAULT.with(|c| c.get())
}

#[cfg(test)]
fn publish_post_verify_fault_enabled() -> bool {
    PUBLISH_POST_VERIFY_FAULT.with(|c| c.get())
}

struct PublishedFileGuard<'a> {
    parent: &'a CapDir,
    file_name: &'a str,
    armed: bool,
}

impl<'a> PublishedFileGuard<'a> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<'a> Drop for PublishedFileGuard<'a> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.parent.remove_file(self.file_name);
        }
    }
}

pub(crate) fn publish_bytes_no_replace(destination: &Path, bytes: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
    let file_name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
    validate_single_component(file_name)
        .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    for component in destination.components() {
        match component {
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {}
            Component::CurDir | Component::ParentDir => {
                return Err(GkrmError::TrustedCliUpdateSecurityRejection);
            }
        }
    }

    let parent_open = open_existing_directory(parent, "cli-output-parent")
        .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    let parent_identity = dir_identity(&parent_open.dir, "cli-output-parent")
        .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    if parent_open.dir.exists(file_name) {
        return Err(GkrmError::TrustedCliUpdateDestinationExists);
    }

    let tmp_name =
        allocate_temp_name(&parent_open.dir).map_err(|_| GkrmError::TrustedCliUpdateIo {
            kind: std::io::ErrorKind::Other,
        })?;
    let write_result = (|| -> Result<()> {
        let mut file = create_new_file(&parent_open.dir, &tmp_name)
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
        file.write_all(bytes)
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
        file.flush()
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
        fsync_file(&file, "cli-output-temp").map_err(|_| GkrmError::TrustedCliUpdateIo {
            kind: std::io::ErrorKind::Other,
        })?;
        drop(file);

        let mut reopened = open_file_nofollow(&parent_open.dir, &tmp_name)
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
        verify_regular_file(&reopened, &tmp_name)
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
        let mut got = Vec::new();
        reopened
            .read_to_end(&mut got)
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
        if got.as_slice() != bytes {
            return Err(GkrmError::TrustedCliUpdateSecurityRejection);
        }
        drop(reopened);

        // Point-of-use: parent identity must still match before rename publication.
        let parent_now = dir_identity(&parent_open.dir, "cli-output-parent")
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
        if parent_now != parent_identity {
            return Err(GkrmError::TrustedCliUpdateSecurityRejection);
        }

        rename_file_noreplace(&parent_open.dir, &tmp_name, file_name).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                GkrmError::TrustedCliUpdateDestinationExists
            } else {
                GkrmError::TrustedCliUpdateIo { kind: e.kind() }
            }
        })?;

        // Arm guard infallibly immediately after rename with no intervening code.
        let mut published_guard = PublishedFileGuard {
            parent: &parent_open.dir,
            file_name,
            armed: true,
        };

        #[cfg(test)]
        if publish_parent_sync_fault_enabled() {
            return Err(GkrmError::TrustedCliUpdateIo {
                kind: std::io::ErrorKind::Other,
            });
        }

        sync_dir(&parent_open.dir, "cli-output-parent").map_err(|_| {
            GkrmError::TrustedCliUpdateIo {
                kind: std::io::ErrorKind::Other,
            }
        })?;

        #[cfg(test)]
        if publish_post_verify_fault_enabled() {
            return Err(GkrmError::TrustedCliUpdateSecurityRejection);
        }

        let mut published = open_file_nofollow(&parent_open.dir, file_name)
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
        verify_regular_file(&published, file_name)
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
        let mut published_bytes = Vec::new();
        published
            .read_to_end(&mut published_bytes)
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
        if published_bytes.as_slice() != bytes {
            return Err(GkrmError::TrustedCliUpdateSecurityRejection);
        }

        published_guard.disarm();
        Ok(())
    })();

    if write_result.is_err() {
        let _ = parent_open.dir.remove_file(&tmp_name);
    }
    write_result
}

pub(crate) fn rename_file_noreplace(parent: &CapDir, src: &str, dest: &str) -> io::Result<()> {
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
        windows_rename_file_noreplace(parent, src, dest)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (parent, src, dest);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no-replace file rename unsupported",
        ))
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn windows_rename_file_noreplace(parent: &CapDir, src: &str, dest: &str) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    use cap_fs_ext::{FollowSymlinks, OpenOptionsExt, OpenOptionsFollowExt};
    use cap_std::fs::OpenOptions;

    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_RENAME_INFORMATION: u32 = 10;
    const FILE_RENAME_INFORMATION_EX: u32 = 65;
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
    // Flags = 0 → no REPLACE_IF_EXISTS.
    buffer[0..4].copy_from_slice(&0_u32.to_le_bytes());
    buffer[8..16].copy_from_slice(&(root_handle as u64).to_le_bytes());
    buffer[16..20].copy_from_slice(&(name_byte_len as u32).to_le_bytes());
    let name_bytes =
        unsafe { std::slice::from_raw_parts(utf16.as_ptr().cast::<u8>(), name_byte_len) };
    buffer[20..20 + name_byte_len].copy_from_slice(name_bytes);

    match nt_set_rename(source.as_raw_handle(), FILE_RENAME_INFORMATION_EX, &buffer) {
        Ok(()) => Ok(()),
        Err(err) if matches!(err.raw_os_error(), Some(1 | 50)) => {
            buffer[0] = 0;
            buffer[1] = 0;
            buffer[2] = 0;
            buffer[3] = 0;
            nt_set_rename(source.as_raw_handle(), FILE_RENAME_INFORMATION, &buffer)
        }
        Err(err) => Err(err),
    }
}

#[cfg(all(windows, not(target_pointer_width = "64")))]
fn windows_rename_file_noreplace(parent: &CapDir, src: &str, dest: &str) -> io::Result<()> {
    let _ = (parent, src, dest);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic file rename requires 64-bit Windows",
    ))
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

pub(crate) fn read_regular_file_limited(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let parent = path
        .parent()
        .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
    validate_single_component(name).map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    let parent_open = open_existing_directory(parent, "cli-input-parent")
        .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    let mut file = open_file_nofollow(&parent_open.dir, name)
        .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    verify_regular_file(&file, name).map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    if bytes.len() > max_bytes {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes",
        });
    }
    Ok(bytes)
}

pub(crate) fn paths_overlap(a: &Path, b: &Path) -> Result<bool> {
    // Fail closed when a path cannot be resolved to an existing ancestor.
    // Non-existent leaf outputs (artifact/decisions targets) resolve via parent + name.
    let a = canonicalize_for_overlap(a)?;
    let b = canonicalize_for_overlap(b)?;
    Ok(a.starts_with(&b) || b.starts_with(&a))
}

fn canonicalize_for_overlap(path: &Path) -> Result<std::path::PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(_) => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
            let parent = std::fs::canonicalize(parent)
                .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
            let name = path
                .file_name()
                .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
            Ok(parent.join(name))
        }
    }
}

pub(crate) fn ensure_output_disjoint(output: &Path, protected: &[&Path]) -> Result<()> {
    let _ = ambient_authority();
    for p in protected {
        if paths_overlap(output, p)? {
            return Err(GkrmError::TrustedCliUpdatePathOverlap);
        }
        if let Some(parent) = output.parent() {
            if paths_overlap(parent, p)? {
                let par = canonicalize_for_overlap(parent)?;
                let prot = canonicalize_for_overlap(p)?;
                if par == prot || par.starts_with(&prot) {
                    return Err(GkrmError::TrustedCliUpdatePathOverlap);
                }
            }
        }
    }
    Ok(())
}
