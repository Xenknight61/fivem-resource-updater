//! 64-bit Windows handle-relative no-replace baseline publication.
//!
//! Task 11 baseline publication supports 64-bit Windows only. The native
//! `FILE_RENAME_INFORMATION` / `EX` and `IO_STATUS_BLOCK` layouts used here are
//! compile-time verified for that target. Non-64-bit Windows must fail closed
//! without attempting these layouts or ambient-path fallbacks.

use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};

use crate::baseline::id::BaselineId;
use crate::file_identity::{
    capture_stable_dir_identity, capture_stable_identity_from_raw_handle,
    is_windows_reparse_point_cap, StableFileIdentity,
};

use super::{
    is_already_exists, open_directory_by_file_id, open_source_directory_for_rename, OwnedWinHandle,
    FILE_LIST_DIRECTORY, FILE_TRAVERSE, SYNCHRONIZE,
};

/// Structured identity-change failure carried inside `io::Error` for publish mapping.
#[derive(Debug)]
pub(super) struct IdentityChangedError {
    pub(super) component: &'static str,
}

impl fmt::Display for IdentityChangedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gkrm-baseline-identity-changed:{}", self.component)
    }
}

impl std::error::Error for IdentityChangedError {}

fn identity_changed_io_error(component: &'static str) -> io::Error {
    io::Error::other(IdentityChangedError { component })
}

/// Explicit 64-bit Windows `FILE_RENAME_INFORMATION` / `FILE_RENAME_INFORMATION_EX` layout.
mod rename_layout_x64 {
    /// `Flags` (Ex) or `ReplaceIfExists` (legacy) field.
    pub const FLAGS_OR_REPLACE_OFFSET: usize = 0;
    pub const ROOT_DIRECTORY_OFFSET: usize = 8;
    pub const FILE_NAME_LENGTH_OFFSET: usize = 16;
    pub const FILE_NAME_OFFSET: usize = 20;
    pub const HEADER_SIZE: usize = 20;
}

/// Explicit 64-bit Windows `IO_STATUS_BLOCK` layout.
mod iosb_layout_x64 {
    pub const STATUS_OFFSET: usize = 0;
    pub const INFORMATION_OFFSET: usize = 8;
    pub const TOTAL_SIZE: usize = 16;
}

#[repr(C)]
struct IoStatusBlock {
    /// Union `{ NTSTATUS Status; PVOID Pointer; }` — pointer-sized on x64.
    status: isize,
    information: usize,
}

const _: () = {
    assert!(usize::BITS == 64);
    assert!(std::mem::size_of::<usize>() == 8);
    assert!(std::mem::size_of::<*mut std::ffi::c_void>() == 8);
    assert!(std::mem::size_of::<RawHandle>() == 8);
    assert!(rename_layout_x64::FLAGS_OR_REPLACE_OFFSET == 0);
    assert!(rename_layout_x64::ROOT_DIRECTORY_OFFSET == 8);
    assert!(rename_layout_x64::FILE_NAME_LENGTH_OFFSET == 16);
    assert!(rename_layout_x64::FILE_NAME_OFFSET == 20);
    assert!(rename_layout_x64::HEADER_SIZE == 20);
    assert!(rename_layout_x64::FILE_NAME_OFFSET == rename_layout_x64::HEADER_SIZE);
    assert!(iosb_layout_x64::STATUS_OFFSET == 0);
    assert!(iosb_layout_x64::INFORMATION_OFFSET == 8);
    assert!(iosb_layout_x64::TOTAL_SIZE == 16);
    assert!(std::mem::size_of::<IoStatusBlock>() == iosb_layout_x64::TOTAL_SIZE);
    assert!(std::mem::align_of::<IoStatusBlock>() == 8);
    assert!(std::mem::offset_of!(IoStatusBlock, status) == iosb_layout_x64::STATUS_OFFSET);
    assert!(
        std::mem::offset_of!(IoStatusBlock, information) == iosb_layout_x64::INFORMATION_OFFSET
    );
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsRenameInfoClass {
    /// Native `FileRenameInformationEx` (65).
    Ex,
    /// Native `FileRenameInformation` (10).
    Legacy,
}

impl WindowsRenameInfoClass {
    pub(super) fn native_class(self) -> u32 {
        match self {
            Self::Ex => 65,
            Self::Legacy => 10,
        }
    }
}

/// Private Windows-only seam around `NtSetInformationFile` rename outcomes.
pub(super) trait NativeRenameSyscall {
    fn set_rename_information(
        &self,
        source_handle: RawHandle,
        info_class: WindowsRenameInfoClass,
        buffer: &[u8],
    ) -> io::Result<()>;
}

struct RealNtSetInformationFile;

impl NativeRenameSyscall for RealNtSetInformationFile {
    fn set_rename_information(
        &self,
        source_handle: RawHandle,
        info_class: WindowsRenameInfoClass,
        buffer: &[u8],
    ) -> io::Result<()> {
        #[link(name = "ntdll")]
        extern "system" {
            fn NtSetInformationFile(
                file_handle: *mut std::ffi::c_void,
                io_status_block: *mut IoStatusBlock,
                file_information: *const std::ffi::c_void,
                length: u32,
                file_information_class: u32,
            ) -> i32;
        }

        let length = u32::try_from(buffer.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "rename information buffer is too large",
            )
        })?;
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                source_handle,
                &mut iosb,
                buffer.as_ptr().cast(),
                length,
                info_class.native_class(),
            )
        };
        if status >= 0 {
            Ok(())
        } else {
            Err(ntstatus_to_io_error(status))
        }
    }
}

fn ntstatus_to_io_error(status: i32) -> io::Error {
    #[link(name = "ntdll")]
    extern "system" {
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    let win32 = unsafe { RtlNtStatusToDosError(status) };
    if win32 == 0 || win32 == 0xFFFF_FFFF {
        io::Error::from_raw_os_error(status)
    } else {
        io::Error::from_raw_os_error(win32 as i32)
    }
}

/// Ex→legacy fallback only for clearly unsupported information-class results.
pub(super) fn is_file_rename_info_ex_unsupported(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(1 | 50))
}

pub(super) fn is_handle_relative_rename_unsupported(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported || matches!(error.raw_os_error(), Some(1 | 50))
}

/// Apply Ex-then-legacy rename policy through the private syscall seam.
pub(super) fn apply_rename_noreplace_policy<S: NativeRenameSyscall>(
    syscall: &S,
    source_handle: RawHandle,
    buffer: &[u8],
) -> io::Result<()> {
    match syscall.set_rename_information(source_handle, WindowsRenameInfoClass::Ex, buffer) {
        Ok(()) => Ok(()),
        Err(error) if is_already_exists(&error) => Err(error),
        Err(error) if is_file_rename_info_ex_unsupported(&error) => {
            match syscall.set_rename_information(
                source_handle,
                WindowsRenameInfoClass::Legacy,
                buffer,
            ) {
                Ok(()) => Ok(()),
                Err(legacy) if is_already_exists(&legacy) => Err(legacy),
                Err(legacy) if is_handle_relative_rename_unsupported(&legacy) => {
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "handle-relative no-replace rename is unsupported",
                    ))
                }
                Err(legacy) => Err(legacy),
            }
        }
        Err(error) if is_handle_relative_rename_unsupported(&error) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "handle-relative no-replace rename is unsupported",
        )),
        Err(error) => Err(error),
    }
}

fn validate_handle_relative_dest_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains(':')
        || name.contains('\0')
        || name.starts_with(r"\\")
        || name.starts_with("//")
        || !name.is_ascii()
        || name
            .chars()
            .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination FileName must be a relative lowercase hexadecimal baseline id",
        ));
    }
    let parsed = BaselineId::parse(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination FileName must be exactly one lowercase 64-character baseline id",
        )
    })?;
    if parsed.as_str() != name || name.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination FileName must be exactly one lowercase 64-character baseline id",
        ));
    }
    Ok(())
}

/// Checked allocation size for header + UTF-16 filename + optional NUL.
pub(super) fn checked_rename_allocation_size(utf16_code_units: usize) -> io::Result<usize> {
    let name_byte_len = utf16_code_units.checked_mul(2).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "UTF-16 byte length overflow")
    })?;
    let with_nul = name_byte_len.checked_add(2).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "rename buffer NUL space overflow",
        )
    })?;
    rename_layout_x64::HEADER_SIZE
        .checked_add(with_nul)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "rename buffer allocation size overflow",
            )
        })
}

/// Build a handle-relative rename buffer with compile-time layout offsets.
pub(super) fn build_handle_relative_rename_buffer(
    root_directory: RawHandle,
    relative_name: &str,
    use_ex: bool,
) -> io::Result<Vec<u8>> {
    if root_directory.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RootDirectory must be a verified destination directory handle",
        ));
    }
    validate_handle_relative_dest_name(relative_name)?;

    let utf16: Vec<u16> = relative_name.encode_utf16().collect();
    if utf16.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination FileName UTF-16 length must be 64 code units",
        ));
    }
    let name_byte_len = utf16.len().checked_mul(2).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "UTF-16 byte length overflow")
    })?;
    let name_byte_len_u32 = u32::try_from(name_byte_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "FileNameLength does not fit in u32",
        )
    })?;
    let total = checked_rename_allocation_size(utf16.len())?;
    let mut buffer = vec![0_u8; total];

    if use_ex {
        // Flags = 0 (no FILE_RENAME_FLAG_REPLACE_IF_EXISTS).
        buffer[rename_layout_x64::FLAGS_OR_REPLACE_OFFSET
            ..rename_layout_x64::FLAGS_OR_REPLACE_OFFSET + 4]
            .copy_from_slice(&0_u32.to_le_bytes());
    } else {
        // ReplaceIfExists = FALSE.
        buffer[rename_layout_x64::FLAGS_OR_REPLACE_OFFSET] = 0;
    }

    let root = root_directory as u64;
    buffer[rename_layout_x64::ROOT_DIRECTORY_OFFSET..rename_layout_x64::ROOT_DIRECTORY_OFFSET + 8]
        .copy_from_slice(&root.to_le_bytes());
    buffer[rename_layout_x64::FILE_NAME_LENGTH_OFFSET
        ..rename_layout_x64::FILE_NAME_LENGTH_OFFSET + 4]
        .copy_from_slice(&name_byte_len_u32.to_le_bytes());

    let name_start = rename_layout_x64::FILE_NAME_OFFSET;
    let name_end = name_start
        .checked_add(name_byte_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "filename range overflow"))?;
    let name_bytes =
        unsafe { std::slice::from_raw_parts(utf16.as_ptr().cast::<u8>(), name_byte_len) };
    buffer[name_start..name_end].copy_from_slice(name_bytes);
    // Optional NUL terminator is outside the declared FileNameLength range.
    let nul_offset = name_end;
    if nul_offset
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "NUL placement overflow"))?
        >= buffer.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rename buffer missing NUL terminator space",
        ));
    }
    buffer[nul_offset] = 0;
    buffer[nul_offset + 1] = 0;
    debug_assert_eq!(
        u32::from_le_bytes(
            buffer[rename_layout_x64::FILE_NAME_LENGTH_OFFSET
                ..rename_layout_x64::FILE_NAME_LENGTH_OFFSET + 4]
                .try_into()
                .unwrap()
        ) as usize,
        name_byte_len
    );
    debug_assert!(nul_offset >= name_start + name_byte_len);
    Ok(buffer)
}

#[cfg(test)]
thread_local! {
    static FORCE_SOURCE_IDENTITY_CHANGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FORCE_DEST_IDENTITY_CHANGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) struct IdentitySeamGuard {
    clear_source: bool,
    clear_dest: bool,
}

#[cfg(test)]
impl IdentitySeamGuard {
    pub(super) fn force_source_change() -> Self {
        FORCE_SOURCE_IDENTITY_CHANGE.with(|c| c.set(true));
        Self {
            clear_source: true,
            clear_dest: false,
        }
    }

    pub(super) fn force_dest_change() -> Self {
        FORCE_DEST_IDENTITY_CHANGE.with(|c| c.set(true));
        Self {
            clear_source: false,
            clear_dest: true,
        }
    }
}

#[cfg(test)]
impl Drop for IdentitySeamGuard {
    fn drop(&mut self) {
        if self.clear_source {
            FORCE_SOURCE_IDENTITY_CHANGE.with(|c| c.set(false));
        }
        if self.clear_dest {
            FORCE_DEST_IDENTITY_CHANGE.with(|c| c.set(false));
        }
    }
}

fn revalidate_identity(
    handle: RawHandle,
    expected: &StableFileIdentity,
    component: &'static str,
) -> io::Result<()> {
    #[cfg(test)]
    {
        let forced = match component {
            "source" => FORCE_SOURCE_IDENTITY_CHANGE.with(|c| c.get()),
            "destination" => FORCE_DEST_IDENTITY_CHANGE.with(|c| c.get()),
            _ => false,
        };
        if forced {
            return Err(identity_changed_io_error(component));
        }
    }
    let after = capture_stable_identity_from_raw_handle(handle)?;
    if &after != expected {
        return Err(identity_changed_io_error(component));
    }
    Ok(())
}

pub(super) fn windows_rename_noreplace_relative(
    source_parent: &cap_std::fs::Dir,
    source_name: &str,
    dest_parent: &cap_std::fs::Dir,
    dest_name: &str,
) -> io::Result<()> {
    windows_rename_noreplace_relative_with_syscall(
        source_parent,
        source_name,
        dest_parent,
        dest_name,
        &RealNtSetInformationFile,
    )
}

pub(super) fn windows_rename_noreplace_relative_with_syscall<S: NativeRenameSyscall>(
    source_parent: &cap_std::fs::Dir,
    source_name: &str,
    dest_parent: &cap_std::fs::Dir,
    dest_name: &str,
    syscall: &S,
) -> io::Result<()> {
    validate_handle_relative_dest_name(dest_name)?;

    let dest_meta = dest_parent.dir_metadata()?;
    if !dest_meta.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination capability is not a directory",
        ));
    }
    if is_windows_reparse_point_cap(&dest_meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination capability is a reparse point",
        ));
    }
    let dest_identity = capture_stable_dir_identity(dest_parent)?;

    let dest_root_handle = dest_parent.as_raw_handle();
    if dest_root_handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "destination capability handle is unavailable for handle-relative rename",
        ));
    }

    let dest_root_owned = open_directory_by_file_id(
        dest_root_handle,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
    )
    .ok();
    let root_handle = dest_root_owned
        .as_ref()
        .map(OwnedWinHandle::as_raw_handle)
        .unwrap_or(dest_root_handle);

    // Open the exact temporary source once; retain this handle through the syscall.
    let source = open_source_directory_for_rename(source_parent, source_name)?;
    let source_handle = source.as_raw_handle();
    if source_handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "source temporary handle is unavailable for handle-relative rename",
        ));
    }
    let source_identity = capture_stable_identity_from_raw_handle(source_handle)?;

    revalidate_identity(dest_parent.as_raw_handle(), &dest_identity, "destination")?;
    revalidate_identity(source_handle, &source_identity, "source")?;

    // Prefer Ex layout flags field; legacy ReplaceIfExists is also FALSE at the same offset.
    let buffer = build_handle_relative_rename_buffer(root_handle, dest_name, true)?;
    retry_retained_rename(
        || apply_rename_noreplace_policy(syscall, source_handle, &buffer),
        || {
            revalidate_identity(dest_parent.as_raw_handle(), &dest_identity, "destination")?;
            revalidate_identity(source_handle, &source_identity, "source")?;
            // A retained source handle alone does not prove its original name still selects it.
            let named = open_source_directory_for_rename(source_parent, source_name)?;
            if capture_stable_identity_from_raw_handle(named.as_raw_handle())? != source_identity {
                return Err(identity_changed_io_error("source"));
            }
            Ok(())
        },
        std::thread::sleep,
    )
}

/// Windows refuses a directory rename while a descendant is open. A short-lived reader can
/// therefore deny publication even after all of our own readers have closed. Retry the exact
/// no-replace operation with retained capabilities; never treat access denial as unsupported,
/// switch to ambient paths, replace a destination, or continue after failed identity checks.
fn retry_retained_rename(
    mut rename: impl FnMut() -> io::Result<()>,
    mut validate: impl FnMut() -> io::Result<()>,
    mut pause: impl FnMut(std::time::Duration),
) -> io::Result<()> {
    const DELAYS_MS: [u64; 6] = [1, 4, 16, 64, 128, 256];
    for delay in DELAYS_MS {
        validate()?;
        match rename() {
            Ok(()) => return Ok(()),
            Err(error) if matches!(error.raw_os_error(), Some(5 | 32 | 33)) => {
                pause(std::time::Duration::from_millis(delay));
            }
            Err(error) => return Err(error),
        }
    }
    validate()?;
    rename()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use cap_fs_ext::ambient_authority;
    use cap_std::fs::Dir as CapDir;
    use tempfile::tempdir;

    fn sample_baseline_id() -> String {
        "ab".repeat(32)
    }

    #[derive(Clone)]
    struct ScriptedSyscall {
        ex: i32,
        legacy: i32,
        calls: Rc<RefCell<Vec<WindowsRenameInfoClass>>>,
        source_handles: Rc<RefCell<Vec<usize>>>,
    }

    impl ScriptedSyscall {
        fn new(ex: i32, legacy: i32) -> Self {
            Self {
                ex,
                legacy,
                calls: Rc::new(RefCell::new(Vec::new())),
                source_handles: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl NativeRenameSyscall for ScriptedSyscall {
        fn set_rename_information(
            &self,
            source_handle: RawHandle,
            info_class: WindowsRenameInfoClass,
            _buffer: &[u8],
        ) -> io::Result<()> {
            self.calls.borrow_mut().push(info_class);
            self.source_handles
                .borrow_mut()
                .push(source_handle as usize);
            let code = match info_class {
                WindowsRenameInfoClass::Ex => self.ex,
                WindowsRenameInfoClass::Legacy => self.legacy,
            };
            if code == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(code))
            }
        }
    }

    #[test]
    fn layout_constants_match_x64_windows() {
        assert_eq!(std::mem::size_of::<usize>(), 8);
        assert_eq!(std::mem::size_of::<RawHandle>(), 8);
        assert_eq!(rename_layout_x64::FLAGS_OR_REPLACE_OFFSET, 0);
        assert_eq!(rename_layout_x64::ROOT_DIRECTORY_OFFSET, 8);
        assert_eq!(rename_layout_x64::FILE_NAME_LENGTH_OFFSET, 16);
        assert_eq!(rename_layout_x64::FILE_NAME_OFFSET, 20);
        assert_eq!(std::mem::size_of::<IoStatusBlock>(), 16);
        assert_eq!(std::mem::align_of::<IoStatusBlock>(), 8);
        assert_eq!(WindowsRenameInfoClass::Ex.native_class(), 65);
        assert_eq!(WindowsRenameInfoClass::Legacy.native_class(), 10);
    }

    #[test]
    fn rename_buffer_layout_ex_and_legacy_values() {
        let dest_name = sample_baseline_id();
        let sentinel = 0x1122_3344_5566_7788_u64 as usize as RawHandle;
        assert!(!sentinel.is_null());
        let ex = build_handle_relative_rename_buffer(sentinel, &dest_name, true).expect("ex");
        assert_eq!(
            u32::from_le_bytes(ex[0..4].try_into().unwrap()),
            0,
            "Ex Flags must be 0"
        );
        let root = u64::from_le_bytes(ex[8..16].try_into().unwrap());
        assert_eq!(root, sentinel as u64);
        assert_ne!(root, 0);
        let name_len = u32::from_le_bytes(ex[16..20].try_into().unwrap()) as usize;
        assert_eq!(name_len, 128);
        let expected: Vec<u8> = dest_name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(&ex[20..20 + name_len], expected.as_slice());
        assert_eq!(ex[20 + name_len], 0);
        assert_eq!(ex[20 + name_len + 1], 0);
        assert_eq!(ex.len(), 20 + 128 + 2);
        assert!(!dest_name.contains('\\') && !dest_name.contains('/'));

        let legacy =
            build_handle_relative_rename_buffer(sentinel, &dest_name, false).expect("legacy");
        assert_eq!(legacy[0], 0, "ReplaceIfExists must be FALSE");
        assert_eq!(
            u64::from_le_bytes(legacy[8..16].try_into().unwrap()),
            sentinel as u64
        );
        assert_eq!(u32::from_le_bytes(legacy[16..20].try_into().unwrap()), 128);
    }

    #[test]
    fn rename_buffer_rejects_null_separators_and_overflow() {
        let id = sample_baseline_id();
        let err =
            build_handle_relative_rename_buffer(std::ptr::null_mut(), &id, true).expect_err("null");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let sentinel = std::ptr::dangling_mut::<std::ffi::c_void>();
        for bad in [
            format!(r"C:\store\{id}"),
            format!(r"\\?\C:\store\{id}"),
            "child2".to_owned(),
            "AB".repeat(32),
            format!("{id}/x"),
            format!("{id}:x"),
        ] {
            let err = build_handle_relative_rename_buffer(sentinel, &bad, true)
                .expect_err("rejected name");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "bad={bad}");
        }

        assert!(checked_rename_allocation_size(usize::MAX / 2 + 1).is_err());
        assert!(checked_rename_allocation_size(usize::MAX).is_err());
    }

    #[test]
    fn ex_unsupported_falls_back_to_legacy_only_for_1_or_50() {
        for code in [1_i32, 50] {
            let scripted = ScriptedSyscall::new(code, 0);
            apply_rename_noreplace_policy(&scripted, std::ptr::null_mut(), &[])
                .expect("legacy success");
            assert_eq!(
                *scripted.calls.borrow(),
                [WindowsRenameInfoClass::Ex, WindowsRenameInfoClass::Legacy]
            );
        }
    }

    #[test]
    fn no_legacy_fallback_for_non_unsupported_ex_errors() {
        for code in [80_i32, 183, 5, 6, 32, 87, 1234] {
            let scripted = ScriptedSyscall::new(code, 0);
            let err = apply_rename_noreplace_policy(&scripted, std::ptr::null_mut(), &[])
                .expect_err("must not fall back");
            assert_eq!(*scripted.calls.borrow(), [WindowsRenameInfoClass::Ex]);
            assert_eq!(err.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn both_classes_unsupported_returns_unsupported() {
        let scripted = ScriptedSyscall::new(50, 50);
        let err = apply_rename_noreplace_policy(&scripted, std::ptr::null_mut(), &[])
            .expect_err("unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            *scripted.calls.borrow(),
            [WindowsRenameInfoClass::Ex, WindowsRenameInfoClass::Legacy]
        );
    }

    #[test]
    fn target_exists_skips_legacy_and_preserves_os_error() {
        for code in [80_i32, 183] {
            let scripted = ScriptedSyscall::new(code, 0);
            let err = apply_rename_noreplace_policy(&scripted, std::ptr::null_mut(), &[])
                .expect_err("exists");
            assert_eq!(*scripted.calls.borrow(), [WindowsRenameInfoClass::Ex]);
            assert!(is_already_exists(&err));
            assert_eq!(err.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn renames_directory_between_sibling_parents() {
        let temp = tempdir().expect("temp");
        let root = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open root");
        root.create_dir("a").expect("a");
        root.create_dir("b").expect("b");
        let a = root.open_dir("a").expect("open a");
        a.create_dir("child").expect("child");
        drop(a);
        let a = root.open_dir("a").expect("reopen a");
        let b = root.open_dir("b").expect("open b");
        let dest_name = sample_baseline_id();
        windows_rename_noreplace_relative(&a, "child", &b, &dest_name)
            .unwrap_or_else(|error| panic!("rename failed: {error:?}"));
        assert!(temp.path().join("b").join(&dest_name).is_dir());
        assert!(!temp.path().join("a").join("child").exists());
    }

    #[test]
    fn rename_noreplace_does_not_overwrite() {
        let temp = tempdir().expect("temp");
        let root = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open root");
        root.create_dir("a").expect("a");
        root.create_dir("b").expect("b");
        let dest_name = sample_baseline_id();
        let a = root.open_dir("a").expect("open a");
        a.create_dir("child").expect("child");
        drop(a);
        let b = root.open_dir("b").expect("open b");
        b.create_dir(&dest_name).expect("existing dest");
        drop(b);
        let a = root.open_dir("a").expect("reopen a");
        let b = root.open_dir("b").expect("reopen b");
        let err = windows_rename_noreplace_relative(&a, "child", &b, &dest_name)
            .expect_err("must not overwrite");
        assert!(temp.path().join("a").join("child").is_dir());
        assert!(temp.path().join("b").join(&dest_name).is_dir());
        assert!(
            err.raw_os_error() == Some(80)
                || err.raw_os_error() == Some(183)
                || err.kind() == io::ErrorKind::AlreadyExists,
            "expected already-exists semantics, got {err:?}"
        );
    }

    #[test]
    fn source_handle_retained_and_identity_revalidated_before_syscall() {
        let temp = tempdir().expect("temp");
        let root = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open root");
        root.create_dir("a").expect("a");
        root.create_dir("b").expect("b");
        let a = root.open_dir("a").expect("open a");
        a.create_dir("child").expect("child");
        drop(a);
        let a = root.open_dir("a").expect("reopen a");
        let b = root.open_dir("b").expect("open b");
        let dest_name = sample_baseline_id();
        let scripted = ScriptedSyscall::new(0, 0);
        windows_rename_noreplace_relative_with_syscall(&a, "child", &b, &dest_name, &scripted)
            .expect("scripted rename");
        let handles = scripted.source_handles.borrow().clone();
        assert_eq!(handles.len(), 1);
        assert_ne!(handles[0], 0, "source handle must be non-null");
        // Scripted success does not move the directory; source still present proves no real publish.
        assert!(temp.path().join("a").join("child").is_dir());
        assert!(!temp.path().join("b").join(&dest_name).exists());
    }

    #[test]
    fn source_identity_change_aborts_before_syscall() {
        let temp = tempdir().expect("temp");
        let root = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open root");
        root.create_dir("a").expect("a");
        root.create_dir("b").expect("b");
        let a = root.open_dir("a").expect("open a");
        a.create_dir("child").expect("child");
        drop(a);
        let a = root.open_dir("a").expect("reopen a");
        let b = root.open_dir("b").expect("open b");
        let dest_name = sample_baseline_id();
        let scripted = ScriptedSyscall::new(0, 0);
        let _guard = IdentitySeamGuard::force_source_change();
        let err =
            windows_rename_noreplace_relative_with_syscall(&a, "child", &b, &dest_name, &scripted)
                .expect_err("identity change");
        assert!(scripted.calls.borrow().is_empty(), "syscall must not run");
        assert!(err
            .get_ref()
            .and_then(|e| e.downcast_ref::<IdentityChangedError>())
            .is_some_and(|e| e.component == "source"));
        assert!(temp.path().join("a").join("child").is_dir());
        assert!(!temp.path().join("b").join(&dest_name).exists());
    }

    #[test]
    fn destination_identity_change_aborts_before_syscall() {
        let temp = tempdir().expect("temp");
        let root = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open root");
        root.create_dir("a").expect("a");
        root.create_dir("b").expect("b");
        let a = root.open_dir("a").expect("open a");
        a.create_dir("child").expect("child");
        drop(a);
        let a = root.open_dir("a").expect("reopen a");
        let b = root.open_dir("b").expect("open b");
        let dest_name = sample_baseline_id();
        let scripted = ScriptedSyscall::new(0, 0);
        let _guard = IdentitySeamGuard::force_dest_change();
        let err =
            windows_rename_noreplace_relative_with_syscall(&a, "child", &b, &dest_name, &scripted)
                .expect_err("identity change");
        assert!(scripted.calls.borrow().is_empty(), "syscall must not run");
        assert!(err
            .get_ref()
            .and_then(|e| e.downcast_ref::<IdentityChangedError>())
            .is_some_and(|e| e.component == "destination"));
        assert!(temp.path().join("a").join("child").is_dir());
        assert!(!temp.path().join("b").join(&dest_name).exists());
    }

    #[test]
    fn real_descendant_reader_can_close_between_retained_rename_attempts() {
        use std::os::windows::fs::OpenOptionsExt;
        let temp = tempdir().expect("temp");
        std::fs::create_dir_all(temp.path().join("a/child")).expect("source");
        std::fs::create_dir(temp.path().join("b")).expect("destination");
        std::fs::write(temp.path().join("a/child/content"), b"original").expect("content");
        let root = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("root");
        let a = root.open_dir("a").expect("a");
        let b = root.open_dir("b").expect("b");
        let source = open_source_directory_for_rename(&a, "child").expect("source handle");
        let identity =
            capture_stable_identity_from_raw_handle(source.as_raw_handle()).expect("identity");
        let name = sample_baseline_id();
        let buffer =
            build_handle_relative_rename_buffer(b.as_raw_handle(), &name, true).expect("buffer");
        let mut reader = Some(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(temp.path().join("a/child/content"))
                .expect("reader"),
        );
        let attempts = std::cell::Cell::new(0);
        retry_retained_rename(
            || {
                attempts.set(attempts.get() + 1);
                apply_rename_noreplace_policy(
                    &RealNtSetInformationFile,
                    source.as_raw_handle(),
                    &buffer,
                )
            },
            || revalidate_identity(source.as_raw_handle(), &identity, "source"),
            |_| {
                drop(reader.take());
            },
        )
        .expect("published after reader closes");
        assert!(attempts.get() >= 2);
        assert!(!temp.path().join("a/child").exists());
        assert_eq!(
            std::fs::read(temp.path().join("b").join(name).join("content")).expect("published"),
            b"original"
        );
    }

    #[test]
    fn transient_rename_denials_retry_the_same_operation_after_validation() {
        let calls = std::cell::Cell::new(0);
        let validations = std::cell::Cell::new(0);
        let mut delays = Vec::new();
        retry_retained_rename(
            || {
                calls.set(calls.get() + 1);
                match calls.get() {
                    1 => Err(io::Error::from_raw_os_error(5)),
                    2 => Err(io::Error::from_raw_os_error(32)),
                    _ => Ok(()),
                }
            },
            || {
                validations.set(validations.get() + 1);
                Ok(())
            },
            |delay| delays.push(delay),
        )
        .expect("retry");
        assert_eq!(calls.get(), 3);
        assert_eq!(validations.get(), 3);
        assert_eq!(
            delays,
            [
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(4)
            ]
        );
    }

    #[test]
    fn permanent_rename_denial_is_bounded_and_returned() {
        let calls = std::cell::Cell::new(0);
        let error = retry_retained_rename(
            || {
                calls.set(calls.get() + 1);
                Err(io::Error::from_raw_os_error(5))
            },
            || Ok(()),
            |_| {},
        )
        .expect_err("denied");
        assert_eq!(calls.get(), 7);
        assert_eq!(error.raw_os_error(), Some(5));
    }

    #[test]
    fn retry_stops_before_another_syscall_on_identity_change() {
        let calls = std::cell::Cell::new(0);
        let checks = std::cell::Cell::new(0);
        let error = retry_retained_rename(
            || {
                calls.set(calls.get() + 1);
                Err(io::Error::from_raw_os_error(5))
            },
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(identity_changed_io_error("source"))
                } else {
                    Ok(())
                }
            },
            |_| {},
        )
        .expect_err("identity");
        assert_eq!(calls.get(), 1);
        assert!(error
            .get_ref()
            .and_then(|e| e.downcast_ref::<IdentityChangedError>())
            .is_some());
    }

    #[test]
    fn destination_collision_and_unrelated_errors_are_never_retried() {
        for code in [80, 183, 50, 87, 2] {
            let calls = std::cell::Cell::new(0);
            let error = retry_retained_rename(
                || {
                    calls.set(calls.get() + 1);
                    Err(io::Error::from_raw_os_error(code))
                },
                || Ok(()),
                |_| panic!("unexpected pause"),
            )
            .expect_err("rejected");
            assert_eq!(calls.get(), 1);
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn production_impl_compiled_only_for_64_bit_windows() {
        const _: () = assert!(cfg!(all(windows, target_pointer_width = "64")));
    }
}
