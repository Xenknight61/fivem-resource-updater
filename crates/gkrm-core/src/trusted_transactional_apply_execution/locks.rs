//! Shared OS-level exclusive locks for Task 23 execution and Task 24 recovery.
//!
//! Lock-file existence is never ownership. Ownership is the live exclusive OS lock
//! held by an open capability.

use std::io::{Read, Write};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir as CapDir, File as CapFile, OpenOptions};

use crate::baseline::fs_security::{
    create_new_child_dir, create_new_file, try_open_child_dir, validate_single_component,
    verify_regular_file,
};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, Result, Sha256Digest, TransactionalApplyIoOperation};

use super::journal::{map_baseline_to_io, map_io};

const RESOURCE_LOCK_MAGIC: &[u8] = b"gkrm-resource-lock-v1\n";
const TRANSACTION_LOCK_MAGIC: &[u8] = b"gkrm-transaction-lock-v1\n";

/// Held exclusive locks. Dropping releases OS ownership; files persist.
pub(crate) struct HeldTransactionLocks {
    _resource: CapFile,
    _transaction: CapFile,
}

pub(crate) fn encode_resource_lock_id(resource_key: &str) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-resource-lock-id-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    enc.string(resource_key)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure)?;
    Ok(enc.finish())
}

fn ensure_locks_layout(root: &CapDir) -> Result<CapDir> {
    let locks = match try_open_child_dir(root, "locks").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
    })? {
        Some(d) => d,
        None => create_new_child_dir(root, "locks").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
        })?,
    };
    match try_open_child_dir(&locks, "resources").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
    })? {
        Some(d) => Ok(d),
        None => create_new_child_dir(&locks, "resources").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
        }),
    }
}

/// Acquire resource then transaction exclusive locks (fixed order).
#[allow(dead_code)] // retained for callers that already hold neither lock
pub(crate) fn acquire_resource_and_transaction_locks(
    transaction_root: &CapDir,
    resource_key: &str,
    txn_dir: &CapDir,
    plan_id: &Sha256Digest,
) -> Result<HeldTransactionLocks> {
    let resource_lock_id = encode_resource_lock_id(resource_key)?;
    let resources_dir = ensure_locks_layout(transaction_root)?;
    let resource_name = format!("{}.lock", resource_lock_id);
    // open_or_create_lock_file acquires the exclusive OS lock before returning.
    let resource = open_or_create_lock_file(
        &resources_dir,
        &resource_name,
        RESOURCE_LOCK_MAGIC,
        resource_lock_id.as_bytes(),
        TransactionalApplyIoOperation::AcquireResourceLock,
    )?;

    let txn_lock = open_or_create_lock_file(
        txn_dir,
        "recovery.lock",
        TRANSACTION_LOCK_MAGIC,
        plan_id.as_bytes(),
        TransactionalApplyIoOperation::AcquireTransactionLock,
    )?;

    Ok(HeldTransactionLocks {
        _resource: resource,
        _transaction: txn_lock,
    })
}

/// Acquire only the resource lock (before the published transaction directory exists).
pub(crate) fn acquire_resource_lock(
    transaction_root: &CapDir,
    resource_key: &str,
) -> Result<CapFile> {
    let resource_lock_id = encode_resource_lock_id(resource_key)?;
    let resources_dir = ensure_locks_layout(transaction_root)?;
    let resource_name = format!("{}.lock", resource_lock_id);
    // open_or_create_lock_file acquires the exclusive OS lock before returning.
    open_or_create_lock_file(
        &resources_dir,
        &resource_name,
        RESOURCE_LOCK_MAGIC,
        resource_lock_id.as_bytes(),
        TransactionalApplyIoOperation::AcquireResourceLock,
    )
}

/// Acquire the transaction lock while already holding the resource lock.
pub(crate) fn acquire_transaction_lock(
    txn_dir: &CapDir,
    plan_id: &Sha256Digest,
) -> Result<CapFile> {
    // open_or_create_lock_file acquires the exclusive OS lock before returning.
    open_or_create_lock_file(
        txn_dir,
        "recovery.lock",
        TRANSACTION_LOCK_MAGIC,
        plan_id.as_bytes(),
        TransactionalApplyIoOperation::AcquireTransactionLock,
    )
}

pub(crate) struct HeldSplitLocks {
    pub(crate) resource: CapFile,
    pub(crate) transaction: CapFile,
}

impl HeldSplitLocks {
    pub(crate) fn into_held(self) -> HeldTransactionLocks {
        HeldTransactionLocks {
            _resource: self.resource,
            _transaction: self.transaction,
        }
    }
}

fn open_or_create_lock_file(
    parent: &CapDir,
    name: &str,
    magic: &[u8],
    binding: &[u8],
    operation: TransactionalApplyIoOperation,
) -> Result<CapFile> {
    validate_single_component(name)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject)?;

    match try_open_lock_existing(parent, name, magic, binding, operation) {
        Ok(file) => return Ok(file),
        Err(GkrmError::TrustedTransactionalApplyExecutionIo {
            operation: op,
            kind: std::io::ErrorKind::NotFound,
        }) if op == operation => {}
        Err(e) => {
            // Missing via baseline mapper may also surface; try create path.
            if !is_not_found(&e) {
                return Err(e);
            }
        }
    }

    match create_new_file(parent, name) {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(magic);
            bytes.extend_from_slice(binding);
            file.write_all(&bytes).map_err(|e| map_io(operation, e))?;
            file.sync_all().map_err(|e| map_io(operation, e))?;
            drop(file);
            try_open_lock_existing(parent, name, magic, binding, operation)
        }
        Err(e) => {
            // Race: another process created it.
            if is_already_exists_baseline(&e) {
                try_open_lock_existing(parent, name, magic, binding, operation)
            } else {
                Err(map_baseline_to_io(operation, e))
            }
        }
    }
}

fn try_open_lock_existing(
    parent: &CapDir,
    name: &str,
    magic: &[u8],
    binding: &[u8],
    operation: TransactionalApplyIoOperation,
) -> Result<CapFile> {
    // Acquire the OS exclusive lock before reading contents. On Windows, LockFileEx
    // byte-range locks make ReadFile fail with ERROR_LOCK_VIOLATION on locked bytes;
    // validating before lock therefore mis-classified contention as generic I/O failure.
    let mut options = OpenOptions::new();
    options.read(true);
    options.write(true);
    options.follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|e| map_io(operation, e))?;
    verify_regular_file(&file, name)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject)?;
    try_lock_exclusive(&file, operation)?;
    use std::io::Seek;
    file.rewind().map_err(|e| map_io(operation, e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| map_io(operation, e))?;
    let expected_len = magic
        .len()
        .checked_add(binding.len())
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    if bytes.len() != expected_len || !bytes.starts_with(magic) || &bytes[magic.len()..] != binding
    {
        // Dropping the file releases the exclusive lock.
        return Err(GkrmError::TrustedTransactionalApplyExecutionLockBindingMismatch);
    }
    Ok(file)
}

fn try_lock_exclusive(file: &CapFile, operation: TransactionalApplyIoOperation) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock
            || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(libc::EAGAIN)
        {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLockContention);
        }
        return Err(map_io(operation, err));
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            h_event: *mut core::ffi::c_void,
        }
        extern "system" {
            fn LockFileEx(
                h_file: *mut core::ffi::c_void,
                dw_flags: u32,
                dw_reserved: u32,
                n_number_of_bytes_to_lock_low: u32,
                n_number_of_bytes_to_lock_high: u32,
                lp_overlapped: *mut Overlapped,
            ) -> i32;
            fn GetLastError() -> u32;
        }
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
        const ERROR_LOCK_VIOLATION: u32 = 33;
        const ERROR_IO_PENDING: u32 = 997;
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: core::ptr::null_mut(),
        };
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        // ERROR_LOCK_VIOLATION (33) is the normal contention code. Treat related
        // busy/sharing failures as closed contention rather than generic I/O.
        const ERROR_BUSY: u32 = 170;
        const ERROR_SHARING_VIOLATION: u32 = 32;
        if code == ERROR_LOCK_VIOLATION
            || code == ERROR_IO_PENDING
            || code == ERROR_BUSY
            || code == ERROR_SHARING_VIOLATION
        {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLockContention);
        }
        Err(map_io(
            operation,
            std::io::Error::from_raw_os_error(code as i32),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, operation);
        Err(GkrmError::TrustedTransactionalApplyExecutionLockUnsupported)
    }
}

fn is_not_found(err: &GkrmError) -> bool {
    matches!(
        err,
        GkrmError::TrustedTransactionalApplyExecutionIo {
            kind: std::io::ErrorKind::NotFound,
            ..
        }
    ) || matches!(err, GkrmError::BaselineStoreMissing { .. })
}

fn is_already_exists_baseline(err: &GkrmError) -> bool {
    match err {
        GkrmError::BaselineStoreIo { cause: source, .. } => {
            source.kind() == std::io::ErrorKind::AlreadyExists
        }
        _ => false,
    }
}
