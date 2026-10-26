use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::baseline::blob_provider::{
    copy_verified_blob_to_writer, InMemoryBlobProvider, VerifiedBaselineBlobProvider,
};
use crate::baseline::dto::{decode_baseline_document, encode_baseline_json};
use crate::baseline::fs_security::{
    capture_file_identity, create_new_child_dir, create_new_file, dir_identity, ensure_child_dir,
    open_child_dir, open_existing_store_root, open_file_nofollow,
    open_or_create_store_root_for_write, remove_temp_child_nofollow, try_open_child_dir,
    verify_regular_file, OpenStoreRoot,
};
use crate::baseline::id::BaselineId;
use crate::baseline::key::SafeResourceKey;
use crate::baseline::model::{
    BaselineStoreLimits, StoredBaseline, StoredBaselineLocator, ValidatedBaselineBundle,
};
use crate::{GkrmError, Result, Sha256Digest};

#[cfg(test)]
use std::sync::{Mutex, MutexGuard};
#[cfg(test)]
use std::thread::ThreadId;

/// 64-bit Windows handle-relative no-replace publication (Task 11).
#[cfg(all(windows, target_pointer_width = "64"))]
#[path = "windows_publish.rs"]
mod windows_publish;

const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[cfg(test)]
type BeforeBlobIdentityRevalidationHook = Box<dyn FnOnce() + Send>;

#[cfg(test)]
struct StreamVerifiedBlobIdentityHookState {
    owner: ThreadId,
    hook: Option<BeforeBlobIdentityRevalidationHook>,
}

#[cfg(test)]
static STREAM_VERIFIED_BLOB_IDENTITY_HOOK_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static BEFORE_BLOB_IDENTITY_REVALIDATION_HOOK: Mutex<Option<StreamVerifiedBlobIdentityHookState>> =
    Mutex::new(None);

#[cfg(test)]
fn lock_blob_identity_hook_state(
) -> MutexGuard<'static, Option<StreamVerifiedBlobIdentityHookState>> {
    BEFORE_BLOB_IDENTITY_REVALIDATION_HOOK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) struct StreamVerifiedBlobIdentityHookGuard {
    _guard: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for StreamVerifiedBlobIdentityHookGuard {
    fn drop(&mut self) {
        clear_before_blob_identity_revalidation_hook();
    }
}

#[cfg(test)]
pub(crate) fn lock_stream_verified_blob_identity_hook() -> StreamVerifiedBlobIdentityHookGuard {
    let guard = STREAM_VERIFIED_BLOB_IDENTITY_HOOK_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_before_blob_identity_revalidation_hook();
    *lock_blob_identity_hook_state() = Some(StreamVerifiedBlobIdentityHookState {
        owner: std::thread::current().id(),
        hook: None,
    });
    StreamVerifiedBlobIdentityHookGuard { _guard: guard }
}

#[cfg(test)]
pub(crate) fn set_before_blob_identity_revalidation_hook(hook: impl FnOnce() + Send + 'static) {
    let mut state = lock_blob_identity_hook_state();
    let Some(state) = state.as_mut() else {
        return;
    };
    if state.owner == std::thread::current().id() {
        state.hook = Some(Box::new(hook));
    }
}

#[cfg(test)]
fn clear_before_blob_identity_revalidation_hook() {
    *lock_blob_identity_hook_state() = None;
}

#[cfg(test)]
fn run_before_blob_identity_revalidation_hook() {
    let hook = {
        let mut state = lock_blob_identity_hook_state();
        state
            .as_mut()
            .filter(|state| state.owner == std::thread::current().id())
            .and_then(|state| state.hook.take())
    };
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_before_blob_identity_revalidation_hook() {}

/// Atomically publish a validated official baseline into the local store.
pub(crate) fn write_baseline_bundle<P: VerifiedBaselineBlobProvider>(
    store_root: &Path,
    bundle: &ValidatedBaselineBundle,
    blobs: &P,
    limits: BaselineStoreLimits,
) -> Result<StoredBaselineLocator> {
    limits.validate()?;
    let json = encode_baseline_json(bundle)?;
    if json.len() as u64 > limits.max_manifest_bytes() {
        return Err(GkrmError::BaselineManifestLimitExceeded {
            limit: limits.max_manifest_bytes(),
            actual: json.len() as u64,
        });
    }

    let store = open_or_create_store_root_for_write(store_root)?;
    let tmp_root = ensure_child_dir(&store.dir, ".tmp")?;
    let baselines_root = ensure_child_dir(&store.dir, "baselines")?;
    let key_dir = ensure_child_dir(&baselines_root, bundle.resource_key().as_str())?;

    if let Some(_existing) = try_open_child_dir(&key_dir, bundle.baseline_id().as_str())? {
        return finish_existing_target(&store, &key_dir, bundle, limits);
    }

    let temp_name = allocate_temp_name(&tmp_root)?;
    let temp_dir = create_new_child_dir(&tmp_root, &temp_name)?;

    let write_result = write_temp_and_publish(
        &store, &tmp_root, temp_dir, &temp_name, &key_dir, bundle, blobs, &json, limits,
    );

    if write_result.is_err() {
        let _ = remove_temp_child_nofollow(&tmp_root, &temp_name);
    }

    write_result
}

#[allow(clippy::too_many_arguments)]
fn write_temp_and_publish<P: VerifiedBaselineBlobProvider>(
    store: &OpenStoreRoot,
    tmp_root: &cap_std::fs::Dir,
    temp_dir: cap_std::fs::Dir,
    temp_name: &str,
    key_dir: &cap_std::fs::Dir,
    bundle: &ValidatedBaselineBundle,
    blobs: &P,
    json: &[u8],
    limits: BaselineStoreLimits,
) -> Result<StoredBaselineLocator> {
    let tmp_identity = dir_identity(tmp_root, ".tmp")?;
    let key_identity = dir_identity(key_dir, "baselines")?;

    {
        let blobs_dir = create_new_child_dir(&temp_dir, "blobs")?;
        for (digest, expected_size) in bundle.blob_sizes() {
            write_blob_from_provider(&blobs_dir, digest, *expected_size, blobs, limits)?;
        }
        sync_dir(&blobs_dir, "blobs")?;
    }

    {
        let mut manifest = create_new_file(&temp_dir, "baseline.json")?;
        let before = capture_file_identity(&manifest, "baseline.json")?;
        manifest
            .write_all(json)
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: "baseline.json".to_owned(),
                cause: source,
            })?;
        manifest
            .flush()
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: "baseline.json".to_owned(),
                cause: source,
            })?;
        fsync_file(&manifest, "baseline.json")?;
        drop(manifest);
        let after_file = open_file_nofollow(&temp_dir, "baseline.json")?;
        let after = capture_file_identity(&after_file, "baseline.json")?;
        drop(after_file);
        if before != after {
            return Err(GkrmError::BaselineIncompleteTemporary);
        }
    }

    sync_dir(&temp_dir, ".tmp")?;
    drop(temp_dir);

    let tmp_identity_after = dir_identity(tmp_root, ".tmp")?;
    let key_identity_after = dir_identity(key_dir, "baselines")?;
    if tmp_identity != tmp_identity_after {
        return Err(GkrmError::BaselineStoreIdentityChanged { component: ".tmp" });
    }
    if key_identity != key_identity_after {
        return Err(GkrmError::BaselineStoreIdentityChanged {
            component: "baselines",
        });
    }

    // Confirm source still resolves as a real directory under .tmp before publish.
    {
        let source = open_child_dir(tmp_root, temp_name)?;
        drop(source);
    }

    // Prepare cleanup ownership before rename; arm infallibly immediately after success.
    let cleanup_key = key_dir
        .try_clone()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "baselines".to_owned(),
            cause: source,
        })?;
    let mut published_guard = PublishedBaselineGuard {
        key_dir: cleanup_key,
        baseline_id: bundle.baseline_id().as_str().to_owned(),
        armed: false,
    };

    match rename_noreplace_relative(tmp_root, temp_name, key_dir, bundle.baseline_id().as_str()) {
        Ok(()) => {
            published_guard.arm();
            sync_dir(key_dir, "baselines")?;
            // Reopen and fully validate before treating publication as durable completion.
            let _validated = load_baseline_from_key_dir(
                store,
                key_dir,
                bundle.resource_key(),
                bundle.baseline_id(),
                limits,
            )?;
            published_guard.disarm();
            Ok(StoredBaselineLocator::new(
                bundle.resource_key().clone(),
                bundle.baseline_id().clone(),
            ))
        }
        Err(error) if is_already_exists(&error) => {
            let _ = remove_temp_child_nofollow(tmp_root, temp_name);
            finish_existing_target(store, key_dir, bundle, limits)
        }
        Err(error) => Err(map_publish_error(error)),
    }
}

/// Owns a published baseline child after rename until reopen/validate succeeds.
struct PublishedBaselineGuard {
    key_dir: cap_std::fs::Dir,
    baseline_id: String,
    armed: bool,
}

impl PublishedBaselineGuard {
    fn arm(&mut self) {
        self.armed = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PublishedBaselineGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_temp_child_nofollow(&self.key_dir, &self.baseline_id);
        }
    }
}

/// Remove one published baseline from the local store, and say whether it was there.
///
/// A baseline is kept so a later update can tell the operator's work from the developer's. One
/// that no installation is on and no undo could reach is answering a question nobody will ask, and
/// it is the largest thing this application holds — so there has to be a way to let it go.
///
/// Deciding *which* is emphatically not this function's business. It is handed one identity and
/// removes exactly that, because the references that make a baseline worth keeping live outside
/// the store and only the caller can see them.
pub fn discard_baseline_bundle(
    store_root: &Path,
    resource_key: &SafeResourceKey,
    baseline_id: &BaselineId,
) -> Result<bool> {
    let store = open_existing_store_root(store_root)?;
    discard_baseline_bundle_from_dir(&store.dir, resource_key, baseline_id)
}

/// Managed-workspace callers retain the validated store capability throughout
/// reference inspection and deletion rather than reopening an ambient pathname.
pub(crate) fn discard_baseline_bundle_from_dir(
    store: &cap_std::fs::Dir,
    resource_key: &SafeResourceKey,
    baseline_id: &BaselineId,
) -> Result<bool> {
    let Some(baselines) = try_open_child_dir(store, "baselines")? else {
        return Ok(false);
    };
    let Some(key_dir) = try_open_child_dir(&baselines, resource_key.as_str())? else {
        return Ok(false);
    };
    // Opened before it is removed, so a name that is not a directory of ours — a link, a file — is
    // refused by the same rules that guard reading rather than deleted on the strength of its name.
    if try_open_child_dir(&key_dir, baseline_id.as_str())?.is_none() {
        return Ok(false);
    }
    key_dir
        .remove_dir_all(baseline_id.as_str())
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "baseline directory".to_owned(),
            cause: source,
        })?;
    sync_dir(&key_dir, "baseline key directory")?;
    Ok(true)
}

/// Load and fully validate a published baseline from the local store.
pub fn load_baseline_bundle(
    store_root: &Path,
    resource_key: &SafeResourceKey,
    baseline_id: &BaselineId,
    limits: BaselineStoreLimits,
) -> Result<StoredBaseline> {
    limits.validate()?;
    let store = open_existing_store_root(store_root)?;
    load_baseline_from_open_store(&store, resource_key, baseline_id, limits)
}

pub(crate) fn load_baseline_from_open_store(
    store: &OpenStoreRoot,
    resource_key: &SafeResourceKey,
    baseline_id: &BaselineId,
    limits: BaselineStoreLimits,
) -> Result<StoredBaseline> {
    let baselines = open_child_dir(&store.dir, "baselines")?;
    let key_dir = open_child_dir(&baselines, resource_key.as_str())?;
    load_baseline_from_key_dir(store, &key_dir, resource_key, baseline_id, limits)
}

fn load_baseline_from_key_dir(
    store: &OpenStoreRoot,
    key_dir: &cap_std::fs::Dir,
    resource_key: &SafeResourceKey,
    baseline_id: &BaselineId,
    limits: BaselineStoreLimits,
) -> Result<StoredBaseline> {
    let baseline_dir = open_child_dir(key_dir, baseline_id.as_str())?;

    let manifest = open_file_nofollow(&baseline_dir, "baseline.json")?;
    let manifest_meta = manifest
        .metadata()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "baseline.json".to_owned(),
            cause: source,
        })?;
    if manifest_meta.len() > limits.max_manifest_bytes() {
        return Err(GkrmError::BaselineManifestLimitExceeded {
            limit: limits.max_manifest_bytes(),
            actual: manifest_meta.len(),
        });
    }
    let before = capture_file_identity(&manifest, "baseline.json")?;
    let json = read_capped(manifest, limits.max_manifest_bytes(), "baseline.json")?;
    if json.len() as u64 > limits.max_manifest_bytes() {
        return Err(GkrmError::BaselineManifestLimitExceeded {
            limit: limits.max_manifest_bytes(),
            actual: json.len() as u64,
        });
    }
    let after_file = open_file_nofollow(&baseline_dir, "baseline.json")?;
    let after_meta = after_file
        .metadata()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "baseline.json".to_owned(),
            cause: source,
        })?;
    let after = capture_file_identity(&after_file, "baseline.json")?;
    if before != after || after_meta.len() != json.len() as u64 {
        return Err(GkrmError::BaselineIncompleteBundle {
            reason: "baseline.json changed while reading",
        });
    }

    let blobs_dir = open_child_dir(&baseline_dir, "blobs")?;
    let blobs = load_all_blobs(&blobs_dir, limits)?;
    reject_unexpected_bundle_entries(&baseline_dir)?;

    let bundle = decode_baseline_document(&json, blobs, limits)?;
    if bundle.resource_key() != resource_key {
        return Err(GkrmError::BaselineResourceKeyMismatch {
            requested: resource_key.to_string(),
            stored: bundle.resource_key().to_string(),
        });
    }
    if bundle.baseline_id() != baseline_id {
        return Err(GkrmError::BaselineRequestedIdMismatch {
            requested: baseline_id.to_string(),
            stored: bundle.baseline_id().to_string(),
        });
    }

    Ok(StoredBaseline::from_validated(store.path.clone(), &bundle))
}

pub(crate) fn read_verified_blob(
    baseline: &StoredBaseline,
    digest: &Sha256Digest,
    limits: &BaselineStoreLimits,
) -> Result<Vec<u8>> {
    limits.validate()?;
    let expected_size = baseline
        .files()
        .iter()
        .find(|file| file.blob_sha256() == Some(digest))
        .map(crate::baseline::BaselineFileRecord::size)
        .ok_or_else(|| GkrmError::BaselineMissingBlob {
            digest: digest.to_string(),
        })?;

    if expected_size > limits.max_blob_bytes() {
        return Err(GkrmError::BaselineBlobLimitExceeded {
            digest: digest.to_string(),
            limit: limits.max_blob_bytes(),
            actual: expected_size,
        });
    }

    let store = open_existing_store_root(baseline.store_root())?;
    let baselines = open_child_dir(&store.dir, "baselines")?;
    let key_dir = open_child_dir(&baselines, baseline.resource_key().as_str())?;
    let baseline_dir = open_child_dir(&key_dir, baseline.baseline_id().as_str())?;
    let blobs_dir = open_child_dir(&baseline_dir, "blobs")?;
    let name = digest.to_string();
    let file = open_file_nofollow(&blobs_dir, &name)?;
    let before = capture_file_identity(&file, &name)?;
    let (bytes, actual_digest) = read_and_hash_file(file, expected_size, limits.max_blob_bytes())?;
    let after_file = open_file_nofollow(&blobs_dir, &name)?;
    let after = capture_file_identity(&after_file, &name)?;
    if before != after {
        return Err(GkrmError::BaselineIncompleteBundle {
            reason: "blob identity changed while reading",
        });
    }
    if bytes.len() as u64 != expected_size {
        return Err(GkrmError::BaselineBlobSizeMismatch {
            digest: digest.to_string(),
            expected: expected_size,
            actual: bytes.len() as u64,
        });
    }
    if &actual_digest != digest {
        return Err(GkrmError::BaselineBlobDigestMismatch {
            digest: digest.to_string(),
        });
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedBlobMetadata {
    pub(crate) expected_digest: Sha256Digest,
    pub(crate) expected_size: u64,
}

pub(crate) fn stream_verified_blob_for_path(
    baseline: &StoredBaseline,
    path: &crate::ResourceRelativePath,
    limits: &BaselineStoreLimits,
    mut on_chunk: impl FnMut(&[u8]) -> Result<()>,
) -> Result<VerifiedBlobMetadata> {
    limits.validate()?;
    let record = baseline
        .files()
        .iter()
        .find(|file| file.relative_path() == path)
        .ok_or(GkrmError::BaselineIncompleteBundle {
            reason: "baseline record missing",
        })?;
    let digest = record.blob_sha256().ok_or(GkrmError::BaselineMissingBlob {
        digest: record.sha256().to_string(),
    })?;
    let expected_size = record.size();

    if expected_size > limits.max_blob_bytes() {
        return Err(GkrmError::BaselineBlobLimitExceeded {
            digest: digest.to_string(),
            limit: limits.max_blob_bytes(),
            actual: expected_size,
        });
    }

    let store = open_existing_store_root(baseline.store_root())?;
    let baselines = open_child_dir(&store.dir, "baselines")?;
    let key_dir = open_child_dir(&baselines, baseline.resource_key().as_str())?;
    let baseline_dir = open_child_dir(&key_dir, baseline.baseline_id().as_str())?;
    let blobs_dir = open_child_dir(&baseline_dir, "blobs")?;
    let name = digest.to_string();
    let mut file = open_file_nofollow(&blobs_dir, &name)?;
    let before = capture_file_identity(&file, &name)?;

    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    let mut callback_error = None;
    let mut stream_error = None;
    loop {
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(source) => {
                stream_error = Some(GkrmError::BaselineStoreIo {
                    component: "blob".to_owned(),
                    cause: source,
                });
                break;
            }
        };
        if read == 0 {
            break;
        }
        match bytes_read.checked_add(read as u64) {
            Some(total) => bytes_read = total,
            None => {
                stream_error = Some(GkrmError::BaselineTotalBlobLimitExceeded {
                    limit: limits.max_total_blob_bytes(),
                    actual: u64::MAX,
                });
                break;
            }
        }
        if bytes_read > expected_size {
            stream_error = Some(GkrmError::BaselineBlobSizeMismatch {
                digest: digest.to_string(),
                expected: expected_size,
                actual: bytes_read,
            });
            break;
        }
        hasher.update(&buffer[..read]);
        if let Err(error) = on_chunk(&buffer[..read]) {
            callback_error.get_or_insert(error);
        }
    }
    drop(file);

    let verification_error = stream_error.or_else(|| {
        verify_streamed_blob_after_callback(
            &blobs_dir,
            &name,
            before,
            bytes_read,
            expected_size,
            digest,
            hasher,
        )
        .err()
    });

    match (callback_error, verification_error) {
        (None, None) => Ok(VerifiedBlobMetadata {
            expected_digest: *digest,
            expected_size,
        }),
        (Some(primary), None) => Err(primary),
        (None, Some(verification)) => Err(verification),
        (Some(primary), Some(verification)) => Err(
            GkrmError::BaselineVerifiedBlobCallbackAndVerificationFailed {
                primary: Box::new(primary),
                verification: Box::new(verification),
            },
        ),
    }
}

fn verify_streamed_blob_after_callback(
    blobs_dir: &cap_std::fs::Dir,
    name: &str,
    before: crate::file_identity::StableFileIdentity,
    bytes_read: u64,
    expected_size: u64,
    digest: &Sha256Digest,
    hasher: Sha256,
) -> Result<()> {
    run_before_blob_identity_revalidation_hook();
    let after_file = open_file_nofollow(blobs_dir, name)?;
    let after = capture_file_identity(&after_file, name)?;
    if before != after {
        return Err(GkrmError::BaselineIncompleteBundle {
            reason: "blob identity changed while reading",
        });
    }
    if bytes_read != expected_size {
        return Err(GkrmError::BaselineBlobSizeMismatch {
            digest: digest.to_string(),
            expected: expected_size,
            actual: bytes_read,
        });
    }
    let actual_digest = Sha256Digest::new(hasher.finalize().into());
    if &actual_digest != digest {
        return Err(GkrmError::BaselineBlobDigestMismatch {
            digest: digest.to_string(),
        });
    }
    Ok(())
}

fn finish_existing_target(
    store: &OpenStoreRoot,
    key_dir: &cap_std::fs::Dir,
    bundle: &ValidatedBaselineBundle,
    limits: BaselineStoreLimits,
) -> Result<StoredBaselineLocator> {
    let loaded = load_baseline_from_key_dir(
        store,
        key_dir,
        bundle.resource_key(),
        bundle.baseline_id(),
        limits,
    )
    .map_err(|error| match error {
        GkrmError::BaselineStoreMissing { .. }
        | GkrmError::BaselineIncompleteBundle { .. }
        | GkrmError::BaselineIdMismatch { .. }
        | GkrmError::BaselineCountMismatch { .. }
        | GkrmError::BaselineInconsistentEscrowBlob { .. }
        | GkrmError::BaselineMissingBlob { .. }
        | GkrmError::BaselineUnexpectedBlob { .. }
        | GkrmError::BaselineBlobDigestMismatch { .. }
        | GkrmError::BaselineBlobSizeMismatch { .. }
        | GkrmError::BaselineStoreIo { .. }
        | GkrmError::BaselineStoreSymlink { .. }
        | GkrmError::BaselineStoreReparsePoint { .. }
        | GkrmError::BaselineStoreHardLink { .. }
        | GkrmError::BaselineStoreUnexpectedType { .. } => GkrmError::BaselineExistingConflict {
            resource_key: bundle.resource_key().to_string(),
            baseline_id: bundle.baseline_id().to_string(),
        },
        other => other,
    })?;

    if baselines_equivalent(&loaded, bundle) {
        Ok(StoredBaselineLocator::new(
            bundle.resource_key().clone(),
            bundle.baseline_id().clone(),
        ))
    } else {
        Err(GkrmError::BaselineExistingConflict {
            resource_key: bundle.resource_key().to_string(),
            baseline_id: bundle.baseline_id().to_string(),
        })
    }
}

fn baselines_equivalent(loaded: &StoredBaseline, bundle: &ValidatedBaselineBundle) -> bool {
    loaded.baseline_id() == bundle.baseline_id()
        && loaded.resource_key() == bundle.resource_key()
        && loaded.resource_name() == bundle.resource_name()
        && loaded.resource_version() == bundle.resource_version()
        && loaded.source_package_fingerprint() == bundle.source_package_fingerprint()
        && loaded.counts() == bundle.counts()
        && loaded.files() == bundle.files()
}

fn write_blob_from_provider<P: VerifiedBaselineBlobProvider>(
    blobs_dir: &cap_std::fs::Dir,
    digest: &Sha256Digest,
    expected_size: u64,
    provider: &P,
    limits: BaselineStoreLimits,
) -> Result<()> {
    let name = digest.to_string();
    if expected_size > limits.max_blob_bytes() {
        return Err(GkrmError::BaselineBlobLimitExceeded {
            digest: name,
            limit: limits.max_blob_bytes(),
            actual: expected_size,
        });
    }
    let reader = provider.open_verified_blob(digest)?;
    if reader.expected_size() != expected_size || reader.expected_digest() != digest {
        return Err(GkrmError::BaselineBlobDigestMismatch { digest: name });
    }
    let mut file = create_new_file(blobs_dir, &name)?;
    let before = capture_file_identity(&file, &name)?;
    // Source identity is bound and revalidated inside copy; flush only after success.
    copy_verified_blob_to_writer(reader, &mut file, limits.max_blob_bytes())?;
    file.flush().map_err(|source| GkrmError::BaselineStoreIo {
        component: name.clone(),
        cause: source,
    })?;
    fsync_file(&file, &name)?;
    let after_file = open_file_nofollow(blobs_dir, &name)?;
    let after = capture_file_identity(&after_file, &name)?;
    if before != after {
        return Err(GkrmError::BaselineIncompleteTemporary);
    }
    Ok(())
}

#[allow(dead_code)]
fn write_blob_file(
    blobs_dir: &cap_std::fs::Dir,
    digest: &Sha256Digest,
    bytes: &[u8],
    limits: BaselineStoreLimits,
) -> Result<()> {
    let mut map = BTreeMap::new();
    map.insert(*digest, bytes.to_vec());
    let provider = InMemoryBlobProvider::new(map);
    write_blob_from_provider(blobs_dir, digest, bytes.len() as u64, &provider, limits)
}

fn load_all_blobs(
    blobs_dir: &cap_std::fs::Dir,
    limits: BaselineStoreLimits,
) -> Result<BTreeMap<Sha256Digest, Vec<u8>>> {
    let mut blobs = BTreeMap::new();
    let mut total = 0_u64;
    let entries = blobs_dir
        .entries()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "blobs".to_owned(),
            cause: source,
        })?;

    for entry in entries {
        let entry = entry.map_err(|source| GkrmError::BaselineStoreIo {
            component: "blobs".to_owned(),
            cause: source,
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            GkrmError::BaselineStoreUnsafeComponent {
                component: "blobs-entry".to_owned(),
            }
        })?;
        let digest = Sha256Digest::from_lowercase_hex(&name)?;
        if digest.to_string() != name {
            return Err(GkrmError::BaselineUnexpectedBlob { name });
        }
        let file = open_file_nofollow(blobs_dir, &name)?;
        let meta = file
            .metadata()
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: name.clone(),
                cause: source,
            })?;
        if meta.len() > limits.max_blob_bytes() {
            return Err(GkrmError::BaselineBlobLimitExceeded {
                digest: name,
                limit: limits.max_blob_bytes(),
                actual: meta.len(),
            });
        }
        total = total
            .checked_add(meta.len())
            .ok_or(GkrmError::BaselineTotalBlobLimitExceeded {
                limit: limits.max_total_blob_bytes(),
                actual: u64::MAX,
            })?;
        if total > limits.max_total_blob_bytes() {
            return Err(GkrmError::BaselineTotalBlobLimitExceeded {
                limit: limits.max_total_blob_bytes(),
                actual: total,
            });
        }
        let (bytes, actual) = read_and_hash_file(file, meta.len(), limits.max_blob_bytes())?;
        if actual != digest {
            return Err(GkrmError::BaselineBlobDigestMismatch { digest: name });
        }
        if bytes.len() as u64 != meta.len() {
            return Err(GkrmError::BaselineBlobSizeMismatch {
                digest: name,
                expected: meta.len(),
                actual: bytes.len() as u64,
            });
        }
        blobs.insert(digest, bytes);
    }

    Ok(blobs)
}

fn reject_unexpected_bundle_entries(baseline_dir: &cap_std::fs::Dir) -> Result<()> {
    let mut seen_manifest = false;
    let mut seen_blobs = false;
    let entries = baseline_dir
        .entries()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "baseline".to_owned(),
            cause: source,
        })?;
    for entry in entries {
        let entry = entry.map_err(|source| GkrmError::BaselineStoreIo {
            component: "baseline".to_owned(),
            cause: source,
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            GkrmError::BaselineStoreUnsafeComponent {
                component: "baseline-entry".to_owned(),
            }
        })?;
        match name.as_str() {
            "baseline.json" => {
                seen_manifest = true;
                let _ = open_file_nofollow(baseline_dir, &name)?;
            }
            "blobs" => {
                seen_blobs = true;
                let _ = open_child_dir(baseline_dir, &name)?;
            }
            other => {
                return Err(GkrmError::BaselineUnexpectedBlob {
                    name: other.to_owned(),
                });
            }
        }
    }
    if !seen_manifest || !seen_blobs {
        return Err(GkrmError::BaselineIncompleteBundle {
            reason: "baseline directory must contain baseline.json and blobs",
        });
    }
    Ok(())
}

fn read_capped(mut file: cap_std::fs::File, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    read_reader_capped(&mut file, max_bytes, label)
}

fn read_reader_capped(reader: &mut impl Read, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let limit = max_bytes
        .checked_add(1)
        .ok_or(GkrmError::BaselineManifestLimitExceeded {
            limit: max_bytes,
            actual: u64::MAX,
        })?;
    let mut limited = reader.take(limit);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(GkrmError::BaselineManifestLimitExceeded {
            limit: max_bytes,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

fn read_and_hash_file(
    mut file: cap_std::fs::File,
    expected_size: u64,
    max_blob_bytes: u64,
) -> Result<(Vec<u8>, Sha256Digest)> {
    verify_regular_file(&file, "blob")?;
    if expected_size > max_blob_bytes {
        return Err(GkrmError::BaselineBlobLimitExceeded {
            digest: "blob".to_owned(),
            limit: max_blob_bytes,
            actual: expected_size,
        });
    }
    let mut hasher = Sha256::new();
    let mut bytes = Vec::with_capacity(expected_size as usize);
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: "blob".to_owned(),
                cause: source,
            })?;
        if read == 0 {
            break;
        }
        if bytes.len() as u64 + read as u64 > expected_size {
            return Err(GkrmError::BaselineBlobSizeMismatch {
                digest: "blob".to_owned(),
                expected: expected_size,
                actual: bytes.len() as u64 + read as u64,
            });
        }
        hasher.update(&buffer[..read]);
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok((bytes, Sha256Digest::new(hasher.finalize().into())))
}

pub(crate) fn allocate_temp_name(tmp_root: &cap_std::fs::Dir) -> Result<String> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

    for attempt in 0..64_u32 {
        let mut seed = [0_u8; 24];
        seed[0..4].copy_from_slice(&attempt.to_le_bytes());
        seed[4..12].copy_from_slice(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos() as u64)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        seed[12..20].copy_from_slice(&TEMP_SEQ.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        seed[20..24].copy_from_slice(&attempt.wrapping_mul(0x9e37_79b9).to_le_bytes());
        let digest = Sha256::digest(seed);
        let name = format!(
            "tmp-{}",
            digest
                .iter()
                .take(8)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        match tmp_root.create_dir(&name) {
            Ok(()) => {
                let _ = tmp_root.remove_dir(&name);
                return Ok(name);
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(GkrmError::BaselineStoreIo {
                    component: ".tmp".to_owned(),
                    cause: source,
                });
            }
        }
    }
    Err(GkrmError::BaselineIncompleteTemporary)
}

pub(crate) fn fsync_file(file: &cap_std::fs::File, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        nix_fsync(file.as_raw_fd()).map_err(|source| GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        })?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        flush_file_buffers(file.as_raw_handle()).map_err(|source| GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        })?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        return Err(GkrmError::BaselineUnsupportedNoReplacePublish);
    }
    Ok(())
}

pub(crate) fn sync_dir(dir: &cap_std::fs::Dir, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        nix_fsync(dir.as_raw_fd()).map_err(|source| GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        })?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;

        // CapDir handles are often read-only; open the same directory by file ID with write
        // access so FlushFileBuffers can succeed without resolving a pathname.
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        let flush_handle =
            match directory_flush_handle(dir.as_raw_handle(), GENERIC_WRITE | SYNCHRONIZE) {
                Ok(handle) => handle,
                // Open-by-file-id is the only pathname-free way to reach this directory with
                // write access, so a filesystem or filter driver that refuses the operation
                // itself leaves no durable directory flush to perform. That is the same
                // conclusion as FlushFileBuffers reporting the flush unsupported below, and it
                // takes the same policy: ACCESS_DENIED and every other error still fail closed,
                // because those mean the flush was reachable and was refused rather than absent.
                Err(source) if is_windows_directory_flush_unsupported(&source) => return Ok(()),
                Err(source) => {
                    return Err(GkrmError::BaselineStoreIo {
                        component: label.to_owned(),
                        cause: source,
                    });
                }
            };
        match flush_file_buffers(flush_handle.as_raw_handle()) {
            Ok(()) => {}
            Err(source) if is_windows_directory_flush_unsupported(&source) => {
                // FlushFileBuffers was invoked; this filesystem rejected directory flushes.
            }
            Err(source) => {
                return Err(GkrmError::BaselineStoreIo {
                    component: label.to_owned(),
                    cause: source,
                });
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (dir, label);
        return Err(GkrmError::BaselineUnsupportedNoReplacePublish);
    }
    Ok(())
}

fn is_already_exists(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        return true;
    }
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(80 | 183))
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn map_publish_error(error: std::io::Error) -> GkrmError {
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        if let Some(inner) = error.get_ref() {
            if let Some(changed) = inner.downcast_ref::<windows_publish::IdentityChangedError>() {
                return GkrmError::BaselineStoreIdentityChanged {
                    component: changed.component,
                };
            }
        }
    }
    if error.kind() == std::io::ErrorKind::Unsupported {
        GkrmError::BaselineUnsupportedNoReplacePublish
    } else {
        GkrmError::BaselineAtomicPublishFailure { cause: error }
    }
}

pub(crate) fn rename_noreplace_relative(
    source_parent: &cap_std::fs::Dir,
    source_name: &str,
    dest_parent: &cap_std::fs::Dir,
    dest_name: &str,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        let from = CString::new(source_name)?;
        let to = CString::new(dest_name)?;
        const RENAME_NOREPLACE: libc::c_uint = 1;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source_parent.as_raw_fd(),
                from.as_ptr(),
                dest_parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        return Err(std::io::Error::last_os_error());
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        let from = CString::new(source_name)?;
        let to = CString::new(dest_name)?;
        const RENAME_EXCL: u32 = 0x0000_0004;
        let rc = unsafe {
            libc::renameatx_np(
                source_parent.as_raw_fd(),
                from.as_ptr(),
                dest_parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_EXCL,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        return Err(std::io::Error::last_os_error());
    }

    #[cfg(windows)]
    {
        windows_rename_noreplace_relative(source_parent, source_name, dest_parent, dest_name)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (source_parent, source_name, dest_parent, dest_name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no-replace rename is unsupported on this platform",
        ))
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
use windows_publish::windows_rename_noreplace_relative;

/// Non-64-bit Windows cannot use the verified x64 rename layouts; fail closed.
#[cfg(all(windows, not(target_pointer_width = "64")))]
fn windows_rename_noreplace_relative(
    source_parent: &cap_std::fs::Dir,
    source_name: &str,
    dest_parent: &cap_std::fs::Dir,
    dest_name: &str,
) -> std::io::Result<()> {
    let _ = (source_parent, source_name, dest_parent, dest_name);
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Task 11 baseline publication supports 64-bit Windows only",
    ))
}

#[cfg(windows)]
const FILE_LIST_DIRECTORY: u32 = 0x0001;
#[cfg(windows)]
const FILE_TRAVERSE: u32 = 0x0020;
#[cfg(windows)]
const SYNCHRONIZE: u32 = 0x0010_0000;

#[cfg(windows)]
struct OwnedWinHandle(std::os::windows::io::RawHandle);

#[cfg(windows)]
impl OwnedWinHandle {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.0
    }
}

#[cfg(windows)]
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

#[cfg(all(test, windows))]
thread_local! {
    static FORCE_DIRECTORY_FLUSH_OPEN_ERROR: std::cell::Cell<Option<i32>> =
        const { std::cell::Cell::new(None) };
}

/// Substitute an `OpenFileById` failure while preparing a durable directory flush, so both the
/// unsupported and the fail-closed classification can be exercised without a filesystem that
/// actually refuses open-by-file-id.
#[cfg(all(test, windows))]
pub(crate) struct DirectoryFlushOpenSeamGuard;

#[cfg(all(test, windows))]
impl DirectoryFlushOpenSeamGuard {
    pub(crate) fn force_open_error(raw_os_error: i32) -> Self {
        FORCE_DIRECTORY_FLUSH_OPEN_ERROR.with(|cell| cell.set(Some(raw_os_error)));
        Self
    }
}

#[cfg(all(test, windows))]
impl Drop for DirectoryFlushOpenSeamGuard {
    fn drop(&mut self) {
        FORCE_DIRECTORY_FLUSH_OPEN_ERROR.with(|cell| cell.set(None));
    }
}

/// Acquire the write-access handle a durable directory flush needs, through the test seam.
#[cfg(windows)]
fn directory_flush_handle(
    existing: std::os::windows::io::RawHandle,
    desired_access: u32,
) -> std::io::Result<OwnedWinHandle> {
    #[cfg(test)]
    {
        if let Some(code) = FORCE_DIRECTORY_FLUSH_OPEN_ERROR.with(|cell| cell.get()) {
            return Err(std::io::Error::from_raw_os_error(code));
        }
    }
    open_directory_by_file_id(existing, desired_access)
}

/// Open the same directory object with explicit access using OpenFileById (no pathname).
#[cfg(windows)]
fn open_directory_by_file_id(
    existing: std::os::windows::io::RawHandle,
    desired_access: u32,
) -> std::io::Result<OwnedWinHandle> {
    use winapi_util::HandleRef;

    const FILE_SHARE_READ: u32 = 0x0001;
    const FILE_SHARE_WRITE: u32 = 0x0002;
    const FILE_SHARE_DELETE: u32 = 0x0004;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ID_TYPE_FILE_ID: u32 = 0; // FileIdType
    const INVALID_HANDLE_VALUE: isize = -1;

    #[repr(C)]
    struct FileIdDescriptor {
        dw_size: u32,
        type_: u32,
        // Union is 16 bytes (LARGE_INTEGER | GUID | FILE_ID_128).
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
    if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedWinHandle(handle))
}

#[cfg(windows)]
fn open_source_directory_for_rename(
    source_parent: &cap_std::fs::Dir,
    source_name: &str,
) -> std::io::Result<cap_std::fs::File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsExt, OpenOptionsFollowExt, OsMetadataExt};
    use cap_std::fs::OpenOptions;

    use crate::file_identity::is_windows_reparse_point_cap;

    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let mut options = OpenOptions::new();
    options.read(true);
    options.write(true);
    options.follow(FollowSymlinks::No);
    options.access_mode(DELETE | SYNCHRONIZE | FILE_LIST_DIRECTORY);
    // Open the reparse point itself so junctions/symlinks are visible and rejected.
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let source = source_parent.open_with(source_name, &options)?;
    let metadata = source.metadata()?;
    if is_windows_reparse_point_cap(&metadata) || (metadata.file_attributes() & 0x400) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source temporary bundle is a reparse point",
        ));
    }
    if !metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source temporary bundle is not a directory",
        ));
    }
    Ok(source)
}

#[cfg(windows)]
fn is_windows_directory_flush_unsupported(error: &std::io::Error) -> bool {
    // Only clearly unsupported filesystem/API errors. ACCESS_DENIED (5) must fail closed.
    matches!(error.raw_os_error(), Some(1 | 50))
}

#[cfg(test)]
mod read_cap_tests {
    use super::read_reader_capped;
    use crate::GkrmError;
    use std::io::Cursor;

    #[test]
    fn rejects_content_past_hard_cap() {
        let mut data = Cursor::new(vec![b'x'; 8]);
        let err = read_reader_capped(&mut data, 7, "baseline.json").expect_err("cap");
        assert!(matches!(
            err,
            GkrmError::BaselineManifestLimitExceeded {
                limit: 7,
                actual: 8
            }
        ));
    }

    #[test]
    fn accepts_exact_limit() {
        let mut data = Cursor::new(vec![b'y'; 7]);
        let bytes = read_reader_capped(&mut data, 7, "baseline.json").expect("ok");
        assert_eq!(bytes.len(), 7);
    }

    #[test]
    fn rejects_max_plus_one_without_overflow() {
        let err = read_reader_capped(&mut Cursor::new([0_u8; 1]), u64::MAX, "baseline.json")
            .expect_err("overflow");
        assert!(matches!(
            err,
            GkrmError::BaselineManifestLimitExceeded {
                limit: u64::MAX,
                actual: u64::MAX
            }
        ));
    }

    #[test]
    fn rejects_reader_that_grows_past_cap_during_read() {
        use std::io::Read;

        struct Growing {
            emitted: usize,
        }
        impl Read for Growing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.emitted >= 64 {
                    return Ok(0);
                }
                let n = buf.len().min(8);
                buf[..n].fill(b'z');
                self.emitted += n;
                Ok(n)
            }
        }
        let err = read_reader_capped(&mut Growing { emitted: 0 }, 10, "baseline.json")
            .expect_err("growth");
        assert!(matches!(
            err,
            GkrmError::BaselineManifestLimitExceeded { limit: 10, .. }
        ));
    }
}

#[cfg(all(test, windows))]
mod windows_flush_tests {
    use super::{
        flush_file_buffers, is_windows_directory_flush_unsupported, sync_dir,
        DirectoryFlushOpenSeamGuard,
    };
    use crate::GkrmError;
    use cap_fs_ext::ambient_authority;
    use cap_std::fs::Dir as CapDir;
    use std::io;
    use std::os::windows::io::RawHandle;
    use tempfile::tempdir;

    #[test]
    fn flush_file_buffers_is_not_a_silent_noop() {
        let invalid: RawHandle = std::ptr::null_mut();
        let err = flush_file_buffers(invalid).expect_err("null handle must fail");
        assert!(err.raw_os_error().is_some());
    }

    #[test]
    fn directory_flush_error_policy() {
        assert!(is_windows_directory_flush_unsupported(
            &io::Error::from_raw_os_error(1)
        ));
        assert!(is_windows_directory_flush_unsupported(
            &io::Error::from_raw_os_error(50)
        ));
        assert!(!is_windows_directory_flush_unsupported(
            &io::Error::from_raw_os_error(5)
        ));
        assert!(!is_windows_directory_flush_unsupported(
            &io::Error::from_raw_os_error(6)
        ));
        assert!(!is_windows_directory_flush_unsupported(
            &io::Error::from_raw_os_error(32)
        ));
        assert!(!is_windows_directory_flush_unsupported(
            &io::Error::from_raw_os_error(87)
        ));
    }

    /// The handle a directory flush needs is acquired by file ID, and a filesystem or filter
    /// driver can refuse that operation itself. Refusing the operation is the same condition as
    /// refusing the flush, so it takes the same classification; a reachable-but-denied flush is
    /// still an error.
    #[test]
    fn an_unsupported_flush_handle_is_tolerated_and_every_other_failure_is_not() {
        let temp = tempdir().expect("temp");
        let dir = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open dir");

        for unsupported in [1, 50] {
            let _seam = DirectoryFlushOpenSeamGuard::force_open_error(unsupported);
            sync_dir(&dir, "flush-seam").expect("an unsupported operation leaves nothing to flush");
        }

        for refused in [5, 6, 32, 87] {
            let _seam = DirectoryFlushOpenSeamGuard::force_open_error(refused);
            let error = sync_dir(&dir, "flush-seam").expect_err("a reachable flush fails closed");
            let GkrmError::BaselineStoreIo { component, cause } = error else {
                panic!("expected a store I/O failure");
            };
            assert_eq!(component, "flush-seam");
            assert_eq!(cause.raw_os_error(), Some(refused));
        }
    }

    /// Without the seam the real operation runs: it either flushes or reports the operation
    /// unsupported, and neither outcome is a failure.
    #[test]
    fn a_real_directory_flush_reports_success() {
        let temp = tempdir().expect("temp");
        let dir = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open dir");
        sync_dir(&dir, "flush-real").expect("directory flush");
    }
}

/// Non-64-bit Windows builds compile only the fail-closed stub (no NtSetInformationFile path).
#[cfg(all(test, windows, not(target_pointer_width = "64")))]
mod windows_non64_publish_tests {
    use super::windows_rename_noreplace_relative;
    use cap_fs_ext::ambient_authority;
    use cap_std::fs::Dir as CapDir;
    use tempfile::tempdir;

    #[test]
    fn non_64_bit_windows_fails_closed_without_publication() {
        let temp = tempdir().expect("temp");
        let root = CapDir::open_ambient_dir(temp.path(), ambient_authority()).expect("open root");
        root.create_dir("a").expect("a");
        root.create_dir("b").expect("b");
        let a = root.open_dir("a").expect("open a");
        a.create_dir("child").expect("child");
        drop(a);
        let a = root.open_dir("a").expect("reopen a");
        let b = root.open_dir("b").expect("open b");
        let dest_name = "ab".repeat(32);
        let err = windows_rename_noreplace_relative(&a, "child", &b, &dest_name)
            .expect_err("must fail closed");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(temp.path().join("a").join("child").is_dir());
        assert!(!temp.path().join("b").join(&dest_name).exists());
    }
}

#[cfg(unix)]
fn nix_fsync(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    let rc = unsafe { libc::fsync(fd) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn flush_file_buffers(handle: std::os::windows::io::RawHandle) -> std::io::Result<()> {
    #[link(name = "kernel32")]
    extern "system" {
        fn FlushFileBuffers(h_file: *mut std::ffi::c_void) -> i32;
    }
    let ok = unsafe { FlushFileBuffers(handle) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
