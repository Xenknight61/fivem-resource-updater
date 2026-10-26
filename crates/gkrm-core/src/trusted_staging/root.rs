//! Read-only trusted staging root capability.

use std::path::Path;
use std::sync::atomic::AtomicUsize;

#[cfg(test)]
use std::sync::atomic::Ordering;

use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{dir_identity, open_existing_directory};
use crate::file_identity::StableFileIdentity;
use crate::{GkrmError, Result};

#[cfg(test)]
use std::sync::{Mutex, MutexGuard};
#[cfg(test)]
use std::thread::ThreadId;

/// Opaque retained staging-root capability. Opening is strictly read-only.
pub struct TrustedStagingRoot {
    path: std::path::PathBuf,
    dir: CapDir,
    identity: StableFileIdentity,
}

impl TrustedStagingRoot {
    /// Open an existing staging root without creating any filesystem objects.
    pub fn try_open(path: &Path) -> Result<Self> {
        note_open_attempt();
        let opened = open_existing_directory(path, "staging-root")
            .map_err(|_| GkrmError::TrustedStagingRootOverlap)?;
        let identity = dir_identity(&opened.dir, "staging-root")
            .map_err(|_| GkrmError::TrustedStagingRootOverlap)?;
        Ok(Self {
            path: path.to_path_buf(),
            dir: opened.dir,
            identity,
        })
    }

    pub(crate) fn dir(&self) -> &CapDir {
        &self.dir
    }

    pub(super) fn identity(&self) -> &StableFileIdentity {
        &self.identity
    }

    pub(crate) fn path_for_disjointness(&self) -> &Path {
        &self.path
    }

    pub(crate) fn revalidate_identity(&self) -> Result<()> {
        let current = dir_identity(&self.dir, "staging-root")
            .map_err(|_| GkrmError::TrustedStagingRootReplaced)?;
        if current != self.identity {
            return Err(GkrmError::TrustedStagingRootReplaced);
        }
        Ok(())
    }
}

impl std::fmt::Debug for TrustedStagingRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedStagingRoot")
    }
}

#[cfg(test)]
static STAGING_HOOK_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static STAGING_HOOKS: Mutex<Option<StagingTestHooks>> = Mutex::new(None);
#[cfg(test)]
static STAGING_MUTATION_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
struct StagingTestHooks {
    owner: ThreadId,
}

#[cfg(test)]
pub(super) struct StagingHookGuard {
    _guard: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for StagingHookGuard {
    fn drop(&mut self) {
        *STAGING_HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = None;
        STAGING_MUTATION_COUNT.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(super) fn lock_staging_hooks() -> StagingHookGuard {
    let guard = STAGING_HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    *STAGING_HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = Some(StagingTestHooks {
        owner: std::thread::current().id(),
    });
    STAGING_MUTATION_COUNT.store(0, Ordering::SeqCst);
    StagingHookGuard { _guard: guard }
}

#[cfg(test)]
pub(super) fn staging_mutation_count() -> usize {
    STAGING_MUTATION_COUNT.load(Ordering::SeqCst)
}

#[cfg(test)]
pub(super) fn staging_hooks_owned() -> bool {
    let hooks = STAGING_HOOKS.lock().unwrap_or_else(|p| p.into_inner());
    hooks
        .as_ref()
        .is_some_and(|hooks| hooks.owner == std::thread::current().id())
}

pub(super) fn note_staging_mutation() {
    #[cfg(test)]
    {
        let hooks = STAGING_HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(hooks) = hooks.as_ref() {
            if hooks.owner == std::thread::current().id() {
                STAGING_MUTATION_COUNT.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

fn note_open_attempt() {
    let _ = AtomicUsize::new(0);
}
