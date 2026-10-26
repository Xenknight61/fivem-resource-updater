use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::dto::{SelectionKind, SelectionSummary};
use crate::error::{DesktopFailure, DesktopResult};
use crate::state::DesktopAppState;

pub const MAX_SELECTIONS: usize = 16;
const MAX_HANDLE_GENERATION_ATTEMPTS: usize = 32;
const MAX_LABEL_CHARS: usize = 48;
const MAX_LABEL_BYTES: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SelectionHandle(String);

#[derive(Debug, Clone)]
pub struct SelectionRecord {
    pub handle: SelectionHandle,
    pub kind: SelectionKind,
    pub display_label: String,
    pub path: PathBuf,
    generation: u64,
    lease_count: u32,
    validation: SelectionValidation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionValidation {
    is_dir: bool,
    is_file: bool,
    len: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSelection {
    pub kind: SelectionKind,
    pub path: PathBuf,
    pub generation: u64,
    pub handle: SelectionHandle,
    pub display_label: String,
}

#[derive(Debug, Clone)]
pub struct SelectionResolutionInput {
    handle: SelectionHandle,
    kind: SelectionKind,
    path: PathBuf,
    generation: u64,
    display_label: String,
    validation: SelectionValidation,
}

pub struct SelectionLeaseGuard<'a> {
    state: &'a DesktopAppState,
    handles: Vec<SelectionHandle>,
}

pub trait HandleGenerator {
    fn generate(&mut self) -> SelectionHandle;
}

#[derive(Debug, Default)]
pub struct UuidHandleGenerator;

impl HandleGenerator for UuidHandleGenerator {
    fn generate(&mut self) -> SelectionHandle {
        SelectionHandle(Uuid::new_v4().to_string())
    }
}

#[derive(Debug, Default)]
pub struct SelectionRegistry {
    records: BTreeMap<SelectionHandle, SelectionRecord>,
    issued_handles: BTreeSet<SelectionHandle>,
    next_generation: u64,
}

impl SelectionHandle {
    pub fn parse(value: &str) -> DesktopResult<Self> {
        if value.len() != 36 {
            return Err(DesktopFailure::InvalidRequest);
        }
        let uuid = Uuid::parse_str(value).map_err(|_| DesktopFailure::InvalidRequest)?;
        if uuid.get_version_num() != 4 {
            return Err(DesktopFailure::InvalidRequest);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SelectionResolutionInput {
    pub fn kind(&self) -> SelectionKind {
        self.kind
    }

    pub fn handle(&self) -> &SelectionHandle {
        &self.handle
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn display_label(&self) -> &str {
        &self.display_label
    }
}

impl Drop for SelectionLeaseGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.state.selections.lock() {
            for handle in &self.handles {
                registry.release_lease(handle);
            }
        }
    }
}

impl SelectionRecord {
    pub fn summary(&self) -> SelectionSummary {
        SelectionSummary {
            handle: self.handle.as_str().to_owned(),
            kind: self.kind,
            display_label: self.display_label.clone(),
        }
    }
}

impl SelectionRegistry {
    pub fn insert(
        &mut self,
        kind: SelectionKind,
        path: PathBuf,
        generator: &mut impl HandleGenerator,
    ) -> DesktopResult<SelectionSummary> {
        let validation = validate_selection_shape(&path, kind)?;
        self.insert_validated(kind, path, validation, generator)
    }

    pub fn insert_validated(
        &mut self,
        kind: SelectionKind,
        path: PathBuf,
        validation: SelectionValidation,
        generator: &mut impl HandleGenerator,
    ) -> DesktopResult<SelectionSummary> {
        if self.records.len() >= MAX_SELECTIONS {
            return Err(DesktopFailure::SelectionLimitReached);
        }
        let display_label = unique_display_label(kind, &path, self.records.values());
        let handle = self.generate_unique_handle(generator)?;
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(DesktopFailure::Internal)?;
        // A desktop selection handle identifies backend session state only. It does not
        // replace gkrm-core filesystem validation or capability acquisition.
        let record = SelectionRecord {
            handle: handle.clone(),
            kind,
            display_label,
            path,
            generation,
            lease_count: 0,
            validation,
        };
        let summary = record.summary();
        self.issued_handles.insert(handle.clone());
        self.records.insert(handle, record);
        Ok(summary)
    }

    pub fn list(&self, kind: Option<SelectionKind>) -> Vec<SelectionSummary> {
        self.records
            .values()
            .filter(|record| kind.is_none_or(|k| record.kind == k))
            .map(SelectionRecord::summary)
            .collect()
    }

    pub fn release(&mut self, handle: &str) -> DesktopResult<()> {
        let handle =
            SelectionHandle::parse(handle).map_err(|_| DesktopFailure::SelectionNotFound)?;
        if self
            .records
            .get(&handle)
            .ok_or(DesktopFailure::SelectionNotFound)?
            .lease_count
            > 0
        {
            return Err(DesktopFailure::SelectionBusy);
        }
        self.records
            .remove(&handle)
            .map(|_| ())
            .ok_or(DesktopFailure::SelectionNotFound)
    }

    pub fn acquire_lease(&mut self, handle: &SelectionHandle) -> DesktopResult<()> {
        let record = self
            .records
            .get_mut(handle)
            .ok_or(DesktopFailure::SelectionNotFound)?;
        record.lease_count = record
            .lease_count
            .checked_add(1)
            .ok_or(DesktopFailure::Internal)?;
        Ok(())
    }

    fn can_acquire_lease(&self, handle: &SelectionHandle) -> DesktopResult<()> {
        let record = self
            .records
            .get(handle)
            .ok_or(DesktopFailure::SelectionNotFound)?;
        record
            .lease_count
            .checked_add(1)
            .map(|_| ())
            .ok_or(DesktopFailure::Internal)
    }

    fn acquire_lease_after_preflight(&mut self, handle: &SelectionHandle) {
        if let Some(record) = self.records.get_mut(handle) {
            record.lease_count = record.lease_count.saturating_add(1);
        }
    }

    pub fn release_lease(&mut self, handle: &SelectionHandle) {
        if let Some(record) = self.records.get_mut(handle) {
            record.lease_count = record.lease_count.saturating_sub(1);
        }
    }

    fn clone_for_resolution(
        &self,
        handle: &SelectionHandle,
    ) -> DesktopResult<SelectionResolutionInput> {
        let record = self
            .records
            .get(handle)
            .ok_or(DesktopFailure::SelectionNotFound)?;
        Ok(SelectionResolutionInput {
            handle: handle.clone(),
            kind: record.kind,
            path: record.path.clone(),
            generation: record.generation,
            display_label: record.display_label.clone(),
            validation: record.validation.clone(),
        })
    }

    fn active_record_matches(&self, input: &SelectionResolutionInput) -> bool {
        self.records.get(&input.handle).is_some_and(|record| {
            record.kind == input.kind
                && record.generation == input.generation
                && record.validation == input.validation
        })
    }

    fn generate_unique_handle(
        &self,
        generator: &mut impl HandleGenerator,
    ) -> DesktopResult<SelectionHandle> {
        for _ in 0..MAX_HANDLE_GENERATION_ATTEMPTS {
            let handle = generator.generate();
            if !self.records.contains_key(&handle) && !self.issued_handles.contains(&handle) {
                return Ok(handle);
            }
        }
        Err(DesktopFailure::Internal)
    }
}

pub fn clone_selection_for_resolution(
    state: &DesktopAppState,
    handle: &str,
) -> DesktopResult<SelectionResolutionInput> {
    let handle = SelectionHandle::parse(handle).map_err(|_| DesktopFailure::SelectionNotFound)?;
    let registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    registry.clone_for_resolution(&handle)
}

pub fn lease_selections_for_resolution<'a>(
    state: &'a DesktopAppState,
    handles: &[&str],
) -> DesktopResult<(SelectionLeaseGuard<'a>, Vec<SelectionResolutionInput>)> {
    let mut parsed = Vec::with_capacity(handles.len());
    for handle in handles {
        parsed.push(SelectionHandle::parse(handle).map_err(|_| DesktopFailure::SelectionNotFound)?);
    }
    parsed.sort();
    parsed.dedup();

    let mut registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    let mut inputs = Vec::with_capacity(parsed.len());
    for handle in &parsed {
        inputs.push(registry.clone_for_resolution(handle)?);
    }
    for handle in &parsed {
        registry.can_acquire_lease(handle)?;
    }
    for handle in &parsed {
        registry.acquire_lease_after_preflight(handle);
    }
    Ok((
        SelectionLeaseGuard {
            state,
            handles: parsed,
        },
        inputs,
    ))
}

pub fn confirm_selection_active(
    state: &DesktopAppState,
    input: &SelectionResolutionInput,
) -> DesktopResult<()> {
    let registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    if registry.active_record_matches(input) {
        Ok(())
    } else {
        Err(DesktopFailure::SelectionStale)
    }
}

pub fn resolve_selection_for_future_use(
    state: &DesktopAppState,
    handle: &str,
) -> DesktopResult<ResolvedSelection> {
    resolve_selection_for_future_use_with_validator(state, handle, validate_selection_shape)
}

fn resolve_selection_for_future_use_with_validator(
    state: &DesktopAppState,
    handle: &str,
    validator: impl FnOnce(&Path, SelectionKind) -> DesktopResult<SelectionValidation>,
) -> DesktopResult<ResolvedSelection> {
    let input = clone_selection_for_resolution(state, handle)?;
    let active_input = input.clone();
    let resolved = revalidate_selection_with(input, validator)?;
    let registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    if registry.active_record_matches(&active_input) {
        Ok(resolved)
    } else {
        Err(DesktopFailure::SelectionStale)
    }
}

pub fn revalidate_selection(input: SelectionResolutionInput) -> DesktopResult<ResolvedSelection> {
    revalidate_selection_with(input, validate_selection_shape)
}

fn revalidate_selection_with(
    input: SelectionResolutionInput,
    validator: impl FnOnce(&Path, SelectionKind) -> DesktopResult<SelectionValidation>,
) -> DesktopResult<ResolvedSelection> {
    let current = validator(&input.path, input.kind).map_err(|_| DesktopFailure::SelectionStale)?;
    if current.is_dir != input.validation.is_dir
        || current.is_file != input.validation.is_file
        || current.len != input.validation.len
    {
        return Err(DesktopFailure::SelectionStale);
    }
    Ok(ResolvedSelection {
        kind: input.kind,
        path: input.path,
        generation: input.generation,
        handle: input.handle,
        display_label: input.display_label,
    })
}

pub fn validate_selection_shape(
    path: &Path,
    kind: SelectionKind,
) -> DesktopResult<SelectionValidation> {
    let metadata = fs::symlink_metadata(path).map_err(|_| stale_or_invalid(kind))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(DesktopFailure::SecurityRejection);
    }
    match kind {
        SelectionKind::InstalledRoot => {
            if !file_type.is_dir() {
                return Err(DesktopFailure::InvalidInstalledRoot);
            }
        }
        SelectionKind::PackageFile => {
            if !file_type.is_file() || !is_zip_extension(path) {
                return Err(DesktopFailure::InvalidPackageFile);
            }
        }
    }
    Ok(SelectionValidation {
        is_dir: file_type.is_dir(),
        is_file: file_type.is_file(),
        len: if file_type.is_file() {
            Some(metadata.len())
        } else {
            None
        },
    })
}

fn stale_or_invalid(kind: SelectionKind) -> DesktopFailure {
    match kind {
        SelectionKind::InstalledRoot => DesktopFailure::InvalidInstalledRoot,
        SelectionKind::PackageFile => DesktopFailure::InvalidPackageFile,
    }
}

fn is_zip_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
}

fn unique_display_label<'a>(
    kind: SelectionKind,
    path: &Path,
    existing: impl Iterator<Item = &'a SelectionRecord>,
) -> String {
    let base = display_label_base(kind, path);
    let active: BTreeSet<_> = existing
        .map(|record| record.display_label.as_str())
        .collect();
    if !active.contains(base.as_str()) {
        return base;
    }
    for ordinal in 2..=MAX_SELECTIONS {
        let candidate = truncate_label(&format!("{base} ({ordinal})"));
        if !active.contains(candidate.as_str()) {
            return candidate;
        }
    }
    truncate_label(match kind {
        SelectionKind::InstalledRoot => "Installed root",
        SelectionKind::PackageFile => "Package file",
    })
}

fn display_label_base(kind: SelectionKind, path: &Path) -> String {
    let fallback = match kind {
        SelectionKind::InstalledRoot => "Installed root",
        SelectionKind::PackageFile => "Package file",
    };
    let raw = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback);
    let scrubbed: String = raw
        .chars()
        .map(|c| {
            if c.is_control() || c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let trimmed = scrubbed.trim();
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        truncate_label(trimmed)
    }
}

fn truncate_label(label: &str) -> String {
    let mut output = String::new();
    for c in label.chars().take(MAX_LABEL_CHARS) {
        if output.len() + c.len_utf8() > MAX_LABEL_BYTES {
            break;
        }
        output.push(c);
    }
    if output.is_empty() {
        "Selection".to_owned()
    } else {
        output
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{mpsc, Arc};
    use std::thread;

    use tempfile::tempdir;

    use super::*;

    #[derive(Default)]
    struct FakeGenerator {
        handles: Vec<SelectionHandle>,
        index: usize,
    }

    impl FakeGenerator {
        fn new(handles: &[&str]) -> Self {
            Self {
                handles: handles
                    .iter()
                    .map(|h| SelectionHandle((*h).to_owned()))
                    .collect(),
                index: 0,
            }
        }
    }

    impl HandleGenerator for FakeGenerator {
        fn generate(&mut self) -> SelectionHandle {
            let handle = self.handles[self.index % self.handles.len()].clone();
            self.index += 1;
            handle
        }
    }

    fn uuid(n: u128) -> String {
        let mut bytes = n.to_be_bytes();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes).to_string()
    }

    #[test]
    fn handle_parse_is_strict() {
        assert!(SelectionHandle::parse(&uuid(1)).is_ok());
        assert!(SelectionHandle::parse("bad").is_err());
        assert!(SelectionHandle::parse("123e4567-e89b-12d3-a456-426614174000").is_err());
    }

    #[test]
    fn registry_handles_lifecycle_limits_and_ordering() {
        let temp = tempdir().unwrap();
        let mut registry = SelectionRegistry::default();
        let handles: Vec<_> = (1..=20).map(uuid).collect();
        let handle_refs: Vec<_> = handles.iter().map(String::as_str).collect();
        let mut generator = FakeGenerator::new(&handle_refs);
        for i in 0..MAX_SELECTIONS {
            let path = temp.path().join(format!("dir{i}"));
            fs::create_dir(&path).unwrap();
            registry
                .insert(SelectionKind::InstalledRoot, path, &mut generator)
                .unwrap();
        }
        assert_eq!(registry.list(None).len(), MAX_SELECTIONS);
        let extra = temp.path().join("extra");
        fs::create_dir(&extra).unwrap();
        assert!(matches!(
            registry.insert(SelectionKind::InstalledRoot, extra, &mut generator),
            Err(DesktopFailure::SelectionLimitReached)
        ));
        let first = registry.list(None)[0].handle.clone();
        registry.release(&first).unwrap();
        assert!(matches!(
            registry.release(&first),
            Err(DesktopFailure::SelectionNotFound)
        ));
        let replacement = temp.path().join("replacement");
        fs::create_dir(&replacement).unwrap();
        let mut reused_generator = FakeGenerator::new(&[&first]);
        assert!(matches!(
            registry.insert(
                SelectionKind::InstalledRoot,
                replacement,
                &mut reused_generator
            ),
            Err(DesktopFailure::Internal)
        ));
    }

    #[test]
    fn registry_retries_colliding_handles() {
        let temp = tempdir().unwrap();
        let one = temp.path().join("one");
        let two = temp.path().join("two");
        fs::create_dir(&one).unwrap();
        fs::create_dir(&two).unwrap();
        let h1 = uuid(1);
        let h2 = uuid(2);
        let mut generator = FakeGenerator::new(&[&h1, &h1, &h2]);
        let mut registry = SelectionRegistry::default();
        registry
            .insert(SelectionKind::InstalledRoot, one, &mut generator)
            .unwrap();
        let second = registry
            .insert(SelectionKind::InstalledRoot, two, &mut generator)
            .unwrap();
        assert_eq!(second.handle, h2);
    }

    #[test]
    fn filtering_and_resolution_fail_closed() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("resources");
        let zip = temp.path().join("update.zip");
        fs::create_dir(&dir).unwrap();
        fs::write(&zip, b"zip").unwrap();
        let mut registry = SelectionRegistry::default();
        let handles = [uuid(1), uuid(2)];
        let mut generator = FakeGenerator::new(&[&handles[0], &handles[1]]);
        let installed = registry
            .insert(SelectionKind::InstalledRoot, dir.clone(), &mut generator)
            .unwrap();
        registry
            .insert(SelectionKind::PackageFile, zip.clone(), &mut generator)
            .unwrap();
        assert_eq!(registry.list(Some(SelectionKind::InstalledRoot)).len(), 1);
        let state = DesktopAppState {
            selections: std::sync::Mutex::new(registry),
            ..DesktopAppState::default()
        };
        let resolved = resolve_selection_for_future_use(&state, &installed.handle).unwrap();
        assert_eq!(resolved.kind, SelectionKind::InstalledRoot);
        fs::remove_dir(&dir).unwrap();
        assert!(matches!(
            resolve_selection_for_future_use(&state, &installed.handle),
            Err(DesktopFailure::SelectionStale)
        ));
        assert!(matches!(
            resolve_selection_for_future_use(&state, &uuid(200)),
            Err(DesktopFailure::SelectionNotFound)
        ));
    }

    #[test]
    fn resolution_validation_does_not_hold_registry_lock_and_release_race_stales() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("resources");
        fs::create_dir(&dir).unwrap();
        let mut registry = SelectionRegistry::default();
        let handle = uuid(1);
        let mut generator = FakeGenerator::new(&[&handle]);
        let summary = registry
            .insert(SelectionKind::InstalledRoot, dir, &mut generator)
            .unwrap();
        let state = Arc::new(DesktopAppState {
            selections: std::sync::Mutex::new(registry),
            ..DesktopAppState::default()
        });
        let (validation_started_tx, validation_started_rx) = mpsc::channel();
        let (continue_validation_tx, continue_validation_rx) = mpsc::channel();
        let worker_state = Arc::clone(&state);
        let worker_handle = summary.handle.clone();
        let worker = thread::spawn(move || {
            resolve_selection_for_future_use_with_validator(
                &worker_state,
                &worker_handle,
                move |_path, _kind| {
                    validation_started_tx.send(()).unwrap();
                    continue_validation_rx.recv().unwrap();
                    Ok(SelectionValidation {
                        is_dir: true,
                        is_file: false,
                        len: None,
                    })
                },
            )
        });

        validation_started_rx.recv().unwrap();
        {
            let registry = state.selections.lock().unwrap();
            assert_eq!(registry.list(None).len(), 1);
        }
        state
            .selections
            .lock()
            .unwrap()
            .release(&summary.handle)
            .unwrap();
        continue_validation_tx.send(()).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(DesktopFailure::SelectionStale)
        ));
    }

    #[test]
    fn resolution_recheck_rejects_changed_active_record() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("resources");
        fs::create_dir(&dir).unwrap();
        let mut registry = SelectionRegistry::default();
        let handle = uuid(1);
        let mut generator = FakeGenerator::new(&[&handle]);
        let summary = registry
            .insert(SelectionKind::InstalledRoot, dir, &mut generator)
            .unwrap();
        let state = Arc::new(DesktopAppState {
            selections: std::sync::Mutex::new(registry),
            ..DesktopAppState::default()
        });
        let (validation_started_tx, validation_started_rx) = mpsc::channel();
        let (continue_validation_tx, continue_validation_rx) = mpsc::channel();
        let worker_state = Arc::clone(&state);
        let worker_handle = summary.handle.clone();
        let worker = thread::spawn(move || {
            resolve_selection_for_future_use_with_validator(
                &worker_state,
                &worker_handle,
                move |_path, _kind| {
                    validation_started_tx.send(()).unwrap();
                    continue_validation_rx.recv().unwrap();
                    Ok(SelectionValidation {
                        is_dir: true,
                        is_file: false,
                        len: None,
                    })
                },
            )
        });

        validation_started_rx.recv().unwrap();
        {
            let mut registry = state.selections.lock().unwrap();
            let parsed = SelectionHandle::parse(&summary.handle).unwrap();
            registry.records.get_mut(&parsed).unwrap().validation.len = Some(1);
        }
        continue_validation_tx.send(()).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(DesktopFailure::SelectionStale)
        ));
    }

    #[test]
    fn revalidation_detects_replacement_and_redacts_stale_error() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("resources");
        fs::create_dir(&dir).unwrap();
        let mut registry = SelectionRegistry::default();
        let handle = uuid(1);
        let mut generator = FakeGenerator::new(&[&handle]);
        let summary = registry
            .insert(SelectionKind::InstalledRoot, dir.clone(), &mut generator)
            .unwrap();
        let state = DesktopAppState {
            selections: std::sync::Mutex::new(registry),
            ..DesktopAppState::default()
        };
        let input = clone_selection_for_resolution(&state, &summary.handle).unwrap();
        fs::remove_dir(&dir).unwrap();
        fs::write(&dir, b"replacement").unwrap();
        let error = revalidate_selection(input).unwrap_err();
        assert!(matches!(error, DesktopFailure::SelectionStale));
        let json = serde_json::to_string(&error.dto()).unwrap();
        assert!(!json.contains(temp.path().to_string_lossy().as_ref()));
        assert!(!json.contains("resources"));
    }

    #[test]
    fn poisoned_registry_fails_closed_during_resolution_clone() {
        let state = Arc::new(DesktopAppState::default());
        let poisoned = Arc::clone(&state);
        let _ = thread::spawn(move || {
            let _guard = poisoned.selections.lock().unwrap();
            panic!("poison registry for test");
        })
        .join();

        assert!(matches!(
            clone_selection_for_resolution(&state, &uuid(1)),
            Err(DesktopFailure::Internal)
        ));
    }

    #[test]
    fn shape_validation_rejects_wrong_types() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("resource");
        let file = temp.path().join("package.txt");
        let zip = temp.path().join("package.zip");
        fs::create_dir(&dir).unwrap();
        fs::write(&file, b"data").unwrap();
        fs::write(&zip, b"data").unwrap();
        assert!(validate_selection_shape(&dir, SelectionKind::InstalledRoot).is_ok());
        assert!(validate_selection_shape(&zip, SelectionKind::PackageFile).is_ok());
        assert!(matches!(
            validate_selection_shape(&file, SelectionKind::PackageFile),
            Err(DesktopFailure::InvalidPackageFile)
        ));
        assert!(matches!(
            validate_selection_shape(&file, SelectionKind::InstalledRoot),
            Err(DesktopFailure::InvalidInstalledRoot)
        ));
    }

    #[test]
    fn labels_are_basename_only_sanitized_bounded_and_deduplicated() {
        for path in [
            Path::new(
                r"C:\Users\Name\same
	name",
            ),
            Path::new("/tmp/sentinel/same\n\tname"),
            Path::new(
                r"\\server\share\same
	name",
            ),
        ] {
            let label = display_label_base(SelectionKind::InstalledRoot, path);
            assert!(!label.contains("Users"));
            assert!(!label.contains("tmp"));
            assert!(!label.contains("server"));
            assert!(!label.contains('\n'));
            assert!(!label.contains('\t'));
            assert!(label.len() <= MAX_LABEL_BYTES);
        }

        let long_unicode = format!("{}{}", "資".repeat(80), ".zip");
        let label = display_label_base(SelectionKind::PackageFile, Path::new(&long_unicode));
        assert!(label.chars().count() <= MAX_LABEL_CHARS);
        assert!(label.len() <= MAX_LABEL_BYTES);

        let temp = tempdir().unwrap();
        let mut registry = SelectionRegistry::default();
        let handles = [uuid(1), uuid(2), uuid(3)];
        let mut generator = FakeGenerator::new(&[&handles[0], &handles[1], &handles[2]]);
        for parent in ["one", "two"] {
            let path = temp.path().join(parent).join("same-name");
            fs::create_dir_all(&path).unwrap();
            let summary = registry
                .insert(SelectionKind::InstalledRoot, path, &mut generator)
                .unwrap();
            assert_eq!(summary.kind, SelectionKind::InstalledRoot);
        }
        let labels: Vec<_> = registry
            .list(None)
            .into_iter()
            .map(|s| s.display_label)
            .collect();
        assert!(labels.iter().any(|label| label.ends_with("(2)")));
    }

    #[test]
    fn success_dto_does_not_serialize_path() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("private").join("resources");
        fs::create_dir_all(&path).unwrap();
        let mut registry = SelectionRegistry::default();
        let h = uuid(1);
        let mut generator = FakeGenerator::new(&[&h]);
        let summary = registry
            .insert(SelectionKind::InstalledRoot, path, &mut generator)
            .unwrap();
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("private"));
        assert!(!json.contains(temp.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn lease_acquisition_is_rollback_atomic() {
        let temp = tempdir().unwrap();
        let one = temp.path().join("one");
        let two = temp.path().join("two");
        fs::create_dir(&one).unwrap();
        fs::create_dir(&two).unwrap();
        let handles = [uuid(1), uuid(2)];
        let mut generator = FakeGenerator::new(&[&handles[0], &handles[1]]);
        let mut registry = SelectionRegistry::default();
        let first = registry
            .insert(SelectionKind::InstalledRoot, one, &mut generator)
            .unwrap();
        let second = registry
            .insert(SelectionKind::InstalledRoot, two, &mut generator)
            .unwrap();
        let second_handle = SelectionHandle::parse(&second.handle).unwrap();
        registry
            .records
            .get_mut(&second_handle)
            .unwrap()
            .lease_count = u32::MAX;
        let state = DesktopAppState {
            selections: std::sync::Mutex::new(registry),
            ..DesktopAppState::default()
        };

        assert!(matches!(
            lease_selections_for_resolution(&state, &[&first.handle, &second.handle]),
            Err(DesktopFailure::Internal)
        ));

        let registry = state.selections.lock().unwrap();
        let first_handle = SelectionHandle::parse(&first.handle).unwrap();
        assert_eq!(registry.records.get(&first_handle).unwrap().lease_count, 0);
    }
}
