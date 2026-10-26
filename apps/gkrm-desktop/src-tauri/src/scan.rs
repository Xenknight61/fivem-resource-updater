use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use gkrm_core::{
    discover_zip_resources, inspect_package_resources, inspect_zip_package,
    installed_resource_source_commitment, scan_installed_resources, InstalledInstallationScan,
    InstalledResourceSourceCommitment, InstalledScanLimits, PackageLimits,
    PackageResourceInspectionOptions, PackageResourceInspectionReport, PackageSourceCommitment,
    SafeResourceKey, ZipRelativePath,
};
use uuid::Uuid;

use crate::dto::{
    EscrowState, EscrowSummary, FindingCode, FindingSeverity, FindingSummary, ManifestKind,
    ManifestSummary, ResourceDetail, ResourceStatistics, ResourceStatus, ResourceSummary,
    ScanListResourcesRequest, ScanListResourcesResponse, ScanSourceKind, ScanSummary,
};
use crate::error::{DesktopFailure, DesktopResult};

pub const MAX_SCANS: usize = 8;
const MAX_HANDLE_GENERATION_ATTEMPTS: usize = 32;
const MAX_LABEL_CHARS: usize = 48;
const MAX_LABEL_BYTES: usize = 80;
const MAX_FINDINGS: usize = 50;
pub const DEFAULT_PAGE_SIZE: u32 = 25;
pub const MAX_PAGE_SIZE: u32 = 50;
const MAX_QUERY_CHARS: usize = 64;
const MAX_QUERY_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScanHandle(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceHandle(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReference {
    pub selection_handle: String,
    pub generation: u64,
    pub kind: ScanSourceKind,
}

#[derive(Debug)]
pub struct ScanRecord {
    pub handle: ScanHandle,
    pub source_kind: ScanSourceKind,
    pub source_selection: SelectionReference,
    pub created_sequence: u64,
    pub package_commitment: Option<PackageSourceCommitment>,
    pub summary: ScanSummary,
    pub resources: Vec<ResourceRecord>,
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub handle: ResourceHandle,
    pub resource_key: Option<SafeResourceKey>,
    pub installed_commitment: Option<InstalledResourceSourceCommitment>,
    pub package_manifest_path: Option<ZipRelativePath>,
    pub sort_ordinal: u32,
    pub searchable_name: String,
    pub summary: ResourceSummary,
    pub detail: ResourceDetail,
}

pub trait ScanHandleGenerator {
    fn generate_scan(&mut self) -> ScanHandle;
    fn generate_resource(&mut self) -> ResourceHandle;
}

struct ResourceHandleAllocator<'a, G> {
    generator: &'a mut G,
    allocated: HashSet<ResourceHandle>,
}

impl<'a, G: ScanHandleGenerator> ResourceHandleAllocator<'a, G> {
    fn new(generator: &'a mut G) -> Self {
        Self {
            generator,
            allocated: HashSet::new(),
        }
    }

    fn allocate(&mut self) -> DesktopResult<ResourceHandle> {
        for _ in 0..MAX_HANDLE_GENERATION_ATTEMPTS {
            let handle = self.generator.generate_resource();
            if self.allocated.insert(handle.clone()) {
                return Ok(handle);
            }
        }
        Err(DesktopFailure::Internal)
    }
}

#[derive(Debug, Default)]
pub struct UuidScanHandleGenerator;

impl ScanHandleGenerator for UuidScanHandleGenerator {
    fn generate_scan(&mut self) -> ScanHandle {
        ScanHandle(Uuid::new_v4().to_string())
    }

    fn generate_resource(&mut self) -> ResourceHandle {
        ResourceHandle(Uuid::new_v4().to_string())
    }
}

#[derive(Debug, Default)]
pub struct ScanRegistry {
    records: HashMap<ScanHandle, Arc<ScanRecord>>,
    issued_scan_handles: Vec<ScanHandle>,
    next_sequence: u64,
}

pub struct ScanPermit {
    occupied: Arc<AtomicBool>,
}

impl Drop for ScanPermit {
    fn drop(&mut self) {
        self.occupied.store(false, Ordering::Release);
    }
}

impl ScanHandle {
    pub fn parse(value: &str) -> DesktopResult<Self> {
        parse_uuid_handle(value).map(ScanHandle)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ResourceHandle {
    pub fn parse(value: &str) -> DesktopResult<Self> {
        parse_uuid_handle(value).map(ResourceHandle)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_uuid_handle(value: &str) -> DesktopResult<String> {
    if value.len() != 36 {
        return Err(DesktopFailure::InvalidRequest);
    }
    let uuid = Uuid::parse_str(value).map_err(|_| DesktopFailure::InvalidRequest)?;
    if uuid.get_version_num() != 4 || uuid.to_string() != value {
        return Err(DesktopFailure::InvalidRequest);
    }
    Ok(value.to_owned())
}

impl ScanRegistry {
    pub fn has_capacity(&self) -> bool {
        self.records.len() < MAX_SCANS
    }

    pub fn insert(
        &mut self,
        mut record: ScanRecord,
        generator: &mut impl ScanHandleGenerator,
    ) -> DesktopResult<Arc<ScanRecord>> {
        if !self.has_capacity() {
            return Err(DesktopFailure::ScanLimitReached);
        }
        let handle = self.generate_unique_scan_handle(generator)?;
        record.handle = handle.clone();
        record.created_sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(DesktopFailure::Internal)?;
        let record = Arc::new(record);
        self.issued_scan_handles.push(handle.clone());
        self.records.insert(handle, Arc::clone(&record));
        Ok(record)
    }

    pub fn get(&self, handle: &str) -> DesktopResult<Arc<ScanRecord>> {
        let handle = ScanHandle::parse(handle).map_err(|_| DesktopFailure::ScanNotFound)?;
        self.records
            .get(&handle)
            .cloned()
            .ok_or(DesktopFailure::ScanNotFound)
    }

    pub fn release(&mut self, handle: &str) -> DesktopResult<()> {
        let handle = ScanHandle::parse(handle).map_err(|_| DesktopFailure::ScanNotFound)?;
        self.records
            .remove(&handle)
            .map(|_| ())
            .ok_or(DesktopFailure::ScanNotFound)
    }

    fn generate_unique_scan_handle(
        &self,
        generator: &mut impl ScanHandleGenerator,
    ) -> DesktopResult<ScanHandle> {
        for _ in 0..MAX_HANDLE_GENERATION_ATTEMPTS {
            let handle = generator.generate_scan();
            if !self.records.contains_key(&handle) && !self.issued_scan_handles.contains(&handle) {
                return Ok(handle);
            }
        }
        Err(DesktopFailure::Internal)
    }

    #[cfg(test)]
    pub(crate) fn records_is_empty_for_test(&self) -> bool {
        self.records.is_empty()
    }
}

pub fn acquire_scan_permit(occupied: &Arc<AtomicBool>) -> DesktopResult<ScanPermit> {
    occupied
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| DesktopFailure::ScanBusy)?;
    Ok(ScanPermit {
        occupied: Arc::clone(occupied),
    })
}

pub fn build_installed_scan_record(
    source_label: String,
    selection: SelectionReference,
    path: PathBuf,
    generator: &mut impl ScanHandleGenerator,
) -> DesktopResult<ScanRecord> {
    let scan = scan_installed_resources(&path, InstalledScanLimits::default())
        .map_err(|_| DesktopFailure::InspectionRejected)?;
    adapt_installed_scan(source_label, selection, scan, generator)
}

pub fn build_package_scan_record(
    source_label: String,
    selection: SelectionReference,
    path: PathBuf,
    generator: &mut impl ScanHandleGenerator,
) -> DesktopResult<ScanRecord> {
    let report = inspect_package_resources(&path, PackageResourceInspectionOptions::default())
        .map_err(|_| DesktopFailure::InspectionRejected)?;
    let discovery = discover_zip_resources(
        &inspect_zip_package(&path, PackageLimits::default())
            .map_err(|_| DesktopFailure::InspectionRejected)?,
    )
    .map_err(|_| DesktopFailure::InspectionRejected)?;
    adapt_package_report(source_label, selection, report, discovery, generator)
}

pub fn list_resources(
    record: &ScanRecord,
    request: &ScanListResourcesRequest,
) -> DesktopResult<ScanListResourcesResponse> {
    validate_page_request(request)?;
    let query = request.query.as_deref().map(normalize_query).transpose()?;
    let mut filtered = record
        .resources
        .iter()
        .filter(|resource| {
            request
                .status
                .is_none_or(|status| resource.summary.status == status)
        })
        .filter(|resource| {
            query
                .as_ref()
                .is_none_or(|query| resource.searchable_name.contains(query))
        })
        .collect::<Vec<_>>();
    filtered.sort_by(|left, right| {
        left.summary
            .display_name
            .cmp(&right.summary.display_name)
            .then(left.summary.source_kind.cmp(&right.summary.source_kind))
            .then(left.sort_ordinal.cmp(&right.sort_ordinal))
    });

    let total = to_u32(filtered.len())?;
    let offset = request.offset as usize;
    let limit = request.limit as usize;
    let resources = if offset >= filtered.len() {
        Vec::new()
    } else {
        filtered[offset..filtered.len().min(offset + limit)]
            .iter()
            .map(|resource| resource.summary.clone())
            .collect()
    };

    Ok(ScanListResourcesResponse {
        total,
        offset: request.offset,
        limit: request.limit,
        resources,
    })
}

pub fn resource_detail(record: &ScanRecord, handle: &str) -> DesktopResult<ResourceDetail> {
    let handle = ResourceHandle::parse(handle).map_err(|_| DesktopFailure::ResourceNotFound)?;
    record
        .resources
        .iter()
        .find(|resource| resource.handle == handle)
        .map(|resource| resource.detail.clone())
        .ok_or(DesktopFailure::ResourceNotFound)
}

fn adapt_installed_scan(
    source_label: String,
    selection: SelectionReference,
    scan: InstalledInstallationScan,
    generator: &mut impl ScanHandleGenerator,
) -> DesktopResult<ScanRecord> {
    let mut total_file_count = 0u32;
    let mut total_bytes = 0u64;
    let mut resources = Vec::with_capacity(scan.resources.len());
    let mut labels = BTreeMap::<String, usize>::new();
    let mut handles = ResourceHandleAllocator::new(generator);

    for (index, resource) in scan.resources.into_iter().enumerate() {
        let file_count = to_u32(resource.files.len())?;
        let bytes = resource.files.iter().try_fold(0u64, |acc, file| {
            acc.checked_add(file.size)
                .ok_or(DesktopFailure::InspectionRejected)
        })?;
        total_file_count = checked_u32_add(total_file_count, file_count)?;
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or(DesktopFailure::InspectionRejected)?;
        let warning_count = 0u32;
        let display_name = unique_label(
            &sanitize_label(&resource.name, "Installed resource"),
            &mut labels,
        );
        let resource_key = SafeResourceKey::parse(&resource.name).ok();
        let installed_commitment = resource_key
            .as_ref()
            .map(|key| installed_resource_source_commitment(&resource, key))
            .transpose()
            .map_err(|_| DesktopFailure::InspectionRejected)?;
        let handle = handles.allocate()?;
        let summary = ResourceSummary {
            resource_handle: handle.as_str().to_owned(),
            source_kind: ScanSourceKind::InstalledRoot,
            display_name: display_name.clone(),
            status: ResourceStatus::Available,
            file_count,
            total_bytes: bytes,
            warning_count,
        };
        let detail = ResourceDetail {
            resource_handle: handle.as_str().to_owned(),
            source_kind: ScanSourceKind::InstalledRoot,
            display_name: display_name.clone(),
            status: ResourceStatus::Available,
            manifest: ManifestSummary {
                kind: ManifestKind::Fxmanifest,
                client_script_count: 0,
                server_script_count: 0,
                shared_script_count: 0,
                data_file_count: 0,
                has_ui_page: false,
            },
            escrow: EscrowSummary {
                state: EscrowState::NotAvailable,
                protected_file_count: 0,
                ignored_file_count: 0,
                unsupported_file_count: 0,
            },
            statistics: ResourceStatistics {
                file_count,
                total_bytes: bytes,
            },
            findings: Vec::new(),
            omitted_finding_count: 0,
        };
        resources.push(ResourceRecord {
            handle,
            resource_key,
            installed_commitment,
            package_manifest_path: None,
            sort_ordinal: to_u32(index)?,
            searchable_name: normalize_search_text(&display_name),
            summary,
            detail,
        });
    }

    let warning_count = to_u32(scan.warnings.len())?;
    Ok(ScanRecord {
        handle: ScanHandle(String::new()),
        source_kind: ScanSourceKind::InstalledRoot,
        source_selection: selection,
        created_sequence: 0,
        package_commitment: None,
        summary: ScanSummary {
            source_kind: ScanSourceKind::InstalledRoot,
            source_label,
            resource_count: to_u32(resources.len())?,
            warning_count,
            total_file_count,
            total_bytes,
        },
        resources,
    })
}

fn adapt_package_report(
    source_label: String,
    selection: SelectionReference,
    report: PackageResourceInspectionReport,
    discovery: gkrm_core::ZipResourceDiscovery,
    generator: &mut impl ScanHandleGenerator,
) -> DesktopResult<ScanRecord> {
    if report.resources().len() != discovery.resources.len() {
        return Err(DesktopFailure::InspectionRejected);
    }
    let mut labels = BTreeMap::<String, usize>::new();
    let mut resources = Vec::with_capacity(report.resources().len());
    let mut handles = ResourceHandleAllocator::new(generator);
    let package_commitment = report.package_commitment();
    for (index, resource) in report.resources().iter().enumerate() {
        let discovered = discovery
            .resources
            .get(index)
            .ok_or(DesktopFailure::InspectionRejected)?;
        let discovered_key = match &discovered.name {
            gkrm_core::ZipResourceName::Directory(name) => SafeResourceKey::parse(name).ok(),
            gkrm_core::ZipResourceName::ZipRoot => None,
        };
        if discovered_key != resource.resource_key().cloned() {
            return Err(DesktopFailure::InspectionRejected);
        }
        let file_count = to_u32(resource.file_count())?;
        let warning_count = to_u32(resource.warning_count())?;
        let status = if warning_count == 0 {
            ResourceStatus::Available
        } else {
            ResourceStatus::Warnings
        };
        let display_name = unique_label(
            &sanitize_label(resource.display_name(), "Package resource"),
            &mut labels,
        );
        let resource_key = resource.resource_key().cloned();
        let handle = handles.allocate()?;
        let manifest = resource.manifest();
        let escrow = resource.escrow();
        let findings = findings_for_counts(0, warning_count, 0);
        let summary = ResourceSummary {
            resource_handle: handle.as_str().to_owned(),
            source_kind: ScanSourceKind::PackageFile,
            display_name: display_name.clone(),
            status,
            file_count,
            total_bytes: resource.total_bytes(),
            warning_count,
        };
        let detail = ResourceDetail {
            resource_handle: handle.as_str().to_owned(),
            source_kind: ScanSourceKind::PackageFile,
            display_name: display_name.clone(),
            status,
            manifest: ManifestSummary {
                kind: ManifestKind::Fxmanifest,
                client_script_count: to_u32(manifest.client_script_count)?,
                server_script_count: to_u32(manifest.server_script_count)?,
                shared_script_count: to_u32(manifest.shared_script_count)?,
                data_file_count: to_u32(manifest.data_file_count)?,
                has_ui_page: manifest.has_ui_page,
            },
            escrow: EscrowSummary {
                state: escrow_state(escrow.protected_file_count, escrow.ignored_file_count),
                protected_file_count: to_u32(escrow.protected_file_count)?,
                ignored_file_count: to_u32(escrow.ignored_file_count)?,
                unsupported_file_count: to_u32(escrow.unsupported_file_count)?,
            },
            statistics: ResourceStatistics {
                file_count,
                total_bytes: resource.total_bytes(),
            },
            findings,
            omitted_finding_count: 0,
        };
        resources.push(ResourceRecord {
            handle,
            resource_key,
            installed_commitment: None,
            package_manifest_path: Some(discovered.manifest_path.clone()),
            sort_ordinal: to_u32(index)?,
            searchable_name: normalize_search_text(&display_name),
            summary,
            detail,
        });
    }

    Ok(ScanRecord {
        handle: ScanHandle(String::new()),
        source_kind: ScanSourceKind::PackageFile,
        source_selection: selection,
        created_sequence: 0,
        package_commitment: Some(package_commitment),
        summary: ScanSummary {
            source_kind: ScanSourceKind::PackageFile,
            source_label,
            resource_count: to_u32(report.resource_count())?,
            warning_count: to_u32(report.warning_count())?,
            total_file_count: to_u32(report.total_file_count())?,
            total_bytes: report.total_bytes(),
        },
        resources,
    })
}

fn findings_for_counts(
    scan_warnings: u32,
    manifest_warnings: u32,
    escrow_warnings: u32,
) -> Vec<FindingSummary> {
    let mut findings = Vec::new();
    if scan_warnings > 0 {
        findings.push(FindingSummary {
            code: FindingCode::ScanWarningsPresent,
            severity: FindingSeverity::Warning,
            message: "The scan produced warnings.",
        });
    }
    if manifest_warnings > 0 {
        findings.push(FindingSummary {
            code: FindingCode::ManifestWarningsPresent,
            severity: FindingSeverity::Warning,
            message: "The manifest produced warnings.",
        });
    }
    if escrow_warnings > 0 {
        findings.push(FindingSummary {
            code: FindingCode::EscrowWarningsPresent,
            severity: FindingSeverity::Warning,
            message: "Escrow classification produced warnings.",
        });
    }
    findings.truncate(MAX_FINDINGS);
    findings
}

fn escrow_state(protected: usize, ignored: usize) -> EscrowState {
    match (protected, ignored) {
        (0, 0) => EscrowState::None,
        (_, 0) => EscrowState::Protected,
        (0, _) => EscrowState::Partial,
        (_, _) => EscrowState::Partial,
    }
}

fn validate_page_request(request: &ScanListResourcesRequest) -> DesktopResult<()> {
    if request.limit == 0 || request.limit > MAX_PAGE_SIZE {
        return Err(DesktopFailure::InvalidRequest);
    }
    let _ = request
        .offset
        .checked_add(request.limit)
        .ok_or(DesktopFailure::InvalidRequest)?;
    if let Some(query) = request.query.as_deref() {
        let _ = normalize_query(query)?;
    }
    Ok(())
}

fn normalize_query(query: &str) -> DesktopResult<String> {
    if query.chars().count() > MAX_QUERY_CHARS || query.len() > MAX_QUERY_BYTES {
        return Err(DesktopFailure::InvalidRequest);
    }
    if query.chars().any(char::is_control) {
        return Err(DesktopFailure::InvalidRequest);
    }
    Ok(normalize_search_text(query.trim()))
}

fn normalize_search_text(value: &str) -> String {
    value.to_lowercase()
}

fn sanitize_label(value: &str, fallback: &str) -> String {
    let scrubbed = value
        .chars()
        .map(|c| {
            if c.is_control()
                || c == '\u{202a}'
                || c == '\u{202b}'
                || c == '\u{202d}'
                || c == '\u{202e}'
                || c == '\u{2066}'
                || c == '\u{2067}'
                || c == '\u{2068}'
                || c == '\u{2069}'
            {
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
        truncate_label(fallback)
    } else {
        truncate_label(trimmed)
    }
}

fn unique_label(base: &str, labels: &mut BTreeMap<String, usize>) -> String {
    let count = labels.entry(base.to_owned()).or_insert(0);
    *count += 1;
    if *count == 1 {
        return base.to_owned();
    }
    truncate_label(&format!("{base} ({count})"))
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
        "Resource".to_owned()
    } else {
        output
    }
}

fn checked_u32_add(left: u32, right: u32) -> DesktopResult<u32> {
    left.checked_add(right)
        .ok_or(DesktopFailure::InspectionRejected)
}

fn to_u32(value: usize) -> DesktopResult<u32> {
    u32::try_from(value).map_err(|_| DesktopFailure::InspectionRejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn uuid(n: u128) -> String {
        let mut bytes = n.to_be_bytes();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes).to_string()
    }

    struct ScriptedGenerator {
        scans: VecDeque<ScanHandle>,
        resources: VecDeque<ResourceHandle>,
        fallback: u128,
    }

    impl ScriptedGenerator {
        fn new(resources: Vec<String>) -> Self {
            Self {
                scans: VecDeque::new(),
                resources: resources.into_iter().map(ResourceHandle).collect(),
                fallback: 100,
            }
        }
    }

    impl ScanHandleGenerator for ScriptedGenerator {
        fn generate_scan(&mut self) -> ScanHandle {
            self.scans
                .pop_front()
                .unwrap_or_else(|| ScanHandle(uuid(self.fallback)))
        }

        fn generate_resource(&mut self) -> ResourceHandle {
            self.resources.pop_front().unwrap_or_else(|| {
                self.fallback += 1;
                ResourceHandle(uuid(self.fallback))
            })
        }
    }

    fn write_installed_resource(root: &Path, name: &str) {
        let resource = root.join(name);
        fs::create_dir_all(&resource).unwrap();
        fs::write(
            resource.join("fxmanifest.lua"),
            b"fx_version 'cerulean'\ngame 'gta5'\n",
        )
        .unwrap();
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, contents) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn handles_are_strict_and_separate() {
        assert!(ScanHandle::parse(&uuid(1)).is_ok());
        assert!(ResourceHandle::parse(&uuid(2)).is_ok());
        assert!(ScanHandle::parse("bad").is_err());
        assert!(ResourceHandle::parse("123e4567-e89b-12d3-a456-426614174000").is_err());
    }

    #[test]
    fn pagination_validation_rejects_bad_limits_and_queries() {
        let request = ScanListResourcesRequest {
            scan_handle: uuid(1),
            query: None,
            status: None,
            offset: 0,
            limit: 0,
        };
        assert!(matches!(
            validate_page_request(&request),
            Err(DesktopFailure::InvalidRequest)
        ));
        let request = ScanListResourcesRequest {
            limit: MAX_PAGE_SIZE + 1,
            ..request
        };
        assert!(matches!(
            validate_page_request(&request),
            Err(DesktopFailure::InvalidRequest)
        ));
        let request = ScanListResourcesRequest {
            limit: DEFAULT_PAGE_SIZE,
            query: Some("x".repeat(MAX_QUERY_CHARS + 1)),
            ..request
        };
        assert!(matches!(
            validate_page_request(&request),
            Err(DesktopFailure::InvalidRequest)
        ));
    }

    #[test]
    fn labels_are_sanitized_and_deduplicated() {
        let mut labels = BTreeMap::new();
        let first = unique_label(&sanitize_label("same\nname", "Fallback"), &mut labels);
        let second = unique_label(&sanitize_label("same\tname", "Fallback"), &mut labels);
        assert_eq!(first, "same name");
        assert_eq!(second, "same name (2)");
    }

    #[test]
    fn scan_permit_is_raii() {
        let occupied = Arc::new(AtomicBool::new(false));
        let permit = acquire_scan_permit(&occupied).unwrap();
        assert!(matches!(
            acquire_scan_permit(&occupied),
            Err(DesktopFailure::ScanBusy)
        ));
        drop(permit);
        assert!(acquire_scan_permit(&occupied).is_ok());
    }

    #[test]
    fn installed_resource_handle_collision_retries_and_details_are_unambiguous() {
        let temp = tempdir().unwrap();
        write_installed_resource(temp.path(), "alpha");
        write_installed_resource(temp.path(), "beta");
        let mut generator = ScriptedGenerator::new(vec![uuid(1), uuid(1), uuid(2)]);

        let record = build_installed_scan_record(
            "root".to_owned(),
            SelectionReference {
                selection_handle: uuid(10),
                generation: 1,
                kind: ScanSourceKind::InstalledRoot,
            },
            temp.path().to_path_buf(),
            &mut generator,
        )
        .unwrap();

        let handles = record
            .resources
            .iter()
            .map(|resource| resource.handle.as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(handles, vec![uuid(1), uuid(2)]);
        let first = resource_detail(&record, &handles[0]).unwrap();
        let second = resource_detail(&record, &handles[1]).unwrap();
        assert_ne!(first.display_name, second.display_name);
    }

    #[test]
    fn installed_resource_handle_repeated_collision_fails_closed() {
        let temp = tempdir().unwrap();
        write_installed_resource(temp.path(), "alpha");
        write_installed_resource(temp.path(), "beta");
        let mut generator = ScriptedGenerator::new(
            std::iter::repeat_n(uuid(1), MAX_HANDLE_GENERATION_ATTEMPTS + 1).collect(),
        );

        assert!(matches!(
            build_installed_scan_record(
                "root".to_owned(),
                SelectionReference {
                    selection_handle: uuid(10),
                    generation: 1,
                    kind: ScanSourceKind::InstalledRoot,
                },
                temp.path().to_path_buf(),
                &mut generator,
            ),
            Err(DesktopFailure::Internal)
        ));
    }

    #[test]
    fn package_resource_handle_collision_retries() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                (
                    "alpha/fxmanifest.lua",
                    b"fx_version 'cerulean'\ngame 'gta5'\n",
                ),
                (
                    "beta/fxmanifest.lua",
                    b"fx_version 'cerulean'\ngame 'gta5'\n",
                ),
            ],
        );
        let mut generator = ScriptedGenerator::new(vec![uuid(3), uuid(3), uuid(4)]);

        let record = build_package_scan_record(
            "package".to_owned(),
            SelectionReference {
                selection_handle: uuid(10),
                generation: 1,
                kind: ScanSourceKind::PackageFile,
            },
            package,
            &mut generator,
        )
        .unwrap();

        let mut handles = record
            .resources
            .iter()
            .map(|resource| resource.handle.as_str().to_owned())
            .collect::<Vec<_>>();
        handles.sort();
        handles.dedup();
        assert_eq!(handles.len(), record.resources.len());
    }

    #[test]
    fn package_resource_handle_repeated_collision_fails_closed() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                (
                    "alpha/fxmanifest.lua",
                    b"fx_version 'cerulean'\ngame 'gta5'\n",
                ),
                (
                    "beta/fxmanifest.lua",
                    b"fx_version 'cerulean'\ngame 'gta5'\n",
                ),
            ],
        );
        let mut generator = ScriptedGenerator::new(
            std::iter::repeat_n(uuid(5), MAX_HANDLE_GENERATION_ATTEMPTS + 1).collect(),
        );

        assert!(matches!(
            build_package_scan_record(
                "package".to_owned(),
                SelectionReference {
                    selection_handle: uuid(10),
                    generation: 1,
                    kind: ScanSourceKind::PackageFile,
                },
                package,
                &mut generator,
            ),
            Err(DesktopFailure::Internal)
        ));
    }

    #[test]
    fn desktop_package_adapter_uses_secure_core_default_limit() {
        assert_eq!(
            PackageResourceInspectionOptions::default().max_package_bytes,
            gkrm_core::PACKAGE_RESOURCE_INSPECTION_MAX_PACKAGE_BYTES
        );
    }
}
