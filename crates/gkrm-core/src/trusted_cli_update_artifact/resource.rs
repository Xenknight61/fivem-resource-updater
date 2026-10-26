//! Exact SafeResourceKey selection from an inspection report.

use crate::{
    FullInspectionReport, GkrmError, IncomingOfficialResourceSnapshot, InstalledResourceRoot,
    InstalledResourceSnapshot, Result, SafeResourceKey, ZipResourceName, ZipResourceRoot,
};

use super::id::encode_resource_commitment;

#[derive(Clone, Debug)]
pub struct SelectedPackageResource {
    pub resource_key: SafeResourceKey,
    pub installed_root: InstalledResourceRoot,
    pub incoming_root: ZipResourceRoot,
    pub resource_commitment: crate::Sha256Digest,
}

/// Resolve the exact package resource. `requested` is required when multiple eligible resources exist.
pub fn resolve_selected_resource(
    report: &FullInspectionReport,
    requested: Option<&SafeResourceKey>,
) -> Result<SelectedPackageResource> {
    let mut eligible: Vec<(SafeResourceKey, InstalledResourceRoot, ZipResourceRoot)> = Vec::new();
    for matched in &report.comparison().matched_resources {
        let installed_root = matched.resource_match.installed_resource.clone();
        let incoming_root = matched.resource_match.incoming_resource.clone();
        let key = match &incoming_root {
            ZipResourceRoot::Root => {
                return Err(GkrmError::TrustedCliUpdateResourceAmbiguous);
            }
            ZipResourceRoot::Path(path) => {
                let name = path
                    .as_str()
                    .split('/')
                    .next()
                    .ok_or(GkrmError::TrustedCliUpdateResourceNotFound)?;
                SafeResourceKey::parse(name)?
            }
        };
        // Prefer name from discovery when available.
        let key = report
            .incoming_discovery()
            .resources
            .iter()
            .find(|r| r.root == incoming_root)
            .and_then(|r| match &r.name {
                ZipResourceName::Directory(n) => SafeResourceKey::parse(n).ok(),
                ZipResourceName::ZipRoot => None,
            })
            .unwrap_or(key);
        eligible.push((key, installed_root, incoming_root));
    }

    // Also allow selecting from installed-only exact name matches against incoming discovery.
    if eligible.is_empty() {
        for resource in &report.incoming_discovery().resources {
            let key = match &resource.name {
                ZipResourceName::Directory(n) => SafeResourceKey::parse(n)?,
                ZipResourceName::ZipRoot => continue,
            };
            let installed_root = InstalledResourceRoot::Path(
                crate::InstallationRelativePath::from_path(std::path::Path::new(key.as_str()))?,
            );
            eligible.push((key, installed_root, resource.root.clone()));
        }
    }

    eligible.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    eligible.dedup_by(|a, b| a.0 == b.0);

    match (requested, eligible.as_slice()) {
        (None, []) => Err(GkrmError::TrustedCliUpdateResourceNotFound),
        (None, [one]) => Ok(SelectedPackageResource {
            resource_commitment: encode_resource_commitment(one.0.as_str())?,
            resource_key: one.0.clone(),
            installed_root: one.1.clone(),
            incoming_root: one.2.clone(),
        }),
        (None, _) => Err(GkrmError::TrustedCliUpdateResourceSelectionRequired),
        (Some(req), items) => {
            let matches: Vec<_> = items.iter().filter(|(k, _, _)| k == req).collect();
            match matches.as_slice() {
                [one] => Ok(SelectedPackageResource {
                    resource_commitment: encode_resource_commitment(one.0.as_str())?,
                    resource_key: one.0.clone(),
                    installed_root: one.1.clone(),
                    incoming_root: one.2.clone(),
                }),
                [] => Err(GkrmError::TrustedCliUpdateResourceNotFound),
                _ => Err(GkrmError::TrustedCliUpdateResourceAmbiguous),
            }
        }
    }
}

pub fn snapshots_for_selection(
    report: &FullInspectionReport,
    selected: &SelectedPackageResource,
) -> Result<(InstalledResourceSnapshot, IncomingOfficialResourceSnapshot)> {
    let installed = InstalledResourceSnapshot::try_from_inspection(
        report,
        &selected.installed_root,
        &selected.resource_key,
    )?;
    let incoming = IncomingOfficialResourceSnapshot::try_from_inspection(
        report,
        &selected.incoming_root,
        &selected.resource_key,
    )?;
    Ok((installed, incoming))
}
