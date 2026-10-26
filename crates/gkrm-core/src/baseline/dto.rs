use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::baseline::id::BaselineId;
use crate::baseline::key::SafeResourceKey;
use crate::baseline::model::{
    counts_from_dto, make_file_record, verify_counts_match, BaselineEscrowClass,
    BaselineStoreLimits, ValidatedBaselineBundle,
};
use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BaselineDocumentDto {
    pub schema_version: u32,
    pub baseline_id: String,
    pub resource_key: String,
    pub resource_name: String,
    pub resource_version: Option<String>,
    pub source_package_fingerprint: Option<String>,
    pub files: Vec<BaselineFileDto>,
    pub counts: BaselineCountsDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BaselineFileDto {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub escrow_class: EscrowClassDto,
    pub blob_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EscrowClassDto {
    Protected,
    Ignored,
    NotSupported,
}

impl EscrowClassDto {
    fn from_trusted(value: BaselineEscrowClass) -> Self {
        match value {
            BaselineEscrowClass::Protected => Self::Protected,
            BaselineEscrowClass::Ignored => Self::Ignored,
            BaselineEscrowClass::NotSupported => Self::NotSupported,
        }
    }

    fn into_trusted(self) -> BaselineEscrowClass {
        match self {
            Self::Protected => BaselineEscrowClass::Protected,
            Self::Ignored => BaselineEscrowClass::Ignored,
            Self::NotSupported => BaselineEscrowClass::NotSupported,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BaselineCountsDto {
    pub files: u64,
    pub protected_files: u64,
    pub ignored_files: u64,
    pub not_supported_files: u64,
    pub blobs: u64,
    pub total_blob_bytes: u64,
}

pub(crate) fn encode_baseline_json(bundle: &ValidatedBaselineBundle) -> Result<Vec<u8>> {
    let dto = BaselineDocumentDto {
        schema_version: 1,
        baseline_id: bundle.baseline_id().to_string(),
        resource_key: bundle.resource_key().to_string(),
        resource_name: bundle.resource_name().to_owned(),
        resource_version: bundle.resource_version().map(str::to_owned),
        source_package_fingerprint: bundle.source_package_fingerprint().map(ToString::to_string),
        files: bundle
            .files()
            .iter()
            .map(|file| BaselineFileDto {
                path: file.relative_path().to_string(),
                size: file.size(),
                sha256: file.sha256().to_string(),
                escrow_class: EscrowClassDto::from_trusted(file.escrow_class()),
                blob_sha256: file.blob_sha256().map(ToString::to_string),
            })
            .collect(),
        counts: BaselineCountsDto {
            files: bundle.counts().files(),
            protected_files: bundle.counts().protected_files(),
            ignored_files: bundle.counts().ignored_files(),
            not_supported_files: bundle.counts().not_supported_files(),
            blobs: bundle.counts().blobs(),
            total_blob_bytes: bundle.counts().total_blob_bytes(),
        },
    };

    let mut bytes = serde_json::to_vec(&dto).map_err(|source| GkrmError::BaselineStoreIo {
        component: "baseline.json".to_owned(),
        cause: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn decode_baseline_document(
    bytes: &[u8],
    blobs: BTreeMap<Sha256Digest, Vec<u8>>,
    limits: BaselineStoreLimits,
) -> Result<ValidatedBaselineBundle> {
    let dto: BaselineDocumentDto =
        serde_json::from_slice(bytes).map_err(|source| GkrmError::BaselineStoreIo {
            component: "baseline.json".to_owned(),
            cause: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })?;

    if dto.schema_version != 1 {
        return Err(GkrmError::BaselineUnsupportedSchema {
            version: dto.schema_version,
        });
    }

    let stored_id = BaselineId::parse(&dto.baseline_id)?;
    let resource_key = SafeResourceKey::parse(&dto.resource_key)?;
    let mut files = Vec::with_capacity(dto.files.len());
    for file in &dto.files {
        let path = ResourceRelativePath::try_from_slash_str(&file.path)?;
        let sha256 = Sha256Digest::from_lowercase_hex(&file.sha256)?;
        let blob_sha256 = match &file.blob_sha256 {
            Some(value) => Some(Sha256Digest::from_lowercase_hex(value)?),
            None => None,
        };
        files.push(make_file_record(
            path,
            file.size,
            sha256,
            file.escrow_class.into_trusted(),
            blob_sha256,
        ));
    }

    let source_package_fingerprint = match &dto.source_package_fingerprint {
        Some(value) => Some(Sha256Digest::from_lowercase_hex(value)?),
        None => None,
    };

    let declared_counts = counts_from_dto(
        dto.counts.files,
        dto.counts.protected_files,
        dto.counts.ignored_files,
        dto.counts.not_supported_files,
        dto.counts.blobs,
        dto.counts.total_blob_bytes,
    );

    ensure_dto_files_sorted(&dto.files)?;

    let bundle = ValidatedBaselineBundle::try_from_parts_with_bytes(
        resource_key,
        dto.resource_name,
        dto.resource_version,
        source_package_fingerprint,
        files,
        blobs,
        limits,
    )?;

    if bundle.baseline_id() != &stored_id {
        return Err(GkrmError::BaselineIdMismatch {
            stored: stored_id.to_string(),
            computed: bundle.baseline_id().to_string(),
        });
    }
    verify_counts_match(bundle.counts(), &declared_counts)?;
    Ok(bundle)
}

fn ensure_dto_files_sorted(files: &[BaselineFileDto]) -> Result<()> {
    let mut previous: Option<&str> = None;
    for file in files {
        if let Some(previous_path) = previous {
            if file.path == previous_path {
                return Err(GkrmError::BaselineDuplicateFilePath {
                    path: file.path.clone(),
                });
            }
            if file.path.as_str() < previous_path {
                return Err(GkrmError::BaselineInvalidOrdering {
                    path: file.path.clone(),
                });
            }
        }
        previous = Some(file.path.as_str());
    }
    Ok(())
}

#[cfg(test)]
mod escrow_dto_tests {
    use super::EscrowClassDto;

    #[test]
    fn stable_snake_case_codes_round_trip() {
        for (json, expected) in [
            ("\"protected\"", EscrowClassDto::Protected),
            ("\"ignored\"", EscrowClassDto::Ignored),
            ("\"not_supported\"", EscrowClassDto::NotSupported),
        ] {
            let parsed: EscrowClassDto = serde_json::from_str(json).expect("parse");
            assert_eq!(parsed, expected);
            assert_eq!(serde_json::to_string(&parsed).expect("encode"), json);
        }
    }
}
