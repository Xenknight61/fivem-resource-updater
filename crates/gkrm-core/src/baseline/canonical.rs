use sha2::{Digest, Sha256};

use crate::baseline::id::BaselineId;
use crate::baseline::model::BaselineEscrowClass;
use crate::Sha256Digest;

pub(crate) const CANONICAL_DOMAIN_TAG: &[u8] = b"gkrm-baseline-id-v1";

pub(crate) struct CanonicalFileInput<'a> {
    pub path: &'a str,
    pub size: u64,
    pub sha256: &'a Sha256Digest,
    pub escrow_class: BaselineEscrowClass,
    pub blob_sha256: Option<&'a Sha256Digest>,
}

pub(crate) struct CanonicalBaselineInput<'a> {
    pub resource_key: &'a str,
    pub resource_name: &'a str,
    pub resource_version: Option<&'a str>,
    pub source_package_fingerprint: Option<&'a Sha256Digest>,
    pub files: Vec<CanonicalFileInput<'a>>,
}

pub(crate) fn compute_baseline_id(input: &CanonicalBaselineInput<'_>) -> BaselineId {
    let payload = encode_canonical_payload(input);
    let digest = Sha256Digest::new(Sha256::digest(&payload).into());
    BaselineId::from_digest(digest)
}

pub(crate) fn encode_canonical_payload(input: &CanonicalBaselineInput<'_>) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(CANONICAL_DOMAIN_TAG);
    put_str(&mut buffer, input.resource_key);
    put_str(&mut buffer, input.resource_name);
    put_optional_str(&mut buffer, input.resource_version);
    put_optional_digest(&mut buffer, input.source_package_fingerprint);

    put_u64(&mut buffer, input.files.len() as u64);
    for file in &input.files {
        put_str(&mut buffer, file.path);
        put_u64(&mut buffer, file.size);
        put_bytes(&mut buffer, file.sha256.as_bytes());
        buffer.push(file.escrow_class.as_stable_code());
        put_optional_digest(&mut buffer, file.blob_sha256);
    }
    buffer
}

fn put_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(buffer: &mut Vec<u8>, value: &[u8]) {
    put_u64(buffer, value.len() as u64);
    buffer.extend_from_slice(value);
}

fn put_str(buffer: &mut Vec<u8>, value: &str) {
    put_bytes(buffer, value.as_bytes());
}

fn put_optional_str(buffer: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => buffer.push(0),
        Some(text) => {
            buffer.push(1);
            put_str(buffer, text);
        }
    }
}

fn put_optional_digest(buffer: &mut Vec<u8>, value: Option<&Sha256Digest>) {
    match value {
        None => buffer.push(0),
        Some(digest) => {
            buffer.push(1);
            put_bytes(buffer, digest.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::model::BaselineEscrowClass;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn sample_input<'a>(
        digest_a: &'a Sha256Digest,
        digest_b: &'a Sha256Digest,
    ) -> CanonicalBaselineInput<'a> {
        CanonicalBaselineInput {
            resource_key: "gksphone",
            resource_name: "gksphone",
            resource_version: Some("1.0.0"),
            source_package_fingerprint: None,
            files: vec![
                CanonicalFileInput {
                    path: "client/main.lua",
                    size: 10,
                    sha256: digest_a,
                    escrow_class: BaselineEscrowClass::Protected,
                    blob_sha256: None,
                },
                CanonicalFileInput {
                    path: "config.lua",
                    size: 4,
                    sha256: digest_b,
                    escrow_class: BaselineEscrowClass::Ignored,
                    blob_sha256: Some(digest_b),
                },
            ],
        }
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let digest_a = digest(0xaa);
        let digest_b = digest(0xbb);
        let input = sample_input(&digest_a, &digest_b);
        let first = encode_canonical_payload(&input);
        let second = encode_canonical_payload(&sample_input(&digest_a, &digest_b));
        assert_eq!(first, second);
        assert_eq!(
            compute_baseline_id(&input),
            compute_baseline_id(&sample_input(&digest_a, &digest_b))
        );
    }

    #[test]
    fn delimiter_like_strings_do_not_collide() {
        let digest_one = digest(1);
        let left = CanonicalBaselineInput {
            resource_key: "resource",
            resource_name: "a\tb",
            resource_version: Some("1=2\n3"),
            source_package_fingerprint: None,
            files: vec![CanonicalFileInput {
                path: "config.lua",
                size: 1,
                sha256: &digest_one,
                escrow_class: BaselineEscrowClass::Protected,
                blob_sha256: None,
            }],
        };
        let right = CanonicalBaselineInput {
            resource_key: "resource",
            resource_name: "a",
            resource_version: Some("tb1=2"),
            source_package_fingerprint: None,
            files: vec![CanonicalFileInput {
                path: "config.lua",
                size: 1,
                sha256: &digest_one,
                escrow_class: BaselineEscrowClass::Protected,
                blob_sha256: None,
            }],
        };
        assert_ne!(
            encode_canonical_payload(&left),
            encode_canonical_payload(&right)
        );
        assert_ne!(compute_baseline_id(&left), compute_baseline_id(&right));
    }

    #[test]
    fn unicode_and_prefix_like_names_are_unambiguous() {
        let left = CanonicalBaselineInput {
            resource_key: "café",
            resource_name: "gkrm-baseline-id-v1",
            resource_version: None,
            source_package_fingerprint: None,
            files: Vec::new(),
        };
        let right = CanonicalBaselineInput {
            resource_key: "cafe\u{301}",
            resource_name: "other",
            resource_version: None,
            source_package_fingerprint: None,
            files: Vec::new(),
        };
        // Length-prefixed UTF-8 bytes differ for composed vs decomposed forms.
        assert_ne!(
            encode_canonical_payload(&left),
            encode_canonical_payload(&right)
        );
    }

    #[test]
    fn optional_blob_changes_identity() {
        let sha = digest(9);
        let without = CanonicalBaselineInput {
            resource_key: "phone",
            resource_name: "phone",
            resource_version: None,
            source_package_fingerprint: None,
            files: vec![CanonicalFileInput {
                path: "config.lua",
                size: 4,
                sha256: &sha,
                escrow_class: BaselineEscrowClass::Ignored,
                blob_sha256: None,
            }],
        };
        let with = CanonicalBaselineInput {
            resource_key: "phone",
            resource_name: "phone",
            resource_version: None,
            source_package_fingerprint: None,
            files: vec![CanonicalFileInput {
                path: "config.lua",
                size: 4,
                sha256: &sha,
                escrow_class: BaselineEscrowClass::Ignored,
                blob_sha256: Some(&sha),
            }],
        };
        assert_ne!(compute_baseline_id(&without), compute_baseline_id(&with));
    }
}
