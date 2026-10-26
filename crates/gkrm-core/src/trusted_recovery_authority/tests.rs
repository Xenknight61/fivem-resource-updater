use crate::file_identity::StableFileIdentity;
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::trusted_apply_planning::{encode_installed_apply_tree_snapshot, ApplyFileState};
use crate::{InstalledResourceRoot, ResourceRelativePath, SafeResourceKey, Sha256Digest};

use super::body::RecoveryAuthorityNode;
use super::canonical::{encode_recovery_authority_body, BODY_MAGIC};
use super::id::{encode_publication_binding_id, encode_recovery_authority_id};
use super::installed::encode_installed_authority_commitment;
use super::{
    encode_recovery_authority_envelope, parse_recovery_authority_body,
    parse_recovery_authority_envelope, RecoveryAuthorityBodyV1, RecoveryAuthorityEnvelopeV1,
    RecoveryAuthorityLimits,
};

fn selected_commitment(key: &SafeResourceKey) -> Sha256Digest {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-selected-resource-v1").unwrap();
    enc.string(key.as_str()).unwrap();
    enc.finish()
}

#[test]
fn selected_resource_commitment_is_recomputed_from_the_validated_key() {
    let key = SafeResourceKey::parse("gksphone").unwrap();
    let other_key = SafeResourceKey::parse("gksphone-next").unwrap();
    let expected = selected_commitment(&key);
    let substituted = Sha256Digest::new([0xa5; 32]);

    super::verify_selected_resource_commitment(&key, &expected).unwrap();
    assert!(super::verify_selected_resource_commitment(&key, &substituted).is_err());
    assert!(super::verify_selected_resource_commitment(&other_key, &expected).is_err());

    // Agreement between all persisted copies is not authority: each copy is
    // independently rejected when it disagrees with the freshly validated key.
    let artifact_stored = substituted;
    let body_stored = substituted;
    assert_eq!(artifact_stored, body_stored);
    assert!(super::verify_selected_resource_commitment(&key, &artifact_stored).is_err());
    assert!(super::verify_selected_resource_commitment(&key, &body_stored).is_err());
}

// Literal fixtures below were produced by an independent Python struct/sha256 encoder; it does
// not import or execute this crate. Decoding literal hex is intentionally not a wire encoder.
fn decode_literal_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid literal hex"),
            };
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect()
}

fn empty_fixture() -> (RecoveryAuthorityBodyV1, Sha256Digest, Sha256Digest) {
    let key = SafeResourceKey::parse("gksphone").unwrap();
    #[cfg(unix)]
    let identity = StableFileIdentity::Unix {
        device: 1,
        inode: 2,
    };
    #[cfg(windows)]
    let identity = StableFileIdentity::Windows {
        volume_serial: 1,
        file_index: 2,
    };
    let installed = encode_installed_authority_commitment(
        &identity,
        &identity,
        &InstalledResourceRoot::Root,
        &key,
    )
    .unwrap();
    let files = std::collections::BTreeMap::new();
    let directories = std::collections::BTreeSet::new();
    let snapshot = encode_installed_apply_tree_snapshot(&files, &directories).unwrap();
    let body = RecoveryAuthorityBodyV1 {
        apply_derivation_version: 1,
        transaction_derivation_version: 1,
        installed_authority_commitment: installed,
        selected_resource_commitment: selected_commitment(&key),
        baseline_id: Sha256Digest::new([0x33; 32]),
        staging_manifest_id: Sha256Digest::new([0x44; 32]),
        staging_bundle_id: Sha256Digest::new([0x55; 32]),
        snapshot_a_id: snapshot,
        apply_plan_id: Sha256Digest::new([0x66; 32]),
        transactional_plan_id: Sha256Digest::new([0x77; 32]),
        nodes: Vec::new(),
    };
    (body, installed, snapshot)
}

#[test]
fn empty_tree_fixed_vectors_are_literal() {
    let (body, installed, snapshot) = empty_fixture();
    let bytes = encode_recovery_authority_body(&body, RecoveryAuthorityLimits::default()).unwrap();
    let authority = encode_recovery_authority_id(&bytes).unwrap();
    const UNIX_BODY_HEX: &str = concat!(
        "676b726d2d7265636f766572792d617574686f726974792d626f64792d76310a010101d52da7b15540d745ea3b150c04d2557b243a886b3a39d8bef3ffa786cbac031e",
        "d4cb61c60acc007ac3d376e4242c8e062c6047c382abf96dd3ab231540a183f93333333333333333333333333333333333333333333333333333333333333333",
        "44444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555",
        "f49b8650ca72d2a9fbcf0d6e68b7ef4ad7b098897d95dd81f34a735f3d79cd6d6666666666666666666666666666666666666666666666666666666666666666",
        "77777777777777777777777777777777777777777777777777777777777777770000000000000000"
    );
    const WINDOWS_BODY_HEX: &str = concat!(
        "676b726d2d7265636f766572792d617574686f726974792d626f64792d76310a010101e7897a2da8a213c0d53ca81f4217cbf51f44be81a7ff86c00447f7447dff208a",
        "d4cb61c60acc007ac3d376e4242c8e062c6047c382abf96dd3ab231540a183f93333333333333333333333333333333333333333333333333333333333333333",
        "44444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555",
        "f49b8650ca72d2a9fbcf0d6e68b7ef4ad7b098897d95dd81f34a735f3d79cd6d6666666666666666666666666666666666666666666666666666666666666666",
        "77777777777777777777777777777777777777777777777777777777777777770000000000000000"
    );
    assert_eq!(
        bytes,
        decode_literal_hex(if cfg!(unix) {
            UNIX_BODY_HEX
        } else {
            WINDOWS_BODY_HEX
        })
    );
    assert_eq!(bytes.len(), 299);
    assert_eq!(
        installed.to_string(),
        if cfg!(unix) {
            "d52da7b15540d745ea3b150c04d2557b243a886b3a39d8bef3ffa786cbac031e"
        } else {
            "e7897a2da8a213c0d53ca81f4217cbf51f44be81a7ff86c00447f7447dff208a"
        }
    );
    assert_eq!(
        snapshot.to_string(),
        "f49b8650ca72d2a9fbcf0d6e68b7ef4ad7b098897d95dd81f34a735f3d79cd6d"
    );
    assert_eq!(
        authority.to_hex(),
        if cfg!(unix) {
            "e107a1ce41c3783355390c9041741deea0b88e74d2f1bc47384338abe4dd02d2"
        } else {
            "9986f8f57c391ed8ef461b4d3deebd92e588052a11915b761548cf7cc83119be"
        }
    );
    assert_eq!(
        parse_recovery_authority_body(&bytes, RecoveryAuthorityLimits::default()).unwrap(),
        body
    );
}

#[test]
fn file_and_empty_directory_fixed_vector_preserves_tree() {
    use sha2::{Digest, Sha256};
    let (mut body, _, _) = empty_fixture();
    let contents = b"fx_version 'cerulean'\n";
    let digest = Sha256Digest::new(Sha256::digest(contents).into());
    let empty = ResourceRelativePath::try_from_slash_str("empty").unwrap();
    let manifest = ResourceRelativePath::try_from_slash_str("fxmanifest.lua").unwrap();
    body.nodes = vec![
        RecoveryAuthorityNode::Directory {
            path: empty.clone(),
        },
        RecoveryAuthorityNode::File {
            path: manifest.clone(),
            digest,
            byte_length: 22,
        },
    ];
    let mut files = std::collections::BTreeMap::new();
    files.insert(
        manifest,
        ApplyFileState::Present {
            digest,
            byte_length: 22,
        },
    );
    let mut directories = std::collections::BTreeSet::new();
    directories.insert(empty);
    body.snapshot_a_id = encode_installed_apply_tree_snapshot(&files, &directories).unwrap();
    let bytes = encode_recovery_authority_body(&body, RecoveryAuthorityLimits::default()).unwrap();
    const UNIX_BODY_HEX: &str = concat!(
        "676b726d2d7265636f766572792d617574686f726974792d626f64792d76310a010101d52da7b15540d745ea3b150c04d2557b243a886b3a39d8bef3ffa786cbac031e",
        "d4cb61c60acc007ac3d376e4242c8e062c6047c382abf96dd3ab231540a183f93333333333333333333333333333333333333333333333333333333333333333",
        "44444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555",
        "0eaa5d834d423c471c9d496b2420fb0106c4cfcf2fe97469288b1c75cd4fd74e6666666666666666666666666666666666666666666666666666666666666666",
        "777777777777777777777777777777777777777777777777777777777777777702000000000000000500000000000000656d707479020e00000000000000",
        "66786d616e69666573742e6c756101e5798e3c02427506462430a1f9e6aebb607d950d17711ad8863b9a3d43457b581600000000000000"
    );
    const WINDOWS_BODY_HEX: &str = concat!(
        "676b726d2d7265636f766572792d617574686f726974792d626f64792d76310a010101e7897a2da8a213c0d53ca81f4217cbf51f44be81a7ff86c00447f7447dff208a",
        "d4cb61c60acc007ac3d376e4242c8e062c6047c382abf96dd3ab231540a183f93333333333333333333333333333333333333333333333333333333333333333",
        "44444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555",
        "0eaa5d834d423c471c9d496b2420fb0106c4cfcf2fe97469288b1c75cd4fd74e6666666666666666666666666666666666666666666666666666666666666666",
        "777777777777777777777777777777777777777777777777777777777777777702000000000000000500000000000000656d707479020e00000000000000",
        "66786d616e69666573742e6c756101e5798e3c02427506462430a1f9e6aebb607d950d17711ad8863b9a3d43457b581600000000000000"
    );
    assert_eq!(
        bytes,
        decode_literal_hex(if cfg!(unix) {
            UNIX_BODY_HEX
        } else {
            WINDOWS_BODY_HEX
        })
    );
    assert_eq!(bytes.len(), 376);
    assert_eq!(
        body.snapshot_a_id.to_string(),
        "0eaa5d834d423c471c9d496b2420fb0106c4cfcf2fe97469288b1c75cd4fd74e"
    );
    assert_eq!(
        encode_recovery_authority_id(&bytes).unwrap().to_hex(),
        if cfg!(unix) {
            "845bdd6ef67fef8282bcda58755d517d132864952b1a1c1cae945c13b9a1f5fc"
        } else {
            "a746df3a092cc7f25a98d7a3afff15a31b994e52fc94868520fd9ba8a36d90c1"
        }
    );
}

#[test]
fn envelope_round_trip_and_mutation_rejection() {
    use sha2::{Digest, Sha256};

    let (body, _, snapshot) = empty_fixture();
    let body_bytes =
        encode_recovery_authority_body(&body, RecoveryAuthorityLimits::default()).unwrap();
    let authority = encode_recovery_authority_id(&body_bytes).unwrap();
    let artifact = Sha256Digest::new([0x88; 32]);
    let resource_lock = Sha256Digest::new([0x99; 32]);
    let binding = encode_publication_binding_id(
        &artifact,
        &authority,
        body.transactional_plan_id(),
        &snapshot,
        &resource_lock,
    )
    .unwrap();
    let envelope = RecoveryAuthorityEnvelopeV1::create(
        body,
        authority,
        artifact,
        binding,
        RecoveryAuthorityLimits::default(),
    )
    .unwrap();
    let envelope_bytes =
        encode_recovery_authority_envelope(&envelope, RecoveryAuthorityLimits::default()).unwrap();
    assert_eq!(
        binding.to_hex(),
        if cfg!(unix) {
            "012a163a69394da94d11137b47430ceda310a9da21dabe4ee6a838a998c435e9"
        } else {
            "35cb27dcaa09fb0c019fddf2634c552e2688113c14cb93235d9ed689c0646fba"
        }
    );
    let mut expected_envelope =
        decode_literal_hex("676b726d2d7265636f766572792d617574686f726974792d656e76656c6f70652d76310a012b01000000000000");
    // The body is separately byte-for-byte pinned above for both platforms.
    expected_envelope.extend_from_slice(&body_bytes);
    expected_envelope.extend_from_slice(&decode_literal_hex(if cfg!(unix) {
        "e107a1ce41c3783355390c9041741deea0b88e74d2f1bc47384338abe4dd02d2"
    } else {
        "9986f8f57c391ed8ef461b4d3deebd92e588052a11915b761548cf7cc83119be"
    }));
    expected_envelope.extend_from_slice(&[0x88; 32]);
    expected_envelope.extend_from_slice(&decode_literal_hex(if cfg!(unix) {
        "012a163a69394da94d11137b47430ceda310a9da21dabe4ee6a838a998c435e9"
    } else {
        "35cb27dcaa09fb0c019fddf2634c552e2688113c14cb93235d9ed689c0646fba"
    }));
    assert_eq!(envelope_bytes, expected_envelope);
    assert_eq!(
        Sha256Digest::new(Sha256::digest(&envelope_bytes).into()).to_string(),
        if cfg!(unix) {
            "6dc164ac5089a84784898cf25f98ef8f8ba14132735da9daf08cfc3aced3fea1"
        } else {
            "b59c88a244b67af2d9e480ad4c9b4680165d1c95e62e7ff0f49092d8dca9c24e"
        }
    );
    assert_eq!(
        parse_recovery_authority_envelope(&envelope_bytes, RecoveryAuthorityLimits::default())
            .unwrap(),
        envelope
    );
    let mut trailing = envelope_bytes;
    trailing.push(0);
    assert!(
        parse_recovery_authority_envelope(&trailing, RecoveryAuthorityLimits::default()).is_err()
    );
}

#[test]
fn parser_rejects_reordering_missing_parents_and_limits() {
    let (mut body, _, _) = empty_fixture();
    let child = ResourceRelativePath::try_from_slash_str("missing/file.lua").unwrap();
    body.nodes.push(RecoveryAuthorityNode::File {
        path: child,
        digest: Sha256Digest::new([1; 32]),
        byte_length: 1,
    });
    assert!(encode_recovery_authority_body(&body, RecoveryAuthorityLimits::default()).is_err());

    let too_small = RecoveryAuthorityLimits {
        max_body_bytes: 32,
        ..RecoveryAuthorityLimits::default()
    };
    let (empty, _, _) = empty_fixture();
    assert!(encode_recovery_authority_body(&empty, too_small).is_err());
}

#[test]
fn parser_peak_memory_is_code_enforced_and_below_seventy_mibibytes() {
    let estimate = RecoveryAuthorityLimits::default()
        .parser_memory_estimate()
        .unwrap();
    assert_eq!(estimate.input_buffer, 36);
    assert_eq!(estimate.path_arena, 64 * 1024 * 1024);
    assert!(estimate.total < 70 * 1024 * 1024, "{estimate:?}");
}

#[test]
fn parser_dispatches_versions_and_rejects_trailing_or_oversized_counts() {
    let (body, _, _) = empty_fixture();
    let bytes = encode_recovery_authority_body(&body, RecoveryAuthorityLimits::default()).unwrap();

    let mut unknown_format = bytes.clone();
    unknown_format[BODY_MAGIC.len()] = 2;
    assert!(matches!(
        parse_recovery_authority_body(&unknown_format, RecoveryAuthorityLimits::default()),
        Err(crate::GkrmError::TrustedRecoveryAuthorityVersionUnsupported)
    ));

    let mut unknown_derivation = bytes.clone();
    unknown_derivation[BODY_MAGIC.len() + 1] = 2;
    let parsed =
        parse_recovery_authority_body(&unknown_derivation, RecoveryAuthorityLimits::default())
            .unwrap();
    assert_eq!(parsed.apply_derivation_version(), 2);
    assert_eq!(parsed.transaction_derivation_version(), 1);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(parse_recovery_authority_body(&trailing, RecoveryAuthorityLimits::default()).is_err());

    let count_offset = BODY_MAGIC.len() + 3 + 8 * 32;
    let mut oversized = bytes;
    oversized[count_offset..count_offset + 8].copy_from_slice(&40_001_u64.to_le_bytes());
    assert!(matches!(
        parse_recovery_authority_body(&oversized, RecoveryAuthorityLimits::default()),
        Err(crate::GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit: "max_nodes" })
    ));
}

#[test]
fn canonical_model_rejects_duplicate_case_unicode_and_file_prefix_conflicts() {
    let (mut duplicate, _, _) = empty_fixture();
    let path = ResourceRelativePath::try_from_slash_str("same").unwrap();
    duplicate.nodes = vec![
        RecoveryAuthorityNode::Directory { path: path.clone() },
        RecoveryAuthorityNode::Directory { path },
    ];
    assert!(
        encode_recovery_authority_body(&duplicate, RecoveryAuthorityLimits::default()).is_err()
    );

    for names in [["A", "a"], ["e\u{301}", "é"]] {
        let (mut collision, _, _) = empty_fixture();
        let mut directories = std::collections::BTreeSet::new();
        collision.nodes = names
            .iter()
            .map(|name| {
                let path = ResourceRelativePath::try_from_slash_str(name).unwrap();
                directories.insert(path.clone());
                RecoveryAuthorityNode::Directory { path }
            })
            .collect();
        collision.nodes.sort_by(|a, b| a.path().cmp(b.path()));
        collision.snapshot_a_id =
            encode_installed_apply_tree_snapshot(&std::collections::BTreeMap::new(), &directories)
                .unwrap();
        assert!(
            encode_recovery_authority_body(&collision, RecoveryAuthorityLimits::default()).is_err()
        );
    }

    let (mut prefix, _, _) = empty_fixture();
    let parent = ResourceRelativePath::try_from_slash_str("file").unwrap();
    let child = ResourceRelativePath::try_from_slash_str("file/child").unwrap();
    let digest = Sha256Digest::new([0x5a; 32]);
    prefix.nodes = vec![
        RecoveryAuthorityNode::File {
            path: parent.clone(),
            digest,
            byte_length: 1,
        },
        RecoveryAuthorityNode::File {
            path: child.clone(),
            digest,
            byte_length: 1,
        },
    ];
    let mut files = std::collections::BTreeMap::new();
    files.insert(
        parent,
        ApplyFileState::Present {
            digest,
            byte_length: 1,
        },
    );
    files.insert(
        child,
        ApplyFileState::Present {
            digest,
            byte_length: 1,
        },
    );
    prefix.snapshot_a_id =
        encode_installed_apply_tree_snapshot(&files, &std::collections::BTreeSet::new()).unwrap();
    assert!(encode_recovery_authority_body(&prefix, RecoveryAuthorityLimits::default()).is_err());
}

#[test]
fn parser_rejects_unknown_node_tag_reordering_and_snapshot_tampering() {
    let (mut body, _, _) = empty_fixture();
    let empty = ResourceRelativePath::try_from_slash_str("empty").unwrap();
    let file = ResourceRelativePath::try_from_slash_str("fxmanifest.lua").unwrap();
    let digest = Sha256Digest::new([0x7b; 32]);
    body.nodes = vec![
        RecoveryAuthorityNode::Directory {
            path: empty.clone(),
        },
        RecoveryAuthorityNode::File {
            path: file.clone(),
            digest,
            byte_length: 9,
        },
    ];
    let mut files = std::collections::BTreeMap::new();
    files.insert(
        file,
        ApplyFileState::Present {
            digest,
            byte_length: 9,
        },
    );
    let mut directories = std::collections::BTreeSet::new();
    directories.insert(empty);
    body.snapshot_a_id = encode_installed_apply_tree_snapshot(&files, &directories).unwrap();
    let bytes = encode_recovery_authority_body(&body, RecoveryAuthorityLimits::default()).unwrap();
    let node_start = BODY_MAGIC.len() + 3 + 8 * 32 + 8;
    let first_end = node_start + 8 + "empty".len() + 1;

    let mut unknown_tag = bytes.clone();
    unknown_tag[node_start + 8 + "empty".len()] = 9;
    assert!(
        parse_recovery_authority_body(&unknown_tag, RecoveryAuthorityLimits::default()).is_err()
    );

    let mut reordered = bytes[..node_start].to_vec();
    reordered.extend_from_slice(&bytes[first_end..]);
    reordered.extend_from_slice(&bytes[node_start..first_end]);
    assert!(parse_recovery_authority_body(&reordered, RecoveryAuthorityLimits::default()).is_err());

    let mut tampered = bytes;
    let file_digest = first_end + 8 + "fxmanifest.lua".len() + 1;
    tampered[file_digest] ^= 1;
    assert!(parse_recovery_authority_body(&tampered, RecoveryAuthorityLimits::default()).is_err());
}
