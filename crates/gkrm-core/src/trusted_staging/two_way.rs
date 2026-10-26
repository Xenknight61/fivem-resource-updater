//! Stage a two-way update: build the candidate tree from an installation and a package.
//!
//! Everything that actually touches the filesystem is shared with the three-way path. This module
//! only decides, per file, where its content comes from; `write_and_publish` then performs the
//! same bounded, no-follow, atomically published write it always has.
//!
//! The manifest identity deliberately carries a fixed marker where the three-way path carries a
//! baseline identifier, so a two-way bundle can never collide with, or be mistaken for, one that
//! was produced by comparing against a captured official baseline.

use super::manifest::{assign_entry_ids, encode_manifest_id, present};
use super::write::{ensure_internal_layout, write_and_publish};
use super::{
    enforce_byte_limits, enforce_structural_limits, probe_present_lengths_from_sources, summarize,
    IncomingStagingContentSource, InstalledStagingContentSource, StagingContentOrigin,
    StagingFinalState, StagingSourceBinding, TrustedStagingBundle, TrustedStagingEntry,
    TrustedStagingManifest, TrustedStagingOperatorMergeInput, TrustedStagingOptions,
    TrustedStagingRoot, TrustedStagingStatus,
};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{
    GkrmError, ResourceRelativePath, Result, Sha256Digest, TwoWayFileAction, TwoWayUpdatePlan,
};

/// Marker used where the three-way manifest identity carries a baseline identifier.
pub(super) const TWO_WAY_BASELINE_MARKER: &str = "two-way:no-official-baseline";

/// What the operator chose for the editable files that differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoWayUpdateMode {
    /// Keep local edits and take what the update adds.
    PreserveLocalEdits,
    /// Take the update's version of every editable file too.
    ReplaceWithIncoming,
}

impl TwoWayUpdateMode {
    fn code(self) -> u8 {
        match self {
            Self::PreserveLocalEdits => 1,
            Self::ReplaceWithIncoming => 2,
        }
    }
}

/// A two-way staging request.
pub struct TwoWayStagingRequest<'a> {
    plan: &'a TwoWayUpdatePlan,
    mode: TwoWayUpdateMode,
    installed_source: &'a InstalledStagingContentSource,
    incoming_source: &'a IncomingStagingContentSource,
    staging_root: &'a TrustedStagingRoot,
    merges: &'a [TrustedStagingOperatorMergeInput<'a>],
    keep_installed: &'a [ResourceRelativePath],
    take_incoming_whole: &'a [ResourceRelativePath],
    options: TrustedStagingOptions,
}

impl<'a> TwoWayStagingRequest<'a> {
    /// `merges` must contain one entry per reviewed file the operator decided line by line.
    ///
    /// `keep_installed` and `take_incoming_whole` name the reviewed files that have no merge to
    /// carry: binary content, an encoding this cannot rewrite, or two sides too far apart to diff.
    /// There is no per-line decision to make for them, so the operator's whole-file answer is the
    /// decision, and naming it in one list or the other says which. Leaving such a file out of
    /// both would make staging guess.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        plan: &'a TwoWayUpdatePlan,
        mode: TwoWayUpdateMode,
        installed_source: &'a InstalledStagingContentSource,
        incoming_source: &'a IncomingStagingContentSource,
        staging_root: &'a TrustedStagingRoot,
        merges: &'a [TrustedStagingOperatorMergeInput<'a>],
        keep_installed: &'a [ResourceRelativePath],
        take_incoming_whole: &'a [ResourceRelativePath],
        options: TrustedStagingOptions,
    ) -> Result<Self> {
        options.validate()?;
        // One file cannot be both kept and replaced. A request that says so has lost track of what
        // was decided, and acting on either half of it would apply a decision nobody made.
        if keep_installed
            .iter()
            .any(|path| take_incoming_whole.contains(path))
        {
            return Err(GkrmError::TrustedStagingReviewUnresolved);
        }
        Ok(Self {
            plan,
            mode,
            installed_source,
            incoming_source,
            staging_root,
            merges,
            keep_installed,
            take_incoming_whole,
            options,
        })
    }
}

/// Identity of the operator's choice, so the manifest is bound to what was actually decided.
fn encode_two_way_review_id(
    plan_id: &Sha256Digest,
    mode: TwoWayUpdateMode,
    merges: &[TrustedStagingOperatorMergeInput<'_>],
    take_incoming_whole: &[ResourceRelativePath],
) -> Result<Sha256Digest> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-two-way-review-v2")
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.digest(plan_id);
    encoder.u8(mode.code());
    encoder
        .usize(merges.len())
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    for merge in merges {
        encoder
            .path(merge.path)
            .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
        encoder.digest(&merge.artifact_id);
        encoder.digest(&merge.content_digest);
    }
    // Handing a whole file to the update is as much a decision as any merge, and two reviews that
    // differ only in which of them were handed over are two different reviews.
    encoder
        .usize(take_incoming_whole.len())
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    for path in take_incoming_whole {
        encoder
            .path(path)
            .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    }
    Ok(encoder.finish())
}

fn map_two_way_entries(
    plan: &TwoWayUpdatePlan,
    mode: TwoWayUpdateMode,
    merges: &[TrustedStagingOperatorMergeInput<'_>],
    keep_installed: &[ResourceRelativePath],
    take_incoming_whole: &[ResourceRelativePath],
) -> Result<Vec<TrustedStagingEntry>> {
    let mut out = Vec::with_capacity(plan.entries().len());
    for entry in plan.entries() {
        let take_incoming = |digest: Option<&Sha256Digest>| -> Result<TrustedStagingEntry> {
            let digest = *digest.ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
            Ok(present(
                entry.path().clone(),
                StagingFinalState::Incoming,
                StagingContentOrigin::Incoming,
                digest,
                StagingSourceBinding::IncomingDigest(digest),
                None,
            ))
        };
        let keep_installed_file = |digest: Option<&Sha256Digest>| -> Result<TrustedStagingEntry> {
            let digest = *digest.ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
            Ok(present(
                entry.path().clone(),
                StagingFinalState::Installed,
                StagingContentOrigin::Installed,
                digest,
                StagingSourceBinding::InstalledDigest(digest),
                None,
            ))
        };

        let mapped = match entry.action() {
            TwoWayFileAction::Unchanged | TwoWayFileAction::KeepLocalOnly => {
                keep_installed_file(entry.installed_digest())?
            }
            TwoWayFileAction::TakeFromUpdate => take_incoming(entry.incoming_digest())?,
            TwoWayFileAction::Review => {
                // A reviewed file reaches staging with the merged bytes the operator approved.
                // Replacing wholesale is the one case that needs no merge, and it is deliberately
                // served by the package's own bytes rather than by a merge that happens to take
                // every line: re-encoding through the operator's newline style would hand them a
                // file that is not byte-for-byte what the developer shipped.
                match merges
                    .iter()
                    .find(|candidate| candidate.path == entry.path())
                {
                    Some(merge) => {
                        if merge.bytes.is_empty() {
                            return Err(GkrmError::TrustedStagingManualMergeResult);
                        }
                        present(
                            entry.path().clone(),
                            StagingFinalState::Merged,
                            StagingContentOrigin::Merged,
                            merge.content_digest,
                            StagingSourceBinding::OperatorMerge(merge.artifact_id),
                            Some(merge.bytes.len() as u64),
                        )
                    }
                    // No merge. Either the operator answered this file whole, or the mode answers
                    // for it. Preserving local edits cannot answer on its own: falling back to
                    // either whole side would apply a decision nobody made.
                    None if keep_installed.contains(entry.path()) => {
                        keep_installed_file(entry.installed_digest())?
                    }
                    None if take_incoming_whole.contains(entry.path()) => {
                        take_incoming(entry.incoming_digest())?
                    }
                    None => match mode {
                        TwoWayUpdateMode::ReplaceWithIncoming => {
                            take_incoming(entry.incoming_digest())?
                        }
                        TwoWayUpdateMode::PreserveLocalEdits => {
                            return Err(GkrmError::TrustedStagingReviewUnresolved)
                        }
                    },
                }
            }
        };
        out.push(mapped);
    }

    out.sort_by(|left, right| left.path().cmp(right.path()));
    for window in out.windows(2) {
        if window[0].path() == window[1].path() {
            return Err(GkrmError::TrustedStagingFinalTreeRejected);
        }
    }
    Ok(out)
}

/// Stage a complete candidate resource tree for a two-way update.
pub fn stage_trusted_resource_two_way(
    request: TwoWayStagingRequest<'_>,
) -> Result<TrustedStagingBundle> {
    request.options.validate()?;

    let mut entries = map_two_way_entries(
        request.plan,
        request.mode,
        request.merges,
        request.keep_installed,
        request.take_incoming_whole,
    )?;
    enforce_structural_limits(&entries, request.options)?;
    request.staging_root.revalidate_identity()?;
    probe_present_lengths_from_sources(
        &mut entries,
        request.installed_source,
        request.incoming_source,
    )?;
    assign_entry_ids(&mut entries, request.plan.plan_id().digest())?;

    let review_id = encode_two_way_review_id(
        request.plan.plan_id().digest(),
        request.mode,
        request.merges,
        request.take_incoming_whole,
    )?;
    let options_tag = request.options.options_tag()?;
    let manifest_id = encode_manifest_id(
        request.plan.plan_id().digest(),
        &review_id,
        None,
        None,
        None,
        None,
        request.plan.resource_key().as_str(),
        TWO_WAY_BASELINE_MARKER,
        request.plan.installed_fingerprint(),
        request.plan.incoming_package_fingerprint(),
        request.plan.incoming_resource_fingerprint(),
        &options_tag,
        &entries,
    )?;

    let summary = summarize(&entries)?;
    enforce_byte_limits(&entries, &summary, request.options)?;

    let manifest = TrustedStagingManifest {
        entries,
        manifest_id,
        plan_id: *request.plan.plan_id().digest(),
        review_id,
        analysis_id: None,
        text_diff_id: None,
        synthesis_id: None,
        merged_bytes_id: None,
    };

    let (tmp_root, bundles_dir) = ensure_internal_layout(request.staging_root)?;
    let (published, guard) = write_and_publish(
        request.staging_root,
        &tmp_root,
        &bundles_dir,
        &manifest,
        request.installed_source,
        super::write::AuxiliaryContentSource::Package(request.incoming_source),
        None,
        request.merges,
    )?;

    let finished = (|| -> Result<TrustedStagingBundle> {
        request.staging_root.revalidate_identity()?;
        let status = TrustedStagingStatus::ReadyForApplyPlanning;
        let bundle_id = super::encode_bundle_id(&manifest, &summary, status)?;
        let staging_root =
            TrustedStagingRoot::try_open(request.staging_root.path_for_disjointness())?;
        Ok(TrustedStagingBundle {
            staging_root,
            published_dir: published.published_dir,
            resource_dir: published.resource_dir,
            manifest,
            summary,
            status,
            bundle_id,
        })
    })();

    match finished {
        Ok(bundle) => {
            guard.disarm();
            Ok(bundle)
        }
        Err(primary) => Err(guard.fail_with_cleanup(primary)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        create_two_way_update_plan, BaselineEscrowClass, IncomingOfficialResourceSnapshot,
        InstalledResourceSnapshot, ResourceRelativePath, SafeResourceKey,
    };

    fn path(value: &str) -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str(value).expect("path")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn fixture_plan() -> TwoWayUpdatePlan {
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let installed = InstalledResourceSnapshot::from_parts_for_test(
            key.clone(),
            vec![
                (path("client/main.lua"), digest(2)),
                (path("config.lua"), digest(3)),
                (path("data/customer_notes.txt"), digest(4)),
            ],
        );
        let incoming = IncomingOfficialResourceSnapshot::from_parts_for_test(
            key,
            digest(200),
            vec![
                (
                    path("client/main.lua"),
                    digest(20),
                    BaselineEscrowClass::Protected,
                ),
                (path("config.lua"), digest(30), BaselineEscrowClass::Ignored),
            ],
        );
        create_two_way_update_plan(&installed, &incoming, None).expect("plan")
    }

    fn entry_for<'a>(entries: &'a [TrustedStagingEntry], value: &str) -> &'a TrustedStagingEntry {
        entries
            .iter()
            .find(|entry| entry.path().as_str() == value)
            .unwrap_or_else(|| panic!("missing {value}"))
    }

    #[test]
    fn preserving_local_edits_stages_the_merged_bytes_for_a_reviewed_file() {
        let plan = fixture_plan();
        let config = path("config.lua");
        let bytes = b"Config.Locale = 'tr'\n".to_vec();
        let merges = [TrustedStagingOperatorMergeInput {
            path: &config,
            artifact_id: digest(7),
            content_digest: digest(8),
            bytes: &bytes,
        }];
        let entries = map_two_way_entries(
            &plan,
            TwoWayUpdateMode::PreserveLocalEdits,
            &merges,
            &[],
            &[],
        )
        .expect("map");

        let merged = entry_for(&entries, "config.lua");
        assert_eq!(merged.final_state, StagingFinalState::Merged);
        assert_eq!(
            merged.source_binding,
            StagingSourceBinding::OperatorMerge(digest(7))
        );
        assert_eq!(merged.expected_byte_length, Some(bytes.len() as u64));
    }

    #[test]
    fn replacing_takes_the_incoming_file_for_the_same_entry() {
        let plan = fixture_plan();
        let entries =
            map_two_way_entries(&plan, TwoWayUpdateMode::ReplaceWithIncoming, &[], &[], &[])
                .expect("map");
        let replaced = entry_for(&entries, "config.lua");
        assert_eq!(replaced.final_state, StagingFinalState::Incoming);
        assert_eq!(
            replaced.source_binding,
            StagingSourceBinding::IncomingDigest(digest(30))
        );
    }

    #[test]
    fn encrypted_files_always_come_from_the_update_and_local_only_files_always_stay() {
        for mode in [
            TwoWayUpdateMode::PreserveLocalEdits,
            TwoWayUpdateMode::ReplaceWithIncoming,
        ] {
            let plan = fixture_plan();
            let config = path("config.lua");
            let bytes = b"x\n".to_vec();
            let merges = [TrustedStagingOperatorMergeInput {
                path: &config,
                artifact_id: digest(7),
                content_digest: digest(8),
                bytes: &bytes,
            }];
            let entries = map_two_way_entries(&plan, mode, &merges, &[], &[]).expect("map");

            let protected = entry_for(&entries, "client/main.lua");
            assert_eq!(protected.final_state, StagingFinalState::Incoming);
            let local_only = entry_for(&entries, "data/customer_notes.txt");
            assert_eq!(local_only.final_state, StagingFinalState::Installed);
            assert_eq!(
                local_only.source_binding,
                StagingSourceBinding::InstalledDigest(digest(4))
            );
        }
    }

    #[test]
    fn a_reviewed_file_without_approved_bytes_is_refused_rather_than_guessed() {
        // Falling back to either whole side here would apply a decision the operator never made.
        let plan = fixture_plan();
        assert!(matches!(
            map_two_way_entries(&plan, TwoWayUpdateMode::PreserveLocalEdits, &[], &[], &[]),
            Err(GkrmError::TrustedStagingReviewUnresolved)
        ));
    }

    #[test]
    fn an_empty_merge_result_is_refused() {
        let plan = fixture_plan();
        let config = path("config.lua");
        let merges = [TrustedStagingOperatorMergeInput {
            path: &config,
            artifact_id: digest(7),
            content_digest: digest(8),
            bytes: &[],
        }];
        assert!(matches!(
            map_two_way_entries(
                &plan,
                TwoWayUpdateMode::PreserveLocalEdits,
                &merges,
                &[],
                &[]
            ),
            Err(GkrmError::TrustedStagingManualMergeResult)
        ));
    }

    #[test]
    fn the_two_modes_produce_different_review_identities() {
        let plan = fixture_plan();
        let preserve = encode_two_way_review_id(
            plan.plan_id().digest(),
            TwoWayUpdateMode::PreserveLocalEdits,
            &[],
            &[],
        )
        .expect("id");
        let replace = encode_two_way_review_id(
            plan.plan_id().digest(),
            TwoWayUpdateMode::ReplaceWithIncoming,
            &[],
            &[],
        )
        .expect("id");
        assert_ne!(preserve, replace);
    }
}
