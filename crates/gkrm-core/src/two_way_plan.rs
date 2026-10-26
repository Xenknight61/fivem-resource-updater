//! Plan an update from an installation and an incoming package, with no official baseline.
//!
//! FiveM asset escrow encrypts the resource's Lua, YFT, YDD, and YDR files, and a server owner
//! cannot read or edit them. Only the files a developer lists in the manifest's `escrow_ignore`
//! stay open, which in practice means configuration. So the file set splits cleanly:
//!
//! * files the operator could not have edited take the update's version automatically;
//! * files the operator could have edited are the ones — and the only ones — worth reviewing.
//!
//! That split needs no baseline. It comes from the incoming manifest's own escrow declaration,
//! which is the same source the three-way planner already trusts for escrow class.
//!
//! Escrow only ever encrypts those four kinds. Everything else in a resource — the JSON a phone
//! script keeps its settings in, the PNGs its app icons are, its HTML and CSS — is plain on disk
//! whatever the manifest declares, and an operator can and does edit it. Reading "escrow did not
//! declare this" as "the operator cannot have written this" replaced their work without asking,
//! which for a customer who had swapped every app icon was the update quietly undoing an
//! afternoon. What escrow could not protect is theirs to have changed.
//!
//! A file present only in the installation is always kept. Without the original package there is
//! no way to tell "the vendor removed this" from "the operator added this", and keeping it cannot
//! destroy anything, while removing it could.
//!
//! Where the operator still has the package they installed from, it answers a question the two
//! sides cannot: which of the editable files they actually edited. An editable file that differs
//! from the update but is byte-for-byte what they installed was changed by the developer, not by
//! them, and asking about it is asking a question they have no answer to. It takes the update's
//! version like anything else they could not have written. That is the whole of what the baseline
//! does here — it is read for evidence and never for content, and no byte of it is ever written.

pub mod execution_descriptor;

use std::collections::BTreeMap;

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{
    BaselineEscrowClass, GkrmError, IncomingOfficialResourceSnapshot, InstalledResourceSnapshot,
    ResourceRelativePath, Result, SafeResourceKey, Sha256Digest,
};

/// What will happen to one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoWayFileAction {
    /// Both sides already hold the same bytes.
    Unchanged,
    /// Not operator-editable, so the update's version is taken without asking.
    TakeFromUpdate,
    /// Operator-editable and different on the two sides. The operator decides.
    Review,
    /// Present only in the installation, so it stays exactly as it is.
    KeepLocalOnly,
}

/// The extension of the pack escrow itself produces.
///
/// It is not one of the kinds escrow encrypts, so nothing about its class says what it is. It is
/// still not a file an operator writes: it is the encrypted assets, emitted by the packer, and
/// meaningless except as the developer shipped it.
const ESCROW_PACK_EXTENSION: &str = "fxap";

/// Whether this is a file the operator could have written.
///
/// Not the same question as whether escrow encrypts it. Encrypted, they could not read it, let
/// alone edit it. Left open by the manifest, they could. And where escrow cannot reach the kind at
/// all — JSON, images, markup — the file is plain on disk and theirs like any other, which is the
/// case this used to get wrong.
fn operator_could_have_written(path: &ResourceRelativePath, class: BaselineEscrowClass) -> bool {
    match class {
        BaselineEscrowClass::Protected => false,
        BaselineEscrowClass::Ignored => true,
        BaselineEscrowClass::NotSupported => !has_extension(path, ESCROW_PACK_EXTENSION),
    }
}

fn has_extension(path: &ResourceRelativePath, extension: &str) -> bool {
    path.as_str()
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .is_some_and(|(_, found)| found.eq_ignore_ascii_case(extension))
}

/// What the operator installed from, by resource-relative path.
///
/// Digests only. This is evidence about who changed what, never a source of content, and a plan
/// built with it is a different plan from one built without — the questions it asks are not the
/// same ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwoWayBaseline {
    files: BTreeMap<ResourceRelativePath, Sha256Digest>,
}

impl TwoWayBaseline {
    pub fn new(files: impl IntoIterator<Item = (ResourceRelativePath, Sha256Digest)>) -> Self {
        Self {
            files: files.into_iter().collect(),
        }
    }

    /// What the operator installed at `path`, if the package they installed from had it.
    pub fn get(&self, path: &ResourceRelativePath) -> Option<&Sha256Digest> {
        self.files.get(path)
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// One planned file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayPlanEntry {
    path: ResourceRelativePath,
    action: TwoWayFileAction,
    editable: bool,
    installed_digest: Option<Sha256Digest>,
    incoming_digest: Option<Sha256Digest>,
    baseline_digest: Option<Sha256Digest>,
}

impl TwoWayPlanEntry {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }

    pub fn action(&self) -> TwoWayFileAction {
        self.action
    }

    /// True when the incoming manifest declares this path escrow-ignored, which is the only way
    /// a server owner can have edited it.
    pub fn editable(&self) -> bool {
        self.editable
    }

    pub fn installed_digest(&self) -> Option<&Sha256Digest> {
        self.installed_digest.as_ref()
    }

    pub fn incoming_digest(&self) -> Option<&Sha256Digest> {
        self.incoming_digest.as_ref()
    }

    /// What the package the operator installed from held here, when they still have it.
    ///
    /// `None` means no baseline was given, or it did not have this file — not that the file is
    /// unchanged. It is the evidence the action was decided on, kept so a plan can be read back
    /// and account for the questions it did not ask.
    pub fn baseline_digest(&self) -> Option<&Sha256Digest> {
        self.baseline_digest.as_ref()
    }

    /// True when the operator has not touched this file since they installed it.
    ///
    /// Only ever true on evidence: without a baseline there is nothing to compare against and
    /// this says nothing rather than guessing.
    pub fn untouched_since_install(&self) -> bool {
        match (&self.baseline_digest, &self.installed_digest) {
            (Some(baseline), Some(installed)) => baseline == installed,
            _ => false,
        }
    }
}

/// Opaque identity of a two-way plan, bound to both sides it was computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TwoWayPlanId(Sha256Digest);

impl TwoWayPlanId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

/// Counts for a two-way plan, for display without walking the entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwoWayPlanSummary {
    unchanged: usize,
    take_from_update: usize,
    review: usize,
    keep_local_only: usize,
}

impl TwoWayPlanSummary {
    pub fn unchanged(&self) -> usize {
        self.unchanged
    }

    /// Files replaced without asking, because the operator could not have edited them.
    pub fn take_from_update(&self) -> usize {
        self.take_from_update
    }

    /// Editable files that differ. These are the only ones the operator has to look at.
    pub fn review(&self) -> usize {
        self.review
    }

    pub fn keep_local_only(&self) -> usize {
        self.keep_local_only
    }

    pub fn total(&self) -> usize {
        self.unchanged + self.take_from_update + self.review + self.keep_local_only
    }
}

/// A complete two-way update plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayUpdatePlan {
    resource_key: SafeResourceKey,
    installed_fingerprint: Sha256Digest,
    incoming_package_fingerprint: Sha256Digest,
    incoming_resource_fingerprint: Sha256Digest,
    entries: Vec<TwoWayPlanEntry>,
    summary: TwoWayPlanSummary,
    plan_id: TwoWayPlanId,
    causal_context: Option<Sha256Digest>,
}

impl TwoWayUpdatePlan {
    pub fn causal_context(&self) -> Option<&Sha256Digest> {
        self.causal_context.as_ref()
    }

    pub(crate) fn with_causal_context(mut self, context: Option<Sha256Digest>) -> Result<Self> {
        let base = encode_two_way_plan_id(
            &self.resource_key,
            &self.installed_fingerprint,
            &self.incoming_package_fingerprint,
            &self.incoming_resource_fingerprint,
            &self.entries,
        )?;
        self.plan_id = match context {
            None => base,
            Some(context) => {
                let mut encoder = CanonicalFingerprintEncoder::new("gkrm-two-way-causal-plan-v1")?;
                encoder.digest(base.digest());
                encoder.digest(&context);
                TwoWayPlanId(encoder.finish())
            }
        };
        self.causal_context = context;
        Ok(self)
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn installed_fingerprint(&self) -> &Sha256Digest {
        &self.installed_fingerprint
    }

    pub fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_package_fingerprint
    }

    pub fn incoming_resource_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_resource_fingerprint
    }

    pub fn entries(&self) -> &[TwoWayPlanEntry] {
        &self.entries
    }

    pub fn summary(&self) -> TwoWayPlanSummary {
        self.summary
    }

    pub fn plan_id(&self) -> &TwoWayPlanId {
        &self.plan_id
    }
}

/// Plan an update from exactly these two snapshots, and what the operator installed from.
///
/// Both snapshots must already be bound to each other by the trusted comparison that produced
/// them; mismatched pairs fail rather than being reconciled here.
///
/// `baseline` is optional and changes only which files are worth asking about. An editable file
/// that differs from the update but still holds exactly what the operator installed was changed
/// by the developer alone, so it takes the update's version without a question nobody could have
/// answered. Everything else is planned as it would be without one.
pub fn create_two_way_update_plan(
    installed: &InstalledResourceSnapshot,
    incoming: &IncomingOfficialResourceSnapshot,
    baseline: Option<&TwoWayBaseline>,
) -> Result<TwoWayUpdatePlan> {
    if installed.resource_key() != incoming.resource_key() {
        return Err(GkrmError::TwoWayPlanSnapshotMismatch);
    }
    if installed.matched_incoming_resource() != incoming.resource_root()
        || incoming.matched_installed_resource() != installed.resource_root()
    {
        return Err(GkrmError::TwoWayPlanSnapshotMismatch);
    }

    let mut installed_files: BTreeMap<&ResourceRelativePath, &Sha256Digest> = BTreeMap::new();
    for (path, digest) in installed.file_states() {
        if installed_files.insert(path, digest).is_some() {
            return Err(GkrmError::TwoWayPlanDuplicatePath);
        }
    }

    let mut incoming_files: BTreeMap<&ResourceRelativePath, (&Sha256Digest, BaselineEscrowClass)> =
        BTreeMap::new();
    for (path, digest, escrow_class) in incoming.incoming_file_states() {
        if incoming_files
            .insert(path, (digest, escrow_class))
            .is_some()
        {
            return Err(GkrmError::TwoWayPlanDuplicatePath);
        }
    }

    let mut paths: Vec<&ResourceRelativePath> = installed_files
        .keys()
        .copied()
        .chain(incoming_files.keys().copied())
        .collect();
    paths.sort();
    paths.dedup();

    let mut entries = Vec::with_capacity(paths.len());
    let mut summary = TwoWayPlanSummary {
        unchanged: 0,
        take_from_update: 0,
        review: 0,
        keep_local_only: 0,
    };

    for path in paths {
        let installed_digest = installed_files.get(path).copied();
        let incoming = incoming_files.get(path).copied();
        let editable = incoming.is_some_and(|(_, class)| operator_could_have_written(path, class));
        let baseline_digest = baseline.and_then(|baseline| baseline.get(path));
        // Editable, changed by the update, and still exactly what the operator installed. Nobody
        // but the developer has touched it, so there is nothing here for the operator to decide.
        let untouched = match (baseline_digest, installed_digest) {
            (Some(base), Some(local)) => base == local,
            _ => false,
        };

        let action = match (installed_digest, incoming) {
            (Some(local), Some((remote, _))) if local == remote => TwoWayFileAction::Unchanged,
            (Some(_), Some(_)) if editable && !untouched => TwoWayFileAction::Review,
            (Some(_), Some(_)) => TwoWayFileAction::TakeFromUpdate,
            (None, Some(_)) => TwoWayFileAction::TakeFromUpdate,
            (Some(_), None) => TwoWayFileAction::KeepLocalOnly,
            (None, None) => return Err(GkrmError::TwoWayPlanInvariant),
        };

        match action {
            TwoWayFileAction::Unchanged => summary.unchanged += 1,
            TwoWayFileAction::TakeFromUpdate => summary.take_from_update += 1,
            TwoWayFileAction::Review => summary.review += 1,
            TwoWayFileAction::KeepLocalOnly => summary.keep_local_only += 1,
        }

        entries.push(TwoWayPlanEntry {
            path: path.clone(),
            action,
            editable,
            installed_digest: installed_digest.copied(),
            incoming_digest: incoming.map(|(digest, _)| *digest),
            baseline_digest: baseline_digest.copied(),
        });
    }

    let plan_id = encode_two_way_plan_id(
        installed.resource_key(),
        installed.fingerprint(),
        incoming.package_fingerprint(),
        incoming.resource_fingerprint(),
        &entries,
    )?;

    Ok(TwoWayUpdatePlan {
        resource_key: installed.resource_key().clone(),
        installed_fingerprint: *installed.fingerprint(),
        incoming_package_fingerprint: *incoming.package_fingerprint(),
        incoming_resource_fingerprint: *incoming.resource_fingerprint(),
        entries,
        summary,
        plan_id,
        causal_context: None,
    })
}

fn action_code(action: TwoWayFileAction) -> u64 {
    match action {
        TwoWayFileAction::Unchanged => 1,
        TwoWayFileAction::TakeFromUpdate => 2,
        TwoWayFileAction::Review => 3,
        TwoWayFileAction::KeepLocalOnly => 4,
    }
}

fn encode_two_way_plan_id(
    resource_key: &SafeResourceKey,
    installed_fingerprint: &Sha256Digest,
    incoming_package_fingerprint: &Sha256Digest,
    incoming_resource_fingerprint: &Sha256Digest,
    entries: &[TwoWayPlanEntry],
) -> Result<TwoWayPlanId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-two-way-update-plan-v2")
        .map_err(|_| GkrmError::TwoWayPlanIdEncodingFailure)?;
    encoder
        .string(resource_key.as_str())
        .map_err(|_| GkrmError::TwoWayPlanIdEncodingFailure)?;
    for digest in [
        installed_fingerprint,
        incoming_package_fingerprint,
        incoming_resource_fingerprint,
    ] {
        encoder.digest(digest);
    }
    encoder
        .usize(entries.len())
        .map_err(|_| GkrmError::TwoWayPlanIdEncodingFailure)?;
    for entry in entries {
        encoder
            .path(&entry.path)
            .map_err(|_| GkrmError::TwoWayPlanIdEncodingFailure)?;
        encoder.u64(action_code(entry.action));
        encoder.bool(entry.editable);
        for digest in [
            entry.installed_digest,
            entry.incoming_digest,
            entry.baseline_digest,
        ] {
            match digest {
                Some(value) => {
                    encoder.u8(1);
                    encoder.digest(&value);
                }
                None => encoder.u8(0),
            }
        }
    }
    Ok(TwoWayPlanId(encoder.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::three_way_plan::{IncomingOfficialResourceSnapshot, InstalledResourceSnapshot};

    fn key(value: &str) -> SafeResourceKey {
        SafeResourceKey::parse(value).expect("key")
    }

    fn path(value: &str) -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str(value).expect("path")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn installed(files: &[(&str, u8)]) -> InstalledResourceSnapshot {
        InstalledResourceSnapshot::from_parts_for_test(
            key("gksphone"),
            files
                .iter()
                .map(|(name, byte)| (path(name), digest(*byte)))
                .collect(),
        )
    }

    fn incoming_with_key(
        files: &[(&str, u8, BaselineEscrowClass)],
        resource: &str,
    ) -> IncomingOfficialResourceSnapshot {
        IncomingOfficialResourceSnapshot::from_parts_for_test(
            key(resource),
            digest(200),
            files
                .iter()
                .map(|(name, byte, class)| (path(name), digest(*byte), *class))
                .collect(),
        )
    }

    fn incoming(files: &[(&str, u8, BaselineEscrowClass)]) -> IncomingOfficialResourceSnapshot {
        incoming_with_key(files, "gksphone")
    }

    /// The gksphone fixture, expressed as the two snapshots a scan and an inspection produce.
    pub(super) fn fixture_plan() -> TwoWayUpdatePlan {
        let installed = installed(&[
            ("client/custom.lua", 1),
            ("client/main.lua", 2),
            ("config.lua", 3),
            ("data/customer_notes.txt", 4),
            ("fxmanifest.lua", 5),
            ("server/main.lua", 6),
        ]);
        let incoming = incoming(&[
            ("client/custom.lua", 1, BaselineEscrowClass::Ignored),
            ("client/main.lua", 20, BaselineEscrowClass::Protected),
            ("client/new_feature.lua", 21, BaselineEscrowClass::Protected),
            ("config.lua", 30, BaselineEscrowClass::Ignored),
            ("fxmanifest.lua", 50, BaselineEscrowClass::Protected),
            ("server/main.lua", 6, BaselineEscrowClass::Protected),
        ]);
        create_two_way_update_plan(&installed, &incoming, None).expect("plan")
    }

    fn action_for(plan: &TwoWayUpdatePlan, path: &str) -> TwoWayFileAction {
        plan.entries()
            .iter()
            .find(|entry| entry.path().as_str() == path)
            .unwrap_or_else(|| panic!("missing {path}"))
            .action()
    }

    #[test]
    fn only_editable_files_that_differ_need_review() {
        let plan = fixture_plan();
        assert_eq!(action_for(&plan, "config.lua"), TwoWayFileAction::Review);
        assert_eq!(plan.summary().review(), 1);
    }

    #[test]
    fn encrypted_files_are_replaced_without_asking() {
        let plan = fixture_plan();
        for path in [
            "client/main.lua",
            "fxmanifest.lua",
            "client/new_feature.lua",
        ] {
            assert_eq!(
                action_for(&plan, path),
                TwoWayFileAction::TakeFromUpdate,
                "{path}"
            );
        }
    }

    #[test]
    fn an_editable_file_the_operator_left_alone_is_not_review_work() {
        // client/custom.lua is escrow-ignored but identical on both sides.
        let plan = fixture_plan();
        assert_eq!(
            action_for(&plan, "client/custom.lua"),
            TwoWayFileAction::Unchanged
        );
    }

    #[test]
    fn a_file_only_the_installation_has_is_kept() {
        // Without the original package there is no way to tell a vendor removal from an operator
        // addition, and keeping it is the only choice that cannot destroy the operator's work.
        let plan = fixture_plan();
        assert_eq!(
            action_for(&plan, "data/customer_notes.txt"),
            TwoWayFileAction::KeepLocalOnly
        );
    }

    #[test]
    fn an_unchanged_encrypted_file_is_left_alone() {
        let plan = fixture_plan();
        assert_eq!(
            action_for(&plan, "server/main.lua"),
            TwoWayFileAction::Unchanged
        );
    }

    #[test]
    fn every_planned_path_is_accounted_for_exactly_once() {
        let plan = fixture_plan();
        assert_eq!(plan.entries().len(), 7);
        assert_eq!(plan.summary().total(), 7);
        assert_eq!(plan.summary().unchanged(), 2);
        assert_eq!(plan.summary().take_from_update(), 3);
        assert_eq!(plan.summary().keep_local_only(), 1);
    }

    #[test]
    fn plan_identity_changes_with_either_side() {
        let first = fixture_plan();
        let second = create_two_way_update_plan(
            &installed(&[("config.lua", 99)]),
            &incoming(&[("config.lua", 30, BaselineEscrowClass::Ignored)]),
            None,
        )
        .expect("plan");
        assert_ne!(first.plan_id(), second.plan_id());
    }

    fn baseline(files: &[(&str, u8)]) -> TwoWayBaseline {
        TwoWayBaseline::new(files.iter().map(|(name, byte)| (path(name), digest(*byte))))
    }

    /// One editable file, changed by the update, with the operator's copy under test.
    fn plan_with_baseline(installed_byte: u8, base: Option<&TwoWayBaseline>) -> TwoWayUpdatePlan {
        create_two_way_update_plan(
            &installed(&[("config.lua", installed_byte)]),
            &incoming(&[("config.lua", 30, BaselineEscrowClass::Ignored)]),
            base,
        )
        .expect("plan")
    }

    #[test]
    fn what_escrow_cannot_protect_is_the_operators_to_have_changed() {
        // Escrow encrypts Lua, YFT, YDD and YDR and nothing else. A phone script's config.json and
        // its app icons are plain on disk whatever the manifest says, and a customer who swapped
        // every icon had them replaced without being asked.
        let plan = create_two_way_update_plan(
            &installed(&[
                ("config/config.json", 3),
                ("html/img/apps/bank.png", 4),
                ("html/index.html", 5),
            ]),
            &incoming(&[
                ("config/config.json", 30, BaselineEscrowClass::NotSupported),
                (
                    "html/img/apps/bank.png",
                    40,
                    BaselineEscrowClass::NotSupported,
                ),
                ("html/index.html", 50, BaselineEscrowClass::NotSupported),
            ]),
            None,
        )
        .expect("plan");

        assert_eq!(plan.summary().review(), 3);
        assert_eq!(plan.summary().take_from_update(), 0);
    }

    #[test]
    fn the_escrow_pack_is_never_the_operators_however_it_is_classified() {
        // The .fxap is the encrypted assets, emitted by the packer. Escrow does not encrypt it, so
        // nothing about its class says what it is — but an operator cannot write one, and asking
        // them about it is asking a question with no answer.
        let plan = create_two_way_update_plan(
            &installed(&[(".fxap", 3)]),
            &incoming(&[(".fxap", 30, BaselineEscrowClass::NotSupported)]),
            None,
        )
        .expect("plan");

        assert_eq!(action_for(&plan, ".fxap"), TwoWayFileAction::TakeFromUpdate);
        assert_eq!(plan.summary().review(), 0);
    }

    #[test]
    fn an_encrypted_file_is_still_not_the_operators() {
        let plan = create_two_way_update_plan(
            &installed(&[("client/main.lua", 3)]),
            &incoming(&[("client/main.lua", 30, BaselineEscrowClass::Protected)]),
            None,
        )
        .expect("plan");

        assert_eq!(
            action_for(&plan, "client/main.lua"),
            TwoWayFileAction::TakeFromUpdate
        );
    }

    #[test]
    fn the_baseline_settles_an_image_the_operator_never_touched() {
        // Which is what keeps the honest answer from becoming four dozen questions: the icons a
        // customer did not touch are the developer's own, and nobody has to look at them.
        let base = baseline(&[("html/img/apps/bank.png", 3)]);
        let plan = create_two_way_update_plan(
            &installed(&[("html/img/apps/bank.png", 3)]),
            &incoming(&[(
                "html/img/apps/bank.png",
                40,
                BaselineEscrowClass::NotSupported,
            )]),
            Some(&base),
        )
        .expect("plan");

        assert_eq!(
            action_for(&plan, "html/img/apps/bank.png"),
            TwoWayFileAction::TakeFromUpdate
        );
        assert!(plan.entries()[0].untouched_since_install());
    }

    #[test]
    fn a_file_the_operator_never_touched_is_not_a_question() {
        // The case the whole baseline exists for. Every editable file the developer changed looks
        // exactly like one the operator changed, and against a real package that was two dozen
        // questions the operator had no answer to for every one they did.
        let base = baseline(&[("config.lua", 3)]);
        let plan = plan_with_baseline(3, Some(&base));

        assert_eq!(
            action_for(&plan, "config.lua"),
            TwoWayFileAction::TakeFromUpdate
        );
        assert_eq!(plan.summary().review(), 0);
        assert!(plan.entries()[0].untouched_since_install());
    }

    #[test]
    fn a_file_the_operator_did_touch_is_still_theirs_to_answer() {
        let base = baseline(&[("config.lua", 3)]);
        let plan = plan_with_baseline(99, Some(&base));

        assert_eq!(action_for(&plan, "config.lua"), TwoWayFileAction::Review);
        assert!(!plan.entries()[0].untouched_since_install());
    }

    #[test]
    fn a_file_the_baseline_does_not_have_is_asked_about_rather_than_assumed() {
        // The operator added it, or the developer added it after they installed. Either way the
        // baseline says nothing about it, and saying nothing is not the same as saying nobody
        // touched it.
        let base = baseline(&[("other.lua", 7)]);
        let plan = plan_with_baseline(99, Some(&base));

        assert_eq!(action_for(&plan, "config.lua"), TwoWayFileAction::Review);
        assert_eq!(plan.entries()[0].baseline_digest(), None);
        assert!(!plan.entries()[0].untouched_since_install());
    }

    #[test]
    fn a_plan_that_asked_a_different_question_has_a_different_identity() {
        // Two plans over the same two sides, one of which knows who changed what. They do not do
        // the same work and must not be able to pass for each other.
        let base = baseline(&[("config.lua", 3)]);
        assert_ne!(
            plan_with_baseline(3, None).plan_id(),
            plan_with_baseline(3, Some(&base)).plan_id()
        );
    }

    #[test]
    fn without_a_baseline_nothing_is_claimed_about_who_touched_what() {
        let plan = plan_with_baseline(3, None);
        assert_eq!(action_for(&plan, "config.lua"), TwoWayFileAction::Review);
        assert!(!plan.entries()[0].untouched_since_install());
    }

    #[test]
    fn snapshots_that_are_not_bound_to_each_other_are_refused() {
        assert!(matches!(
            create_two_way_update_plan(
                &installed(&[("config.lua", 1)]),
                &incoming_with_key(&[("config.lua", 2, BaselineEscrowClass::Ignored)], "other"),
                None,
            ),
            Err(GkrmError::TwoWayPlanSnapshotMismatch)
        ));
    }
}
