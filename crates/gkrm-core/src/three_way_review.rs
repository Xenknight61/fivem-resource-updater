use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{
    BaselineId, GkrmError, ResourceRelativePath, Result, SafeResourceKey, Sha256Digest,
    ThreeWayPlanDisposition, ThreeWayPlanId, ThreeWayUpdatePlan,
};

#[derive(Debug)]
pub struct ThreeWayPlanReviewRequest<'a> {
    plan: &'a ThreeWayUpdatePlan,
    decision_set: &'a ThreeWayPlanDecisionSet,
}

impl<'a> ThreeWayPlanReviewRequest<'a> {
    pub fn try_new(
        plan: &'a ThreeWayUpdatePlan,
        decision_set: &'a ThreeWayPlanDecisionSet,
    ) -> Result<Self> {
        Ok(Self { plan, decision_set })
    }

    pub fn plan(&self) -> &ThreeWayUpdatePlan {
        self.plan
    }

    pub fn decision_set(&self) -> &ThreeWayPlanDecisionSet {
        self.decision_set
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayPlanDecisionChoice {
    AcceptRecommended,
    UseIncomingState,
    PreserveInstalledState,
    QueueMergeAnalysis,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTransitionAcknowledgement {
    NotProvided,
    Acknowledged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPlanDecision {
    path: ResourceRelativePath,
    choice: ThreeWayPlanDecisionChoice,
    policy_acknowledgement: PolicyTransitionAcknowledgement,
}

impl ThreeWayPlanDecision {
    pub fn try_new(
        path: ResourceRelativePath,
        choice: ThreeWayPlanDecisionChoice,
        policy_acknowledgement: PolicyTransitionAcknowledgement,
    ) -> Result<Self> {
        Ok(Self {
            path,
            choice,
            policy_acknowledgement,
        })
    }

    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }

    pub fn choice(&self) -> ThreeWayPlanDecisionChoice {
        self.choice
    }

    pub fn policy_acknowledgement(&self) -> PolicyTransitionAcknowledgement {
        self.policy_acknowledgement
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPlanDecisionSet {
    plan_id: ThreeWayPlanId,
    decisions: Vec<ThreeWayPlanDecision>,
}

impl ThreeWayPlanDecisionSet {
    pub fn try_new(
        plan_id: ThreeWayPlanId,
        mut decisions: Vec<ThreeWayPlanDecision>,
    ) -> Result<Self> {
        let _ = decisions
            .len()
            .checked_add(0)
            .ok_or(GkrmError::ThreeWayReviewArithmeticOverflow)?;
        decisions.sort_by(|left, right| left.path.cmp(&right.path));

        let mut seen = BTreeSet::new();
        for decision in &decisions {
            if !seen.insert(decision.path.clone()) {
                return Err(GkrmError::ThreeWayReviewDuplicateDecisionPath);
            }
        }

        Ok(Self { plan_id, decisions })
    }

    pub fn plan_id(&self) -> &ThreeWayPlanId {
        &self.plan_id
    }

    pub fn decisions(&self) -> &[ThreeWayPlanDecision] {
        &self.decisions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayPlanReviewRequirement {
    NoDecisionRequired,
    DecisionRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayReviewedAction {
    NotRequired,
    Pending,
    UseIncomingState,
    PreserveInstalledState,
    QueueMergeAnalysis,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayPlanReviewStatus {
    Incomplete,
    AwaitingFurtherAnalysis,
    DecisionComplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPlanReviewEntry {
    path: ResourceRelativePath,
    requirement: ThreeWayPlanReviewRequirement,
    recommended_action: Option<ThreeWayReviewedAction>,
    action: ThreeWayReviewedAction,
    policy_acknowledgement: PolicyTransitionAcknowledgement,
}

impl ThreeWayPlanReviewEntry {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }

    pub fn requirement(&self) -> ThreeWayPlanReviewRequirement {
        self.requirement
    }

    pub fn recommended_action(&self) -> Option<ThreeWayReviewedAction> {
        self.recommended_action
    }

    pub fn action(&self) -> ThreeWayReviewedAction {
        self.action
    }

    pub fn policy_acknowledgement(&self) -> PolicyTransitionAcknowledgement {
        self.policy_acknowledgement
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPlanReviewSummary {
    total_entries: usize,
    no_decision_required: usize,
    decisions_required: usize,
    decisions_recorded: usize,
    pending: usize,
    use_incoming: usize,
    preserve_installed: usize,
    queued_merge_analysis: usize,
    manual_review: usize,
    policy_acknowledgements: usize,
}

impl ThreeWayPlanReviewSummary {
    pub fn total_entries(&self) -> usize {
        self.total_entries
    }

    pub fn no_decision_required(&self) -> usize {
        self.no_decision_required
    }

    pub fn decisions_required(&self) -> usize {
        self.decisions_required
    }

    pub fn decisions_recorded(&self) -> usize {
        self.decisions_recorded
    }

    pub fn pending(&self) -> usize {
        self.pending
    }

    pub fn use_incoming(&self) -> usize {
        self.use_incoming
    }

    pub fn preserve_installed(&self) -> usize {
        self.preserve_installed
    }

    pub fn queued_merge_analysis(&self) -> usize {
        self.queued_merge_analysis
    }

    pub fn manual_review(&self) -> usize {
        self.manual_review
    }

    pub fn policy_acknowledgements(&self) -> usize {
        self.policy_acknowledgements
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreeWayPlanReviewId(Sha256Digest);

impl ThreeWayPlanReviewId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPlanReview {
    plan_id: ThreeWayPlanId,
    resource_key: SafeResourceKey,
    baseline_id: BaselineId,
    installed_snapshot_fingerprint: Sha256Digest,
    incoming_package_fingerprint: Sha256Digest,
    incoming_resource_fingerprint: Sha256Digest,
    entries: Vec<ThreeWayPlanReviewEntry>,
    summary: ThreeWayPlanReviewSummary,
    status: ThreeWayPlanReviewStatus,
    review_id: ThreeWayPlanReviewId,
}

impl ThreeWayPlanReview {
    pub fn plan_id(&self) -> &ThreeWayPlanId {
        &self.plan_id
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn baseline_id(&self) -> &BaselineId {
        &self.baseline_id
    }

    pub fn installed_snapshot_fingerprint(&self) -> &Sha256Digest {
        &self.installed_snapshot_fingerprint
    }

    pub fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_package_fingerprint
    }

    pub fn incoming_resource_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_resource_fingerprint
    }

    pub fn entries(&self) -> &[ThreeWayPlanReviewEntry] {
        &self.entries
    }

    pub fn summary(&self) -> &ThreeWayPlanReviewSummary {
        &self.summary
    }

    pub fn status(&self) -> ThreeWayPlanReviewStatus {
        self.status
    }

    pub fn review_id(&self) -> &ThreeWayPlanReviewId {
        &self.review_id
    }

    pub(crate) fn from_desktop_apply_descriptor(
        plan: &ThreeWayUpdatePlan,
        review_id: Sha256Digest,
        entries: Vec<ThreeWayPlanReviewEntry>,
    ) -> Self {
        let summary = summarize_entries_for_descriptor(&entries);
        Self {
            plan_id: *plan.plan_id(),
            resource_key: plan.resource_key().clone(),
            baseline_id: plan.baseline_id().clone(),
            installed_snapshot_fingerprint: *plan.installed_snapshot_fingerprint(),
            incoming_package_fingerprint: *plan.incoming_package_fingerprint(),
            incoming_resource_fingerprint: *plan.incoming_resource_fingerprint(),
            entries,
            summary,
            status: ThreeWayPlanReviewStatus::DecisionComplete,
            review_id: ThreeWayPlanReviewId::from_digest(review_id),
        }
    }
}

impl ThreeWayPlanReviewEntry {
    pub(crate) fn from_desktop_apply_descriptor(
        path: ResourceRelativePath,
        action: ThreeWayReviewedAction,
    ) -> Self {
        Self {
            path,
            requirement: ThreeWayPlanReviewRequirement::NoDecisionRequired,
            recommended_action: None,
            action,
            policy_acknowledgement: PolicyTransitionAcknowledgement::NotProvided,
        }
    }
}

fn summarize_entries_for_descriptor(
    entries: &[ThreeWayPlanReviewEntry],
) -> ThreeWayPlanReviewSummary {
    let mut summary = ThreeWayPlanReviewSummary {
        total_entries: entries.len(),
        no_decision_required: entries.len(),
        decisions_required: 0,
        decisions_recorded: 0,
        pending: 0,
        use_incoming: 0,
        preserve_installed: 0,
        queued_merge_analysis: 0,
        manual_review: 0,
        policy_acknowledgements: 0,
    };
    for entry in entries {
        match entry.action {
            ThreeWayReviewedAction::Pending => summary.pending += 1,
            ThreeWayReviewedAction::UseIncomingState => summary.use_incoming += 1,
            ThreeWayReviewedAction::PreserveInstalledState => summary.preserve_installed += 1,
            ThreeWayReviewedAction::QueueMergeAnalysis => summary.queued_merge_analysis += 1,
            ThreeWayReviewedAction::ManualReview => summary.manual_review += 1,
            ThreeWayReviewedAction::NotRequired => {}
        }
    }
    summary
}

#[derive(Debug, Clone, Copy)]
struct ResolvedDecision<'a> {
    decision: &'a ThreeWayPlanDecision,
    action: ThreeWayReviewedAction,
}

pub fn review_three_way_update_plan(
    request: ThreeWayPlanReviewRequest<'_>,
) -> Result<ThreeWayPlanReview> {
    let plan = request.plan;
    let decision_set = request.decision_set;

    if decision_set.plan_id() != plan.plan_id() {
        return Err(GkrmError::ThreeWayReviewPlanIdMismatch);
    }

    if decision_set.decisions().len() > plan.entries().len() {
        return Err(GkrmError::ThreeWayReviewDecisionCountExceedsPlanEntryCount);
    }

    for decision in decision_set.decisions() {
        if plan_entry_for_path(plan, decision.path()).is_none() {
            return Err(GkrmError::ThreeWayReviewDecisionPathNotInPlan);
        }
    }

    for decision in decision_set.decisions() {
        let entry = plan_entry_for_path(plan, decision.path())
            .ok_or(GkrmError::ThreeWayReviewDecisionPathNotInPlan)?;
        if requirement(entry.disposition()) == ThreeWayPlanReviewRequirement::NoDecisionRequired {
            return Err(GkrmError::ThreeWayReviewDecisionForNoDecisionEntry);
        }
    }

    let mut resolved = Vec::with_capacity(decision_set.decisions().len());
    for decision in decision_set.decisions() {
        let entry = plan_entry_for_path(plan, decision.path())
            .ok_or(GkrmError::ThreeWayReviewDecisionPathNotInPlan)?;
        let action = resolve_action(decision.choice(), entry.disposition())?;
        resolved.push(ResolvedDecision { decision, action });
    }

    for resolved_decision in &resolved {
        let entry = plan_entry_for_path(plan, resolved_decision.decision.path())
            .ok_or(GkrmError::ThreeWayReviewDecisionPathNotInPlan)?;
        if resolved_decision.action == ThreeWayReviewedAction::QueueMergeAnalysis
            && entry.disposition() != ThreeWayPlanDisposition::MergeCandidate
        {
            return Err(GkrmError::ThreeWayReviewMergeAnalysisNotAllowed);
        }
    }

    for resolved_decision in &resolved {
        let entry = plan_entry_for_path(plan, resolved_decision.decision.path())
            .ok_or(GkrmError::ThreeWayReviewDecisionPathNotInPlan)?;
        if !choice_allowed(entry.disposition(), resolved_decision.action) {
            return Err(GkrmError::ThreeWayReviewChoiceNotAllowed);
        }
    }

    for resolved_decision in &resolved {
        let entry = plan_entry_for_path(plan, resolved_decision.decision.path())
            .ok_or(GkrmError::ThreeWayReviewDecisionPathNotInPlan)?;
        validate_acknowledgement(
            entry.disposition(),
            resolved_decision.action,
            resolved_decision.decision.policy_acknowledgement(),
        )?;
    }

    let mut review_entries = Vec::with_capacity(plan.entries().len());
    let mut decision_index = 0;
    for entry in plan.entries() {
        let requirement = requirement(entry.disposition());
        let recommended_action = recommendation(entry.disposition());
        let matched = resolved
            .get(decision_index)
            .filter(|resolved_decision| resolved_decision.decision.path() == entry.path());
        let (action, policy_acknowledgement) = match (requirement, matched) {
            (ThreeWayPlanReviewRequirement::NoDecisionRequired, _) => (
                ThreeWayReviewedAction::NotRequired,
                PolicyTransitionAcknowledgement::NotProvided,
            ),
            (ThreeWayPlanReviewRequirement::DecisionRequired, Some(resolved_decision)) => {
                decision_index += 1;
                (
                    resolved_decision.action,
                    resolved_decision.decision.policy_acknowledgement(),
                )
            }
            (ThreeWayPlanReviewRequirement::DecisionRequired, None) => (
                ThreeWayReviewedAction::Pending,
                PolicyTransitionAcknowledgement::NotProvided,
            ),
        };

        review_entries.push(ThreeWayPlanReviewEntry {
            path: entry.path().clone(),
            requirement,
            recommended_action,
            action,
            policy_acknowledgement,
        });
    }

    if decision_index != resolved.len() {
        return Err(GkrmError::ThreeWayReviewDecisionPathNotInPlan);
    }
    if review_entries.len() != plan.entries().len() {
        return Err(GkrmError::ThreeWayReviewEntryCountMismatch);
    }

    let summary = summarize(&review_entries)?;
    let status = derive_status(&review_entries, &summary)?;
    let review_id = review_id(plan, &review_entries, &summary, status)?;

    Ok(ThreeWayPlanReview {
        plan_id: *plan.plan_id(),
        resource_key: plan.resource_key().clone(),
        baseline_id: plan.baseline_id().clone(),
        installed_snapshot_fingerprint: *plan.installed_snapshot_fingerprint(),
        incoming_package_fingerprint: *plan.incoming_package_fingerprint(),
        incoming_resource_fingerprint: *plan.incoming_resource_fingerprint(),
        entries: review_entries,
        summary,
        status,
        review_id,
    })
}

fn plan_entry_for_path<'a>(
    plan: &'a ThreeWayUpdatePlan,
    path: &ResourceRelativePath,
) -> Option<&'a crate::ThreeWayPlanEntry> {
    plan.entries()
        .binary_search_by(|entry| entry.path().cmp(path))
        .ok()
        .map(|index| &plan.entries()[index])
}

fn requirement(disposition: ThreeWayPlanDisposition) -> ThreeWayPlanReviewRequirement {
    match disposition {
        ThreeWayPlanDisposition::NoChange
        | ThreeWayPlanDisposition::Converged
        | ThreeWayPlanDisposition::ConvergedAddition
        | ThreeWayPlanDisposition::ConvergedDeletion => {
            ThreeWayPlanReviewRequirement::NoDecisionRequired
        }
        ThreeWayPlanDisposition::UseIncoming
        | ThreeWayPlanDisposition::RemoveForIncoming
        | ThreeWayPlanDisposition::PreserveInstalled
        | ThreeWayPlanDisposition::PreserveInstalledDeletion
        | ThreeWayPlanDisposition::AddIncoming
        | ThreeWayPlanDisposition::PreserveInstalledAddition
        | ThreeWayPlanDisposition::MergeCandidate
        | ThreeWayPlanDisposition::ConflictReview
        | ThreeWayPlanDisposition::DeleteVsModifyConflict
        | ThreeWayPlanDisposition::ModifyVsDeleteConflict
        | ThreeWayPlanDisposition::AddVsAddConflict
        | ThreeWayPlanDisposition::PolicyReview
        | ThreeWayPlanDisposition::PolicyConflictReview => {
            ThreeWayPlanReviewRequirement::DecisionRequired
        }
    }
}

fn recommendation(disposition: ThreeWayPlanDisposition) -> Option<ThreeWayReviewedAction> {
    match disposition {
        ThreeWayPlanDisposition::UseIncoming
        | ThreeWayPlanDisposition::RemoveForIncoming
        | ThreeWayPlanDisposition::AddIncoming => Some(ThreeWayReviewedAction::UseIncomingState),
        ThreeWayPlanDisposition::PreserveInstalled
        | ThreeWayPlanDisposition::PreserveInstalledDeletion
        | ThreeWayPlanDisposition::PreserveInstalledAddition => {
            Some(ThreeWayReviewedAction::PreserveInstalledState)
        }
        ThreeWayPlanDisposition::MergeCandidate => Some(ThreeWayReviewedAction::QueueMergeAnalysis),
        ThreeWayPlanDisposition::NoChange
        | ThreeWayPlanDisposition::Converged
        | ThreeWayPlanDisposition::ConvergedAddition
        | ThreeWayPlanDisposition::ConvergedDeletion
        | ThreeWayPlanDisposition::ConflictReview
        | ThreeWayPlanDisposition::DeleteVsModifyConflict
        | ThreeWayPlanDisposition::ModifyVsDeleteConflict
        | ThreeWayPlanDisposition::AddVsAddConflict
        | ThreeWayPlanDisposition::PolicyReview
        | ThreeWayPlanDisposition::PolicyConflictReview => None,
    }
}

fn resolve_action(
    choice: ThreeWayPlanDecisionChoice,
    disposition: ThreeWayPlanDisposition,
) -> Result<ThreeWayReviewedAction> {
    match choice {
        ThreeWayPlanDecisionChoice::AcceptRecommended => {
            recommendation(disposition).ok_or(GkrmError::ThreeWayReviewRecommendationUnavailable)
        }
        ThreeWayPlanDecisionChoice::UseIncomingState => {
            Ok(ThreeWayReviewedAction::UseIncomingState)
        }
        ThreeWayPlanDecisionChoice::PreserveInstalledState => {
            Ok(ThreeWayReviewedAction::PreserveInstalledState)
        }
        ThreeWayPlanDecisionChoice::QueueMergeAnalysis => {
            Ok(ThreeWayReviewedAction::QueueMergeAnalysis)
        }
        ThreeWayPlanDecisionChoice::ManualReview => Ok(ThreeWayReviewedAction::ManualReview),
    }
}

fn choice_allowed(disposition: ThreeWayPlanDisposition, action: ThreeWayReviewedAction) -> bool {
    match disposition {
        ThreeWayPlanDisposition::UseIncoming
        | ThreeWayPlanDisposition::RemoveForIncoming
        | ThreeWayPlanDisposition::AddIncoming
        | ThreeWayPlanDisposition::PreserveInstalled
        | ThreeWayPlanDisposition::PreserveInstalledDeletion
        | ThreeWayPlanDisposition::PreserveInstalledAddition => matches!(
            action,
            ThreeWayReviewedAction::UseIncomingState
                | ThreeWayReviewedAction::PreserveInstalledState
                | ThreeWayReviewedAction::ManualReview
        ),
        ThreeWayPlanDisposition::MergeCandidate => matches!(
            action,
            ThreeWayReviewedAction::QueueMergeAnalysis
                | ThreeWayReviewedAction::UseIncomingState
                | ThreeWayReviewedAction::PreserveInstalledState
                | ThreeWayReviewedAction::ManualReview
        ),
        ThreeWayPlanDisposition::ConflictReview
        | ThreeWayPlanDisposition::DeleteVsModifyConflict
        | ThreeWayPlanDisposition::ModifyVsDeleteConflict
        | ThreeWayPlanDisposition::AddVsAddConflict
        | ThreeWayPlanDisposition::PolicyReview
        | ThreeWayPlanDisposition::PolicyConflictReview => matches!(
            action,
            ThreeWayReviewedAction::UseIncomingState
                | ThreeWayReviewedAction::PreserveInstalledState
                | ThreeWayReviewedAction::ManualReview
        ),
        ThreeWayPlanDisposition::NoChange
        | ThreeWayPlanDisposition::Converged
        | ThreeWayPlanDisposition::ConvergedAddition
        | ThreeWayPlanDisposition::ConvergedDeletion => false,
    }
}

fn validate_acknowledgement(
    disposition: ThreeWayPlanDisposition,
    action: ThreeWayReviewedAction,
    acknowledgement: PolicyTransitionAcknowledgement,
) -> Result<()> {
    if is_policy_disposition(disposition) {
        return match action {
            ThreeWayReviewedAction::UseIncomingState
            | ThreeWayReviewedAction::PreserveInstalledState => {
                if acknowledgement == PolicyTransitionAcknowledgement::Acknowledged {
                    Ok(())
                } else {
                    Err(GkrmError::ThreeWayReviewPolicyAcknowledgementRequired)
                }
            }
            ThreeWayReviewedAction::ManualReview => {
                if acknowledgement == PolicyTransitionAcknowledgement::NotProvided {
                    Ok(())
                } else {
                    Err(GkrmError::ThreeWayReviewPolicyAcknowledgementUnnecessary)
                }
            }
            ThreeWayReviewedAction::NotRequired
            | ThreeWayReviewedAction::Pending
            | ThreeWayReviewedAction::QueueMergeAnalysis => {
                Err(GkrmError::ThreeWayReviewChoiceNotAllowed)
            }
        };
    }

    if acknowledgement == PolicyTransitionAcknowledgement::Acknowledged {
        return Err(GkrmError::ThreeWayReviewPolicyAcknowledgementUnnecessary);
    }
    Ok(())
}

fn is_policy_disposition(disposition: ThreeWayPlanDisposition) -> bool {
    matches!(
        disposition,
        ThreeWayPlanDisposition::PolicyReview | ThreeWayPlanDisposition::PolicyConflictReview
    )
}

fn summarize(entries: &[ThreeWayPlanReviewEntry]) -> Result<ThreeWayPlanReviewSummary> {
    let mut summary = ThreeWayPlanReviewSummary {
        total_entries: 0,
        no_decision_required: 0,
        decisions_required: 0,
        decisions_recorded: 0,
        pending: 0,
        use_incoming: 0,
        preserve_installed: 0,
        queued_merge_analysis: 0,
        manual_review: 0,
        policy_acknowledgements: 0,
    };

    for entry in entries {
        increment(&mut summary.total_entries)?;
        match entry.requirement {
            ThreeWayPlanReviewRequirement::NoDecisionRequired => {
                increment(&mut summary.no_decision_required)?;
            }
            ThreeWayPlanReviewRequirement::DecisionRequired => {
                increment(&mut summary.decisions_required)?;
            }
        }
        match entry.action {
            ThreeWayReviewedAction::NotRequired => {}
            ThreeWayReviewedAction::Pending => increment(&mut summary.pending)?,
            ThreeWayReviewedAction::UseIncomingState => {
                increment(&mut summary.decisions_recorded)?;
                increment(&mut summary.use_incoming)?;
            }
            ThreeWayReviewedAction::PreserveInstalledState => {
                increment(&mut summary.decisions_recorded)?;
                increment(&mut summary.preserve_installed)?;
            }
            ThreeWayReviewedAction::QueueMergeAnalysis => {
                increment(&mut summary.decisions_recorded)?;
                increment(&mut summary.queued_merge_analysis)?;
            }
            ThreeWayReviewedAction::ManualReview => {
                increment(&mut summary.decisions_recorded)?;
                increment(&mut summary.manual_review)?;
            }
        }
        if entry.policy_acknowledgement == PolicyTransitionAcknowledgement::Acknowledged {
            increment(&mut summary.policy_acknowledgements)?;
        }
    }

    validate_summary(&summary)?;
    Ok(summary)
}

fn validate_summary(summary: &ThreeWayPlanReviewSummary) -> Result<()> {
    let total_by_action = summary
        .no_decision_required
        .checked_add(summary.pending)
        .and_then(|value| value.checked_add(summary.use_incoming))
        .and_then(|value| value.checked_add(summary.preserve_installed))
        .and_then(|value| value.checked_add(summary.queued_merge_analysis))
        .and_then(|value| value.checked_add(summary.manual_review))
        .ok_or(GkrmError::ThreeWayReviewArithmeticOverflow)?;
    if total_by_action != summary.total_entries {
        return Err(GkrmError::ThreeWayReviewSummaryInvariant);
    }

    let decisions_by_action = summary
        .pending
        .checked_add(summary.decisions_recorded)
        .ok_or(GkrmError::ThreeWayReviewArithmeticOverflow)?;
    if decisions_by_action != summary.decisions_required {
        return Err(GkrmError::ThreeWayReviewSummaryInvariant);
    }
    Ok(())
}

fn derive_status(
    entries: &[ThreeWayPlanReviewEntry],
    summary: &ThreeWayPlanReviewSummary,
) -> Result<ThreeWayPlanReviewStatus> {
    let status = if summary.pending > 0 {
        ThreeWayPlanReviewStatus::Incomplete
    } else if summary.queued_merge_analysis > 0 || summary.manual_review > 0 {
        ThreeWayPlanReviewStatus::AwaitingFurtherAnalysis
    } else {
        ThreeWayPlanReviewStatus::DecisionComplete
    };

    if status == ThreeWayPlanReviewStatus::DecisionComplete
        && entries
            .iter()
            .any(|entry| entry.action == ThreeWayReviewedAction::Pending)
    {
        return Err(GkrmError::ThreeWayReviewStatusInvariant);
    }
    Ok(status)
}

fn increment(value: &mut usize) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or(GkrmError::ThreeWayReviewArithmeticOverflow)?;
    Ok(())
}

fn review_id(
    plan: &ThreeWayUpdatePlan,
    entries: &[ThreeWayPlanReviewEntry],
    summary: &ThreeWayPlanReviewSummary,
    status: ThreeWayPlanReviewStatus,
) -> Result<ThreeWayPlanReviewId> {
    let mut encoder = CanonicalEncoder::new("gkrm-three-way-plan-review-v1")?;
    encoder.digest(plan.plan_id().digest());
    encoder.string(plan.resource_key().as_str())?;
    encoder.string(plan.baseline_id().as_str())?;
    encoder.digest(plan.installed_snapshot_fingerprint());
    encoder.digest(plan.incoming_package_fingerprint());
    encoder.digest(plan.incoming_resource_fingerprint());
    encoder.usize(entries.len())?;
    for entry in entries {
        encoder.path(&entry.path)?;
        encoder.u8(requirement_code(entry.requirement));
        encoder.optional_action(entry.recommended_action);
        encoder.u8(action_code(entry.action));
        encoder.u8(acknowledgement_code(entry.policy_acknowledgement));
    }
    encoder.u8(status_code(status));
    encoder.summary(summary)?;
    Ok(ThreeWayPlanReviewId(encoder.finish()))
}

struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn new(domain: &'static str) -> Result<Self> {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.string(domain)?;
        Ok(encoder)
    }

    fn string(&mut self, value: &str) -> Result<()> {
        self.usize(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn path(&mut self, path: &ResourceRelativePath) -> Result<()> {
        self.string(path.as_str())
    }

    fn digest(&mut self, digest: &Sha256Digest) {
        self.bytes.extend_from_slice(digest.as_bytes());
    }

    fn usize(&mut self, value: usize) -> Result<()> {
        let value = u64::try_from(value).map_err(|_| GkrmError::ThreeWayReviewIdEncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn optional_action(&mut self, value: Option<ThreeWayReviewedAction>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u8(action_code(value));
            }
            None => self.u8(0),
        }
    }

    fn summary(&mut self, summary: &ThreeWayPlanReviewSummary) -> Result<()> {
        self.usize(summary.total_entries)?;
        self.usize(summary.no_decision_required)?;
        self.usize(summary.decisions_required)?;
        self.usize(summary.decisions_recorded)?;
        self.usize(summary.pending)?;
        self.usize(summary.use_incoming)?;
        self.usize(summary.preserve_installed)?;
        self.usize(summary.queued_merge_analysis)?;
        self.usize(summary.manual_review)?;
        self.usize(summary.policy_acknowledgements)?;
        Ok(())
    }

    fn finish(self) -> Sha256Digest {
        Sha256Digest::new(Sha256::digest(self.bytes).into())
    }
}

fn requirement_code(requirement: ThreeWayPlanReviewRequirement) -> u8 {
    match requirement {
        ThreeWayPlanReviewRequirement::NoDecisionRequired => 0,
        ThreeWayPlanReviewRequirement::DecisionRequired => 1,
    }
}

fn action_code(action: ThreeWayReviewedAction) -> u8 {
    match action {
        ThreeWayReviewedAction::NotRequired => 0,
        ThreeWayReviewedAction::Pending => 1,
        ThreeWayReviewedAction::UseIncomingState => 2,
        ThreeWayReviewedAction::PreserveInstalledState => 3,
        ThreeWayReviewedAction::QueueMergeAnalysis => 4,
        ThreeWayReviewedAction::ManualReview => 5,
    }
}

fn acknowledgement_code(acknowledgement: PolicyTransitionAcknowledgement) -> u8 {
    match acknowledgement {
        PolicyTransitionAcknowledgement::NotProvided => 0,
        PolicyTransitionAcknowledgement::Acknowledged => 1,
    }
}

fn status_code(status: ThreeWayPlanReviewStatus) -> u8 {
    match status {
        ThreeWayPlanReviewStatus::Incomplete => 0,
        ThreeWayPlanReviewStatus::AwaitingFurtherAnalysis => 1,
        ThreeWayPlanReviewStatus::DecisionComplete => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::make_file_record;
    use crate::{
        create_three_way_update_plan, BaselineCounts, BaselineEscrowClass,
        IncomingOfficialResourceSnapshot, InstalledResourceSnapshot, ResolvedOfficialBaseline,
        StoredBaseline, ThreeWayPlannerOptions, ThreeWayUpdatePlanRequest,
    };

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn rel(path: &str) -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str(path).expect("test path")
    }

    fn key() -> SafeResourceKey {
        SafeResourceKey::parse("gksphone").expect("resource key")
    }

    fn baseline_id() -> BaselineId {
        BaselineId::from_digest(digest(0x77))
    }

    fn resolved_baseline(
        files: Vec<(&str, u8, BaselineEscrowClass, bool)>,
    ) -> ResolvedOfficialBaseline {
        let records = files
            .into_iter()
            .map(|(path, byte, class, blob)| {
                make_file_record(
                    rel(path),
                    1,
                    digest(byte),
                    class,
                    blob.then(|| digest(byte)),
                )
            })
            .collect::<Vec<_>>();
        let counts = BaselineCounts::from_parts_for_test(records.len() as u64, 0, 0, 0, 0, 0);
        let stored = StoredBaseline::from_parts_for_test(
            baseline_id(),
            key(),
            "gksphone".to_owned(),
            Some("1.0.0".to_owned()),
            Some(digest(0x44)),
            records,
            counts,
        );
        ResolvedOfficialBaseline::from_stored_baseline_for_test(stored)
    }

    fn installed(files: Vec<(&str, u8)>) -> InstalledResourceSnapshot {
        InstalledResourceSnapshot::from_parts_for_test(
            key(),
            files
                .into_iter()
                .map(|(path, byte)| (rel(path), digest(byte)))
                .collect(),
        )
    }

    fn incoming(files: Vec<(&str, u8, BaselineEscrowClass)>) -> IncomingOfficialResourceSnapshot {
        IncomingOfficialResourceSnapshot::from_parts_for_test(
            key(),
            digest(0x55),
            files
                .into_iter()
                .map(|(path, byte, class)| (rel(path), digest(byte), class))
                .collect(),
        )
    }

    fn create_plan(
        baseline: Vec<(&str, u8, BaselineEscrowClass, bool)>,
        installed_files: Vec<(&str, u8)>,
        incoming_files: Vec<(&str, u8, BaselineEscrowClass)>,
    ) -> ThreeWayUpdatePlan {
        let baseline = resolved_baseline(baseline);
        let installed = installed(installed_files);
        let incoming = incoming(incoming_files);
        create_three_way_update_plan(
            ThreeWayUpdatePlanRequest::try_new(
                &baseline,
                &installed,
                &incoming,
                ThreeWayPlannerOptions::default(),
            )
            .expect("request"),
        )
        .expect("plan")
    }

    fn decision(
        path: &str,
        choice: ThreeWayPlanDecisionChoice,
        acknowledgement: PolicyTransitionAcknowledgement,
    ) -> ThreeWayPlanDecision {
        ThreeWayPlanDecision::try_new(rel(path), choice, acknowledgement).expect("decision")
    }

    fn decision_set(
        plan: &ThreeWayUpdatePlan,
        decisions: Vec<ThreeWayPlanDecision>,
    ) -> ThreeWayPlanDecisionSet {
        ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), decisions).expect("decision set")
    }

    fn review(
        plan: &ThreeWayUpdatePlan,
        decisions: Vec<ThreeWayPlanDecision>,
    ) -> Result<ThreeWayPlanReview> {
        let decision_set = decision_set(plan, decisions);
        review_three_way_update_plan(ThreeWayPlanReviewRequest::try_new(plan, &decision_set)?)
    }

    fn single_plan(disposition: ThreeWayPlanDisposition) -> ThreeWayUpdatePlan {
        use BaselineEscrowClass::{Ignored, Protected};
        match disposition {
            ThreeWayPlanDisposition::NoChange => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 1)],
                vec![("a.lua", 1, Protected)],
            ),
            ThreeWayPlanDisposition::UseIncoming => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 1)],
                vec![("a.lua", 2, Protected)],
            ),
            ThreeWayPlanDisposition::RemoveForIncoming => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 1)],
                vec![],
            ),
            ThreeWayPlanDisposition::PreserveInstalled => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 1, Protected)],
            ),
            ThreeWayPlanDisposition::PreserveInstalledDeletion => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![],
                vec![("a.lua", 1, Protected)],
            ),
            ThreeWayPlanDisposition::AddIncoming => {
                create_plan(vec![], vec![], vec![("a.lua", 1, Protected)])
            }
            ThreeWayPlanDisposition::PreserveInstalledAddition => {
                create_plan(vec![], vec![("a.lua", 1)], vec![])
            }
            ThreeWayPlanDisposition::Converged => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 2, Protected)],
            ),
            ThreeWayPlanDisposition::ConvergedAddition => {
                create_plan(vec![], vec![("a.lua", 1)], vec![("a.lua", 1, Protected)])
            }
            ThreeWayPlanDisposition::ConvergedDeletion => {
                create_plan(vec![("a.lua", 1, Protected, false)], vec![], vec![])
            }
            ThreeWayPlanDisposition::MergeCandidate => create_plan(
                vec![("a.lua", 1, Ignored, true)],
                vec![("a.lua", 2)],
                vec![("a.lua", 3, Ignored)],
            ),
            ThreeWayPlanDisposition::ConflictReview => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![("a.lua", 3, Protected)],
            ),
            ThreeWayPlanDisposition::DeleteVsModifyConflict => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![],
                vec![("a.lua", 2, Protected)],
            ),
            ThreeWayPlanDisposition::ModifyVsDeleteConflict => create_plan(
                vec![("a.lua", 1, Protected, false)],
                vec![("a.lua", 2)],
                vec![],
            ),
            ThreeWayPlanDisposition::AddVsAddConflict => {
                create_plan(vec![], vec![("a.lua", 1)], vec![("a.lua", 2, Protected)])
            }
            ThreeWayPlanDisposition::PolicyReview => create_plan(
                vec![("a.lua", 1, Ignored, true)],
                vec![("a.lua", 1)],
                vec![("a.lua", 1, Protected)],
            ),
            ThreeWayPlanDisposition::PolicyConflictReview => create_plan(
                vec![("a.lua", 1, Ignored, true)],
                vec![("a.lua", 2)],
                vec![("a.lua", 1, Protected)],
            ),
        }
    }

    #[test]
    fn mismatched_plan_id_fails_before_unknown_path_validation() {
        let first = single_plan(ThreeWayPlanDisposition::UseIncoming);
        let second = single_plan(ThreeWayPlanDisposition::AddIncoming);
        assert_ne!(first.plan_id(), second.plan_id());
        let decision_set = ThreeWayPlanDecisionSet::try_new(
            *second.plan_id(),
            vec![decision(
                "not-in-plan.lua",
                ThreeWayPlanDecisionChoice::UseIncomingState,
                PolicyTransitionAcknowledgement::NotProvided,
            )],
        )
        .expect("decision set");

        let err = review_three_way_update_plan(
            ThreeWayPlanReviewRequest::try_new(&first, &decision_set).expect("request"),
        )
        .expect_err("mismatch first");
        assert!(matches!(err, GkrmError::ThreeWayReviewPlanIdMismatch));
    }

    #[test]
    fn duplicate_decision_paths_are_rejected_without_deduplication() {
        let plan = single_plan(ThreeWayPlanDisposition::UseIncoming);
        let err = ThreeWayPlanDecisionSet::try_new(
            *plan.plan_id(),
            vec![
                decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
            ],
        )
        .expect_err("duplicate");
        assert!(matches!(
            err,
            GkrmError::ThreeWayReviewDuplicateDecisionPath
        ));
    }

    #[test]
    fn locked_entries_reject_decisions_and_are_not_required() {
        for disposition in [
            ThreeWayPlanDisposition::NoChange,
            ThreeWayPlanDisposition::Converged,
            ThreeWayPlanDisposition::ConvergedAddition,
            ThreeWayPlanDisposition::ConvergedDeletion,
        ] {
            let plan = single_plan(disposition);
            let reviewed = review(&plan, vec![]).expect("review");
            assert_eq!(
                reviewed.status(),
                ThreeWayPlanReviewStatus::DecisionComplete
            );
            assert_eq!(reviewed.summary().no_decision_required(), 1);
            assert_eq!(
                reviewed.entries()[0].action(),
                ThreeWayReviewedAction::NotRequired
            );
            assert_eq!(reviewed.entries()[0].recommended_action(), None);
            assert_eq!(
                reviewed.entries()[0].policy_acknowledgement(),
                PolicyTransitionAcknowledgement::NotProvided
            );

            let err = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect_err("locked decision");
            assert!(matches!(
                err,
                GkrmError::ThreeWayReviewDecisionForNoDecisionEntry
            ));
        }
    }

    #[test]
    fn recommendations_and_accept_recommended_are_normalized() {
        let cases = [
            (
                ThreeWayPlanDisposition::UseIncoming,
                ThreeWayReviewedAction::UseIncomingState,
            ),
            (
                ThreeWayPlanDisposition::RemoveForIncoming,
                ThreeWayReviewedAction::UseIncomingState,
            ),
            (
                ThreeWayPlanDisposition::AddIncoming,
                ThreeWayReviewedAction::UseIncomingState,
            ),
            (
                ThreeWayPlanDisposition::PreserveInstalled,
                ThreeWayReviewedAction::PreserveInstalledState,
            ),
            (
                ThreeWayPlanDisposition::PreserveInstalledDeletion,
                ThreeWayReviewedAction::PreserveInstalledState,
            ),
            (
                ThreeWayPlanDisposition::PreserveInstalledAddition,
                ThreeWayReviewedAction::PreserveInstalledState,
            ),
            (
                ThreeWayPlanDisposition::MergeCandidate,
                ThreeWayReviewedAction::QueueMergeAnalysis,
            ),
        ];
        for (disposition, expected) in cases {
            let plan = single_plan(disposition);
            let accepted = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::AcceptRecommended,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect("accepted");
            let explicit_choice = match expected {
                ThreeWayReviewedAction::UseIncomingState => {
                    ThreeWayPlanDecisionChoice::UseIncomingState
                }
                ThreeWayReviewedAction::PreserveInstalledState => {
                    ThreeWayPlanDecisionChoice::PreserveInstalledState
                }
                ThreeWayReviewedAction::QueueMergeAnalysis => {
                    ThreeWayPlanDecisionChoice::QueueMergeAnalysis
                }
                _ => unreachable!("recommended source action"),
            };
            let explicit = review(
                &plan,
                vec![decision(
                    "a.lua",
                    explicit_choice,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect("explicit");
            assert_eq!(accepted.entries()[0].recommended_action(), Some(expected));
            assert_eq!(accepted.entries()[0].action(), expected);
            assert_eq!(accepted.review_id(), explicit.review_id());
        }
    }

    #[test]
    fn conflicts_have_no_recommendation_and_cannot_queue_merge() {
        for disposition in [
            ThreeWayPlanDisposition::ConflictReview,
            ThreeWayPlanDisposition::DeleteVsModifyConflict,
            ThreeWayPlanDisposition::ModifyVsDeleteConflict,
            ThreeWayPlanDisposition::AddVsAddConflict,
        ] {
            let plan = single_plan(disposition);
            for choice in [
                ThreeWayPlanDecisionChoice::UseIncomingState,
                ThreeWayPlanDecisionChoice::PreserveInstalledState,
                ThreeWayPlanDecisionChoice::ManualReview,
            ] {
                review(
                    &plan,
                    vec![decision(
                        "a.lua",
                        choice,
                        PolicyTransitionAcknowledgement::NotProvided,
                    )],
                )
                .expect("allowed conflict choice");
            }

            let err = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::AcceptRecommended,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect_err("no recommendation");
            assert!(matches!(
                err,
                GkrmError::ThreeWayReviewRecommendationUnavailable
            ));

            let err = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect_err("no merge");
            assert!(matches!(
                err,
                GkrmError::ThreeWayReviewMergeAnalysisNotAllowed
            ));
        }
    }

    #[test]
    fn ordinary_recommended_dispositions_allow_source_alternatives_and_manual_only() {
        for disposition in [
            ThreeWayPlanDisposition::UseIncoming,
            ThreeWayPlanDisposition::RemoveForIncoming,
            ThreeWayPlanDisposition::AddIncoming,
            ThreeWayPlanDisposition::PreserveInstalled,
            ThreeWayPlanDisposition::PreserveInstalledDeletion,
            ThreeWayPlanDisposition::PreserveInstalledAddition,
        ] {
            let plan = single_plan(disposition);
            for choice in [
                ThreeWayPlanDecisionChoice::UseIncomingState,
                ThreeWayPlanDecisionChoice::PreserveInstalledState,
                ThreeWayPlanDecisionChoice::ManualReview,
            ] {
                review(
                    &plan,
                    vec![decision(
                        "a.lua",
                        choice,
                        PolicyTransitionAcknowledgement::NotProvided,
                    )],
                )
                .expect("allowed source/manual choice");
            }

            let err = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect_err("queue rejected");
            assert!(matches!(
                err,
                GkrmError::ThreeWayReviewMergeAnalysisNotAllowed
            ));
        }
    }

    #[test]
    fn merge_candidate_allows_merge_queue_sources_and_manual() {
        let plan = single_plan(ThreeWayPlanDisposition::MergeCandidate);
        for choice in [
            ThreeWayPlanDecisionChoice::AcceptRecommended,
            ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
            ThreeWayPlanDecisionChoice::UseIncomingState,
            ThreeWayPlanDecisionChoice::PreserveInstalledState,
            ThreeWayPlanDecisionChoice::ManualReview,
        ] {
            review(
                &plan,
                vec![decision(
                    "a.lua",
                    choice,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect("merge candidate choice");
        }
    }

    #[test]
    fn policy_dispositions_require_acknowledged_source_choices() {
        for disposition in [
            ThreeWayPlanDisposition::PolicyReview,
            ThreeWayPlanDisposition::PolicyConflictReview,
        ] {
            let plan = single_plan(disposition);
            for choice in [
                ThreeWayPlanDecisionChoice::UseIncomingState,
                ThreeWayPlanDecisionChoice::PreserveInstalledState,
            ] {
                let err = review(
                    &plan,
                    vec![decision(
                        "a.lua",
                        choice,
                        PolicyTransitionAcknowledgement::NotProvided,
                    )],
                )
                .expect_err("ack required");
                assert!(matches!(
                    err,
                    GkrmError::ThreeWayReviewPolicyAcknowledgementRequired
                ));
                review(
                    &plan,
                    vec![decision(
                        "a.lua",
                        choice,
                        PolicyTransitionAcknowledgement::Acknowledged,
                    )],
                )
                .expect("ack accepted");
            }

            review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                )],
            )
            .expect("manual accepted");

            let err = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::Acknowledged,
                )],
            )
            .expect_err("manual ack unnecessary");
            assert!(matches!(
                err,
                GkrmError::ThreeWayReviewPolicyAcknowledgementUnnecessary
            ));

            let err = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                    PolicyTransitionAcknowledgement::Acknowledged,
                )],
            )
            .expect_err("queue before ack");
            assert!(matches!(
                err,
                GkrmError::ThreeWayReviewMergeAnalysisNotAllowed
            ));

            let err = review(
                &plan,
                vec![decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::AcceptRecommended,
                    PolicyTransitionAcknowledgement::Acknowledged,
                )],
            )
            .expect_err("recommendation before ack");
            assert!(matches!(
                err,
                GkrmError::ThreeWayReviewRecommendationUnavailable
            ));
        }
    }

    #[test]
    fn non_policy_acknowledgement_is_rejected() {
        let plan = single_plan(ThreeWayPlanDisposition::UseIncoming);
        let err = review(
            &plan,
            vec![decision(
                "a.lua",
                ThreeWayPlanDecisionChoice::UseIncomingState,
                PolicyTransitionAcknowledgement::Acknowledged,
            )],
        )
        .expect_err("ack unnecessary");
        assert!(matches!(
            err,
            GkrmError::ThreeWayReviewPolicyAcknowledgementUnnecessary
        ));
    }

    #[test]
    fn partial_status_precedence_and_summary_counts_are_deterministic() {
        let plan = create_plan(
            vec![
                ("a.lua", 1, BaselineEscrowClass::Protected, false),
                ("b.lua", 1, BaselineEscrowClass::Ignored, true),
                ("c.lua", 1, BaselineEscrowClass::Protected, false),
                ("d.lua", 1, BaselineEscrowClass::Protected, false),
            ],
            vec![("a.lua", 1), ("b.lua", 2), ("c.lua", 2), ("d.lua", 1)],
            vec![
                ("a.lua", 1, BaselineEscrowClass::Protected),
                ("b.lua", 3, BaselineEscrowClass::Ignored),
                ("c.lua", 3, BaselineEscrowClass::Protected),
            ],
        );
        assert_eq!(
            plan.entries()
                .iter()
                .map(|entry| entry.disposition())
                .collect::<Vec<_>>(),
            vec![
                ThreeWayPlanDisposition::NoChange,
                ThreeWayPlanDisposition::MergeCandidate,
                ThreeWayPlanDisposition::ConflictReview,
                ThreeWayPlanDisposition::RemoveForIncoming,
            ]
        );

        let empty = review(&plan, vec![]).expect("empty");
        assert_eq!(empty.status(), ThreeWayPlanReviewStatus::Incomplete);
        assert_eq!(empty.summary().total_entries(), 4);
        assert_eq!(empty.summary().no_decision_required(), 1);
        assert_eq!(empty.summary().decisions_required(), 3);
        assert_eq!(empty.summary().pending(), 3);

        let partial = review(
            &plan,
            vec![decision(
                "b.lua",
                ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                PolicyTransitionAcknowledgement::NotProvided,
            )],
        )
        .expect("partial");
        assert_eq!(partial.status(), ThreeWayPlanReviewStatus::Incomplete);
        assert_eq!(partial.summary().pending(), 2);
        assert_eq!(partial.summary().queued_merge_analysis(), 1);

        let awaiting = review(
            &plan,
            vec![
                decision(
                    "b.lua",
                    ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "c.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "d.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
            ],
        )
        .expect("awaiting");
        assert_eq!(
            awaiting.status(),
            ThreeWayPlanReviewStatus::AwaitingFurtherAnalysis
        );
        assert_eq!(awaiting.summary().pending(), 0);
        assert_eq!(awaiting.summary().decisions_recorded(), 3);

        let complete = review(
            &plan,
            vec![
                decision(
                    "b.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "c.lua",
                    ThreeWayPlanDecisionChoice::PreserveInstalledState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "d.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
            ],
        )
        .expect("complete");
        assert_eq!(
            complete.status(),
            ThreeWayPlanReviewStatus::DecisionComplete
        );
        assert_eq!(complete.summary().use_incoming(), 2);
        assert_eq!(complete.summary().preserve_installed(), 1);
    }

    #[test]
    fn shuffled_decisions_have_identical_output_and_review_id() {
        let plan = create_plan(
            vec![
                ("a.lua", 1, BaselineEscrowClass::Protected, false),
                ("b.lua", 1, BaselineEscrowClass::Ignored, true),
                ("c.lua", 1, BaselineEscrowClass::Protected, false),
            ],
            vec![("a.lua", 1), ("b.lua", 2), ("c.lua", 2)],
            vec![
                ("a.lua", 2, BaselineEscrowClass::Protected),
                ("b.lua", 3, BaselineEscrowClass::Ignored),
                ("c.lua", 3, BaselineEscrowClass::Protected),
            ],
        );
        let first = review(
            &plan,
            vec![
                decision(
                    "c.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "b.lua",
                    ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
            ],
        )
        .expect("first");
        let second = review(
            &plan,
            vec![
                decision(
                    "b.lua",
                    ThreeWayPlanDecisionChoice::AcceptRecommended,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "c.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
            ],
        )
        .expect("second");
        assert_eq!(first.entries(), second.entries());
        assert_eq!(first.review_id(), second.review_id());

        let changed = review(
            &plan,
            vec![
                decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "b.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "c.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
            ],
        )
        .expect("changed");
        assert_ne!(first.review_id(), changed.review_id());
    }

    #[test]
    fn unknown_overcount_and_first_applicable_errors_are_deterministic() {
        let plan = single_plan(ThreeWayPlanDisposition::UseIncoming);
        let too_many = ThreeWayPlanDecisionSet::try_new(
            *plan.plan_id(),
            vec![
                decision(
                    "a.lua",
                    ThreeWayPlanDecisionChoice::UseIncomingState,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
                decision(
                    "b.lua",
                    ThreeWayPlanDecisionChoice::ManualReview,
                    PolicyTransitionAcknowledgement::NotProvided,
                ),
            ],
        )
        .expect("decision set");
        let err = review_three_way_update_plan(
            ThreeWayPlanReviewRequest::try_new(&plan, &too_many).expect("request"),
        )
        .expect_err("too many before unknown");
        assert!(matches!(
            err,
            GkrmError::ThreeWayReviewDecisionCountExceedsPlanEntryCount
        ));

        let unknown = ThreeWayPlanDecisionSet::try_new(
            *plan.plan_id(),
            vec![decision(
                "b.lua",
                ThreeWayPlanDecisionChoice::ManualReview,
                PolicyTransitionAcknowledgement::NotProvided,
            )],
        )
        .expect("decision set");
        let err = review_three_way_update_plan(
            ThreeWayPlanReviewRequest::try_new(&plan, &unknown).expect("request"),
        )
        .expect_err("unknown");
        assert!(matches!(
            err,
            GkrmError::ThreeWayReviewDecisionPathNotInPlan
        ));
    }

    #[test]
    fn arithmetic_and_summary_invariant_helpers_fail_closed() {
        let mut value = usize::MAX;
        assert!(matches!(
            increment(&mut value),
            Err(GkrmError::ThreeWayReviewArithmeticOverflow)
        ));

        let bad_summary = ThreeWayPlanReviewSummary {
            total_entries: 1,
            no_decision_required: 0,
            decisions_required: 0,
            decisions_recorded: 0,
            pending: 0,
            use_incoming: 0,
            preserve_installed: 0,
            queued_merge_analysis: 0,
            manual_review: 0,
            policy_acknowledgements: 0,
        };
        assert!(matches!(
            validate_summary(&bad_summary),
            Err(GkrmError::ThreeWayReviewSummaryInvariant)
        ));
    }
}
