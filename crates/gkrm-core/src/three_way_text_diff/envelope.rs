//! Text-envelope metadata and independent three-way scalar planning.

use crate::{GkrmError, MergeNewlineStyle, Result};

/// Newline styles admitted into Task 17 logical-text planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedTextNewlineStyle {
    None,
    Lf,
    CrLf,
}

/// Terminal-newline state derived from retained logical text, or unknown when bytes were not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextTerminalNewline {
    Present,
    Absent,
    Unknown,
}

/// BOM / newline-style / terminal-newline envelope of one verified text source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextEnvelope {
    bom: bool,
    newline_style: SupportedTextNewlineStyle,
    terminal_newline: TextTerminalNewline,
}

impl TextEnvelope {
    pub(crate) fn new(
        bom: bool,
        newline_style: SupportedTextNewlineStyle,
        terminal_newline: TextTerminalNewline,
    ) -> Self {
        Self {
            bom,
            newline_style,
            terminal_newline,
        }
    }

    pub fn bom(&self) -> bool {
        self.bom
    }

    pub fn newline_style(&self) -> SupportedTextNewlineStyle {
        self.newline_style
    }

    pub fn terminal_newline(&self) -> TextTerminalNewline {
        self.terminal_newline
    }
}

/// Closed three-way resolution for one envelope scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayTextScalarResolution {
    KeepBase,
    UseInstalled,
    UseIncoming,
    Converged,
    Conflict,
}

/// Independent envelope-scalar plan for BOM, newline style, and terminal newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreeWayTextEnvelopePlan {
    bom: ThreeWayTextScalarResolution,
    newline_style: ThreeWayTextScalarResolution,
    terminal_newline: ThreeWayTextScalarResolution,
}

impl ThreeWayTextEnvelopePlan {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        bom: ThreeWayTextScalarResolution,
        newline_style: ThreeWayTextScalarResolution,
        terminal_newline: ThreeWayTextScalarResolution,
    ) -> Self {
        Self {
            bom,
            newline_style,
            terminal_newline,
        }
    }

    pub fn bom(&self) -> ThreeWayTextScalarResolution {
        self.bom
    }

    pub fn newline_style(&self) -> ThreeWayTextScalarResolution {
        self.newline_style
    }

    pub fn terminal_newline(&self) -> ThreeWayTextScalarResolution {
        self.terminal_newline
    }
}

/// Whether a full three-way envelope plan is available for an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayTextEnvelopePlanState {
    Planned(ThreeWayTextEnvelopePlan),
    UnavailableSourceTooLarge,
}

impl ThreeWayTextEnvelopePlanState {
    pub fn planned(&self) -> Option<&ThreeWayTextEnvelopePlan> {
        match self {
            Self::Planned(plan) => Some(plan),
            Self::UnavailableSourceTooLarge => None,
        }
    }
}

/// Plan each envelope scalar independently with the ordered three-way truth table.
///
/// Callers must supply known terminal states (`Present` / `Absent`) only. Unknown terminal
/// values must not enter this planner; use [`ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge`].
pub(super) fn plan_envelope(
    base: &TextEnvelope,
    installed: &TextEnvelope,
    incoming: &TextEnvelope,
) -> Result<ThreeWayTextEnvelopePlan> {
    let base_terminal = known_terminal(base.terminal_newline)?;
    let installed_terminal = known_terminal(installed.terminal_newline)?;
    let incoming_terminal = known_terminal(incoming.terminal_newline)?;
    Ok(ThreeWayTextEnvelopePlan {
        bom: resolve_scalar(base.bom, installed.bom, incoming.bom),
        newline_style: resolve_scalar(
            base.newline_style,
            installed.newline_style,
            incoming.newline_style,
        ),
        terminal_newline: resolve_scalar(base_terminal, installed_terminal, incoming_terminal),
    })
}

fn known_terminal(value: TextTerminalNewline) -> Result<bool> {
    match value {
        TextTerminalNewline::Present => Ok(true),
        TextTerminalNewline::Absent => Ok(false),
        TextTerminalNewline::Unknown => Err(GkrmError::ThreeWayTextDiffMalformedLogicalText),
    }
}

/// Map a Task 16 newline style into the Task 17 supported subset.
pub(super) fn map_newline(style: MergeNewlineStyle) -> Result<SupportedTextNewlineStyle> {
    match style {
        MergeNewlineStyle::None => Ok(SupportedTextNewlineStyle::None),
        MergeNewlineStyle::Lf => Ok(SupportedTextNewlineStyle::Lf),
        MergeNewlineStyle::CrLf => Ok(SupportedTextNewlineStyle::CrLf),
        MergeNewlineStyle::Cr | MergeNewlineStyle::Mixed => {
            Err(GkrmError::ThreeWayTextDiffMalformedLogicalText)
        }
    }
}

fn resolve_scalar<T: PartialEq>(
    base: T,
    installed: T,
    incoming: T,
) -> ThreeWayTextScalarResolution {
    // ORDERED: L==N==B must be KeepBase, not Converged.
    if installed == base && incoming == base {
        ThreeWayTextScalarResolution::KeepBase
    } else if installed != base && incoming == base {
        ThreeWayTextScalarResolution::UseInstalled
    } else if installed == base && incoming != base {
        ThreeWayTextScalarResolution::UseIncoming
    } else if installed == incoming && installed != base {
        ThreeWayTextScalarResolution::Converged
    } else {
        ThreeWayTextScalarResolution::Conflict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(bom: bool, style: SupportedTextNewlineStyle, terminal: bool) -> TextEnvelope {
        TextEnvelope::new(
            bom,
            style,
            if terminal {
                TextTerminalNewline::Present
            } else {
                TextTerminalNewline::Absent
            },
        )
    }

    #[test]
    fn truth_table_keep_base_when_all_equal() {
        let b = env(false, SupportedTextNewlineStyle::Lf, true);
        let plan = plan_envelope(&b, &b, &b).unwrap();
        assert_eq!(plan.bom(), ThreeWayTextScalarResolution::KeepBase);
        assert_eq!(plan.newline_style(), ThreeWayTextScalarResolution::KeepBase);
        assert_eq!(
            plan.terminal_newline(),
            ThreeWayTextScalarResolution::KeepBase
        );
    }

    #[test]
    fn truth_table_use_installed() {
        let b = env(false, SupportedTextNewlineStyle::Lf, true);
        let l = env(true, SupportedTextNewlineStyle::Lf, true);
        let n = env(false, SupportedTextNewlineStyle::Lf, true);
        let plan = plan_envelope(&b, &l, &n).unwrap();
        assert_eq!(plan.bom(), ThreeWayTextScalarResolution::UseInstalled);
        assert_eq!(plan.newline_style(), ThreeWayTextScalarResolution::KeepBase);
        assert_eq!(
            plan.terminal_newline(),
            ThreeWayTextScalarResolution::KeepBase
        );
    }

    #[test]
    fn truth_table_use_incoming() {
        let b = env(false, SupportedTextNewlineStyle::Lf, false);
        let l = env(false, SupportedTextNewlineStyle::Lf, false);
        let n = env(false, SupportedTextNewlineStyle::Lf, true);
        let plan = plan_envelope(&b, &l, &n).unwrap();
        assert_eq!(
            plan.terminal_newline(),
            ThreeWayTextScalarResolution::UseIncoming
        );
    }

    #[test]
    fn truth_table_converged_when_sides_match_and_differ_from_base() {
        let b = env(false, SupportedTextNewlineStyle::Lf, true);
        let l = env(true, SupportedTextNewlineStyle::CrLf, false);
        let n = env(true, SupportedTextNewlineStyle::CrLf, false);
        let plan = plan_envelope(&b, &l, &n).unwrap();
        assert_eq!(plan.bom(), ThreeWayTextScalarResolution::Converged);
        assert_eq!(
            plan.newline_style(),
            ThreeWayTextScalarResolution::Converged
        );
        assert_eq!(
            plan.terminal_newline(),
            ThreeWayTextScalarResolution::Converged
        );
    }

    #[test]
    fn truth_table_conflict_when_all_three_diverge() {
        let b = env(false, SupportedTextNewlineStyle::None, false);
        let l = env(true, SupportedTextNewlineStyle::Lf, true);
        let n = env(false, SupportedTextNewlineStyle::CrLf, true);
        let plan = plan_envelope(&b, &l, &n).unwrap();
        assert_eq!(plan.bom(), ThreeWayTextScalarResolution::UseInstalled);
        assert_eq!(plan.newline_style(), ThreeWayTextScalarResolution::Conflict);
        assert_eq!(
            plan.terminal_newline(),
            ThreeWayTextScalarResolution::Converged
        );
    }

    #[test]
    fn plan_envelope_rejects_unknown_terminal() {
        let known = env(false, SupportedTextNewlineStyle::Lf, true);
        let unknown = TextEnvelope::new(
            false,
            SupportedTextNewlineStyle::Lf,
            TextTerminalNewline::Unknown,
        );
        assert!(matches!(
            plan_envelope(&known, &unknown, &known),
            Err(GkrmError::ThreeWayTextDiffMalformedLogicalText)
        ));
    }

    #[test]
    fn map_newline_accepts_supported_styles() {
        assert_eq!(
            map_newline(MergeNewlineStyle::None).unwrap(),
            SupportedTextNewlineStyle::None
        );
        assert_eq!(
            map_newline(MergeNewlineStyle::Lf).unwrap(),
            SupportedTextNewlineStyle::Lf
        );
        assert_eq!(
            map_newline(MergeNewlineStyle::CrLf).unwrap(),
            SupportedTextNewlineStyle::CrLf
        );
    }

    #[test]
    fn map_newline_rejects_cr_and_mixed() {
        for style in [MergeNewlineStyle::Cr, MergeNewlineStyle::Mixed] {
            assert!(matches!(
                map_newline(style),
                Err(GkrmError::ThreeWayTextDiffMalformedLogicalText)
            ));
        }
    }
}
