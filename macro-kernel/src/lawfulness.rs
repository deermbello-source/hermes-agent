//! The lawfulness evaluator.
//!
//! Given (structural state, constraint set, candidate transition) it produces
//! a Verdict wrapped in a PreservationWitness: a machine-checkable record of
//! which constraints were evaluated, against which exact snapshot and
//! constraint-set hashes, with what result. The witness is the evidence that
//! the judgment happened under the structure it claims — not prose after the
//! fact.

use serde::{Deserialize, Serialize};

use crate::constraints::{path_conflicts, Constraint, ConstraintSet, Rule};
use crate::state::StructuralState;
use crate::transitions::{CandidateTransition, Effect, TransitionKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Non-mutating and violates nothing: may proceed.
    Admissible,
    /// Lawful under the constraint set, but mutating — execution would
    /// require explicit approval, and no approval gate exists in milestone 1,
    /// so it cannot run.
    RequiresApproval,
    /// Violates one or more constraints, or falls outside the observed
    /// boundary: must not proceed.
    Inadmissible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Violation,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintCheck {
    pub constraint_id: String,
    pub result: CheckResult,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservationWitness {
    pub schema_version: u32,
    pub evaluated_at: String,
    /// Hash of the exact snapshot the judgment was made against.
    pub snapshot_hash: String,
    /// Hash of the exact constraint set the judgment was made under.
    pub constraint_set_hash: String,
    /// Hash of the transition as judged.
    pub transition_hash: String,
    pub transition_id: String,
    pub transition_kind: String,
    pub effects: Vec<Effect>,
    pub checks: Vec<ConstraintCheck>,
    pub verdict: Verdict,
    pub verdict_reason: String,
}

pub const WITNESS_SCHEMA_VERSION: u32 = 1;

/// Judge one candidate transition against the bounded state and constraints.
pub fn judge(
    state: &StructuralState,
    constraints: &ConstraintSet,
    transition: &CandidateTransition,
) -> PreservationWitness {
    let mut checks = Vec::new();

    // Boundary check first: a transition on a target the kernel did not
    // observe is outside the governed domain and cannot be judged lawful.
    if let Some(check) = boundary_check(state, transition) {
        checks.push(check);
    }

    for constraint in &constraints.constraints {
        checks.push(evaluate_constraint(state, constraint, transition));
    }

    let effects = transition.effects();
    let violations: Vec<&ConstraintCheck> = checks
        .iter()
        .filter(|c| c.result == CheckResult::Violation)
        .collect();

    let (verdict, verdict_reason) = if !violations.is_empty() {
        let ids: Vec<&str> = violations.iter().map(|c| c.constraint_id.as_str()).collect();
        (
            Verdict::Inadmissible,
            format!("violates: {}", ids.join(", ")),
        )
    } else if effects.contains(&Effect::Mutation) {
        (
            Verdict::RequiresApproval,
            "lawful under the constraint set, but mutating; requires explicit approval \
             (no approval gate exists in milestone 1, so it cannot run)"
                .to_string(),
        )
    } else {
        (
            Verdict::Admissible,
            "non-mutating and violates no constraint".to_string(),
        )
    };

    PreservationWitness {
        schema_version: WITNESS_SCHEMA_VERSION,
        evaluated_at: chrono::Utc::now().to_rfc3339(),
        snapshot_hash: state.content_hash(),
        constraint_set_hash: constraints.content_hash(),
        transition_hash: transition.content_hash(),
        transition_id: transition.id.clone(),
        transition_kind: transition.kind.as_str().to_string(),
        effects,
        checks,
        verdict,
        verdict_reason,
    }
}

/// The transition's target must exist inside the observed structural state.
/// Governing what was never observed would be judgment without a boundary.
fn boundary_check(
    state: &StructuralState,
    transition: &CandidateTransition,
) -> Option<ConstraintCheck> {
    let make = |result: CheckResult, detail: Option<String>| {
        Some(ConstraintCheck {
            constraint_id: "boundary".into(),
            result,
            detail,
        })
    };
    match transition.kind {
        TransitionKind::NoopObserve => None,
        TransitionKind::KillProcess => {
            let Ok(pid) = transition.target.parse::<u32>() else {
                return make(
                    CheckResult::Violation,
                    Some(format!("'{}' is not a valid PID", transition.target)),
                );
            };
            if state.processes.iter().any(|p| p.pid == pid) {
                make(CheckResult::Pass, None)
            } else {
                make(
                    CheckResult::Violation,
                    Some(format!("PID {pid} is not in the observed state")),
                )
            }
        }
        TransitionKind::StopService | TransitionKind::RestartService => {
            if state
                .services
                .iter()
                .any(|s| s.name.eq_ignore_ascii_case(&transition.target))
            {
                make(CheckResult::Pass, None)
            } else {
                make(
                    CheckResult::Violation,
                    Some(format!(
                        "service '{}' is not in the observed state",
                        transition.target
                    )),
                )
            }
        }
        TransitionKind::DeletePath => {
            if transition.target.trim().is_empty() {
                make(CheckResult::Violation, Some("empty target path".into()))
            } else if std::path::Path::new(&transition.target).exists() {
                make(CheckResult::Pass, None)
            } else {
                make(
                    CheckResult::Violation,
                    Some(format!(
                        "path '{}' does not exist in the bounded domain",
                        transition.target
                    )),
                )
            }
        }
    }
}

fn evaluate_constraint(
    state: &StructuralState,
    constraint: &Constraint,
    transition: &CandidateTransition,
) -> ConstraintCheck {
    let (result, detail) = match &constraint.rule {
        Rule::ForbidKinds { kinds } => {
            if kinds.iter().any(|k| k == transition.kind.as_str()) {
                (
                    CheckResult::Violation,
                    Some(format!(
                        "transition kind '{}' is forbidden",
                        transition.kind.as_str()
                    )),
                )
            } else {
                (CheckResult::Pass, None)
            }
        }
        Rule::ProtectPaths { paths } => {
            if transition.kind != TransitionKind::DeletePath {
                (CheckResult::NotApplicable, None)
            } else if let Some(hit) = paths
                .iter()
                .find(|p| path_conflicts(p, &transition.target))
            {
                (
                    CheckResult::Violation,
                    Some(format!(
                        "target '{}' conflicts with protected path '{hit}'",
                        transition.target
                    )),
                )
            } else {
                (CheckResult::Pass, None)
            }
        }
        Rule::ProtectProcesses { names } => {
            if transition.kind != TransitionKind::KillProcess {
                (CheckResult::NotApplicable, None)
            } else if transition.target == "1" {
                (
                    CheckResult::Violation,
                    Some("PID 1 is always protected".into()),
                )
            } else if let Some(name) = protected_process_name(state, names, &transition.target) {
                (
                    CheckResult::Violation,
                    Some(format!("process '{name}' is protected")),
                )
            } else {
                (CheckResult::Pass, None)
            }
        }
        Rule::ProtectServices { names } => {
            if !matches!(
                transition.kind,
                TransitionKind::StopService | TransitionKind::RestartService
            ) {
                (CheckResult::NotApplicable, None)
            } else if names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&transition.target))
            {
                (
                    CheckResult::Violation,
                    Some(format!("service '{}' is protected", transition.target)),
                )
            } else {
                (CheckResult::Pass, None)
            }
        }
    };
    ConstraintCheck {
        constraint_id: constraint.id.clone(),
        result,
        detail,
    }
}

/// kill_process targets a PID; the protected-process rule matches by name.
/// Resolve the PID to its observed name via the snapshot — the bounded state
/// is the only source of identity the kernel trusts.
fn protected_process_name(
    state: &StructuralState,
    names: &[String],
    target: &str,
) -> Option<String> {
    let pid: u32 = target.parse().ok()?;
    let process = state.processes.iter().find(|p| p.pid == pid)?;
    names
        .iter()
        .find(|n| n.eq_ignore_ascii_case(&process.name))
        .cloned()
}
