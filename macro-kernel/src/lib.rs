//! macro-kernel: a user-space governing kernel.
//!
//! Reads the machine as a bounded structure, models its state, proposes
//! candidate transitions, and judges their lawfulness. Milestone 1 is
//! strictly read-only — the crate contains no executor.
//!
//! Pipeline (from the agent brief):
//! bounded intake -> structured state -> candidate transition
//! -> lawfulness check -> explicit approval -> execution -> receipt
//! (approval and execution are deliberately absent from this milestone)

pub mod boundary;
pub mod constraints;
pub mod lawfulness;
pub mod receipts;
pub mod state;
pub mod transitions;
