//! Deterministic policy validation and predicate evaluation for DefSecAutMit.
//!
//! Edge-local safety boundaries (`edge_floor`) and central control-plane
//! governance (`control_gate`) are kept explicitly separate.

pub mod action_gate;
pub mod control_gate;
pub mod edge_floor;
pub mod predicate;
