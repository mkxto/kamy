//! Symbolization, register value analysis, and jump-table recovery.

mod dom;
mod sig;
mod xref;

pub use dom::{DomTree, dominance_frontiers, dominator_tree};
pub use sig::infer_signature;
pub use xref::{CallGraph, build_call_graph};
