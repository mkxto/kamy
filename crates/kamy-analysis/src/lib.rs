//! Symbolization, register value analysis, and jump-table recovery.

mod dom;
mod sig;

pub use dom::{DomTree, dominance_frontiers, dominator_tree};
pub use sig::infer_signature;
