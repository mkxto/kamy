//! Core IR primitives shared across the kamy protection engine.
//!
//! Format-agnostic by design (grilling D16): no PE/ELF specifics live here so
//! the IR, lifter, transforms, codegen, and verifier can be reused for future
//! object formats.

mod addr;
mod cfg;
pub mod ir;
mod module;
mod references;
mod reject;
mod reloc;
mod selector;
mod symbol;

pub use addr::Rva;
pub use cfg::{BasicBlock, Function, SwitchTable, Terminator};
pub use module::{Machine, Module, Section, SectionFlags};
pub use references::{Reference, ReferenceKind};
pub use reject::RejectionReason;
pub use reloc::{RelocKind, Relocation};
pub use selector::FunctionSelector;
pub use symbol::{Symbol, SymbolKind};
