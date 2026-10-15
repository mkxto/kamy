//! Core IR primitives shared across the kamy protection engine.
//!
//! This crate is format-agnostic by design (grilling D16): no PE/ELF specifics
//! live here so the IR, lifter, transforms, codegen, and verifier can be reused
//! for future object formats.

mod reject;

pub use reject::RejectionReason;

/// Relocatable virtual address, expressed as an offset from the module image base.
///
/// Absolute addresses are never stored in the IR; every cross-reference is a
/// symbolic link resolved at emit time (see `docs/architecture.md` §3).
pub type Rva = u32;
