//! SEH/unwind: RUNTIME_FUNCTION, UNWIND_INFO, and C_SCOPE_TABLE parse/rebuild.

mod unwind;

pub use unwind::{UnwindRange, unwind_ranges};
