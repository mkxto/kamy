use crate::Rva;
use std::collections::HashSet;

/// Allow/deny set over function entry RVAs, used to restrict which functions
/// are SSA-lowered. `only` admits exclusively the listed RVAs; `reject` admits
/// everything except them.
#[derive(Clone, Debug)]
pub struct FunctionSelector {
    set: HashSet<Rva>,
    mode: Mode,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    AllowOnly,
    RejectListed,
}

impl FunctionSelector {
    /// Allow ONLY the given RVAs.
    pub fn only<I: IntoIterator<Item = Rva>>(rvas: I) -> Self {
        Self {
            set: rvas.into_iter().collect(),
            mode: Mode::AllowOnly,
        }
    }

    /// Allow all RVAs EXCEPT the given ones.
    pub fn reject<I: IntoIterator<Item = Rva>>(rvas: I) -> Self {
        Self {
            set: rvas.into_iter().collect(),
            mode: Mode::RejectListed,
        }
    }

    pub fn allows(&self, rva: Rva) -> bool {
        match self.mode {
            Mode::AllowOnly => self.set.contains(&rva),
            Mode::RejectListed => !self.set.contains(&rva),
        }
    }
}
