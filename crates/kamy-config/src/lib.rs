//! Protection profile schema and loader.
//!
//! Mirrors the YAML config documented in `docs/architecture.md` §5 (grilling D8).
//! YAML is parsed with `serde_norway`, the maintained fork of the archived
//! `serde_yaml` crate (keeps kamy within constraint C2).

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Top-level protection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: String,
    #[serde(default)]
    pub module_settings: ModuleSettings,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub exclude: Vec<Exclude>,
}

impl Config {
    /// Parse a profile from a YAML string.
    pub fn from_yaml_str(yaml: &str) -> anyhow::Result<Self> {
        serde_norway::from_str(yaml).context("parsing YAML protection profile")
    }

    /// Load and parse a profile from a file path.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        tracing::debug!(path = %path.display(), "loading protection profile");
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("reading profile {}", path.display()))?;
        let cfg = Self::from_yaml_str(&yaml)?;
        tracing::debug!(
            profiles = cfg.profiles.len(),
            version = %cfg.version,
            "loaded protection profile"
        );
        Ok(cfg)
    }
}

/// Module-wide settings (grilling D18).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleSettings {
    #[serde(default)]
    pub import_protection: bool,
    #[serde(default)]
    pub obscure_entry_point: bool,
    #[serde(default)]
    pub clear_unwind_info: bool,
    #[serde(default)]
    pub fake_pdb_string: Toggle,
    #[serde(default)]
    pub custom_section_name: Toggle,
}

/// An opt-in setting carrying an associated string value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Toggle {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub value: String,
}

/// A named selection of functions plus the passes applied to them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub passes: Vec<Pass>,
    #[serde(default)]
    pub compiler_settings: CompilerSettings,
    #[serde(default)]
    pub symbols: Vec<SymbolSelector>,
}

/// A reusable named set of selectors referenced by a profile via `!Group`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    #[serde(default)]
    pub symbols: Vec<SymbolSelector>,
}

/// An obfuscation pass, tagged by its `type` field in YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Pass {
    ObscureReferences,
    ObscureConstants,
    MixedBooleanArithmetic(SemanticPass),
    MutationEngine(SemanticPass),
    LoopEncodeSemantics(SemanticPass),
}

/// Shared parameter shape for the semantics-driven passes (D13).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticPass {
    #[serde(default = "one")]
    pub iterations: u32,
    #[serde(default = "hundred")]
    pub probability: u8,
    #[serde(default)]
    pub semantics: Semantics,
    #[serde(default)]
    pub bitwidths: Bitwidths,
}

/// Enabled arithmetic semantics for a semantics-driven pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Semantics {
    #[serde(default)]
    pub add: bool,
    #[serde(default)]
    pub sub: bool,
    #[serde(default)]
    pub and: bool,
    #[serde(default)]
    pub xor: bool,
    #[serde(default)]
    pub or: bool,
    #[serde(default)]
    pub not: bool,
    #[serde(default)]
    pub neg: bool,
}

/// Enabled operand bit widths for a semantics-driven pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bitwidths {
    #[serde(default)]
    pub bit8: bool,
    #[serde(default)]
    pub bit16: bool,
    #[serde(default)]
    pub bit32: bool,
    #[serde(default)]
    pub bit64: bool,
}

/// Always-on compiler settings (grilling D1, D3, D21).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompilerSettings {
    #[serde(default)]
    pub assembler_settings: AssemblerSettings,
    #[serde(default)]
    pub optimization_settings: OptimizationSettings,
    #[serde(default)]
    pub lifter_settings: LifterSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssemblerSettings {
    #[serde(default)]
    pub shuffle_basic_blocks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSettings {
    #[serde(default = "yes")]
    pub constant_propagation: bool,
    #[serde(default = "yes")]
    pub instruction_combine: bool,
    #[serde(default = "yes")]
    pub dead_code_elim: bool,
    #[serde(default = "yes")]
    pub prune_useless_block_params: bool,
}

impl Default for OptimizationSettings {
    fn default() -> Self {
        Self {
            constant_propagation: true,
            instruction_combine: true,
            dead_code_elim: true,
            prune_useless_block_params: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifterSettings {
    #[serde(default = "yes")]
    pub lift_calls: bool,
    #[serde(default)]
    pub calling_convention: CallingConvention,
    #[serde(default = "default_stack_copy")]
    pub max_stack_copy_size: u32,
    #[serde(default = "yes")]
    pub split_on_calls_fallback: bool,
}

impl Default for LifterSettings {
    fn default() -> Self {
        Self {
            lift_calls: true,
            calling_convention: CallingConvention::default(),
            max_stack_copy_size: default_stack_copy(),
            split_on_calls_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConvention {
    #[default]
    WindowsAbi,
}

/// A function selector. Serialized as a YAML tag, e.g. `!Name main`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolSelector {
    Name(String),
    Pattern(String),
    Address(u64),
    Group(String),
    TopXref(usize),
}

/// A function-exclusion rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exclude {
    pub pattern: String,
    #[serde(default)]
    pub reason: String,
}

fn one() -> u32 {
    1
}
fn hundred() -> u8 {
    100
}
fn yes() -> bool {
    true
}
fn default_stack_copy() -> u32 {
    512
}

#[cfg(test)]
mod tests {
    use super::*;

    // The documented `heavy` profile from docs/architecture.md §5.
    const HEAVY: &str = r#"
version: 1.0.0
module_settings:
  import_protection: false
  obscure_entry_point: false
  clear_unwind_info: false
  fake_pdb_string:
    enabled: false
    value: ''
  custom_section_name:
    enabled: false
    value: ''
profiles:
- name: heavy
  passes:
  - type: ObscureReferences
  - type: ObscureConstants
  - type: MixedBooleanArithmetic
    iterations: 2
    probability: 100
    semantics: { add: true, sub: true, and: true, xor: true, or: true, not: true, neg: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  - type: LoopEncodeSemantics
    iterations: 1
    probability: 25
    semantics: { add: true, sub: true, and: true, xor: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  - type: MutationEngine
    iterations: 1
    probability: 100
    semantics: { add: true, sub: true, and: true, xor: true, or: true, not: true, neg: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  compiler_settings:
    assembler_settings:
      shuffle_basic_blocks: true
    optimization_settings:
      constant_propagation: true
      instruction_combine: true
      dead_code_elim: true
      prune_useless_block_params: true
    lifter_settings:
      lift_calls: true
      calling_convention: WindowsAbi
      max_stack_copy_size: 512
      split_on_calls_fallback: true
  symbols:
  - !Name decrypt_key
  - !Pattern "crypto_*"
exclude:
- pattern: "test_*"
  reason: "test functions"
"#;

    #[test]
    fn parses_documented_heavy_profile() {
        let cfg = Config::from_yaml_str(HEAVY).expect("heavy profile should parse");
        assert_eq!(cfg.version, "1.0.0");

        let profile = &cfg.profiles[0];
        assert_eq!(profile.name, "heavy");
        assert_eq!(profile.passes.len(), 5);

        // Ordered pass list with per-pass heterogeneous params (D13).
        assert!(matches!(profile.passes[0], Pass::ObscureReferences));
        match &profile.passes[2] {
            Pass::MixedBooleanArithmetic(p) => {
                assert_eq!(p.iterations, 2);
                assert!(p.semantics.xor && p.bitwidths.bit64);
            }
            other => panic!("expected MBA, got {other:?}"),
        }

        // Tagged-union selectors.
        assert_eq!(
            profile.symbols[0],
            SymbolSelector::Name("decrypt_key".into())
        );
        assert_eq!(
            profile.symbols[1],
            SymbolSelector::Pattern("crypto_*".into())
        );

        // Always-on compiler settings land on their documented values.
        let lifter = &profile.compiler_settings.lifter_settings;
        assert_eq!(lifter.max_stack_copy_size, 512);
        assert_eq!(lifter.calling_convention, CallingConvention::WindowsAbi);

        assert_eq!(cfg.exclude[0].pattern, "test_*");
    }

    #[test]
    fn address_selector_accepts_hex() {
        let cfg = Config::from_yaml_str(
            "version: '1'\nprofiles:\n- name: p\n  symbols:\n  - !Address 0x140001000\n",
        )
        .expect("hex address selector should parse");
        assert_eq!(
            cfg.profiles[0].symbols[0],
            SymbolSelector::Address(0x1_4000_1000)
        );
    }
}
