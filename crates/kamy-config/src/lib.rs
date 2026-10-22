//! Protection profile schema and loader.
//!
//! Mirrors the YAML config documented in `docs/architecture.md` §5 (grilling D8).
//! YAML is parsed with `serde_norway`, the maintained fork of the archived
//! `serde_yaml` crate (keeps kamy within constraint C2).

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Top-level protection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        let config: Self =
            serde_norway::from_str(yaml).context("parsing YAML protection profile")?;
        let name = &config.module_settings.custom_section_name;
        if name.enabled {
            validate_section_name(&name.value)
                .context("validating module_settings.custom_section_name")?;
        }
        let injection = &config.module_settings.injection;
        if injection.enabled {
            anyhow::ensure!(
                !injection.plugins.is_empty(),
                "enabled injection requires plugins"
            );
            let mut names = std::collections::HashSet::new();
            for plugin in &injection.plugins {
                anyhow::ensure!(
                    !plugin.name.is_empty() && !plugin.name.contains("::"),
                    "plugin name MUST be nonempty and MUST NOT contain ::"
                );
                anyhow::ensure!(
                    names.insert(&plugin.name),
                    "duplicate plugin name {}",
                    plugin.name
                );
                anyhow::ensure!(
                    !plugin.path.as_os_str().is_empty(),
                    "plugin {} has an empty path",
                    plugin.name
                );
            }
        }
        config.validate_supported()?;
        Ok(config)
    }

    /// Load and parse a profile from a file path.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        tracing::debug!(path = %path.display(), "loading protection profile");
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("reading profile {}", path.display()))?;
        let mut cfg = Self::from_yaml_str(&yaml)
            .with_context(|| format!("parsing profile {}", path.display()))?;
        for plugin in &mut cfg.module_settings.injection.plugins {
            if plugin.path.is_relative() {
                plugin.path = path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(&plugin.path);
            }
        }
        tracing::debug!(
            profiles = cfg.profiles.len(),
            version = %cfg.version,
            "loaded protection profile"
        );
        Ok(cfg)
    }

    fn validate_supported(&self) -> anyhow::Result<()> {
        let module = &self.module_settings;
        for (setting, enabled) in [
            ("import_protection", module.import_protection),
            ("obscure_entry_point", module.obscure_entry_point),
            ("clear_unwind_info", module.clear_unwind_info),
            ("fake_pdb_string", module.fake_pdb_string.enabled),
        ] {
            anyhow::ensure!(!enabled, "unsupported module_settings.{setting}");
        }
        for (index, profile) in self.profiles.iter().enumerate() {
            validate_profile(profile)
                .with_context(|| format!("validating profiles[{index}] ({:?})", profile.name))?;
        }
        Ok(())
    }
}

/// Module-wide settings (grilling D18).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub injection: Injection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Injection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: InjectionMode,
    #[serde(default)]
    pub plugins: Vec<Plugin>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InjectionMode {
    Inline,
    #[default]
    InitTable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugin {
    pub name: String,
    pub path: std::path::PathBuf,
}

/// An opt-in setting carrying an associated string value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toggle {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub value: String,
}

/// A named selection of functions plus the passes applied to them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    #[serde(default)]
    pub symbols: Vec<SymbolSelector>,
}

/// An obfuscation pass, tagged by its `type` field in YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Pass {
    ObscureReferences,
    ObscureConstants,
    MixedBooleanArithmetic(SemanticPass),
    MutationEngine(SemanticPass),
    LoopEncodeSemantics(SemanticPass),
}

/// Shared parameter shape for the semantics-driven passes (D13).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct CompilerSettings {
    #[serde(default)]
    pub assembler_settings: AssemblerSettings,
    #[serde(default)]
    pub optimization_settings: OptimizationSettings,
    #[serde(default)]
    pub lifter_settings: LifterSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblerSettings {
    #[serde(default)]
    pub shuffle_basic_blocks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct LifterSettings {
    #[serde(default = "yes")]
    pub lift_calls: bool,
    #[serde(default)]
    pub calling_convention: CallingConvention,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stack_copy_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_on_calls_fallback: Option<bool>,
}

impl Default for LifterSettings {
    fn default() -> Self {
        Self {
            lift_calls: true,
            calling_convention: CallingConvention::default(),
            max_stack_copy_size: None,
            split_on_calls_fallback: None,
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
#[serde(deny_unknown_fields)]
pub struct Exclude {
    pub pattern: String,
    #[serde(default)]
    pub reason: String,
}

fn validate_profile(profile: &Profile) -> anyhow::Result<()> {
    for (index, pass) in profile.passes.iter().enumerate() {
        let Pass::MixedBooleanArithmetic(settings) = pass else {
            anyhow::bail!("unsupported passes[{index}]: {pass:?}");
        };
        anyhow::ensure!(
            settings.probability <= 100,
            "passes[{index}].probability MUST be at most 100"
        );
        for (semantic, enabled) in [
            ("and", settings.semantics.and),
            ("or", settings.semantics.or),
            ("not", settings.semantics.not),
            ("neg", settings.semantics.neg),
        ] {
            anyhow::ensure!(!enabled, "unsupported passes[{index}].semantics.{semantic}");
        }
    }
    let compiler = &profile.compiler_settings;
    anyhow::ensure!(
        !compiler.assembler_settings.shuffle_basic_blocks,
        "unsupported compiler_settings.assembler_settings.shuffle_basic_blocks"
    );
    let optimization = &compiler.optimization_settings;
    for (setting, enabled) in [
        ("constant_propagation", optimization.constant_propagation),
        ("instruction_combine", optimization.instruction_combine),
        ("dead_code_elim", optimization.dead_code_elim),
        (
            "prune_useless_block_params",
            optimization.prune_useless_block_params,
        ),
    ] {
        anyhow::ensure!(
            enabled,
            "unsupported compiler_settings.optimization_settings.{setting}: false"
        );
    }
    let lifter = &compiler.lifter_settings;
    anyhow::ensure!(
        lifter.lift_calls,
        "unsupported compiler_settings.lifter_settings.lift_calls: false"
    );
    anyhow::ensure!(
        lifter.max_stack_copy_size.is_none(),
        "unsupported compiler_settings.lifter_settings.max_stack_copy_size"
    );
    anyhow::ensure!(
        lifter.split_on_calls_fallback.is_none(),
        "unsupported compiler_settings.lifter_settings.split_on_calls_fallback"
    );
    Ok(())
}

fn validate_section_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.contains('\0'),
        "section name MUST NOT contain NUL bytes"
    );
    anyhow::ensure!(
        name.is_ascii(),
        "section name MUST contain only ASCII bytes"
    );
    anyhow::ensure!(name.len() <= 8, "section name MUST contain at most 8 bytes");
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPORTED: &str = r#"
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
  - type: MixedBooleanArithmetic
    iterations: 2
    probability: 100
    semantics: { add: true, sub: true, xor: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  - type: MixedBooleanArithmetic
    iterations: 1
    probability: 100
    semantics: { xor: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  compiler_settings:
    assembler_settings:
      shuffle_basic_blocks: false
    optimization_settings:
      constant_propagation: true
      instruction_combine: true
      dead_code_elim: true
      prune_useless_block_params: true
    lifter_settings:
      lift_calls: true
      calling_convention: WindowsAbi
  symbols:
  - !Name decrypt_key
  - !Pattern "crypto_*"
exclude:
- pattern: "test_*"
  reason: "test functions"
"#;

    #[test]
    fn parses_ordered_supported_profile() {
        let cfg = Config::from_yaml_str(SUPPORTED).expect("supported profile should parse");
        assert_eq!(cfg.version, "1.0.0");

        let profile = &cfg.profiles[0];
        assert_eq!(profile.name, "heavy");
        assert_eq!(profile.passes.len(), 2);

        match &profile.passes[0] {
            Pass::MixedBooleanArithmetic(p) => {
                assert_eq!(p.iterations, 2);
                assert!(p.semantics.xor && p.bitwidths.bit64);
            }
            other => panic!("expected MBA, got {other:?}"),
        }
        match &profile.passes[1] {
            Pass::MixedBooleanArithmetic(p) => {
                assert_eq!(p.iterations, 1);
                assert!(p.semantics.xor && !p.semantics.add);
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
        assert!(lifter.max_stack_copy_size.is_none());
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

    #[test]
    fn enabled_section_names_preserve_exact_bytes() {
        for name in ["", "a", ".decoy", "12345678"] {
            let yaml = format!(
                "version: '1'\nmodule_settings:\n  custom_section_name:\n    enabled: true\n    value: \"{name}\"\n"
            );
            let cfg = Config::from_yaml_str(&yaml).expect("valid section name should parse");
            assert!(cfg.module_settings.custom_section_name.enabled);
            assert_eq!(cfg.module_settings.custom_section_name.value, name);
        }
    }

    #[test]
    fn enabled_section_names_reject_invalid_bytes() {
        for (name, reason) in [("123456789", "at most 8"), ("é", "ASCII"), (r"a\0b", "NUL")] {
            let yaml = format!(
                "version: '1'\nmodule_settings:\n  custom_section_name:\n    enabled: true\n    value: \"{name}\"\n"
            );
            let error = Config::from_yaml_str(&yaml).expect_err("invalid section name should fail");
            let message = format!("{error:#}");
            assert!(message.contains("module_settings.custom_section_name"));
            assert!(message.contains(reason));
        }
    }

    #[test]
    fn disabled_section_names_ignore_invalid_values() {
        for (name, expected) in [("123456789", "123456789"), ("é", "é"), (r"a\0b", "a\0b")] {
            let yaml = format!(
                "version: '1'\nmodule_settings:\n  custom_section_name:\n    enabled: false\n    value: \"{name}\"\n"
            );
            let cfg =
                Config::from_yaml_str(&yaml).expect("disabled section name should be ignored");
            assert!(!cfg.module_settings.custom_section_name.enabled);
            assert_eq!(cfg.module_settings.custom_section_name.value, expected);
        }
    }

    #[test]
    fn enabled_injection_rejects_ambiguous_plugin_identities() {
        for (plugins, reason) in [
            ("[]", "requires plugins"),
            (
                "[{name: a, path: a.dll}, {name: a, path: b.dll}]",
                "duplicate plugin name a",
            ),
            ("[{name: 'a::b', path: a.dll}]", "MUST NOT contain ::"),
            ("[{name: a, path: ''}]", "empty path"),
        ] {
            let yaml = format!(
                "version: '1'\nmodule_settings:\n  injection:\n    enabled: true\n    plugins: {plugins}\n"
            );
            let error = Config::from_yaml_str(&yaml).unwrap_err();
            assert!(format!("{error:#}").contains(reason));
        }
    }

    #[test]
    fn unsupported_passes_fail_with_profile_and_pass_context() {
        for pass in [
            "ObscureReferences",
            "ObscureConstants",
            "MutationEngine",
            "LoopEncodeSemantics",
        ] {
            let yaml =
                format!("version: '1'\nprofiles:\n- name: guarded\n  passes:\n  - type: {pass}\n");
            let error = Config::from_yaml_str(&yaml).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("profiles[0] (\"guarded\")"));
            assert!(message.contains("passes[0]"));
            assert!(message.contains(pass));
        }
    }

    #[test]
    fn unsupported_enabled_settings_fail_contextually() {
        for setting in ["and", "or", "not", "neg"] {
            let yaml = format!(
                "version: '1'\nprofiles:\n- name: p\n  passes:\n  - type: MixedBooleanArithmetic\n    semantics: {{ {setting}: true }}\n"
            );
            let message = format!("{:#}", Config::from_yaml_str(&yaml).unwrap_err());
            assert!(message.contains(&format!("passes[0].semantics.{setting}")));
        }
        for setting in [
            "import_protection: true",
            "obscure_entry_point: true",
            "clear_unwind_info: true",
            "fake_pdb_string: { enabled: true, value: fake.pdb }",
        ] {
            let yaml = format!("version: '1'\nmodule_settings:\n  {setting}\n");
            let message = format!("{:#}", Config::from_yaml_str(&yaml).unwrap_err());
            assert!(message.contains("unsupported module_settings."));
            assert!(message.contains(setting.split(':').next().unwrap()));
        }
        for (settings, field) in [
            (
                "assembler_settings: { shuffle_basic_blocks: true }",
                "shuffle_basic_blocks",
            ),
            (
                "optimization_settings: { constant_propagation: false }",
                "constant_propagation",
            ),
            (
                "optimization_settings: { instruction_combine: false }",
                "instruction_combine",
            ),
            (
                "optimization_settings: { dead_code_elim: false }",
                "dead_code_elim",
            ),
            (
                "optimization_settings: { prune_useless_block_params: false }",
                "prune_useless_block_params",
            ),
            ("lifter_settings: { lift_calls: false }", "lift_calls"),
            (
                "lifter_settings: { max_stack_copy_size: 1024 }",
                "max_stack_copy_size",
            ),
            (
                "lifter_settings: { max_stack_copy_size: 512 }",
                "max_stack_copy_size",
            ),
            (
                "lifter_settings: { split_on_calls_fallback: false }",
                "split_on_calls_fallback",
            ),
            (
                "lifter_settings: { split_on_calls_fallback: true }",
                "split_on_calls_fallback",
            ),
        ] {
            let yaml = format!(
                "version: '1'\nprofiles:\n- name: p\n  compiler_settings:\n    {settings}\n"
            );
            let message = format!("{:#}", Config::from_yaml_str(&yaml).unwrap_err());
            assert!(message.contains("profiles[0]"));
            assert!(message.contains(field));
        }
    }

    #[test]
    fn probability_and_unknown_settings_fail_instead_of_being_ignored() {
        for yaml in [
            "version: '1'\nprofiles:\n- name: p\n  passes:\n  - type: MixedBooleanArithmetic\n    probability: 101\n",
            "version: '1'\nmodule_settings:\n  compact: true\n",
            "version: '1'\nprofiles:\n- name: p\n  compiler_settings:\n    lifter_settings:\n      imaginary: true\n",
        ] {
            assert!(Config::from_yaml_str(yaml).is_err());
        }
    }

    #[test]
    fn disabled_injection_does_not_validate_or_open_plugin_paths() {
        let cfg = Config::from_yaml_str(
            "version: '1'\nmodule_settings:\n  injection:\n    enabled: false\n    plugins: [{ name: 'bad::name', path: missing.dll }]\n",
        )
        .unwrap();
        assert!(!cfg.module_settings.injection.enabled);
    }

    #[test]
    fn shipped_example_requests_only_supported_settings() {
        Config::from_yaml_str(include_str!("../../../examples/kamy.yml")).unwrap();
    }

    #[test]
    fn missing_profile_errors_retain_path_context() {
        let path = std::env::temp_dir()
            .join(format!("kamy-missing-profile-{}", std::process::id()))
            .join("profile.yml");
        let error = Config::from_path(&path).unwrap_err();
        assert!(format!("{error:#}").contains(&path.display().to_string()));
    }
}
