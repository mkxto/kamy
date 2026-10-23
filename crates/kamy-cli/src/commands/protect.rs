//! `kamy protect`: SSA-identity and profile-driven protection.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use kamy_config::Config;
use kamy_core::ir::IrFunction;
use kamy_core::{FunctionSelector, Rva, SymbolId, SymbolKind};
use kamy_disasm::discover_functions;
use kamy_pe::PeFile;

use super::{parse_rvas, report_to_coverage};

pub(crate) struct Args {
    pub(crate) input: PathBuf,
    pub(crate) profile: Option<PathBuf>,
    pub(crate) output: PathBuf,
    pub(crate) debug_map: Option<PathBuf>,
    pub(crate) link_report: Option<PathBuf>,
    pub(crate) no_transform: bool,
    pub(crate) ssa_identity: bool,
    pub(crate) only_rva: Option<String>,
    pub(crate) reject_rva: Option<String>,
}

pub(crate) fn run(args: Args) -> anyhow::Result<()> {
    validate_args(&args)?;
    if let Some(profile) = &args.profile {
        with_profile(&args, profile)
    } else {
        ssa_identity(&args)
    }
}

fn validate_args(args: &Args) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.only_rva.is_none() || args.reject_rva.is_none(),
        "--only-rva and --reject-rva are mutually exclusive"
    );
    anyhow::ensure!(
        args.profile.is_none() || (args.only_rva.is_none() && args.reject_rva.is_none()),
        "--only-rva/--reject-rva conflict with --profile; use profile host !Address selectors"
    );
    anyhow::ensure!(
        args.profile.is_some() || args.ssa_identity || args.no_transform,
        "protect requires --profile (or --no-transform / --ssa-identity)"
    );
    Ok(())
}

fn ssa_identity(args: &Args) -> anyhow::Result<()> {
    let selector = match (&args.only_rva, &args.reject_rva) {
        (Some(only), None) => Some(FunctionSelector::only(parse_rvas(only)?)),
        (None, Some(reject)) => Some(FunctionSelector::reject(parse_rvas(reject)?)),
        _ => None,
    };
    let report = kamy_triage::protect_identity(&args.input, &args.output, selector.as_ref())?;
    if let Some(path) = &args.debug_map {
        write_debug_map(path, &report)?;
    }
    if let Some(path) = &args.link_report {
        write_link_report(path, &report)?;
    }
    log_report(&report);
    Ok(())
}

fn with_profile(args: &Args, profile_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::from_path(profile_path)
        .with_context(|| format!("loading profile {}", profile_path.display()))?;
    let bytes =
        std::fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", args.input.display()))?;
    if cfg.module_settings.injection.enabled {
        anyhow::ensure!(
            pe.subsystem() != 1,
            "SDK module injection is prohibited for kernel images"
        );
    }

    let mut module = pe.to_module();
    module.functions = discover_functions(&module, &pe.seeds());
    let cg = kamy_analysis::build_call_graph(&module);
    let mut names: HashMap<_, _> = module
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
        .map(|symbol| (symbol.rva, symbol.name.as_str()))
        .collect();
    for symbol in module
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Export)
    {
        names.insert(symbol.rva, symbol.name.as_str());
    }
    let injection = &cfg.module_settings.injection;
    let plugins = if injection.enabled {
        injection
            .plugins
            .iter()
            .map(|plugin| {
                let bytes = std::fs::read(&plugin.path).with_context(|| {
                    format!(
                        "reading plugin {} from {}",
                        plugin.name,
                        plugin.path.display()
                    )
                })?;
                Ok(kamy_link::module::Plugin {
                    name: plugin.name.clone(),
                    module: kamy_pe::module::AuthoredModule::parse(&bytes, &plugin.name)
                        .with_context(|| format!("parsing plugin {}", plugin.name))?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let mut entries: Vec<_> = module
        .functions
        .iter()
        .map(|function| crate::target::Entry {
            symbol: SymbolId::Host {
                rva: function.entry,
            },
            name: names.get(&function.entry).map_or_else(
                || format!("sub_{:x}", function.entry.get()),
                |name| (*name).to_string(),
            ),
        })
        .collect();
    entries.extend(
        kamy_link::module::planned_functions(&plugins)?
            .into_iter()
            .map(|function| crate::target::Entry {
                symbol: function.symbol,
                name: format!("{}::{}", function.plugin, function.name),
            }),
    );
    let owners = crate::target::profile_owners(&cfg, &entries, &cg, module.image_base)?;
    let options = profile_options(&cfg, owners.keys().cloned().collect());
    let identity = args.ssa_identity || args.no_transform;
    let passes = profile_passes(&cfg, identity);
    for (index, profile) in cfg.profiles.iter().enumerate() {
        tracing::info!(
            profile = %profile.name,
            functions = owners.values().filter(|&&owner| owner == index).count(),
            mba_passes = passes[index].len(),
            identity,
            "profile targets"
        );
    }
    let mut transform = |symbol: &SymbolId, function: &mut IrFunction, intensity: f32| {
        let transformed = owners
            .get(symbol)
            .is_some_and(|&index| apply_passes(&passes[index], function, intensity));
        Ok(kamy_link::TransformOutcome { transformed })
    };
    let cc = kamy_link::build_callconv(&pe, &module)?;
    let mode = match injection.mode {
        kamy_config::InjectionMode::Inline => kamy_link::module::EntryMode::Inline,
        kamy_config::InjectionMode::InitTable => kamy_link::module::EntryMode::InitTable,
    };
    let (image, report) = kamy_link::protect(
        &pe,
        &module,
        &module.functions,
        &options,
        &cc,
        &mut transform,
        kamy_link::module::Injection {
            plugins: &plugins,
            mode,
        },
    )?;
    std::fs::write(&args.output, &image)
        .with_context(|| format!("writing {}", args.output.display()))?;
    if let Some(path) = &args.debug_map {
        write_debug_map(path, &report)?;
    }
    if let Some(path) = &args.link_report {
        write_link_report(path, &report)?;
    }
    log_report(&report);
    Ok(())
}

fn profile_options(
    cfg: &Config,
    selected: std::collections::BTreeSet<SymbolId>,
) -> kamy_link::Options {
    let mut options = kamy_link::Options {
        selected_symbols: Some(selected),
        ..Default::default()
    };
    let name = &cfg.module_settings.custom_section_name;
    if name.enabled {
        options.code_section.clone_from(&name.value);
        options.metadata_section.clone_from(&name.value);
        options.pdata_section.clone_from(&name.value);
    }
    options
}

fn profile_passes(cfg: &Config, identity: bool) -> Vec<Vec<kamy_transforms::MbaPass>> {
    cfg.profiles
        .iter()
        .map(|profile| {
            if identity {
                return Vec::new();
            }
            profile
                .passes
                .iter()
                .map(|pass| match pass {
                    kamy_config::Pass::MixedBooleanArithmetic(settings) => mba_from(settings),
                    _ => unreachable!("Config validation rejects unsupported passes"),
                })
                .collect()
        })
        .collect()
}

fn apply_passes(
    passes: &[kamy_transforms::MbaPass],
    function: &mut IrFunction,
    intensity: f32,
) -> bool {
    let mut transformed = false;
    for pass in passes {
        transformed |= pass.run_with_intensity(function, intensity);
    }
    transformed
}

fn log_report(report: &kamy_link::Report) {
    let cov = report_to_coverage(report);
    tracing::info!(
        selected = report
            .functions
            .iter()
            .filter(|function| function.selected)
            .count(),
        eligible = report
            .functions
            .iter()
            .filter(|function| function.eligible)
            .count(),
        ssa_lowered = report.ssa_lowered,
        transformed = report
            .functions
            .iter()
            .filter(|function| function.transformed)
            .count(),
        memory_backed = report
            .functions
            .iter()
            .filter(|function| function.allocation.is_some())
            .count(),
        memory_homes = report
            .functions
            .iter()
            .filter_map(|function| function.allocation)
            .map(|allocation| allocation.memory_homes)
            .sum::<usize>(),
        largest_frame = report
            .functions
            .iter()
            .filter_map(|function| function.allocation)
            .map(|allocation| allocation.frame_size)
            .max()
            .unwrap_or(0),
        rejected = cov.rejected,
        relocated = cov.relocated,
        "protection complete"
    );
    let mut intensities = BTreeMap::<u32, usize>::new();
    for function in &report.functions {
        if function.lowered {
            *intensities.entry(function.intensity.to_bits()).or_default() += 1;
        }
        if let Some(allocation) = function.allocation {
            tracing::debug!(
                symbol = ?function.symbol,
                memory_homes = allocation.memory_homes,
                gpr_homes = allocation.gpr_homes,
                xmm_homes = allocation.xmm_homes,
                flag_homes = allocation.flag_homes,
                frame_size = allocation.frame_size,
                original_frame_size = allocation.original_frame_size,
                outgoing_frame_size = allocation.outgoing_frame_size,
                nonvolatile_saves = allocation.nonvolatile_saves,
                scratch_gprs = allocation.scratch_gprs,
                scratch_xmms = allocation.scratch_xmms,
                max_frame_size = allocation.max_frame_size,
                "memory-backed allocation"
            );
        }
    }
    for (bits, functions) in intensities {
        tracing::info!(
            intensity = f32::from_bits(bits),
            functions,
            "actual lowering intensity"
        );
    }
    for (reason, count) in &cov.by_reason {
        tracing::info!(reason = %reason, count, "reject summary");
    }
}

pub(super) fn write_debug_map(path: &Path, report: &kamy_link::Report) -> anyhow::Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("creating debug map {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serialize_debug_map(&mut writer, &report.address_map)
        .with_context(|| format!("writing debug map {}", path.display()))?;
    writer
        .flush()
        .with_context(|| format!("writing debug map {}", path.display()))
}

pub(super) fn write_link_report(path: &Path, report: &kamy_link::Report) -> anyhow::Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("creating link report {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &link_report_json(report))
        .with_context(|| format!("serializing link report {}", path.display()))?;
    writer
        .flush()
        .with_context(|| format!("writing link report {}", path.display()))
}

fn symbol_json(symbol: &SymbolId) -> serde_json::Value {
    let (origin, module, name, rva) = match symbol {
        SymbolId::Host { rva } => (
            "host",
            None,
            format!("host:0x{:08x}", rva.get()),
            Some(rva.get()),
        ),
        SymbolId::Authored { module, symbol } => {
            ("authored", Some(module.as_ref()), symbol.to_string(), None)
        }
        SymbolId::Generated { name } => ("generated", None, name.to_string(), None),
        SymbolId::HostImageBase => ("host-image-base", None, "__ImageBase".into(), None),
    };
    serde_json::json!({
        "origin": origin,
        "source_module": module,
        "source_symbol": name,
        "host_source_rva": rva,
    })
}

fn placement_json(placement: &kamy_link::Placement) -> serde_json::Value {
    let ownership = match placement.ownership {
        kamy_link::Ownership::Retained => "retained",
        kamy_link::Ownership::Resident => "resident",
        kamy_link::Ownership::Generated => "generated",
        kamy_link::Ownership::Retired => "retired",
    };
    serde_json::json!({
        "symbol": symbol_json(&placement.symbol),
        "rva": placement.rva.get(),
        "size": placement.size,
        "ownership": ownership,
    })
}

fn link_report_json(report: &kamy_link::Report) -> serde_json::Value {
    let functions: Vec<_> = report
        .functions
        .iter()
        .map(|function| {
            let allocation = function.allocation.map(|allocation| {
                serde_json::json!({
                    "memory_homes": allocation.memory_homes,
                    "gpr_homes": allocation.gpr_homes,
                    "xmm_homes": allocation.xmm_homes,
                    "flag_homes": allocation.flag_homes,
                    "frame_size": allocation.frame_size,
                    "original_frame_size": allocation.original_frame_size,
                    "outgoing_frame_size": allocation.outgoing_frame_size,
                    "nonvolatile_saves": allocation.nonvolatile_saves,
                    "scratch_gprs": allocation.scratch_gprs,
                    "scratch_xmms": allocation.scratch_xmms,
                    "max_frame_size": allocation.max_frame_size,
                })
            });
            serde_json::json!({
                "symbol": symbol_json(&function.symbol),
                "selected": function.selected,
                "eligible": function.eligible,
                "lowered": function.lowered,
                "transformed": function.transformed,
                "intensity": function.intensity,
                "allocation": allocation,
            })
        })
        .collect();
    let placements: Vec<_> = report.placements.iter().map(placement_json).collect();
    let directories: Vec<_> = report
        .directories
        .iter()
        .map(|directory| {
            let contributions: Vec<_> =
                directory.contributions.iter().map(placement_json).collect();
            serde_json::json!({
                "index": directory.index,
                "rva": directory.rva.get(),
                "file_offset": directory.file_offset,
                "size": directory.size,
                "contributions": contributions,
            })
        })
        .collect();
    let rejections: Vec<_> = report
        .rejected
        .iter()
        .map(|(symbol, reason)| {
            serde_json::json!({
                "symbol": symbol_json(symbol), "reason": reason.tag(),
            })
        })
        .collect();
    serde_json::json!({
        "schema": "kamy-link-report",
        "version": 1,
        "functions": functions,
        "placements": placements,
        "directories": directories,
        "rejections": rejections,
    })
}

fn serialize_debug_map(
    writer: &mut impl std::io::Write,
    addresses: &BTreeMap<SymbolId, Rva>,
) -> anyhow::Result<()> {
    writeln!(writer, "kamy-debug-map,2")?;
    writeln!(
        writer,
        "origin,source_module,source_symbol,host_source_rva,new_rva"
    )?;
    for (symbol, target) in addresses {
        match symbol {
            SymbolId::Host { rva } => {
                write!(
                    writer,
                    "host,,host:0x{:08x},0x{:08x},",
                    rva.get(),
                    rva.get()
                )?;
            }
            SymbolId::Authored { module, symbol } => {
                write!(writer, "authored,")?;
                write_csv_field(writer, module)?;
                write!(writer, ",")?;
                write_csv_field(writer, symbol)?;
                write!(writer, ",,")?;
            }
            SymbolId::Generated { name } => {
                write!(writer, "generated,,")?;
                write_csv_field(writer, name)?;
                write!(writer, ",,")?;
            }
            SymbolId::HostImageBase => write!(writer, "host-image-base,,__ImageBase,,")?,
        }
        writeln!(writer, "0x{:08x}", target.get())?;
    }
    Ok(())
}

fn write_csv_field(writer: &mut impl std::io::Write, value: &str) -> anyhow::Result<()> {
    if !value.contains([',', '"', '\r', '\n']) {
        writer.write_all(value.as_bytes())?;
        return Ok(());
    }
    writer.write_all(b"\"")?;
    for part in value.split_inclusive('"') {
        writer.write_all(part.as_bytes())?;
        if part.ends_with('"') {
            writer.write_all(b"\"")?;
        }
    }
    writer.write_all(b"\"")?;
    Ok(())
}

fn mba_from(sp: &kamy_config::SemanticPass) -> kamy_transforms::MbaPass {
    kamy_transforms::MbaPass {
        config: kamy_transforms::mba::MbaConfig {
            iterations: sp.iterations,
            probability: sp.probability,
            semantics: kamy_transforms::mba::MbaSemantics {
                add: sp.semantics.add,
                sub: sp.semantics.sub,
                xor: sp.semantics.xor,
            },
            bitwidths: kamy_transforms::mba::MbaBitwidths {
                bit8: sp.bitwidths.bit8,
                bit16: sp.bitwidths.bit16,
                bit32: sp.bitwidths.bit32,
                bit64: sp.bitwidths.bit64,
            },
        },
        seed: 42,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::{BlockId, Inst, IrBlock, IrOp, IrTerminator, IrType, ValueId};

    fn args() -> Args {
        Args {
            input: "input.exe".into(),
            profile: None,
            output: "output.exe".into(),
            debug_map: None,
            link_report: None,
            no_transform: false,
            ssa_identity: false,
            only_rva: None,
            reject_rva: None,
        }
    }

    fn function() -> IrFunction {
        IrFunction {
            entry: BlockId(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                term: IrTerminator::Ret,
                insts: vec![Inst {
                    dest: Some(ValueId(2)),
                    op: IrOp::Sub,
                    args: vec![ValueId(0), ValueId(1)],
                    ty: IrType::I32,
                }],
            }],
            next_value: 3,
        }
    }

    #[test]
    fn identity_composes_with_profile_and_rejects_rva_conflicts() {
        let mut args = args();
        assert!(validate_args(&args).is_err());
        args.ssa_identity = true;
        assert!(validate_args(&args).is_ok());
        args.profile = Some("profile.yml".into());
        assert!(validate_args(&args).is_ok());
        args.only_rva = Some("1000".into());
        assert!(
            validate_args(&args)
                .unwrap_err()
                .to_string()
                .contains("conflict with --profile")
        );
        args.profile = None;
        assert!(validate_args(&args).is_ok());
        args.reject_rva = Some("2000".into());
        assert!(
            validate_args(&args)
                .unwrap_err()
                .to_string()
                .contains("mutually exclusive")
        );
    }

    fn ordered_config() -> Config {
        Config::from_yaml_str(
            "version: '1'\nmodule_settings:\n  custom_section_name: { enabled: true, value: decoy }\n  injection:\n    enabled: true\n    plugins: [{ name: payload, path: payload.dll }]\nprofiles:\n- name: ordered\n  passes:\n  - type: MixedBooleanArithmetic\n    semantics: { sub: true }\n    bitwidths: { bit32: true }\n  - type: MixedBooleanArithmetic\n    semantics: { add: true }\n    bitwidths: { bit32: true }\n",
        ).unwrap()
    }

    #[test]
    fn all_mba_passes_execute_in_declared_order() {
        let cfg = ordered_config();
        let passes = profile_passes(&cfg, false);
        assert_eq!(passes[0].len(), 2);
        let mut forward = function();
        assert!(apply_passes(&passes[0], &mut forward, 1.0));
        let forward_count = forward.blocks[0].insts.len();
        let mut reversed = function();
        for pass in passes[0].iter().rev() {
            pass.run_with_intensity(&mut reversed, 1.0);
        }
        assert!(forward_count > reversed.blocks[0].insts.len());
        assert!(
            forward.blocks[0]
                .insts
                .iter()
                .any(|inst| matches!(inst.op, IrOp::Xor))
        );
        assert!(
            !reversed.blocks[0]
                .insts
                .iter()
                .any(|inst| matches!(inst.op, IrOp::Xor))
        );
    }

    #[test]
    fn profile_identity_preserves_nonsemantic_policy_and_does_not_transform() {
        let cfg = ordered_config();
        let passes = profile_passes(&cfg, true);
        let mut function = function();
        let before = format!("{function:?}");
        assert!(!apply_passes(&passes[0], &mut function, 1.0));
        assert_eq!(before, format!("{function:?}"));
        assert!(cfg.module_settings.injection.enabled);
        assert_eq!(cfg.module_settings.injection.plugins[0].name, "payload");
        let symbol = SymbolId::Host {
            rva: Rva::new(0x1000),
        };
        let options = profile_options(&cfg, [symbol.clone()].into_iter().collect());
        assert_eq!(options.code_section, "decoy");
        assert_eq!(options.metadata_section, "decoy");
        assert_eq!(options.pdata_section, "decoy");
        assert!(options.selected_symbols.unwrap().contains(&symbol));
    }

    #[test]
    fn map_v2_preserves_origins_and_csv_symbol_identity_without_module_rvas() {
        let addresses = BTreeMap::from([
            (
                SymbolId::Host {
                    rva: Rva::new(0x1000),
                },
                Rva::new(0x9000),
            ),
            (
                SymbolId::Authored {
                    module: "first".into(),
                    symbol: "same,\"symbol".into(),
                },
                Rva::new(0x9100),
            ),
            (
                SymbolId::Authored {
                    module: "second".into(),
                    symbol: "same,\"symbol".into(),
                },
                Rva::new(0x9200),
            ),
        ]);
        let mut bytes = Vec::new();
        serialize_debug_map(&mut bytes, &addresses).unwrap();
        let map = String::from_utf8(bytes).unwrap();
        assert!(map.starts_with(
            "kamy-debug-map,2\norigin,source_module,source_symbol,host_source_rva,new_rva\n"
        ));
        assert!(map.contains("host,,host:0x00001000,0x00001000,0x00009000\n"));
        assert!(map.contains("authored,first,\"same,\"\"symbol\",,0x00009100\n"));
        assert!(map.contains("authored,second,\"same,\"\"symbol\",,0x00009200\n"));
        let mut empty = Vec::new();
        serialize_debug_map(&mut empty, &BTreeMap::new()).unwrap();
        assert!(
            String::from_utf8(empty)
                .unwrap()
                .starts_with("kamy-debug-map,2\n")
        );
    }

    #[test]
    fn portable_profile_fixtures_exercise_supported_and_unsupported_requests() {
        let cfg = Config::from_yaml_str(include_str!(
            "../../tests/fixtures/profiles/ordered-mba.yml"
        ))
        .unwrap();
        let passes = profile_passes(&cfg, false);
        let mut function = function();
        assert!(apply_passes(&passes[0], &mut function, 1.0));
        assert_eq!(passes[0].len(), 2);
        let error = Config::from_yaml_str(include_str!(
            "../../tests/fixtures/profiles/unsupported-references.yml"
        ))
        .unwrap_err();
        assert!(format!("{error:#}").contains("ObscureReferences"));
        let cfg = Config::from_yaml_str(include_str!(
            "../../tests/fixtures/profiles/disabled-injection.yml"
        ))
        .unwrap();
        assert!(!cfg.module_settings.injection.enabled);
    }

    #[test]
    fn link_report_schema_preserves_real_outcomes_and_directory_contributions() {
        let symbol = SymbolId::Authored {
            module: "plugin".into(),
            symbol: "compiler_symbol".into(),
        };
        let placement = kamy_link::Placement {
            symbol: symbol.clone(),
            source_rva: None,
            rva: Rva::new(0x9000),
            size: 32,
            ownership: kamy_link::Ownership::Generated,
        };
        let report = kamy_link::Report {
            functions: vec![kamy_link::FunctionReport {
                symbol: symbol.clone(),
                selected: true,
                eligible: true,
                lowered: true,
                transformed: true,
                intensity: 1.0,
                allocation: Some(kamy_link::AllocationMetrics {
                    memory_homes: 12,
                    gpr_homes: 8,
                    xmm_homes: 2,
                    flag_homes: 2,
                    frame_size: 0x208,
                    original_frame_size: 0x80,
                    outgoing_frame_size: 0x20,
                    nonvolatile_saves: 2,
                    scratch_gprs: 7,
                    scratch_xmms: 4,
                    max_frame_size: kamy_core::MAX_FRAME_SIZE,
                }),
            }],
            placements: vec![placement.clone()],
            directories: vec![
                kamy_link::DirectoryReport {
                    index: 3,
                    rva: Rva::new(0xa000),
                    file_offset: None,
                    size: 12,
                    contributions: vec![placement],
                },
                kamy_link::DirectoryReport {
                    index: 4,
                    rva: Rva::ZERO,
                    file_offset: Some(0x1200),
                    size: 64,
                    contributions: vec![],
                },
            ],
            ..Default::default()
        };
        let value = link_report_json(&report);
        assert_eq!(value["schema"], "kamy-link-report");
        assert_eq!(value["version"], 1);
        assert_eq!(value["functions"][0]["intensity"], 1.0);
        assert_eq!(value["functions"][0]["transformed"], true);
        let allocation = &value["functions"][0]["allocation"];
        assert_eq!(allocation["memory_homes"], 12);
        assert_eq!(allocation["gpr_homes"], 8);
        assert_eq!(allocation["xmm_homes"], 2);
        assert_eq!(allocation["flag_homes"], 2);
        assert_eq!(allocation["frame_size"], 0x208);
        assert_eq!(allocation["original_frame_size"], 0x80);
        assert_eq!(allocation["outgoing_frame_size"], 0x20);
        assert_eq!(allocation["nonvolatile_saves"], 2);
        assert_eq!(allocation["scratch_gprs"], 7);
        assert_eq!(allocation["scratch_xmms"], 4);
        assert_eq!(allocation["max_frame_size"], kamy_core::MAX_FRAME_SIZE);
        assert_eq!(
            value["functions"][0]["symbol"]["source_symbol"],
            "compiler_symbol"
        );
        assert!(value["functions"][0]["symbol"]["host_source_rva"].is_null());
        assert_eq!(
            value["directories"][0]["contributions"][0]["symbol"],
            symbol_json(&symbol)
        );
        assert!(value["directories"][0]["file_offset"].is_null());
        assert_eq!(value["directories"][1]["file_offset"], 0x1200);
        assert_eq!(value["directories"][1]["rva"], 0);
        assert_eq!(value["placements"][0]["size"], 32);
        assert_eq!(value["placements"][0]["ownership"], "generated");
    }

    #[test]
    fn map_and_report_filesystem_errors_include_the_requested_path() {
        let path = std::env::temp_dir()
            .join(format!("kamy-missing-{}", std::process::id()))
            .join("missing")
            .join("map.csv");
        let report = kamy_link::Report::default();
        for result in [
            write_debug_map(&path, &report),
            write_link_report(&path, &report),
        ] {
            let error = result.unwrap_err();
            assert!(format!("{error:#}").contains(&path.display().to_string()));
        }
    }
}
