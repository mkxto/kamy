//! `kamy corpus`: build/bless/verify/list/doctor over the differential corpus.

use std::path::Path;

use anyhow::Context as _;
use kamy_core::{FunctionSelector, Module, Rva, SymbolId, SymbolKind};

use crate::CorpusCmd;

use super::{corpus_dir, print_coverage, report_to_coverage};

pub(crate) fn dispatch(cmd: CorpusCmd) -> anyhow::Result<()> {
    match cmd {
        CorpusCmd::Build { corpus } => kamy_corpus::build_corpus(&corpus_dir(corpus)?),
        CorpusCmd::Bless { corpus, member } => {
            kamy_corpus::bless_corpus(&corpus_dir(corpus)?, member.as_deref())
        }
        CorpusCmd::List { corpus } => kamy_corpus::list_corpus(&corpus_dir(corpus)?),
        CorpusCmd::Verify {
            corpus,
            member,
            keep,
            baseline,
            write_baseline,
        } => verify(
            &corpus_dir(corpus)?,
            member,
            keep,
            baseline.as_deref(),
            write_baseline.as_deref(),
        ),
        CorpusCmd::Doctor { corpus, member } => doctor(&corpus_dir(corpus)?, member.as_deref()),
    }
}

/// Run differential verification, print the coverage table, optionally save and
/// diff a baseline, then error if any member diverged.
fn verify(
    dir: &Path,
    member: Option<String>,
    keep: bool,
    baseline: Option<&Path>,
    write_baseline: Option<&Path>,
) -> anyhow::Result<()> {
    let opts = kamy_corpus::VerifyOptions { member, keep };
    let cov = kamy_corpus::verify_corpus(
        dir,
        &|member, inp, outp| {
            let required = if member.lower_exports.is_empty() {
                Vec::new()
            } else {
                let bytes =
                    std::fs::read(inp).with_context(|| format!("reading {}", inp.display()))?;
                let pe = kamy_pe::PeFile::parse(&bytes)
                    .with_context(|| format!("parsing {}", inp.display()))?;
                resolve_required_exports(
                    &pe.to_module(),
                    pe.data_directory(0),
                    &member.lower_exports,
                )?
            };
            let selector = (!required.is_empty())
                .then(|| FunctionSelector::only(required.iter().map(|(_, rva)| *rva)));
            let report = kamy_triage::protect_identity(inp, outp, selector.as_ref())?;
            if keep {
                // Sidecars describe this exact output, even if required lowering or its oracle fails.
                super::protect::write_debug_map(&sidecar_path(outp, ".debug-map.csv"), &report)?;
                super::protect::write_link_report(
                    &sidecar_path(outp, ".link-report.json"),
                    &report,
                )?;
            }
            Ok((
                report_to_coverage(&report),
                require_lowered_exports(&required, &report),
            ))
        },
        &opts,
    )?;
    print_coverage(&cov);

    if let Some(path) = write_baseline {
        cov.save(path)?;
    }
    if let Some(path) = baseline {
        let old = kamy_corpus::CorpusCoverage::load(path)?;
        println!("baseline delta:");
        for line in kamy_corpus::coverage_delta(&old, &cov) {
            println!("  {line}");
        }
    }

    if cov.failed > 0 {
        eprintln!("→ isolate: kamy bisect <member-orig-binary> --expect-exit <code>");
        eprintln!("→ inspect IR: kamy dump <input> --rva <hex> --stage regalloc");
        anyhow::bail!("{} member(s) failed verification", cov.failed);
    }
    Ok(())
}

/// Oracle/ABI self-check across the selected corpus originals.
fn doctor(dir: &Path, member: Option<&str>) -> anyhow::Result<()> {
    let report = kamy_corpus::doctor_corpus(dir, member)?;
    let mut failed = 0usize;
    for (name, ok, msgs) in &report.members {
        println!("{name:<24} {}", if *ok { "OK" } else { "FAIL" });
        for m in msgs {
            println!("    {m}");
        }
        if !*ok {
            failed += 1;
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} member(s) failed doctor");
    }
    Ok(())
}

fn sidecar_path(output: &Path, suffix: &str) -> std::path::PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}

/// Resolve named host exports only: an import, data export, or forwarder is not a proof target.
fn resolve_required_exports(
    module: &Module,
    export_directory: Option<(Rva, u32)>,
    names: &[String],
) -> anyhow::Result<Vec<(String, Rva)>> {
    names
        .iter()
        .map(|name| {
            let mut matches = module.symbols.iter().filter(|symbol| {
                symbol.kind == SymbolKind::Export
                    && symbol.name == *name
                    && matches!(&symbol.id, SymbolId::Host { rva } if *rva == symbol.rva)
            });
            let symbol = matches
                .next()
                .with_context(|| format!("required host export {name:?} is absent"))?;
            anyhow::ensure!(
                matches.next().is_none(),
                "required host export {name:?} is ambiguous"
            );
            let forwarded = export_directory.is_some_and(|(start, size)| {
                let rva = u64::from(symbol.rva.get());
                (u64::from(start.get())..u64::from(start.get()) + u64::from(size)).contains(&rva)
            });
            anyhow::ensure!(
                !forwarded,
                "required export {name:?} is a forwarder, not callable host code"
            );
            anyhow::ensure!(
                module.is_executable(symbol.rva)
                    && module
                        .bytes_at(symbol.rva)
                        .is_some_and(|bytes| !bytes.is_empty()),
                "required export {name:?} is data or has no executable host bytes"
            );
            Ok((name.clone(), symbol.rva))
        })
        .collect()
}

/// Return member-verdict diagnostics without discarding the report or its exact output.
fn require_lowered_exports(required: &[(String, Rva)], report: &kamy_link::Report) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, rva) in required {
        let symbol = SymbolId::Host { rva: *rva };
        if let Some((_, reason)) = report.rejected.iter().find(|(id, _)| *id == symbol) {
            failures.push(format!("{name:?} at {rva}: rejected ({})", reason.tag()));
        } else if !report.functions.iter().any(|function| {
            function.symbol == symbol && function.selected && function.eligible && function.lowered
        }) || !report.ssa_lowered_symbols.contains(&symbol)
        {
            failures.push(format!("{name:?} at {rva}: not successfully SSA-lowered"));
        }
    }
    if failures.is_empty() {
        failures
    } else {
        vec![format!(
            "required export lowering failed: {}",
            failures.join("; ")
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::{Machine, Section, SectionFlags, Symbol};

    fn host() -> Module {
        Module {
            image_base: 0,
            machine: Machine::X64,
            entry_point: None,
            sections: vec![Section {
                name: ".text".into(),
                rva: Rva::new(0x1000),
                virtual_size: 0x100,
                data: vec![0xc3; 0x100],
                flags: SectionFlags {
                    execute: true,
                    ..Default::default()
                },
            }],
            symbols: [0x1000, 0x1010]
                .into_iter()
                .enumerate()
                .map(|(index, rva)| Symbol {
                    id: SymbolId::Host { rva: Rva::new(rva) },
                    name: format!("export{index}"),
                    rva: Rva::new(rva),
                    kind: SymbolKind::Export,
                })
                .collect(),
            relocations: Vec::new(),
            functions: Vec::new(),
        }
    }

    #[test]
    fn required_selection_uses_only_named_callable_host_exports() {
        let mut module = host();
        let names = vec!["export1".into()];
        let targets = resolve_required_exports(&module, None, &names).unwrap();
        let selector = FunctionSelector::only(targets.iter().map(|(_, rva)| *rva));
        assert!(!selector.allows(Rva::new(0x1000)));
        assert!(selector.allows(Rva::new(0x1010)));
        assert!(resolve_required_exports(&module, None, &["absent".into()]).is_err());
        module.symbols[1].kind = SymbolKind::Import;
        assert!(resolve_required_exports(&module, None, &names).is_err());
        module.symbols[1].kind = SymbolKind::Export;
        module.symbols[1].id = SymbolId::Generated {
            name: "export1".into(),
        };
        assert!(resolve_required_exports(&module, None, &names).is_err());
    }

    #[test]
    fn data_and_forwarder_exports_cannot_be_lowering_witnesses() {
        let mut module = host();
        let names = vec!["export0".into()];
        let forwarder = resolve_required_exports(&module, Some((Rva::new(0x1000), 0x10)), &names);
        assert!(forwarder.unwrap_err().to_string().contains("forwarder"));
        module.sections[0].flags.execute = false;
        let data = resolve_required_exports(&module, None, &names);
        assert!(data.unwrap_err().to_string().contains("data"));
    }

    #[test]
    fn required_lowering_cannot_pass_by_relocation_rejection_or_unrelated_coverage() {
        let required = vec![("export0".into(), Rva::new(0x1000))];
        let target = SymbolId::Host {
            rva: Rva::new(0x1000),
        };
        let other = SymbolId::Host {
            rva: Rva::new(0x1010),
        };
        let mut report = kamy_link::Report {
            moved: vec![target.clone(), other.clone()],
            ssa_lowered: 1,
            ssa_lowered_symbols: vec![other.clone()],
            functions: vec![kamy_link::FunctionReport {
                symbol: other,
                selected: true,
                eligible: true,
                lowered: true,
                transformed: false,
                intensity: 0.0,
                allocation: None,
            }],
            ..Default::default()
        };
        assert!(!require_lowered_exports(&required, &report).is_empty());
        report.functions.push(kamy_link::FunctionReport {
            symbol: target.clone(),
            selected: true,
            eligible: true,
            lowered: true,
            transformed: false,
            intensity: 0.0,
            allocation: None,
        });
        assert!(!require_lowered_exports(&required, &report).is_empty());
        report.ssa_lowered_symbols.push(target.clone());
        report.ssa_lowered += 1;
        assert!(require_lowered_exports(&required, &report).is_empty());
        report
            .rejected
            .push((target, kamy_core::RejectionReason::ResolvableIndirect));
        assert!(
            require_lowered_exports(&required, &report)
                .iter()
                .any(|message| message.contains("rejected"))
        );
        assert!(require_lowered_exports(&[], &report).is_empty());
    }

    struct TestCampaign(std::path::PathBuf);

    impl TestCampaign {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kamy-required-coverage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestCampaign {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn required_rejection_keeps_campaign_counts_baseline_and_exact_sidecars() {
        let campaign = TestCampaign::new();
        for name in ["first", "second"] {
            let dir = campaign.0.join("members").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("meta.yml"),
                "kind: dll\nprebuilt: original.dll\nlower_exports: [required]\nexports:\n  - name: required\n    ret: u64\n",
            )
            .unwrap();
            // This fixture need not be executable: a rejected requirement must skip observation.
            std::fs::write(dir.join("original.dll"), b"exact rejected output fixture").unwrap();
            kamy_corpus::BehaviorRecord {
                oracle: kamy_corpus::MemberKind::Dll,
                runs: 0,
                observations: Vec::new(),
                results: vec![kamy_corpus::DllResult {
                    call: "required()".into(),
                    ret: "7".into(),
                }],
                provenance: None,
            }
            .save(&dir.join("expected.yml"))
            .unwrap();
        }
        let required_rva = Rva::new(0x1000);
        let target = SymbolId::Host { rva: required_rva };
        let lowered = SymbolId::Host {
            rva: Rva::new(0x1010),
        };
        let report = kamy_link::Report {
            moved: vec![lowered.clone()],
            ssa_lowered: 1,
            ssa_lowered_symbols: vec![lowered.clone()],
            functions: vec![
                kamy_link::FunctionReport {
                    symbol: target.clone(),
                    selected: true,
                    eligible: false,
                    lowered: false,
                    transformed: false,
                    intensity: 0.0,
                    allocation: None,
                },
                kamy_link::FunctionReport {
                    symbol: lowered,
                    selected: true,
                    eligible: true,
                    lowered: true,
                    transformed: false,
                    intensity: 0.0,
                    allocation: None,
                },
            ],
            rejected: vec![(target, kamy_core::RejectionReason::ResolvableIndirect)],
            ..Default::default()
        };
        let retained = std::cell::RefCell::new(Vec::new());
        let result = kamy_corpus::verify_corpus(
            &campaign.0,
            &|member, inp, outp| {
                std::fs::copy(inp, outp)?;
                let map = sidecar_path(outp, ".debug-map.csv");
                let link_report = sidecar_path(outp, ".link-report.json");
                super::super::protect::write_debug_map(&map, &report)?;
                super::super::protect::write_link_report(&link_report, &report)?;
                retained.borrow_mut().push((
                    member.name.clone(),
                    outp.to_path_buf(),
                    std::fs::read(map)?,
                    std::fs::read(link_report)?,
                ));
                let required = vec![(member.lower_exports[0].clone(), required_rva)];
                Ok((
                    report_to_coverage(&report),
                    require_lowered_exports(&required, &report),
                ))
            },
            &kamy_corpus::VerifyOptions {
                member: None,
                keep: true,
            },
        )
        .unwrap();

        assert_eq!(result.passed, 0);
        assert_eq!(result.failed, 2);
        assert_eq!(result.total.selected, 4);
        assert_eq!(result.total.eligible, 2);
        assert_eq!(result.total.ssa_lowered, 2);
        assert_eq!(result.total.rejected, 2);
        let reason = kamy_core::RejectionReason::ResolvableIndirect.tag();
        assert_eq!(result.total.by_reason[reason], 2);
        assert_eq!(result.total.actual_intensity["0"], 2);
        assert_eq!(
            result
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        for member in &result.members {
            assert!(!member.passed);
            assert_eq!(member.coverage.selected, 2);
            assert_eq!(member.coverage.ssa_lowered, 1);
            assert_eq!(member.coverage.rejected, 1);
            assert_eq!(member.coverage.by_reason[reason], 1);
            assert_eq!(member.diagnostics.len(), 1);
            assert!(member.diagnostics[0].contains("required export lowering failed"));
            assert!(member.diagnostics[0].contains(reason));
        }
        let retained = retained.into_inner();
        assert_eq!(retained.len(), 2);
        for (name, output, map, link_report) in retained {
            assert_eq!(
                std::fs::read(&output).unwrap(),
                b"exact rejected output fixture"
            );
            assert_eq!(
                std::fs::read(sidecar_path(&output, ".debug-map.csv")).unwrap(),
                map
            );
            assert_eq!(
                std::fs::read(sidecar_path(&output, ".link-report.json")).unwrap(),
                link_report
            );
            assert_eq!(
                kamy_corpus::BehaviorRecord::load(
                    &campaign.0.join("members").join(name).join("expected.yml")
                )
                .unwrap()
                .results[0]
                    .ret,
                "7"
            );
        }

        let baseline = campaign.0.join("coverage.yml");
        result.save(&baseline).unwrap();
        let saved = kamy_corpus::CorpusCoverage::load(&baseline).unwrap();
        assert_eq!(
            serde_json::to_value(&saved).unwrap(),
            serde_json::to_value(&result).unwrap()
        );
        assert_eq!(saved.failed, 2);
        assert_eq!(saved.total.selected, 4);
        assert_eq!(saved.total.ssa_lowered, 2);
        assert_eq!(saved.total.rejected, 2);
        assert_eq!(saved.total.by_reason[reason], 2);
    }
}
