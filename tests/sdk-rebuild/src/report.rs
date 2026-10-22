use crate::pe::Pe;
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
use kamy_core::SymbolId;
use kamy_core::ir::{AbiClass, AbiLocation, AbiPassing, AbiValue, PhysReg, XmmReg};
use kamy_pe::module::{AuthoredModule, CodeSymbol};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

fn number(value: &Value, name: &str) -> Result<u32> {
    u32::try_from(
        value
            .get(name)
            .and_then(Value::as_u64)
            .with_context(|| format!("report lacks numeric {name}"))?,
    )
    .context("report coordinate exceeds RVA range")
}

fn array<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    value
        .get(name)
        .and_then(Value::as_array)
        .with_context(|| format!("report lacks array {name}"))
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("report lacks string {name}"))
}

fn origin(placement: &Value) -> Result<&str> {
    text(
        placement
            .get("symbol")
            .context("placement lacks source-qualified symbol")?,
        "origin",
    )
}

fn source_symbol(placement: &Value) -> Result<&str> {
    text(
        placement
            .get("symbol")
            .context("placement lacks source-qualified symbol")?,
        "source_symbol",
    )
}

const SCALAR_F64_NAME: &str = "sdk_rebuild_scalar_f64";

fn scalar_function(module: &AuthoredModule) -> Result<&CodeSymbol> {
    let mut matches = module
        .code
        .iter()
        .filter(|function| function.name == SCALAR_F64_NAME);
    let function = matches
        .next()
        .context("producer omitted the standalone scalar f64 helper")?;
    ensure!(
        matches.next().is_none(),
        "producer duplicated the scalar f64 helper"
    );
    let value = AbiValue {
        location: AbiLocation::Register(PhysReg::Xmm(XmmReg::Xmm0)),
        class: AbiClass::Float,
        bits: 64,
        passing: AbiPassing::Direct,
    };
    let signature = &function.signature;
    ensure!(
        signature.args.len() == 1
            && signature.args[0] == value
            && signature.returns.len() == 1
            && signature.returns[0] == value
            && !signature.noreturn,
        "compiler scalar f64 contract is not Float64 XMM0 input/return: {signature:?}"
    );
    Ok(function)
}

fn scalar_call(pe: &Pe, functions: &[(u32, u32)], entry: u32, target: u32) -> Result<(u32, u32)> {
    let mut pending = vec![entry];
    let mut visited = BTreeSet::new();
    while let Some(begin) = pending.pop() {
        if !visited.insert(begin) {
            continue;
        }
        let (_, end) = functions
            .iter()
            .find(|(start, _)| *start == begin)
            .context("callback call graph lacks a compiler function boundary")?;
        let mut decoder = Decoder::with_ip(
            64,
            pe.slice(begin, usize::try_from(end - begin)?)?,
            u64::from(begin),
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let instruction = decoder.decode();
            ensure!(
                !instruction.is_invalid(),
                "invalid native instruction in scalar call witness at {:#x}",
                instruction.ip()
            );
            if instruction.op0_kind() != OpKind::NearBranch64
                || !matches!(
                    instruction.flow_control(),
                    FlowControl::Call | FlowControl::UnconditionalBranch
                )
            {
                continue;
            }
            let destination = u32::try_from(instruction.near_branch64())?;
            if instruction.flow_control() == FlowControl::Call && destination == target {
                ensure!(
                    begin != target,
                    "scalar witness is only a recursive self-call"
                );
                return Ok((begin, u32::try_from(instruction.ip())?));
            }
            if functions.iter().any(|(start, _)| *start == destination) {
                pending.push(destination);
            }
        }
    }
    anyhow::bail!(
        "compiled callback has no reachable cross-function call to scalar f64 target {target:#x}"
    )
}

pub fn inspect_scalar_producer(path: &Path) -> Result<AuthoredModule> {
    let pe = Pe::read(path)?;
    let module = AuthoredModule::parse(&pe.bytes, "abi").with_context(|| {
        format!(
            "reading actual compiler ABI metadata from {}",
            path.display()
        )
    })?;
    let scalar = scalar_function(&module)?;
    let functions: Vec<_> = module
        .code
        .iter()
        .map(|function| (function.start.get(), function.end.get()))
        .collect();
    let (caller, call) = scalar_call(&pe, &functions, module.entry.get(), scalar.start.get())?;
    println!(
        "scalar_f64_producer={} abi=Float64:XMM0->Float64:XMM0 symbol={:?} caller={caller:#x} call={call:#x} target={:#x}",
        path.display(),
        scalar.symbol,
        scalar.start.get()
    );
    Ok(module)
}

fn authored_function_range(placements: &[Value], symbol: &SymbolId) -> Result<(u32, u32)> {
    let SymbolId::Authored { module, symbol } = symbol else {
        anyhow::bail!("scalar witness function lacks authored source identity");
    };
    let mut matching = placements.iter().filter(|placement| {
        placement["ownership"].as_str() != Some("retired")
            && placement["symbol"]["origin"].as_str() == Some("authored")
            && placement["symbol"]["source_module"].as_str() == Some(module.as_ref())
            && placement["symbol"]["source_symbol"].as_str() == Some(symbol.as_ref())
    });
    let placement = matching
        .next()
        .with_context(|| format!("final output omitted authored function {module}::{symbol}"))?;
    ensure!(
        matching.next().is_none(),
        "authored function has multiple live placements: {module}::{symbol}"
    );
    let begin = number(placement, "rva")?;
    let size = number(placement, "size")?;
    ensure!(
        size != 0,
        "authored function has no final native body: {module}::{symbol}"
    );
    Ok((
        begin,
        begin
            .checked_add(size)
            .context("authored function range overflow")?,
    ))
}

fn inspect_scalar_artifact(path: &Path, pe: &Pe, placements: &[Value]) -> Result<()> {
    let module = inspect_scalar_producer(path)?;
    let scalar = scalar_function(&module)?;
    let callback = module
        .code
        .iter()
        .find(|function| function.start == module.entry)
        .context("producer callback has no compiler function identity")?;
    let functions: Vec<_> = module
        .code
        .iter()
        .map(|function| authored_function_range(placements, &function.symbol))
        .collect::<Result<_>>()?;
    for (begin, end) in &functions {
        ensure!(
            begin < end && *end <= pe.image_size && pe.section(*begin)?.flags & 0x2000_0000 != 0,
            "scalar witness final function range is not executable"
        );
    }
    let (entry, _) = authored_function_range(placements, &callback.symbol)?;
    let (target, _) = authored_function_range(placements, &scalar.symbol)?;
    let (caller, call) = scalar_call(pe, &functions, entry, target)?;
    let caller_symbol = module
        .code
        .iter()
        .zip(&functions)
        .find(|(_, (begin, _))| *begin == caller)
        .map(|(function, _)| &function.symbol)
        .context("final scalar caller lacks compiler source identity")?;
    println!(
        "scalar_f64_final=Float64:XMM0->Float64:XMM0 caller={caller_symbol:?}@{caller:#x} call={call:#x} target={:?}@{target:#x}",
        scalar.symbol
    );
    Ok(())
}

pub struct Inspection {
    pub unwind_ranges: String,
    pub bss_rvas: Vec<(u32, u32)>,
}

pub fn inspect(
    original: &Path,
    output: &Path,
    map_path: &Path,
    report_path: &Path,
    modules: &[&str],
    identity: bool,
    abi_module: Option<&Path>,
) -> Result<Inspection> {
    let before = Pe::read(original)?;
    let pe = Pe::read(output)?;
    let report: Value = serde_json::from_slice(&std::fs::read(report_path)?)?;
    ensure!(
        report.get("schema").and_then(Value::as_str) == Some("kamy-link-report")
            && report.get("version").and_then(Value::as_u64) == Some(1),
        "link-report schema/version mismatch"
    );
    ensure!(
        pe.sections.iter().all(|section| section.name != ".kmod"),
        "source provenance section leaked into runtime output"
    );
    ensure!(
        !pe.bytes.windows(8).any(|bytes| bytes == b"KAMYMOD\0"),
        "serialized compiler provenance leaked into runtime bytes"
    );
    ensure!(
        pe.directories[15] == (0, 0),
        "reserved source metadata directory leaked into output"
    );
    let before_imports = before.imports()?;
    let imports = pe.imports()?;
    ensure!(
        !before_imports.is_empty(),
        "host fixture MUST exercise a real import/IAT"
    );
    ensure!(
        before_imports.keys().all(|key| imports.contains_key(key)),
        "host imports were dropped or renamed"
    );
    let exports = pe.exports()?;
    ensure!(
        exports.contains_key("SDK_STATE") && exports.contains_key("HOST_BSS"),
        "host data exports were not preserved"
    );
    let runtime = pe.runtime_ranges()?;
    let relocations = pe.relocations()?;
    let directories = array(&report, "directories")?;
    let placements = array(&report, "placements")?;
    let mut probed = BTreeSet::new();
    let mut unwind_ranges = Vec::new();
    for index in [3u32, 5] {
        let matching: Vec<_> = directories
            .iter()
            .filter(|directory| {
                directory.get("index").and_then(Value::as_u64) == Some(u64::from(index))
            })
            .collect();
        ensure!(
            matching.len() == 1,
            "report MUST have one active directory contribution set for index {index}"
        );
        let directory = matching[0];
        ensure!(
            (number(directory, "rva")?, number(directory, "size")?)
                == pe.directories[index as usize],
            "reported directory does not target active PE directory {index}"
        );
        let mut reported = BTreeSet::new();
        let mut origins = BTreeSet::new();
        let mut loader_runtime = false;
        for contribution in array(directory, "contributions")? {
            let ownership = text(contribution, "ownership")?;
            ensure!(
                matches!(ownership, "retained" | "resident" | "generated"),
                "active directory contains invalid/retired contribution ownership {ownership}"
            );
            let source = origin(contribution)?;
            origins.insert(source);
            let rva = number(contribution, "rva")?;
            let size = number(contribution, "size")?;
            ensure!(
                reported.insert((rva, size)),
                "duplicate active source contribution in directory {index}"
            );
            if index == 3 && matches!(source, "generated" | "authored") {
                let symbol = contribution
                    .get("symbol")
                    .context("unwind contribution lacks source identity")?;
                let mut owners = placements.iter().filter(|placement| {
                    placement.get("symbol") == Some(symbol)
                        && placement.get("ownership").and_then(Value::as_str) != Some("retired")
                });
                let function = owners
                    .next()
                    .context("unwind contribution lacks logical source-symbol placement")?;
                ensure!(
                    owners.next().is_none(),
                    "unwind source symbol has multiple live placements"
                );
                let begin = number(function, "rva")?;
                let end = begin
                    .checked_add(number(function, "size")?)
                    .context("logical function extent overflow")?;
                let range_end = rva
                    .checked_add(size)
                    .context("runtime contribution extent overflow")?;
                ensure!(
                    begin <= rva && rva < range_end && range_end <= end && end <= pe.image_size,
                    "runtime contribution lies outside its logical source-symbol placement"
                );
                ensure!(
                    pe.section(begin)?.flags & 0x2000_0000 != 0,
                    "unwind source placement is not executable"
                );
                let identity = (
                    source,
                    symbol.get("source_module").and_then(Value::as_str),
                    source_symbol(contribution)?,
                );
                if probed.insert(identity) {
                    let pc = crate::native::decode_prologue(
                        pe.slice(begin, (end - begin) as usize)?,
                        begin,
                    )?
                    .pc;
                    ensure!(
                        runtime.iter().any(
                            |(range_begin, range_end, _)| *range_begin <= pc && pc < *range_end
                        ),
                        "independently decoded post-prologue PC has no active runtime record"
                    );
                    unwind_ranges.push(format!("{source}@{begin}:{pc}:{end}"));
                }
                if source == "generated"
                    && pe.entry >= rva
                    && u64::from(pe.entry) < u64::from(rva) + u64::from(size)
                {
                    loader_runtime = true;
                }
            }
            if index == 5 {
                ensure!(
                    size == 8,
                    "AMD64 relocation contribution is not a DIR64 field"
                );
            }
        }
        if index == 3 {
            let actual: BTreeSet<_> = runtime
                .iter()
                .map(|(begin, end, _)| (*begin, end - begin))
                .collect();
            ensure!(
                reported == actual,
                "active Exception ranges differ from source-owned contributions"
            );
            ensure!(
                origins.contains("host"),
                "host runtime contributions disappeared"
            );
            if !modules.is_empty() {
                ensure!(
                    origins.contains("generated") && origins.contains("authored"),
                    "active Exception table MUST include loader and module sources"
                );
                ensure!(
                    loader_runtime,
                    "active Exception table omitted the actual generated entry-loader range"
                );
            }
        } else {
            let actual: BTreeSet<_> = relocations.iter().map(|rva| (*rva, 8)).collect();
            ensure!(
                reported == actual,
                "active BaseReloc fields differ from source-owned contributions"
            );
        }
    }
    for index in [3usize, 5] {
        let name = format!("directory-{index}");
        let tables: Vec<_> = placements
            .iter()
            .filter(|placement| {
                origin(placement).is_ok_and(|origin| origin == "generated")
                    && source_symbol(placement).is_ok_and(|symbol| symbol == name)
                    && placement.get("ownership").and_then(Value::as_str) != Some("retired")
            })
            .collect();
        ensure!(
            tables.len() == 1,
            "expected one live generated directory-{index} placement, not an intermediate host-only table"
        );
        ensure!(
            (number(tables[0], "rva")?, number(tables[0], "size")?) == pe.directories[index],
            "live generated table storage is not the final active directory-{index}"
        );
        if before.directories[index].0 != pe.directories[index].0
            && before.directories[index].1 != 0
        {
            ensure!(
                placements.iter().any(|placement| {
                    placement.get("ownership").and_then(Value::as_str) == Some("retired")
                        && placement
                            .get("symbol")
                            .and_then(|symbol| symbol.get("host_source_rva"))
                            .and_then(Value::as_u64)
                            == Some(u64::from(before.directories[index].0))
                        && placement.get("size").and_then(Value::as_u64)
                            == Some(u64::from(before.directories[index].1))
                }),
                "replaced original directory-{index} storage lacks explicit retired ownership"
            );
        }
    }
    let mut bss_rvas = Vec::new();
    let mut saw_read_only = false;
    let mut saw_interior = false;
    let mut saw_module_bss = false;
    let mut bounds_slots = 0;
    for placement in placements {
        let ownership = text(placement, "ownership")?;
        ensure!(
            matches!(ownership, "retained" | "resident" | "generated" | "retired"),
            "unknown placement ownership"
        );
        if ownership == "retired" {
            continue;
        }
        let rva = number(placement, "rva")?;
        let size = number(placement, "size")?;
        if size == 0 {
            continue;
        }
        let name = source_symbol(placement)?;
        if name.contains("SDK_READ_ONLY") {
            let section = pe.section(rva)?;
            ensure!(
                section.flags & 0x4000_0000 != 0 && section.flags & 0xa000_0000 == 0,
                "module read-only data became writable/executable"
            );
            ensure!(
                pe.qword(rva)? == 23 && pe.qword(rva + 8)? == 22,
                "module read-only initializer changed"
            );
            saw_read_only = true;
        }
        if name.contains("SDK_MODULE_BSS") || name.contains("HOST_BSS") {
            let section = pe.section(rva)?;
            ensure!(
                section.flags & 0xc000_0000 == 0xc000_0000 && section.flags & 0x2000_0000 == 0,
                "BSS permissions are not read/write non-executable"
            );
            let end = u64::from(rva) + u64::from(size);
            let raw_end = u64::from(section.rva) + u64::from(section.raw_size);
            ensure!(
                end > raw_end && end <= u64::from(section.rva) + u64::from(section.virtual_size),
                "BSS was entirely serialized as file-backed zeros or lies outside virtual tail"
            );
            if u64::from(rva) < raw_end {
                ensure!(
                    pe.slice(rva, usize::try_from(raw_end.min(end) - u64::from(rva))?)?
                        .iter()
                        .all(|byte| *byte == 0),
                    "file-alignment prefix of BSS contains nonzero bytes"
                );
            }
            bss_rvas.push((rva, size));
            saw_module_bss |= name.contains("SDK_MODULE_BSS");
        }
        if name.contains("SDK_INTERIOR") {
            let target = pe
                .qword(rva)?
                .checked_sub(pe.image_base)
                .context("module data pointer is not image-relative")?;
            ensure!(
                relocations.contains(&rva),
                "module absolute data pointer lacks DIR64 fixup"
            );
            ensure!(
                pe.qword(u32::try_from(target)?)? == 22,
                "module data-interior pointer lost its addend"
            );
            saw_interior = true;
        }
        if name.contains("SYMBOL_init_table_start") || name.contains("SYMBOL_init_table_end") {
            ensure!(
                relocations.contains(&rva),
                "linker-filled bounds slot lacks a loader fixup"
            );
            let bound = pe.qword(rva)?;
            ensure!(
                bound > pe.image_base && bound < pe.image_base + u64::from(pe.image_size),
                "linker-filled bounds slot points outside final image"
            );
            bounds_slots += 1;
        }
    }
    ensure!(
        bounds_slots == modules.len() * 2,
        "source map omitted linker-filled bounds slots: {bounds_slots} for {} modules",
        modules.len()
    );
    if modules.contains(&"abi") {
        ensure!(
            saw_read_only && saw_interior && saw_module_bss,
            "report omitted required module data/BSS provenance"
        );
        inspect_scalar_artifact(
            abi_module.context("ABI case lacks its produced module artifact")?,
            &pe,
            placements,
        )?;
    }
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_path(map_path)?;
    let mut records = reader.records();
    let version = records.next().context("empty map")??;
    ensure!(
        version.iter().collect::<Vec<_>>() == ["kamy-debug-map", "2"],
        "debug map lacks explicit version 2"
    );
    let header = records.next().context("missing map header")??;
    ensure!(
        header.iter().collect::<Vec<_>>()
            == [
                "origin",
                "source_module",
                "source_symbol",
                "host_source_rva",
                "new_rva"
            ],
        "debug map uses obsolete/synthetic-RVA fields"
    );
    let mut mapped_modules = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for row in records {
        let row = row?;
        ensure!(
            row.len() == 5 && !row[2].is_empty(),
            "invalid source-qualified map row"
        );
        ensure!(
            identities.insert((row[0].to_owned(), row[1].to_owned(), row[2].to_owned())),
            "map contains duplicate source symbol identity"
        );
        let rva = u32::from_str_radix(
            row[4]
                .strip_prefix("0x")
                .context("map final RVA lacks hex prefix")?,
            16,
        )?;
        ensure!(rva < pe.image_size, "map final RVA is outside image");
        match &row[0] {
            "host" => {
                ensure!(
                    row[1].is_empty() && row[3].starts_with("0x"),
                    "host map coordinate contract is broken"
                );
            }
            "authored" => {
                ensure!(
                    row[3].is_empty() && !row[1].is_empty(),
                    "authored map leaked fabricated host source RVA"
                );
                mapped_modules.insert(row[1].to_owned());
            }
            "generated" => {
                ensure!(row[3].is_empty(), "generated map leaked host source RVA");
            }
            "host-image-base" => {
                ensure!(
                    row[1].is_empty() && &row[2] == "__ImageBase" && row[3].is_empty(),
                    "host base anchor was assigned a fabricated source RVA"
                );
            }
            other => anyhow::bail!("invalid map origin {other}"),
        }
    }
    ensure!(
        modules
            .iter()
            .all(|module| mapped_modules.contains(*module)),
        "map omitted an injected module instance"
    );
    for function in array(&report, "functions")? {
        if identity {
            ensure!(
                function.get("transformed").and_then(Value::as_bool) == Some(false),
                "profile-plus-identity applied a semantic transform"
            );
            ensure!(
                function.get("intensity").and_then(Value::as_f64) == Some(0.0),
                "identity report claimed nonzero semantic intensity"
            );
        }
        for field in ["selected", "eligible", "lowered"] {
            ensure!(
                function.get(field).and_then(Value::as_bool).is_some(),
                "function report lacks truthful {field} axis"
            );
            if origin(function)? == "authored" {
                ensure!(
                    function.get(field).and_then(Value::as_bool) == Some(true),
                    "mandatory authored function is not {field}: {}",
                    source_symbol(function)?
                );
            }
        }
    }
    println!(
        "structure={} exception_sources={} relocation_sources={} imports={} mapped_modules={}",
        output.display(),
        runtime.len(),
        relocations.len(),
        imports.len(),
        mapped_modules.len()
    );
    Ok(Inspection {
        unwind_ranges: unwind_ranges.join(","),
        bss_rvas,
    })
}
