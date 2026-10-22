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

pub(crate) fn inspect_allocation(function: &Value, require_homes: bool) -> Result<()> {
    let lowered = function["lowered"]
        .as_bool()
        .context("missing lowered outcome")?;
    let allocation = &function["allocation"];
    if !lowered {
        ensure!(
            allocation.is_null(),
            "unlowered function claims final allocation: {function}"
        );
        return Ok(());
    }
    ensure!(
        allocation.is_object(),
        "lowered function omitted concrete allocation: {function}"
    );
    let homes = number(allocation, "memory_homes")?;
    let frame = number(allocation, "frame_size")?;
    let maximum = number(allocation, "max_frame_size")?;
    ensure!(
        maximum != 0 && frame <= maximum,
        "allocation exceeds concrete frame resource bound: {function}"
    );
    ensure!(
        !require_homes || (homes != 0 && frame != 0),
        "witness did not use memory-backed lowering: {function}"
    );
    ensure!(
        number(allocation, "scratch_gprs")? <= 7 && number(allocation, "scratch_xmms")? <= 4,
        "allocation exceeds the bounded memory-backed scratch working set: {function}"
    );
    ensure!(
        number(allocation, "original_frame_size")? <= frame
            && number(allocation, "outgoing_frame_size")? <= frame,
        "reported frame zones exceed their containing allocation: {function}"
    );
    Ok(())
}

fn inspect_directory_storage(
    before: &Pe,
    pe: &Pe,
    directory: &Value,
    placements: &[Value],
    functions: &[Value],
    modules: &[&str],
) -> Result<()> {
    let index = usize::try_from(number(directory, "index")?)?;
    ensure!(matches!(index, 3 | 5), "unexpected rebuilt directory index");
    ensure!(
        (number(directory, "rva")?, number(directory, "size")?) == pe.directories[index],
        "reported directory does not target active PE directory {index}"
    );
    let name = if index == 3 {
        "directory-3"
    } else {
        "directory-5"
    };
    let mut tables = placements.iter().filter(|placement| {
        origin(placement).is_ok_and(|origin| origin == "generated")
            && source_symbol(placement).is_ok_and(|symbol| symbol == name)
            && placement.get("ownership").and_then(Value::as_str) != Some("retired")
    });
    if let Some(table) = tables.next() {
        ensure!(
            tables.next().is_none() && text(table, "ownership")? == "generated",
            "expected one live generated directory-{index} placement, not an intermediate host-only table"
        );
        ensure!(
            (number(table, "rva")?, number(table, "size")?) == pe.directories[index],
            "live generated table storage is not the final active directory-{index}"
        );
        if before.directories[index].0 != pe.directories[index].0
            && before.directories[index].1 != 0
        {
            ensure!(
                placements.iter().any(|placement| {
                    placement.get("ownership").and_then(Value::as_str) == Some("retired")
                        && origin(placement).is_ok_and(|origin| origin == "host")
                        && placement["symbol"]["host_source_rva"].as_u64()
                            == Some(u64::from(before.directories[index].0))
                        && placement["rva"].as_u64() == Some(u64::from(before.directories[index].0))
                        && placement["size"].as_u64()
                            == Some(u64::from(before.directories[index].1))
                }),
                "replaced original directory-{index} storage lacks explicit retired ownership"
            );
        }
        return Ok(());
    }
    ensure!(
        modules.is_empty()
            && functions.iter().all(|function| {
                function["lowered"].as_bool() == Some(false)
                    && origin(function).is_ok_and(|origin| origin == "host")
                    && placements
                        .iter()
                        .any(|placement| placement.get("symbol") == function.get("symbol"))
            }),
        "directory-{index} lacks generated storage despite emitted/injected functions"
    );
    let (rva, size) = before.directories[index];
    ensure!(
        rva != 0 && size != 0 && pe.directories[index] == (rva, size),
        "directory-{index} without generated storage MUST retain the original active pointer/extent"
    );
    ensure!(
        before.slice(rva, size as usize)? == pe.slice(rva, size as usize)?,
        "retained directory-{index} table contents changed without generated ownership"
    );
    ensure!(
        pe.image_base == before.image_base && pe.entry == before.entry,
        "retained directory graph has a changed image base or entry point"
    );
    let contributions = array(directory, "contributions")?;
    for record in placements.iter().chain(contributions) {
        ensure!(
            matches!(text(record, "ownership")?, "retained" | "resident")
                && origin(record)? == "host"
                && record["symbol"]["source_module"].is_null()
                && number(&record["symbol"], "host_source_rva")? == number(record, "rva")?,
            "directory-{index} without generated storage has non-retained/moved source ownership"
        );
    }
    if index == 3 {
        for contribution in contributions {
            let mut owners = placements.iter().filter(|placement| {
                ["symbol", "ownership", "rva", "size"]
                    .iter()
                    .all(|field| placement.get(field) == contribution.get(field))
            });
            ensure!(
                owners.next().is_some() && owners.next().is_none(),
                "retained runtime contribution lacks exactly one matching source/ownership placement"
            );
        }
        for (begin, end, _) in before.runtime_ranges()? {
            ensure!(
                before.slice(begin, (end - begin) as usize)?
                    == pe.slice(begin, (end - begin) as usize)?,
                "retained Exception table covers modified host code without generated ownership"
            );
        }
    } else {
        ensure!(
            contributions
                .iter()
                .all(|contribution| contribution["ownership"].as_str() == Some("retained")),
            "original BaseReloc fields lack retained ownership"
        );
        for field in before.relocations()? {
            ensure!(
                before.qword(field)? == pe.qword(field)?,
                "retained BaseReloc field changed without generated ownership"
            );
        }
    }
    Ok(())
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
    let functions = array(&report, "functions")?;
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
        inspect_directory_storage(&before, &pe, directory, placements, functions, modules)?;
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
    for function in functions {
        inspect_allocation(function, false)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::Section;
    use serde_json::json;

    fn host_record(rva: u32, size: u32, ownership: &str) -> Value {
        json!({
            "symbol": {
                "origin": "host",
                "source_module": null,
                "source_symbol": format!("host:{rva:#010x}"),
                "host_source_rva": rva,
            },
            "ownership": ownership,
            "rva": rva,
            "size": size,
        })
    }

    fn retained_graph() -> (Pe, Vec<Value>, Vec<Value>, [Value; 2]) {
        let mut bytes = vec![0; 0x800];
        bytes[..9].copy_from_slice(&[0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
        bytes[0x10..0x13].copy_from_slice(&[0x53, 0x5b, 0xc3]);
        bytes[0x200..0x208].copy_from_slice(&0x0001_8000_2010u64.to_le_bytes());
        bytes[0x300..0x310]
            .copy_from_slice(&[1, 4, 1, 0, 4, 0x42, 0, 0, 1, 1, 1, 0, 1, 0x30, 0, 0]);
        for (offset, value) in [0x1000u32, 0x1009, 0x2100, 0x1010, 0x1013, 0x2108]
            .into_iter()
            .enumerate()
        {
            bytes[0x400 + offset * 4..0x404 + offset * 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x600..0x60c].copy_from_slice(&[0, 0x20, 0, 0, 12, 0, 0, 0, 0, 0xa0, 0, 0]);
        let mut directories = [(0, 0); 16];
        directories[3] = (0x3000, 24);
        directories[5] = (0x4000, 12);
        let pe = Pe {
            bytes,
            image_base: 0x0001_8000_0000,
            entry: 0x1000,
            image_size: 0x5000,
            sections: [".text", ".rdata", ".pdata", ".reloc"]
                .into_iter()
                .enumerate()
                .map(|(index, name)| Section {
                    name: name.to_owned(),
                    rva: (index as u32 + 1) * 0x1000,
                    virtual_size: 0x200,
                    raw_size: 0x200,
                    raw: index as u32 * 0x200,
                    flags: if index == 0 { 0x6000_0020 } else { 0x4000_0040 },
                })
                .collect(),
            directories,
        };
        let placements = vec![
            host_record(0x1000, 9, "resident"),
            host_record(0x1010, 3, "retained"),
        ];
        let functions = placements
            .iter()
            .map(|placement| json!({"symbol": placement["symbol"], "lowered": false}))
            .collect();
        let exception = json!({
            "index": 3, "rva": 0x3000, "size": 24, "contributions": placements,
        });
        let relocations = json!({
            "index": 5, "rva": 0x4000, "size": 12,
            "contributions": [host_record(0x2000, 8, "retained")],
        });
        (pe, placements, functions, [exception, relocations])
    }

    fn copy_pe(pe: &Pe) -> Pe {
        Pe {
            bytes: pe.bytes.clone(),
            image_base: pe.image_base,
            entry: pe.entry,
            image_size: pe.image_size,
            sections: pe.sections.clone(),
            directories: pe.directories,
        }
    }

    #[test]
    fn unchanged_host_graph_retains_nonempty_original_tables() {
        let (before, placements, functions, directories) = retained_graph();
        for directory in &directories {
            inspect_directory_storage(&before, &before, directory, &placements, &functions, &[])
                .unwrap();
        }
    }

    #[test]
    fn retained_tables_require_unmoved_host_ownership_and_no_emission() {
        let (before, placements, functions, directories) = retained_graph();
        let mut moved = placements.clone();
        moved[0]["rva"] = json!(0x1020);
        let mut generated = placements.clone();
        generated[0]["ownership"] = json!("generated");
        let mut lowered = functions.clone();
        lowered[0]["lowered"] = json!(true);
        for directory in &directories {
            for invalid in [moved.as_slice(), generated.as_slice(), &placements[1..]] {
                assert!(
                    inspect_directory_storage(
                        &before,
                        &before,
                        directory,
                        invalid,
                        &functions,
                        &[]
                    )
                    .is_err()
                );
            }
            assert!(
                inspect_directory_storage(&before, &before, directory, &placements, &lowered, &[])
                    .is_err()
            );
            assert!(
                inspect_directory_storage(
                    &before,
                    &before,
                    directory,
                    &placements,
                    &functions,
                    &["injected"],
                )
                .is_err()
            );
            let mut invalid = directory.clone();
            invalid["contributions"][0]["ownership"] = json!("retired");
            assert!(
                inspect_directory_storage(&before, &before, &invalid, &placements, &functions, &[])
                    .is_err()
            );
        }
        let mut inconsistent = directories[0].clone();
        inconsistent["contributions"][0]["ownership"] = json!("retained");
        assert!(
            inspect_directory_storage(
                &before,
                &before,
                &inconsistent,
                &placements,
                &functions,
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn retained_tables_reject_changed_pointers_contents_code_and_fixups() {
        let (before, placements, functions, directories) = retained_graph();
        for directory in &directories {
            let index = number(directory, "index").unwrap() as usize;
            let mut changed = copy_pe(&before);
            changed.directories[index].0 += 4;
            assert!(
                inspect_directory_storage(
                    &before,
                    &changed,
                    directory,
                    &placements,
                    &functions,
                    &[]
                )
                .is_err()
            );
            let mut changed = copy_pe(&before);
            let raw = if index == 3 { 0x400 } else { 0x600 };
            changed.bytes[raw] ^= 1;
            assert!(
                inspect_directory_storage(
                    &before,
                    &changed,
                    directory,
                    &placements,
                    &functions,
                    &[]
                )
                .is_err()
            );
        }
        for (directory, raw) in [(&directories[0], 0), (&directories[1], 0x200)] {
            let mut changed = copy_pe(&before);
            changed.bytes[raw] ^= 1;
            assert!(
                inspect_directory_storage(
                    &before,
                    &changed,
                    directory,
                    &placements,
                    &functions,
                    &[]
                )
                .is_err()
            );
        }
    }

    #[test]
    fn generated_tables_require_one_exact_active_owner_and_retire_original_storage() {
        let (before, mut placements, functions, directories) = retained_graph();
        for directory in &directories {
            let index = number(directory, "index").unwrap() as usize;
            let (rva, size) = before.directories[index];
            let mut pe = copy_pe(&before);
            pe.directories[index].0 += 0x20;
            let raw = if index == 3 { 0x400 } else { 0x600 };
            pe.bytes.copy_within(raw..raw + size as usize, raw + 0x20);
            let mut active = directory.clone();
            active["rva"] = json!(rva + 0x20);
            let table = json!({
                "symbol": {
                    "origin": "generated", "source_module": null,
                    "source_symbol": format!("directory-{index}"), "host_source_rva": null,
                },
                "ownership": "generated", "rva": rva + 0x20, "size": size,
            });
            let original_len = placements.len();
            placements.push(table.clone());
            assert!(
                inspect_directory_storage(
                    &before,
                    &pe,
                    &active,
                    &placements,
                    &functions,
                    &["module"]
                )
                .is_err()
            );
            placements.push(host_record(rva, size, "retired"));
            inspect_directory_storage(&before, &pe, &active, &placements, &functions, &["module"])
                .unwrap();
            assert!(
                inspect_directory_storage(
                    &before,
                    &pe,
                    directory,
                    &placements,
                    &functions,
                    &["module"]
                )
                .is_err()
            );
            placements.push(table);
            assert!(
                inspect_directory_storage(
                    &before,
                    &pe,
                    &active,
                    &placements,
                    &functions,
                    &["module"]
                )
                .is_err()
            );
            placements.pop();
            placements[original_len]["rva"] = json!(rva);
            assert!(
                inspect_directory_storage(
                    &before,
                    &pe,
                    &active,
                    &placements,
                    &functions,
                    &["module"]
                )
                .is_err()
            );
            placements.truncate(original_len);
        }
    }
}
