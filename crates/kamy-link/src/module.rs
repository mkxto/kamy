use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Context, bail, ensure};
use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction, MemoryOperand, Mnemonic, OpKind, Register,
};
use kamy_core::ir::{CallingConvLookup, IrFunction};
use kamy_core::{Function, Module, RelocKind, Relocation, Rva};
use kamy_pe::module::{AuthoredModule, ModuleReferenceKind, ModuleTarget};
use kamy_pe::{DirectoryUpdate, NewSection, PeEdits, PeFile};

use crate::{Options, Report};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EntryMode {
    Inline,
    #[default]
    InitTable,
}

pub struct Plugin {
    pub name: String,
    pub module: AuthoredModule,
}

pub struct Injection<'a> {
    pub plugins: &'a [Plugin],
    pub mode: EntryMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedFunction {
    pub plugin: String,
    pub name: String,
    pub rva: Rva,
}

struct Namespace {
    start: u32,
    module: Module,
    retired: HashSet<usize>,
}

struct Compiled {
    plugin: usize,
    symbol: usize,
    source: Rva,
    instructions: Vec<Instruction>,
    references: Vec<crate::Operand>,
    body: Vec<u8>,
    slot: u32,
    rva: u32,
}

struct PlacedData {
    plugin: usize,
    source: Rva,
    section: NewSection,
}

/// These RVAs identify transform/profile targets, not their final output placement.
/// A plugin function's qualified name is `plugin::symbol`.
pub fn planned_functions(
    host: &Module,
    plugins: &[Plugin],
) -> anyhow::Result<Vec<PlannedFunction>> {
    let namespaces = namespaces(host, plugins)?;
    let mut planned = Vec::new();
    for (plugin, namespace) in plugins.iter().zip(namespaces) {
        for symbol in &plugin.module.code {
            planned.push(PlannedFunction {
                plugin: plugin.name.clone(),
                name: symbol.name.clone(),
                rva: add(namespace.start, symbol.start.get())?.into(),
            });
        }
    }
    Ok(planned)
}

pub fn protect_with_modules(
    pe: &PeFile,
    host: &Module,
    functions: &[Function],
    opts: &Options,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(Rva, &mut IrFunction, f32),
    injection: Injection<'_>,
) -> anyhow::Result<(Vec<u8>, Report)> {
    let Injection { plugins, mode } = injection;
    if plugins.is_empty() {
        return crate::protect_with_transforms(pe, host, functions, opts, cc, transform);
    }
    ensure!(
        pe.subsystem() != 1,
        "SDK module injection is prohibited for kernel images"
    );
    ensure!(
        host.entry_point.is_some(),
        "SDK module injection requires an original entry point"
    );
    let has_table = mode == EntryMode::InitTable
        || plugins.iter().any(|plugin| {
            plugin.module.data.iter().any(|symbol| {
                matches!(
                    symbol.name.as_str(),
                    "SYMBOL_init_table_start" | "SYMBOL_init_table_end"
                )
            })
        });
    let has_startup = has_table && !pe.is_dll();
    let mut namespaces = namespaces(host, plugins)?;
    let (image, mut report) =
        crate::protect_with_transforms(pe, host, functions, opts, cc, transform)?;
    let output = PeFile::parse(&image).context("parsing transformed host for module placement")?;
    let transformed = output.to_module();
    let original_entry = transformed
        .entry_point
        .context("transformed host lost its entry point")?;
    let base = host.image_base;
    let alignment = output.section_alignment();
    let mut cursor = crate::align_up(image_end(&transformed)?, alignment)?;
    let mut data = Vec::new();
    let mut addresses = BTreeMap::new();
    for (index, namespace) in namespaces.iter().enumerate() {
        for (section_index, section) in namespace.module.sections.iter().enumerate() {
            if section.virtual_size == 0
                || section.flags.execute
                || namespace.retired.contains(&section_index)
            {
                continue;
            }
            cursor = crate::align_up(cursor, alignment)?;
            let mut bytes = section.data.clone();
            bytes.resize(section.virtual_size as usize, 0);
            data.push(PlacedData {
                plugin: index,
                source: Rva::new(add(namespace.start, section.rva.get())?),
                section: NewSection {
                    name: opts.metadata_section.clone(),
                    rva: Rva::new(cursor),
                    flags: section.flags,
                    data: bytes,
                },
            });
            cursor = add(cursor, section.virtual_size)?;
        }
    }
    let code_rva = crate::align_up(cursor, alignment)?;
    let mut compiled =
        Vec::with_capacity(plugins.iter().map(|plugin| plugin.module.code.len()).sum());
    for (index, namespace) in namespaces.iter_mut().enumerate() {
        prepare_view(&plugins[index], namespace, base)
            .with_context(|| format!("preparing plugin {}", plugins[index].name))?;
        let starts: BTreeSet<_> = plugins[index]
            .module
            .code
            .iter()
            .flat_map(|symbol| {
                [
                    namespace.start + symbol.start.get(),
                    namespace.start + symbol.end.get(),
                ]
            })
            .collect();
        for (symbol_index, symbol) in plugins[index].module.code.iter().enumerate() {
            let source = Rva::new(add(namespace.start, symbol.start.get())?);
            let end = add(namespace.start, symbol.end.get())?;
            let function =
                kamy_disasm::recover_function(&namespace.module, source, &starts, &BTreeSet::new());
            ensure!(
                !function.blocks.is_empty()
                    && function.blocks.iter().all(|block| {
                        block.start.get() >= source.get() && block.end.get() <= end
                    }),
                "plugin {}::{} has control flow outside its authored range",
                plugins[index].name,
                symbol.name
            );
            let mut instructions =
                crate::ssa_instructions(&namespace.module, &function, cc, transform).map_err(
                    |reason| {
                        anyhow::anyhow!(
                            "plugin {}::{} cannot pass SSA/codegen: {reason:?}",
                            plugins[index].name,
                            symbol.name
                        )
                    },
                )?;
            ensure!(
                !instructions.is_empty(),
                "plugin {}::{} generated no code",
                plugins[index].name,
                symbol.name
            );
            instructions.insert(0, Instruction::with(Code::Endbr64));
            let mut references = Vec::new();
            for (index, instruction) in instructions.iter().enumerate() {
                if instruction.op0_kind() == OpKind::NearBranch64 {
                    references.push(crate::Operand::Branch(
                        index,
                        instruction.near_branch_target(),
                    ));
                }
                if instruction.is_ip_rel_memory_operand() {
                    references.push(crate::Operand::Rip(
                        index,
                        instruction.ip_rel_memory_address(),
                    ));
                }
            }
            let body =
                kamy_codegen::relocate(&instructions, va(base, code_rva)?).with_context(|| {
                    format!("encoding plugin {}::{}", plugins[index].name, symbol.name)
                })?;
            let slot = u32::try_from(body.len()).context("module function exceeds RVA space")?;
            compiled.push(Compiled {
                plugin: index,
                symbol: symbol_index,
                source,
                instructions,
                references,
                body,
                slot,
                rva: code_rva,
            });
        }
    }
    for placed in &data {
        let namespace = &namespaces[placed.plugin];
        for reference in &plugins[placed.plugin].module.references {
            if let ModuleTarget::Rva(target) = reference.target {
                let virtual_target = add(namespace.start, target.get())?;
                if virtual_target >= placed.source.get()
                    && virtual_target <= add(placed.source.get(), placed.section.data.len() as u32)?
                {
                    addresses.insert(
                        va(base, virtual_target)?,
                        va(
                            base,
                            add(
                                placed.section.rva.get(),
                                virtual_target - placed.source.get(),
                            )?,
                        )?,
                    );
                }
            }
        }
        addresses.insert(
            va(base, placed.source.get())?,
            va(base, placed.section.rva.get())?,
        );
    }
    let (loader_rva, table_rva, table_end, startup_rva, code_end, loader, startup) = loop {
        cursor = code_rva;
        for function in &mut compiled {
            cursor = crate::align_up(cursor, crate::FUNCTION_ALIGN)?;
            function.rva = cursor;
            addresses.insert(va(base, function.source.get())?, va(base, cursor)?);
            cursor = add(cursor, function.slot)?;
        }
        let loader_rva = crate::align_up(cursor, crate::FUNCTION_ALIGN)?;
        let plugin_entries = plugin_entries(plugins, &namespaces, &addresses, base)?;
        let probe = entry_loader(
            base,
            loader_rva,
            &plugin_entries,
            original_entry,
            pe.is_dll(),
            mode,
            0..0,
        )?;
        let loader_end = add(loader_rva, probe.len() as u32)?;
        let (startup_rva, startup) = if has_startup {
            let rva = crate::align_up(loader_end, crate::FUNCTION_ALIGN)?;
            (rva, startup_thunk(base, rva, original_entry)?)
        } else {
            (loader_end, Vec::new())
        };
        let code_end = add(startup_rva, startup.len() as u32)?;
        let table_rva = crate::align_up(code_end, alignment)?;
        let count = if has_table {
            plugins
                .len()
                .checked_add(usize::from(!pe.is_dll()))
                .context("init table count overflow")?
        } else {
            0
        };
        let table_end = add(
            table_rva,
            u32::try_from(count.checked_mul(8).context("init table size overflow")?)?,
        )?;
        let loader = entry_loader(
            base,
            loader_rva,
            &plugin_entries,
            original_entry,
            pe.is_dll(),
            mode,
            table_rva..table_end,
        )?;
        ensure!(
            loader.len() == probe.len(),
            "entry loader layout depends on table placement"
        );
        let mut grew = false;
        for function in &mut compiled {
            for reference in &function.references {
                match *reference {
                    crate::Operand::Branch(index, original) => {
                        function.instructions[index].set_near_branch64(
                            addresses.get(&original).copied().unwrap_or(original),
                        );
                    }
                    crate::Operand::Rip(index, original) => {
                        let target =
                            placed_rip_target(original, &addresses, &data, &namespaces, base)
                                .with_context(|| {
                                    format!(
                                        "plugin {}::{} RIP target",
                                        plugins[function.plugin].name,
                                        plugins[function.plugin].module.code[function.symbol].name
                                    )
                                })?;
                        function.instructions[index].set_memory_displacement64(target);
                    }
                }
            }
            function.body = kamy_codegen::relocate(&function.instructions, va(base, function.rva)?)
                .with_context(|| {
                    format!(
                        "placing plugin {}::{}",
                        plugins[function.plugin].name,
                        plugins[function.plugin].module.code[function.symbol].name
                    )
                })?;
            let len =
                u32::try_from(function.body.len()).context("module function exceeds RVA space")?;
            if len > function.slot {
                function.slot = len;
                grew = true;
            }
        }
        if !grew {
            break (
                loader_rva,
                table_rva,
                table_end,
                startup_rva,
                code_end,
                loader,
                startup,
            );
        }
    };
    for (plugin, namespace) in plugins.iter().zip(&namespaces) {
        for reference in &plugin.module.references {
            let source = Rva::new(add(namespace.start, reference.source.get())?);
            let section = namespace
                .module
                .sections
                .iter()
                .position(|section| section.contains(source))
                .context("authored reference source has no section")?;
            if namespace.retired.contains(&section)
                || !namespace.module.sections[section].flags.execute
            {
                continue;
            }
            target_rva(reference.target, namespace, &addresses, base).with_context(|| {
                format!("plugin {} code reference {}", plugin.name, reference.source)
            })?;
        }
    }
    let mut relocations = transformed.relocations.clone();
    rebase_data(
        plugins,
        &namespaces,
        &mut data,
        &addresses,
        base,
        table_rva..table_end,
        &mut relocations,
    )?;
    let mut table = Vec::with_capacity((table_end - table_rva) as usize);
    if has_table {
        for entry in plugin_entries(plugins, &namespaces, &addresses, base)?
            .into_iter()
            .chain(has_startup.then_some(startup_rva))
        {
            relocations.push(Relocation {
                rva: Rva::new(add(table_rva, table.len() as u32)?),
                kind: RelocKind::Dir64,
            });
            table.extend_from_slice(&va(base, entry)?.to_le_bytes());
        }
    }
    ensure!(
        add(table_rva, table.len() as u32)? == table_end,
        "invalid init-table bounds"
    );
    let xdata_rva = crate::align_up(table_end, alignment)?;
    let mut xdata = Vec::new();
    let mut entries: Vec<_> = output
        .runtime_functions()
        .iter()
        .map(|function| {
            (
                function.begin.get(),
                function.end.get(),
                function.unwind.get(),
            )
        })
        .collect();
    let mut code = Vec::with_capacity((code_end - code_rva) as usize);
    for function in &compiled {
        crate::append_code(&mut code, code_rva, function.rva, &function.body)?;
        append_generated_unwind(
            base,
            &mut xdata,
            &mut entries,
            xdata_rva,
            function.rva,
            &function.body,
        )
        .with_context(|| {
            format!(
                "unwind for plugin {}::{}",
                plugins[function.plugin].name,
                plugins[function.plugin].module.code[function.symbol].name
            )
        })?;
        report.moved.push(function.source);
        report.ssa_lowered_rvas.push(function.source);
        report
            .address_map
            .insert(function.source, Rva::new(function.rva));
        tracing::debug!(plugin = %plugins[function.plugin].name, source = %function.source, rva = function.rva, "linked SDK function");
    }
    crate::append_code(&mut code, code_rva, loader_rva, &loader)?;
    append_generated_unwind(
        base,
        &mut xdata,
        &mut entries,
        xdata_rva,
        loader_rva,
        &loader,
    )?;
    if has_startup {
        crate::append_code(&mut code, code_rva, startup_rva, &startup)?;
        append_generated_unwind(
            base,
            &mut xdata,
            &mut entries,
            xdata_rva,
            startup_rva,
            &startup,
        )?;
    }
    ensure!(
        add(code_rva, code.len() as u32)? == code_end,
        "invalid module code extent"
    );
    let relocation_rva = add(xdata_rva, crate::align_up(xdata.len() as u32, 4)?)?;
    let relocation_bytes = kamy_pe::encode_base_relocations(&relocations)?;
    xdata.resize((relocation_rva - xdata_rva) as usize, 0);
    xdata.extend_from_slice(&relocation_bytes);
    let pdata_rva = crate::align_up(add(xdata_rva, xdata.len() as u32)?, alignment)?;
    let pdata = crate::encode_pdata(&mut entries)?;
    let pdata_len = u32::try_from(pdata.len())?;
    let mut sections = Vec::with_capacity(data.len() + 3 + usize::from(has_table));
    sections.extend(data.into_iter().map(|placed| placed.section));
    sections.push(crate::section(
        opts.code_section.clone(),
        code_rva,
        true,
        code,
    ));
    if has_table {
        sections.push(crate::section(
            opts.metadata_section.clone(),
            table_rva,
            false,
            table,
        ));
    }
    sections.extend([
        crate::section(opts.metadata_section.clone(), xdata_rva, false, xdata),
        crate::section(opts.pdata_section.clone(), pdata_rva, false, pdata),
    ]);
    let edits = PeEdits {
        new_sections: sections,
        directories: vec![
            DirectoryUpdate {
                index: 3,
                rva: Rva::new(pdata_rva),
                size: pdata_len,
            },
            DirectoryUpdate {
                index: 5,
                rva: if relocation_bytes.is_empty() {
                    Rva::ZERO
                } else {
                    Rva::new(relocation_rva)
                },
                size: u32::try_from(relocation_bytes.len())?,
            },
        ],
        entry_point: Some(Rva::new(loader_rva)),
        ..Default::default()
    };
    report.ssa_lowered = report.ssa_lowered_rvas.len();
    tracing::info!(
        plugins = plugins.len(),
        functions = compiled.len(),
        "linked SDK modules"
    );
    Ok((
        output
            .rebuild(&edits)
            .context("rebuilding PE with SDK modules")?,
        report,
    ))
}

fn namespaces(host: &Module, plugins: &[Plugin]) -> anyhow::Result<Vec<Namespace>> {
    let mut cursor = crate::align_up(image_end(host)?, 0x1_0000)?;
    let host_targets: Vec<_> = plugins
        .iter()
        .flat_map(|plugin| &plugin.module.references)
        .filter_map(|reference| {
            if reference.target != ModuleTarget::ImageBase {
                return None;
            }
            // An x64 instruction has at most 15 bytes, including any COFF-unbiased tail.
            let (bias, trailing) = match reference.kind {
                ModuleReferenceKind::Relative32 { bias } => (i128::from(bias), 15),
                _ => (0, 0),
            };
            let start = i128::from(reference.addend) - bias;
            Some((start, start + trailing))
        })
        .collect();
    let mut names = HashSet::new();
    let mut result = Vec::new();
    for plugin in plugins {
        ensure!(
            !plugin.name.is_empty() && names.insert(plugin.name.as_str()),
            "plugin names must be nonempty and unique: {}",
            plugin.name
        );
        let pe = PeFile::parse(&plugin.module.image)
            .with_context(|| format!("parsing plugin {}", plugin.name))?;
        ensure!(
            pe.is_dll(),
            "plugin {} is not a specialized DLL",
            plugin.name
        );
        ensure!(
            pe.subsystem() != 1,
            "plugin {} is a kernel image",
            plugin.name
        );
        let module = pe.to_module();
        let retired = retired_sections(&pe, &module)
            .with_context(|| format!("plugin {} directories", plugin.name))?;
        ensure!(
            !plugin.module.code.is_empty(),
            "plugin {} has no authored functions",
            plugin.name
        );
        let mut previous_end = 0;
        let mut code: Vec<_> = plugin.module.code.iter().collect();
        code.sort_by_key(|symbol| symbol.start);
        for symbol in code {
            ensure!(
                symbol.start.get() >= previous_end && symbol.end > symbol.start,
                "plugin {} has overlapping/empty authored function {}",
                plugin.name,
                symbol.name
            );
            let section = module
                .section_at(symbol.start)
                .context("authored function lies outside module")?;
            ensure!(
                section.flags.execute
                    && symbol.end.get() <= add(section.rva.get(), section.virtual_size)?,
                "plugin {} function {} crosses an executable section",
                plugin.name,
                symbol.name
            );
            previous_end = symbol.end.get();
        }
        ensure!(
            plugin
                .module
                .code
                .iter()
                .any(|symbol| symbol.start == plugin.module.entry),
            "plugin {} entry has no authored function",
            plugin.name
        );
        let extent = image_end(&module)?;
        let end = loop {
            let end = add(cursor, extent)
                .with_context(|| format!("plugin {} synthetic namespace extent", plugin.name))?;
            let target = host_targets
                .iter()
                .filter(|&&(start, target_end)| {
                    start <= i128::from(end) && target_end >= i128::from(cursor)
                })
                .map(|&(_, end)| end)
                .max();
            let Some(target) = target else {
                break end;
            };
            cursor = u32::try_from(target)
                .context("host-base-relative target exceeds RVA range")
                .and_then(|target| add(target, 1))
                .and_then(|after| crate::align_up(after, 0x1_0000))
                .with_context(|| {
                    format!(
                        "plugin {} synthetic namespace above host-base-relative target {target:#x}",
                        plugin.name
                    )
                })?;
        };
        let start = cursor;
        cursor = crate::align_up(end, 0x1_0000)
            .with_context(|| format!("plugin {} synthetic namespace end", plugin.name))?;
        result.push(Namespace {
            start,
            module,
            retired,
        });
    }
    Ok(result)
}

fn retired_sections(pe: &PeFile, module: &Module) -> anyhow::Result<HashSet<usize>> {
    let mut retired = HashSet::new();
    for index in 0..16 {
        let Some((rva, size)) = pe.data_directory(index) else {
            continue;
        };
        if rva == Rva::ZERO && size == 0 {
            continue;
        }
        ensure!(
            matches!(index, 3 | 5),
            "unsupported authored module directory {index}; imports/TLS and other loader metadata must be explicitly supported by the SDK producer"
        );
        let section = module
            .sections
            .iter()
            .position(|section| section.contains(rva))
            .context("module directory outside sections")?;
        let record = &module.sections[section];
        ensure!(
            !record.flags.execute && rva.get() == record.rva.get() && size <= record.virtual_size,
            "module directory {index} is not in a dedicated section"
        );
        retired.insert(section);
    }
    for (index, section) in module.sections.iter().enumerate() {
        if matches!(section.name.as_str(), ".kxdata" | ".kmod") {
            retired.insert(index);
        }
    }
    for function in pe.runtime_functions() {
        let header = module
            .bytes_at(function.unwind)
            .and_then(|bytes| bytes.first())
            .context("invalid module unwind record")?;
        ensure!(
            header & 0xf8 == 0,
            "module function {} uses language handlers or chained unwind unsupported by SSA regeneration",
            function.begin
        );
    }
    Ok(retired)
}

fn prepare_view(plugin: &Plugin, namespace: &mut Namespace, base: u64) -> anyhow::Result<()> {
    let start = namespace.start;
    for reference in &plugin.module.references {
        let section_index = namespace
            .module
            .sections
            .iter()
            .position(|section| section.contains(reference.source))
            .context("reference source outside module")?;
        if namespace.retired.contains(&section_index)
            || !namespace.module.sections[section_index].flags.execute
        {
            continue;
        }
        let target = match reference.target {
            ModuleTarget::Rva(rva) => va(base, add(start, rva.get())?)?,
            ModuleTarget::ImageBase => base,
        }
        .checked_add_signed(reference.addend)
        .with_context(|| format!("reference {} VA overflow", reference.source))?;
        let section = &mut namespace.module.sections[section_index];
        let offset = (reference.source.get() - section.rva.get()) as usize;
        match reference.kind {
            ModuleReferenceKind::Relative32 { bias } => {
                let origin = va(
                    base,
                    add(add(start, reference.source.get())?, 4 + u32::from(bias))?,
                )?;
                let displacement = i32::try_from(i128::from(target) - i128::from(origin))
                    .context("authored relative reference exceeds rel32 range")?;
                section
                    .data
                    .get_mut(offset..offset + 4)
                    .context("truncated code reference")?
                    .copy_from_slice(&displacement.to_le_bytes());
            }
            ModuleReferenceKind::Absolute64 => {
                let symbol = plugin
                    .module
                    .code
                    .iter()
                    .find(|symbol| {
                        symbol.start <= reference.source && reference.source < symbol.end
                    })
                    .context("absolute code reference has no authored function")?;
                let function_offset = (symbol.start.get() - section.rva.get()) as usize;
                let function_end = (symbol.end.get() - section.rva.get()) as usize;
                let function_bytes = section
                    .data
                    .get(function_offset..function_end)
                    .context("truncated authored function")?;
                let ip = va(base, add(start, symbol.start.get())?)?;
                let mut decoder = Decoder::with_ip(64, function_bytes, ip, DecoderOptions::NONE);
                let mut replacement = None;
                while decoder.can_decode() {
                    let instruction = decoder.decode();
                    let constants = decoder.get_constant_offsets(&instruction);
                    let instruction_offset =
                        usize::try_from(instruction.ip() - ip)? + function_offset;
                    if instruction_offset + constants.immediate_offset() != offset {
                        continue;
                    }
                    ensure!(
                        instruction.mnemonic() == Mnemonic::Mov
                            && instruction.op0_kind() == OpKind::Register
                            && instruction.op1_kind() == OpKind::Immediate64
                            && constants.immediate_size() == 8,
                        "unsupported authored absolute code operand at {}",
                        reference.source
                    );
                    let mut lea = Instruction::with2(
                        Code::Lea_r64_m,
                        instruction.op0_register(),
                        MemoryOperand::with_base(Register::RIP),
                    )?;
                    lea.set_memory_displacement64(target);
                    let mut encoder = Encoder::new(64);
                    encoder.encode(&lea, instruction.ip())?;
                    let mut bytes = encoder.take_buffer();
                    ensure!(
                        bytes.len() <= instruction.len(),
                        "authored movabs cannot normalize to RIP-relative LEA"
                    );
                    let padding = instruction.len() - bytes.len();
                    crate::append_nops(&mut bytes, padding);
                    replacement = Some((instruction_offset, bytes));
                    break;
                }
                let (offset, bytes) =
                    replacement.context("absolute reference is not an instruction immediate")?;
                section.data[offset..offset + bytes.len()].copy_from_slice(&bytes);
            }
            ModuleReferenceKind::ImageRelative32 => bail!(
                "unsupported image-relative code operand at {}",
                reference.source
            ),
        }
    }
    namespace.module.image_base = base;
    namespace.module.entry_point = Some(Rva::new(add(start, plugin.module.entry.get())?));
    for section in &mut namespace.module.sections {
        section.rva = Rva::new(add(start, section.rva.get())?);
    }
    for symbol in &mut namespace.module.symbols {
        symbol.rva = Rva::new(add(start, symbol.rva.get())?);
    }
    for relocation in &mut namespace.module.relocations {
        relocation.rva = Rva::new(add(start, relocation.rva.get())?);
    }
    Ok(())
}

fn target_rva(
    target: ModuleTarget,
    namespace: &Namespace,
    addresses: &BTreeMap<u64, u64>,
    base: u64,
) -> anyhow::Result<u32> {
    match target {
        ModuleTarget::ImageBase => Ok(0),
        ModuleTarget::Rva(target) => {
            let source = va(base, add(namespace.start, target.get())?)?;
            let mapped = addresses.get(&source).with_context(|| format!("authored target {target} has no final placement (interior code pointers and retired metadata are unsupported)"))?;
            u32::try_from(mapped.checked_sub(base).context("target below host base")?)
                .context("target RVA overflow")
        }
    }
}

fn placed_rip_target(
    original: u64,
    addresses: &BTreeMap<u64, u64>,
    data: &[PlacedData],
    namespaces: &[Namespace],
    base: u64,
) -> anyhow::Result<u64> {
    if let Some(&target) = addresses.get(&original) {
        return Ok(target);
    }
    let Some(rva) = original
        .checked_sub(base)
        .and_then(|rva| u32::try_from(rva).ok())
    else {
        return Ok(original);
    };
    for placed in data {
        if rva >= placed.source.get()
            && rva <= add(placed.source.get(), placed.section.data.len() as u32)?
        {
            return va(
                base,
                add(placed.section.rva.get(), rva - placed.source.get())?,
            );
        }
    }
    ensure!(
        !namespaces.iter().any(|namespace| namespace
            .module
            .section_at(Rva::new(rva))
            .is_some_and(|section| section.flags.execute)),
        "authored code target {rva:#x} has no final placement (interior code pointers are unsupported)"
    );
    Ok(original)
}

fn rebase_data(
    plugins: &[Plugin],
    namespaces: &[Namespace],
    data: &mut [PlacedData],
    addresses: &BTreeMap<u64, u64>,
    base: u64,
    table: std::ops::Range<u32>,
    relocations: &mut Vec<Relocation>,
) -> anyhow::Result<()> {
    for placed in data {
        let plugin = &plugins[placed.plugin];
        let namespace = &namespaces[placed.plugin];
        let original_start = placed.source.get() - namespace.start;
        let original_end = add(original_start, placed.section.data.len() as u32)?;
        let is_bound =
            |name: &str| matches!(name, "SYMBOL_init_table_start" | "SYMBOL_init_table_end");
        for reference in &plugin.module.references {
            if reference.source.get() < original_start || reference.source.get() >= original_end {
                continue;
            }
            if plugin
                .module
                .data
                .iter()
                .any(|symbol| is_bound(&symbol.name) && symbol.start == reference.source)
            {
                continue;
            }
            let target =
                target_rva(reference.target, namespace, addresses, base).with_context(|| {
                    format!("plugin {} reference {}", plugin.name, reference.source)
                })?;
            if let ModuleTarget::Rva(symbol) = reference.target {
                let symbol = Rva::new(add(namespace.start, symbol.get())?);
                ensure!(
                    reference.addend == 0
                        || !namespace
                            .module
                            .section_at(symbol)
                            .is_some_and(|section| section.flags.execute),
                    "plugin {} reference {} has an unsupported interior code pointer",
                    plugin.name,
                    reference.source
                );
            }
            let target = va(base, target)?
                .checked_add_signed(reference.addend)
                .with_context(|| {
                    format!(
                        "plugin {} reference {} VA overflow",
                        plugin.name, reference.source
                    )
                })?;
            let offset = (reference.source.get() - original_start) as usize;
            let source = add(placed.section.rva.get(), offset as u32)?;
            let mut bytes = [0; 8];
            let len = match reference.kind {
                ModuleReferenceKind::Absolute64 => {
                    relocations.push(Relocation {
                        rva: Rva::new(source),
                        kind: RelocKind::Dir64,
                    });
                    bytes.copy_from_slice(&target.to_le_bytes());
                    8
                }
                ModuleReferenceKind::ImageRelative32 => {
                    let target = u32::try_from(i128::from(target) - i128::from(base))
                        .with_context(|| {
                            format!(
                                "plugin {} reference {} image-relative target exceeds RVA range",
                                plugin.name, reference.source
                            )
                        })?;
                    bytes[..4].copy_from_slice(&target.to_le_bytes());
                    4
                }
                ModuleReferenceKind::Relative32 { bias } => {
                    let origin = va(base, add(source, 4 + u32::from(bias))?)?;
                    let displacement = i32::try_from(i128::from(target) - i128::from(origin))
                        .context("data relative reference exceeds rel32 range")?;
                    bytes[..4].copy_from_slice(&displacement.to_le_bytes());
                    4
                }
            };
            placed
                .section
                .data
                .get_mut(offset..offset + len)
                .context("reference crosses module data section")?
                .copy_from_slice(&bytes[..len]);
        }
        for symbol in plugin
            .module
            .data
            .iter()
            .filter(|symbol| is_bound(&symbol.name))
        {
            if symbol.start.get() < original_start || symbol.start.get() >= original_end {
                continue;
            }
            ensure!(
                symbol.size >= 8,
                "plugin {} SDK bound {} is not pointer-sized",
                plugin.name,
                symbol.name
            );
            let offset = (symbol.start.get() - original_start) as usize;
            let target = if symbol.name == "SYMBOL_init_table_start" {
                table.start
            } else {
                table.end
            };
            placed
                .section
                .data
                .get_mut(offset..offset + 8)
                .context("SDK bound crosses data section")?
                .copy_from_slice(&va(base, target)?.to_le_bytes());
            relocations.push(Relocation {
                rva: Rva::new(add(placed.section.rva.get(), offset as u32)?),
                kind: RelocKind::Dir64,
            });
        }
    }
    Ok(())
}

fn plugin_entries(
    plugins: &[Plugin],
    namespaces: &[Namespace],
    addresses: &BTreeMap<u64, u64>,
    base: u64,
) -> anyhow::Result<Vec<u32>> {
    plugins
        .iter()
        .zip(namespaces)
        .map(|(plugin, namespace)| {
            target_rva(
                ModuleTarget::Rva(plugin.module.entry),
                namespace,
                addresses,
                base,
            )
        })
        .collect()
}

fn append_generated_unwind(
    base: u64,
    xdata: &mut Vec<u8>,
    entries: &mut Vec<(u32, u32, u32)>,
    xdata_rva: u32,
    rva: u32,
    body: &[u8],
) -> anyhow::Result<()> {
    let ranges = kamy_seh::unwind_ranges(body, va(base, rva)?)?;
    crate::append_unwind(
        xdata,
        entries,
        xdata_rva,
        rva,
        u32::try_from(body.len())?,
        &ranges,
    )
}

fn startup_thunk(base: u64, rva: u32, original: Rva) -> anyhow::Result<Vec<u8>> {
    kamy_codegen::relocate(
        &[
            Instruction::with(Code::Endbr64),
            Instruction::with_branch(Code::Jmp_rel32_64, va(base, original.get())?)?,
        ],
        va(base, rva)?,
    )
}

fn entry_loader(
    base: u64,
    rva: u32,
    plugins: &[u32],
    original: Rva,
    dll: bool,
    mode: EntryMode,
    table: std::ops::Range<u32>,
) -> anyhow::Result<Vec<u8>> {
    const LOOP: u64 = 0x7ffe_0000_0000;
    const FAIL: u64 = LOOP + 0x1000;
    const DONE: u64 = LOOP + 0x2000;
    const STATUS_FAIL: u64 = LOOP + 0x3000;
    const TRAP: u64 = LOOP + 0x4000;
    let mut instructions = vec![
        Instruction::with(Code::Endbr64),
        Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x48i32)?,
    ];
    for (register, offset) in [(Register::RCX, 32), (Register::RDX, 40), (Register::R8, 48)] {
        instructions.push(Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(Register::RSP, offset),
            register,
        )?);
    }
    let args = || -> anyhow::Result<Vec<Instruction>> {
        [(Register::RCX, 32), (Register::RDX, 40), (Register::R8, 48)]
            .into_iter()
            .map(|(register, offset)| {
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    register,
                    MemoryOperand::with_base_displ(Register::RSP, offset),
                )
                .map_err(Into::into)
            })
            .collect()
    };
    match mode {
        EntryMode::Inline => {
            for &plugin in plugins {
                instructions.extend(args()?);
                instructions.push(Instruction::with_branch(
                    Code::Call_rel32_64,
                    va(base, plugin)?,
                )?);
                instructions.push(Instruction::with2(
                    Code::Test_rm32_r32,
                    Register::EAX,
                    Register::EAX,
                )?);
                instructions.push(Instruction::with_branch(Code::Jne_rel32_64, STATUS_FAIL)?);
            }
        }
        EntryMode::InitTable => {
            let mut start = Instruction::with2(
                Code::Lea_r64_m,
                Register::R10,
                MemoryOperand::with_base(Register::RIP),
            )?;
            start.set_memory_displacement64(va(base, table.start)?);
            instructions.push(start);
            instructions.push(Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::RSP, 56),
                Register::R10,
            )?);
            let mut cursor = Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R10,
                MemoryOperand::with_base_displ(Register::RSP, 56),
            )?;
            cursor.set_ip(LOOP);
            instructions.push(cursor);
            let mut end = Instruction::with2(
                Code::Lea_r64_m,
                Register::R11,
                MemoryOperand::with_base(Register::RIP),
            )?;
            end.set_memory_displacement64(va(base, table.end)?);
            instructions.push(end);
            instructions.push(Instruction::with2(
                Code::Cmp_rm64_r64,
                Register::R10,
                Register::R11,
            )?);
            instructions.push(Instruction::with_branch(
                Code::Jae_rel32_64,
                if dll { DONE } else { FAIL },
            )?);
            instructions.extend(args()?);
            instructions.push(Instruction::with1(
                Code::Call_rm64,
                MemoryOperand::with_base(Register::R10),
            )?);
            instructions.push(Instruction::with2(
                Code::Add_rm64_imm8,
                MemoryOperand::with_base_displ(Register::RSP, 56),
                8i32,
            )?);
            if !dll {
                instructions.push(Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::R10,
                    MemoryOperand::with_base_displ(Register::RSP, 56),
                )?);
                let mut end = Instruction::with2(
                    Code::Lea_r64_m,
                    Register::R11,
                    MemoryOperand::with_base(Register::RIP),
                )?;
                end.set_memory_displacement64(va(base, table.end)?);
                instructions.push(end);
                instructions.push(Instruction::with2(
                    Code::Cmp_rm64_r64,
                    Register::R10,
                    Register::R11,
                )?);
                instructions.push(Instruction::with_branch(Code::Jae_rel32_64, FAIL)?);
            }
            instructions.push(Instruction::with2(
                Code::Test_rm32_r32,
                Register::EAX,
                Register::EAX,
            )?);
            instructions.push(Instruction::with_branch(Code::Jne_rel32_64, STATUS_FAIL)?);
            instructions.push(Instruction::with_branch(Code::Jmp_rel32_64, LOOP)?);
        }
    }
    if dll || mode == EntryMode::Inline {
        let mut done = Instruction::with(Code::Nopd);
        done.set_ip(DONE);
        instructions.push(done);
        instructions.extend(args()?);
        instructions.push(Instruction::with2(
            Code::Add_rm64_imm8,
            Register::RSP,
            0x48i32,
        )?);
        instructions.push(Instruction::with_branch(
            Code::Jmp_rel32_64,
            va(base, original.get())?,
        )?);
    }
    if !dll && mode == EntryMode::InitTable {
        let mut failure = Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 7u32)?;
        failure.set_ip(FAIL);
        instructions.push(failure);
        instructions.push(Instruction::with_branch(Code::Jmp_rel32_64, TRAP)?);
    }
    let mut status_failure = Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX)?;
    status_failure.set_ip(STATUS_FAIL);
    instructions.push(status_failure);
    let mut trap = Instruction::with1(Code::Int_imm8, 0x29u32)?;
    trap.set_ip(TRAP);
    instructions.push(trap);
    instructions.push(Instruction::with(Code::Ud2));
    kamy_codegen::relocate(&instructions, va(base, rva)?)
}

fn image_end(module: &Module) -> anyhow::Result<u32> {
    module.sections.iter().try_fold(0u32, |end, section| {
        Ok(end.max(add(section.rva.get(), section.virtual_size)?))
    })
}

fn add(a: u32, b: u32) -> anyhow::Result<u32> {
    a.checked_add(b).context("module RVA overflow")
}

fn va(base: u64, rva: u32) -> anyhow::Result<u64> {
    base.checked_add(u64::from(rva))
        .context("module VA overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::Win64Default;
    use kamy_pe::module::{CodeSymbol, DataSymbol, ModuleReference};

    const BASE: u64 = 0x1_4000_0000;

    fn fixture(code: &[u8], dll: bool) -> Vec<u8> {
        let mut bytes = vec![0; 0xa00];
        bytes[..2].copy_from_slice(b"MZ");
        put32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut bytes, 0x84, 0x8664);
        put16(&mut bytes, 0x86, 3);
        put16(&mut bytes, 0x94, 0xf0);
        put16(&mut bytes, 0x96, if dll { 0x2022 } else { 0x22 });
        put16(&mut bytes, 0x98, 0x20b);
        put32(&mut bytes, 0xa8, if dll { 0 } else { 0x1000 });
        bytes[0xb0..0xb8].copy_from_slice(&BASE.to_le_bytes());
        put32(&mut bytes, 0xb8, 0x1000);
        put32(&mut bytes, 0xbc, 0x200);
        put32(&mut bytes, 0xd0, 0x4000);
        put32(&mut bytes, 0xd4, 0x400);
        put16(&mut bytes, 0xdc, 3);
        put32(&mut bytes, 0x104, 16);
        for (index, (name, rva, size, flags)) in [
            (b".text".as_slice(), 0x1000, code.len() as u32, 0x6000_0020),
            (b".data".as_slice(), 0x2000, 128, 0xc000_0040),
            (b".rdata".as_slice(), 0x3000, 16, 0x4000_0040),
        ]
        .into_iter()
        .enumerate()
        {
            let header = 0x188 + index * 40;
            bytes[header..header + name.len()].copy_from_slice(name);
            put32(&mut bytes, header + 8, size);
            put32(&mut bytes, header + 12, rva);
            put32(&mut bytes, header + 16, 0x200);
            put32(&mut bytes, header + 20, 0x400 + index as u32 * 0x200);
            put32(&mut bytes, header + 36, flags);
        }
        bytes[0x400..0x400 + code.len()].copy_from_slice(code);
        bytes
    }

    fn plugin(code: &[u8]) -> Plugin {
        Plugin {
            name: "example".into(),
            module: AuthoredModule {
                image: fixture(code, true),
                entry: Rva::new(0x1000),
                code: vec![CodeSymbol {
                    name: "init".into(),
                    start: Rva::new(0x1000),
                    end: Rva::new(0x1000 + code.len() as u32),
                }],
                data: Vec::new(),
                references: Vec::new(),
            },
        }
    }

    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn entry_loaders_preserve_three_arguments_and_own_unwind() {
        for dll in [false, true] {
            for mode in [EntryMode::Inline, EntryMode::InitTable] {
                let bytes = entry_loader(
                    BASE,
                    0x5000,
                    &[0x6000, 0x6100],
                    Rva::new(0x1000),
                    dll,
                    mode,
                    0x7000..if dll { 0x7010 } else { 0x7018 },
                )
                .unwrap();
                let instructions: Vec<_> =
                    Decoder::with_ip(64, &bytes, BASE + 0x5000, DecoderOptions::NONE)
                        .into_iter()
                        .collect();
                assert_eq!(instructions[0].code(), Code::Endbr64);
                assert_eq!(instructions[1].immediate8(), 0x48);
                for (register, offset) in
                    [(Register::RCX, 32), (Register::RDX, 40), (Register::R8, 48)]
                {
                    assert!(instructions.iter().any(|instruction| instruction.code()
                        == Code::Mov_rm64_r64
                        && instruction.op1_register() == register
                        && instruction.memory_base() == Register::RSP
                        && instruction.memory_displacement64() == offset));
                    assert!(instructions.iter().any(|instruction| instruction.code()
                        == Code::Mov_r64_rm64
                        && instruction.op0_register() == register
                        && instruction.memory_base() == Register::RSP
                        && instruction.memory_displacement64() == offset));
                }
                assert!(
                    instructions
                        .iter()
                        .any(|instruction| instruction.code() == Code::Int_imm8
                            && instruction.immediate8() == 0x29)
                );
                if dll {
                    let tail = instructions
                        .iter()
                        .position(|instruction| {
                            instruction.code() == Code::Jmp_rel32_64
                                && instruction.near_branch_target() == BASE + 0x1000
                        })
                        .unwrap();
                    assert_eq!(instructions[tail - 1].code(), Code::Add_rm64_imm8);
                    assert_eq!(instructions[tail - 1].immediate8(), 0x48);
                }
                let ranges = kamy_seh::unwind_ranges(&bytes, BASE + 0x5000).unwrap();
                assert!(!ranges.is_empty());
                assert!(
                    ranges
                        .iter()
                        .all(|range| range.begin < range.end && range.end as usize <= bytes.len())
                );
                for instruction in &instructions {
                    if matches!(instruction.mnemonic(), Mnemonic::Call) {
                        let offset = (instruction.ip() - (BASE + 0x5000)) as u32;
                        let range = ranges
                            .iter()
                            .find(|range| range.begin <= offset && offset < range.end)
                            .unwrap();
                        assert_eq!(range.info, [2, 0, 1, 0, 0, 0x82, 0, 0]);
                    }
                    if instruction.mnemonic() == Mnemonic::Jmp
                        && instruction.near_branch_target() == BASE + 0x1000
                    {
                        let offset = (instruction.ip() - (BASE + 0x5000)) as u32;
                        let range = ranges
                            .iter()
                            .find(|range| range.begin <= offset && offset < range.end)
                            .unwrap();
                        assert_eq!(range.info, [2, 0, 0, 0, 0, 0, 0, 0]);
                    }
                }
            }
        }
    }

    fn execute_fastfail(instructions: &[Instruction], mut ip: u64, eax: u32) -> u32 {
        let mut ecx = None;
        for _ in 0..4 {
            let instruction = instructions
                .iter()
                .find(|instruction| instruction.ip() == ip)
                .unwrap();
            match instruction.mnemonic() {
                Mnemonic::Mov => {
                    assert_eq!(instruction.op0_register(), Register::ECX);
                    ecx = Some(match instruction.op1_kind() {
                        OpKind::Register => {
                            assert_eq!(instruction.op1_register(), Register::EAX);
                            eax
                        }
                        OpKind::Immediate32 => instruction.immediate32(),
                        operand => panic!("unexpected fastfail status operand {operand:?}"),
                    });
                }
                Mnemonic::Jmp => {
                    ip = instruction.near_branch_target();
                    continue;
                }
                Mnemonic::Int => {
                    assert_eq!(instruction.immediate8(), 0x29);
                    return ecx.unwrap();
                }
                opcode => panic!("unexpected fastfail instruction {opcode:?}"),
            }
            ip = instruction.next_ip();
        }
        panic!("fastfail path does not terminate");
    }

    #[test]
    fn callback_failures_forward_eax_but_exe_startup_returns_fail_with_seven() {
        for dll in [false, true] {
            for mode in [EntryMode::Inline, EntryMode::InitTable] {
                let bytes = entry_loader(
                    BASE,
                    0x5000,
                    &[0x6000, 0x6100],
                    Rva::new(0x1000),
                    dll,
                    mode,
                    0x7000..if dll { 0x7010 } else { 0x7018 },
                )
                .unwrap();
                let instructions: Vec<_> =
                    Decoder::with_ip(64, &bytes, BASE + 0x5000, DecoderOptions::NONE)
                        .into_iter()
                        .collect();
                let mut status_branches = 0;
                for (index, branch) in instructions
                    .iter()
                    .enumerate()
                    .filter(|(_, instruction)| instruction.mnemonic() == Mnemonic::Jne)
                {
                    let test = &instructions[index - 1];
                    assert_eq!(test.mnemonic(), Mnemonic::Test);
                    assert_eq!(test.op0_register(), Register::EAX);
                    assert_eq!(test.op1_register(), Register::EAX);
                    for status in [1, 7, 0x1234_5678, 0x8000_0000, u32::MAX] {
                        assert_eq!(
                            execute_fastfail(&instructions, branch.near_branch_target(), status),
                            status
                        );
                    }
                    status_branches += 1;
                }
                assert_eq!(
                    status_branches,
                    if mode == EntryMode::Inline { 2 } else { 1 }
                );
                if mode == EntryMode::Inline {
                    let original = instructions
                        .iter()
                        .position(|instruction| {
                            instruction.mnemonic() == Mnemonic::Jmp
                                && instruction.near_branch_target() == BASE + 0x1000
                        })
                        .unwrap();
                    assert_eq!(instructions[original - 1].code(), Code::Add_rm64_imm8);
                    assert_eq!(instructions[original - 1].op0_register(), Register::RSP);
                    assert_eq!(instructions[original - 1].immediate8(), 0x48);
                    assert!(
                        !instructions
                            .iter()
                            .any(|instruction| instruction.mnemonic() == Mnemonic::Call
                                && instruction.near_branch_target() == BASE + 0x1000)
                    );
                }
                if !dll && mode == EntryMode::InitTable {
                    let bounds: Vec<_> = instructions
                        .iter()
                        .enumerate()
                        .filter(|(_, instruction)| instruction.mnemonic() == Mnemonic::Jae)
                        .collect();
                    assert_eq!(bounds.len(), 2);
                    for (_, bound) in &bounds {
                        assert_eq!(
                            execute_fastfail(
                                &instructions,
                                bound.near_branch_target(),
                                0x1234_5678
                            ),
                            7
                        );
                    }
                    let call = instructions
                        .iter()
                        .position(|instruction| instruction.mnemonic() == Mnemonic::Call)
                        .unwrap();
                    let status = instructions
                        .iter()
                        .position(|instruction| instruction.mnemonic() == Mnemonic::Test)
                        .unwrap();
                    assert!(call < bounds[1].0 && bounds[1].0 < status);
                }
            }
        }
    }

    #[test]
    fn exact_movabs_normalization_does_not_rewrite_equal_literals() {
        let pointer = BASE + 0x2000;
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&pointer.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&pointer.to_le_bytes());
        code.push(0xc3);
        let mut plugin = plugin(&code);
        plugin.module.references.push(ModuleReference {
            source: Rva::new(0x1002),
            target: ModuleTarget::Rva(Rva::new(0x2000)),
            addend: 0,
            kind: ModuleReferenceKind::Absolute64,
        });
        let host = PeFile::parse(&fixture(&[0xc3], false)).unwrap().to_module();
        let plugins = [plugin];
        let mut namespaces = namespaces(&host, &plugins).unwrap();
        prepare_view(&plugins[0], &mut namespaces[0], BASE).unwrap();
        let bytes = namespaces[0]
            .module
            .bytes_at(Rva::new(namespaces[0].start + 0x1000))
            .unwrap();
        let instructions: Vec<_> = Decoder::with_ip(
            64,
            bytes,
            BASE + u64::from(namespaces[0].start) + 0x1000,
            DecoderOptions::NONE,
        )
        .into_iter()
        .collect();
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Lea);
        assert_eq!(
            instructions[0].ip_rel_memory_address(),
            BASE + u64::from(namespaces[0].start) + 0x2000
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction.code() == Code::Mov_r64_imm64
                    && instruction.op0_register() == Register::RDX
                    && instruction.immediate64() == pointer)
        );
    }

    #[test]
    fn authored_image_base_code_references_track_addends_after_placement_and_aslr() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let old_namespace = crate::align_up(image_end(&host).unwrap(), 0x1_0000).unwrap();
        for addend in [
            0,
            -2,
            0x2345,
            0x2_1180,
            i64::from(old_namespace) + 0x1000,
            i64::from(old_namespace) + 0x2000,
        ] {
            for absolute in [false, true] {
                let (mut code, source, kind) = if absolute {
                    let mut code = vec![0x48, 0xb8];
                    code.extend_from_slice(&BASE.checked_add_signed(addend).unwrap().to_le_bytes());
                    (code, 0x1002, ModuleReferenceKind::Absolute64)
                } else {
                    let mut code = vec![0x48, 0x8d, 0x05];
                    let displacement = i32::try_from(addend - 0x1007).unwrap();
                    code.extend_from_slice(&displacement.to_le_bytes());
                    (code, 0x1003, ModuleReferenceKind::Relative32 { bias: 0 })
                };
                code.extend_from_slice(&[0x48, 0x89, 0x01]);
                let local_source = 0x1000 + code.len() as u32 + 3;
                code.extend_from_slice(&[0x48, 0x8d, 0x05]);
                let displacement = i32::try_from(0x2008i64 - i64::from(local_source + 4)).unwrap();
                code.extend_from_slice(&displacement.to_le_bytes());
                code.extend_from_slice(&[0x48, 0x89, 0x41, 8, 0x31, 0xc0, 0xc3]);
                let mut plugin = plugin(&code);
                plugin.module.references.extend([
                    ModuleReference {
                        source: Rva::new(source),
                        target: ModuleTarget::ImageBase,
                        addend,
                        kind,
                    },
                    ModuleReference {
                        source: Rva::new(local_source),
                        target: ModuleTarget::Rva(Rva::new(0x2010)),
                        addend: -8,
                        kind: ModuleReferenceKind::Relative32 { bias: 0 },
                    },
                ]);
                let plugins = [plugin];
                let planned = planned_functions(&host, &plugins).unwrap();
                let mut transformed = Vec::new();
                let (image, report) = protect_with_modules(
                    &pe,
                    &host,
                    &[],
                    &Options::default(),
                    &Win64Default,
                    &mut |rva, _, _| transformed.push(rva),
                    Injection {
                        plugins: &plugins,
                        mode: EntryMode::Inline,
                    },
                )
                .unwrap();
                assert!(!transformed.is_empty());
                assert!(transformed.iter().all(|&rva| rva == planned[0].rva));
                let output = PeFile::parse(&image).unwrap().to_module();
                let entry = report.address_map[&planned[0].rva];
                let data = output
                    .sections
                    .iter()
                    .find(|section| section.flags.write && section.rva.get() >= 0x4000)
                    .unwrap();
                for slide in [0, 0x1234_0000u64] {
                    let pointers: Vec<_> = Decoder::with_ip(
                        64,
                        output.bytes_at(entry).unwrap(),
                        BASE + slide + u64::from(entry.get()),
                        DecoderOptions::NONE,
                    )
                    .into_iter()
                    .take_while(|instruction| instruction.mnemonic() != Mnemonic::Ret)
                    .filter(|instruction| {
                        instruction.mnemonic() == Mnemonic::Lea
                            && instruction.is_ip_rel_memory_operand()
                    })
                    .map(|instruction| instruction.ip_rel_memory_address())
                    .collect();
                    assert!(pointers.contains(&(BASE + slide).checked_add_signed(addend).unwrap()));
                    assert!(pointers.contains(&(BASE + slide + u64::from(data.rva.get()) + 8)));
                }
            }
        }
    }

    #[test]
    fn signed_rel32_addends_preserve_trailing_immediates_and_data_interiors() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        for (target, addend) in [
            (ModuleTarget::ImageBase, -2),
            (ModuleTarget::Rva(Rva::new(0x2000)), 0x10),
            (ModuleTarget::Rva(Rva::new(0x2020)), -0x10),
        ] {
            let symbol = match target {
                ModuleTarget::ImageBase => 0,
                ModuleTarget::Rva(symbol) => i64::from(symbol.get()),
            };
            let displacement = i32::try_from(symbol + addend - 0x1009).unwrap();
            let mut code = vec![0x31, 0xc0, 0x66, 0x81, 0x3d];
            code.extend_from_slice(&displacement.to_le_bytes());
            code.extend_from_slice(&[0x4d, 0x5a, 0x0f, 0x95, 0xc0, 0xc3]);
            let mut plugin = plugin(&code);
            plugin.module.image[0x612..0x614].copy_from_slice(&0x5a4du16.to_le_bytes());
            plugin.module.references.push(ModuleReference {
                source: Rva::new(0x1005),
                target,
                addend,
                kind: ModuleReferenceKind::Relative32 { bias: 0 },
            });
            let plugins = [plugin];
            let planned = planned_functions(&host, &plugins).unwrap();
            let (image, report) = protect_with_modules(
                &pe,
                &host,
                &[],
                &Options::default(),
                &Win64Default,
                &mut |_, _, _| {},
                Injection {
                    plugins: &plugins,
                    mode: EntryMode::Inline,
                },
            )
            .unwrap();
            let output = PeFile::parse(&image).unwrap().to_module();
            let entry = report.address_map[&planned[0].rva];
            let expected = match target {
                ModuleTarget::ImageBase => 0,
                ModuleTarget::Rva(_) => {
                    output
                        .sections
                        .iter()
                        .find(|section| section.flags.write && section.rva.get() >= 0x4000)
                        .unwrap()
                        .rva
                        .get()
                        + 0x12
                }
            };
            for slide in [0, 0x1234_0000u64] {
                let actual = Decoder::with_ip(
                    64,
                    output.bytes_at(entry).unwrap(),
                    BASE + slide + u64::from(entry.get()),
                    DecoderOptions::NONE,
                )
                .into_iter()
                .take_while(|instruction| instruction.mnemonic() != Mnemonic::Ret)
                .filter(|instruction| instruction.is_ip_rel_memory_operand())
                .map(|instruction| instruction.ip_rel_memory_address())
                .find(|&address| address == BASE + slide + u64::from(expected))
                .unwrap();
                let rva = u32::try_from(actual - (BASE + slide)).unwrap();
                let bytes = if rva == 0 {
                    &image[..2]
                } else {
                    &output.bytes_at(Rva::new(rva)).unwrap()[..2]
                };
                assert_eq!(u16::from_le_bytes(bytes.try_into().unwrap()), 0x5a4d);
            }
        }
    }

    #[test]
    fn image_relative_data_expressions_reject_signed_rva_overflow_contextually() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        for addend in [-1, i64::from(u32::MAX) + 1] {
            let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
            plugin.module.references.push(ModuleReference {
                source: Rva::new(0x2000),
                target: ModuleTarget::ImageBase,
                addend,
                kind: ModuleReferenceKind::ImageRelative32,
            });
            let error = protect_with_modules(
                &pe,
                &host,
                &[],
                &Options::default(),
                &Win64Default,
                &mut |_, _, _| {},
                Injection {
                    plugins: &[plugin],
                    mode: EntryMode::Inline,
                },
            )
            .err()
            .unwrap();
            let message = format!("{error:#}");
            assert!(message.contains("plugin example reference"));
            assert!(message.contains("image-relative target exceeds RVA range"));
        }
    }

    #[test]
    fn injected_functions_use_callback_and_preserve_data_fixups() {
        let host_pe = PeFile::parse(&fixture(&[0x31, 0xc0, 0xc3], false)).unwrap();
        let host = host_pe.to_module();
        let old_namespace = crate::align_up(image_end(&host).unwrap(), 0x1_0000).unwrap();
        let image_base_offset = old_namespace + 0x1000;
        let image_relative_offset = 0x2345;
        let relative_offset = old_namespace + 0x2000;
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        plugin.module.image[0x620..0x628]
            .copy_from_slice(&(BASE + u64::from(image_base_offset)).to_le_bytes());
        put32(&mut plugin.module.image, 0x628, image_relative_offset);
        let displacement = i32::try_from(i64::from(relative_offset) - 0x2030).unwrap();
        plugin.module.image[0x62c..0x630].copy_from_slice(&displacement.to_le_bytes());
        plugin.module.image[0x630..0x638].copy_from_slice(&(BASE - 2).to_le_bytes());
        plugin.module.data.extend([
            DataSymbol {
                name: "SYMBOL_init_table_start".into(),
                start: Rva::new(0x2000),
                size: 8,
            },
            DataSymbol {
                name: "SYMBOL_init_table_end".into(),
                start: Rva::new(0x2008),
                size: 8,
            },
        ]);
        plugin.module.references.extend([
            ModuleReference {
                source: Rva::new(0x2010),
                target: ModuleTarget::Rva(Rva::new(0x1000)),
                addend: 0,
                kind: ModuleReferenceKind::Absolute64,
            },
            ModuleReference {
                source: Rva::new(0x2018),
                target: ModuleTarget::Rva(Rva::new(0x3008)),
                addend: -8,
                kind: ModuleReferenceKind::ImageRelative32,
            },
            ModuleReference {
                source: Rva::new(0x2020),
                target: ModuleTarget::ImageBase,
                addend: i64::from(image_base_offset),
                kind: ModuleReferenceKind::Absolute64,
            },
            ModuleReference {
                source: Rva::new(0x2028),
                target: ModuleTarget::ImageBase,
                addend: i64::from(image_relative_offset),
                kind: ModuleReferenceKind::ImageRelative32,
            },
            ModuleReference {
                source: Rva::new(0x202c),
                target: ModuleTarget::ImageBase,
                addend: i64::from(relative_offset),
                kind: ModuleReferenceKind::Relative32 { bias: 0 },
            },
            ModuleReference {
                source: Rva::new(0x2030),
                target: ModuleTarget::ImageBase,
                addend: -2,
                kind: ModuleReferenceKind::Absolute64,
            },
        ]);
        let plugins = [plugin];
        let planned = planned_functions(&host, &plugins).unwrap();
        let (image, report) = protect_with_modules(
            &host_pe,
            &host,
            &[],
            &Options::default(),
            &Win64Default,
            &mut |_, _, _| {},
            Injection {
                plugins: &plugins,
                mode: EntryMode::InitTable,
            },
        )
        .unwrap();
        let pe = PeFile::parse(&image).unwrap();
        let output = pe.to_module();
        let writable: Vec<_> = output
            .sections
            .iter()
            .filter(|section| section.flags.write && section.rva.get() >= 0x4000)
            .collect();
        assert_eq!(writable.len(), 1);
        let data = writable[0];
        assert!(!data.flags.execute);
        assert!(data.data[0x38..].iter().all(|byte| *byte == 0));
        let read_only = Rva::new(u32::from_le_bytes(
            data.data[0x18..0x1c].try_into().unwrap(),
        ));
        let read_only = output.section_at(read_only).unwrap();
        assert!(read_only.flags.read && !read_only.flags.write && !read_only.flags.execute);
        let read64 = |offset| u64::from_le_bytes(data.data[offset..offset + 8].try_into().unwrap());
        let table_start = read64(0);
        let table_end = read64(8);
        assert_eq!(table_end - table_start, 16);
        assert_eq!(
            read64(16),
            BASE + u64::from(report.address_map[&planned[0].rva].get())
        );
        assert_eq!(read64(32), BASE + u64::from(image_base_offset));
        for slide in [0, 0x1234_0000u64] {
            let mut rebased = data.data.clone();
            for relocation in output.relocations.iter().filter(|relocation| {
                relocation.kind == RelocKind::Dir64
                    && relocation.rva >= data.rva
                    && relocation.rva.get() < data.rva.get() + data.data.len() as u32
            }) {
                let offset = (relocation.rva.get() - data.rva.get()) as usize;
                let pointer = u64::from_le_bytes(rebased[offset..offset + 8].try_into().unwrap());
                rebased[offset..offset + 8].copy_from_slice(&(pointer + slide).to_le_bytes());
            }
            let read64 =
                |offset| u64::from_le_bytes(rebased[offset..offset + 8].try_into().unwrap());
            assert_eq!(read64(0), table_start + slide);
            assert_eq!(read64(8), table_end + slide);
            assert_eq!(
                read64(16),
                BASE + slide + u64::from(report.address_map[&planned[0].rva].get())
            );
            assert_eq!(read64(32), BASE + slide + u64::from(image_base_offset));
            assert_eq!(read64(48), BASE + slide - 2);
            assert_eq!(
                u32::from_le_bytes(rebased[0x18..0x1c].try_into().unwrap()),
                read_only.rva.get()
            );
            assert_eq!(
                u32::from_le_bytes(rebased[0x28..0x2c].try_into().unwrap()),
                image_relative_offset
            );
            let displacement = i32::from_le_bytes(rebased[0x2c..0x30].try_into().unwrap());
            assert_eq!(
                (BASE + slide + u64::from(data.rva.get()) + 0x30)
                    .checked_add_signed(i64::from(displacement)),
                Some(BASE + slide + u64::from(relative_offset))
            );
        }
        let table = output
            .bytes_at(Rva::new((table_start - BASE) as u32))
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(table[..8].try_into().unwrap()),
            read64(16)
        );
        let last = u64::from_le_bytes(table[8..16].try_into().unwrap());
        let startup = output.bytes_at(Rva::new((last - BASE) as u32)).unwrap();
        let startup: Vec<_> = Decoder::with_ip(64, startup, last, DecoderOptions::NONE)
            .into_iter()
            .take(2)
            .collect();
        assert_eq!(startup[0].code(), Code::Endbr64);
        assert_eq!(startup[1].near_branch_target(), BASE + 0x1000);
        for offset in [0, 8, 16, 32, 48] {
            assert!(
                output
                    .relocations
                    .iter()
                    .any(|relocation| relocation.rva.get() == data.rva.get() + offset
                        && relocation.kind == RelocKind::Dir64)
            );
        }
        assert!(
            pe.runtime_functions()
                .iter()
                .any(|function| function.begin == report.address_map[&planned[0].rva])
        );
        assert!(
            pe.runtime_functions()
                .iter()
                .any(|function| Some(function.begin) == output.entry_point)
        );
    }

    #[test]
    fn dll_init_table_excludes_original_and_tails_to_its_bool_return() {
        let mut host_image = fixture(&[0xb8, 1, 0, 0, 0, 0xc3], true);
        put32(&mut host_image, 0xa8, 0x1000);
        let pe = PeFile::parse(&host_image).unwrap();
        let host = pe.to_module();
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        plugin.module.data.extend([
            DataSymbol {
                name: "SYMBOL_init_table_start".into(),
                start: Rva::new(0x2000),
                size: 8,
            },
            DataSymbol {
                name: "SYMBOL_init_table_end".into(),
                start: Rva::new(0x2008),
                size: 8,
            },
        ]);
        let (image, _) = protect_with_modules(
            &pe,
            &host,
            &[],
            &Options::default(),
            &Win64Default,
            &mut |_, _, _| {},
            Injection {
                plugins: &[plugin],
                mode: EntryMode::InitTable,
            },
        )
        .unwrap();
        let output = PeFile::parse(&image).unwrap().to_module();
        let data = output
            .sections
            .iter()
            .find(|section| section.flags.write && section.rva.get() >= 0x4000)
            .unwrap();
        let start = u64::from_le_bytes(data.data[..8].try_into().unwrap());
        let end = u64::from_le_bytes(data.data[8..16].try_into().unwrap());
        assert_eq!(end - start, 8);
        let entry = output.entry_point.unwrap();
        let instructions: Vec<_> = Decoder::with_ip(
            64,
            output.bytes_at(entry).unwrap(),
            BASE + u64::from(entry.get()),
            DecoderOptions::NONE,
        )
        .into_iter()
        .collect();
        let tail = instructions
            .iter()
            .position(|instruction| {
                instruction.mnemonic() == Mnemonic::Jmp
                    && instruction.near_branch_target() == BASE + 0x1000
            })
            .unwrap();
        assert_eq!(instructions[tail - 1].code(), Code::Add_rm64_imm8);
    }

    #[test]
    fn kernel_injection_fails_before_running_transforms() {
        let mut image = fixture(&[0xc3], false);
        put16(&mut image, 0xdc, 1);
        let pe = PeFile::parse(&image).unwrap();
        let host = pe.to_module();
        let error = protect_with_modules(
            &pe,
            &host,
            &[],
            &Options::default(),
            &Win64Default,
            &mut |_, _, _| panic!("kernel callback must not run"),
            Injection {
                plugins: &[plugin(&[0x31, 0xc0, 0xc3])],
                mode: EntryMode::Inline,
            },
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("kernel"));
    }

    #[test]
    fn zero_fill_module_storage_keeps_writable_nonexecutable_permissions() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        put32(&mut plugin.module.image, 0x188 + 40 + 16, 0);
        put32(&mut plugin.module.image, 0x188 + 40 + 20, 0);
        let (image, _) = protect_with_modules(
            &pe,
            &host,
            &[],
            &Options::default(),
            &Win64Default,
            &mut |_, _, _| {},
            Injection {
                plugins: &[plugin],
                mode: EntryMode::Inline,
            },
        )
        .unwrap();
        let output = PeFile::parse(&image).unwrap().to_module();
        let data = output
            .sections
            .iter()
            .find(|section| section.flags.write && section.rva.get() >= 0x4000)
            .unwrap();
        assert_eq!(data.virtual_size, 128);
        assert!(data.flags.read && !data.flags.execute);
        assert_eq!(data.data, vec![0; 128]);
    }

    #[test]
    fn planned_namespaces_exclude_host_plugins_and_all_host_base_targets() {
        let host = PeFile::parse(&fixture(&[0xc3], false)).unwrap().to_module();
        let first = plugin(&[0x31, 0xc0, 0xc3]);
        let extent = image_end(&PeFile::parse(&first.module.image).unwrap().to_module()).unwrap();
        let old_namespace = crate::align_up(image_end(&host).unwrap(), 0x1_0000).unwrap();
        let targets = [
            old_namespace,
            old_namespace + 0x1000,
            old_namespace + 0x2000,
            old_namespace + extent,
            old_namespace + 0x1_0000 + 0x1000,
            u32::MAX,
        ];
        let mut second = plugin(&[0x31, 0xc0, 0xc3]);
        second.name = "second".into();
        second
            .module
            .references
            .extend(
                targets
                    .iter()
                    .enumerate()
                    .map(|(index, &offset)| ModuleReference {
                        source: Rva::new(0x2000 + index as u32 * 8),
                        target: ModuleTarget::ImageBase,
                        addend: i64::from(offset),
                        kind: ModuleReferenceKind::Absolute64,
                    }),
            );
        let plugins = [first, second];
        let namespaces = namespaces(&host, &plugins).unwrap();
        let planned = planned_functions(&host, &plugins).unwrap();
        assert_eq!(planned[0].name, "init");
        for (index, namespace) in namespaces.iter().enumerate() {
            let end = namespace.start + image_end(&namespace.module).unwrap();
            assert!(namespace.start >= image_end(&host).unwrap());
            assert!(
                targets
                    .iter()
                    .all(|&target| target < namespace.start || target > end)
            );
            assert_eq!(
                planned[index].rva.get(),
                namespace.start + plugins[index].module.code[0].start.get()
            );
        }
        assert!(planned[1].rva.get() > planned[0].rva.get() + extent);
    }

    #[test]
    fn namespace_reservations_include_effective_rip_trailing_bytes() {
        let host = PeFile::parse(&fixture(&[0xc3], false)).unwrap().to_module();
        let old_namespace = crate::align_up(image_end(&host).unwrap(), 0x1_0000).unwrap();
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        plugin.module.references.push(ModuleReference {
            source: Rva::new(0x2000),
            target: ModuleTarget::ImageBase,
            addend: i64::from(old_namespace) - 2,
            kind: ModuleReferenceKind::Relative32 { bias: 0 },
        });
        let plugins = [plugin];
        let namespaces = namespaces(&host, &plugins).unwrap();
        let planned = planned_functions(&host, &plugins).unwrap();
        assert!(namespaces[0].start > old_namespace + 13);
        assert_eq!(planned[0].rva.get(), namespaces[0].start + 0x1000);
    }

    #[test]
    fn host_base_target_namespace_overflow_identifies_plugin_and_target() {
        let mut host = PeFile::parse(&fixture(&[0xc3], false)).unwrap().to_module();
        let section = host.sections.last_mut().unwrap();
        section.rva = Rva::new(0xfffe_0000);
        section.virtual_size = 0x1_0000;
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        plugin.module.references.push(ModuleReference {
            source: Rva::new(0x2000),
            target: ModuleTarget::ImageBase,
            addend: 0xffff_1000,
            kind: ModuleReferenceKind::Absolute64,
        });
        let error = planned_functions(&host, &[plugin]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("plugin example synthetic namespace"));
        assert!(message.contains("0xffff1000"));
        assert!(message.contains("RVA overflow"));
    }

    #[test]
    fn inline_pic_dll_keeps_empty_relocations_consistent() {
        let mut bytes = fixture(&[0xb8, 1, 0, 0, 0, 0xc3], true);
        put32(&mut bytes, 0xa8, 0x1000);
        let pe = PeFile::parse(&bytes).unwrap();
        let host = pe.to_module();
        let (image, _) = protect_with_modules(
            &pe,
            &host,
            &[],
            &Options::default(),
            &Win64Default,
            &mut |_, _, _| {},
            Injection {
                plugins: &[plugin(&[0x31, 0xc0, 0xc3])],
                mode: EntryMode::Inline,
            },
        )
        .unwrap();
        let rebuilt = PeFile::parse(&image).unwrap();
        assert_eq!(rebuilt.data_directory(5), Some((Rva::ZERO, 0)));
        assert!(rebuilt.to_module().relocations.is_empty());
        assert!(
            rebuilt
                .section_headers()
                .iter()
                .all(|section| section.virtual_size != 0)
        );
    }
}
