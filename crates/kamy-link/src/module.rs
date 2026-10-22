use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Context, bail, ensure};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, MemoryOperand, OpKind, Register};
use kamy_codegen::SelectedInstructions;
use kamy_core::ir::{CallingConvLookup, FnSignature, IrFunction};
use kamy_core::{
    LinkField, Module, OperandReference, Reference, RelocKind, Relocation, Rva, SymbolId,
    SymbolicExpression,
};
use kamy_pe::module::AuthoredModule;
use kamy_pe::{NewSection, PeFile};

use crate::{
    FunctionReport, LoweringError, Options, Ownership, Placement, Report, TransformOutcome,
};

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
    pub symbol: SymbolId,
}

pub fn planned_functions(plugins: &[Plugin]) -> anyhow::Result<Vec<PlannedFunction>> {
    let mut names = HashSet::new();
    let mut result = Vec::new();
    for plugin in plugins {
        ensure!(
            !plugin.name.is_empty() && !plugin.name.contains("::") && names.insert(&plugin.name),
            "plugin names must be nonempty, unique and unqualified: {}",
            plugin.name
        );
        ensure!(
            plugin.module.identity == plugin.name,
            "plugin {} artifact identity does not match its instance",
            plugin.name
        );
        for symbol in &plugin.module.code {
            ensure!(
                matches!(&symbol.symbol, SymbolId::Authored { module, .. } if module.as_ref() == plugin.name),
                "plugin {} contains a symbol from another instance",
                plugin.name
            );
            result.push(PlannedFunction {
                plugin: plugin.name.clone(),
                name: symbol.name.clone(),
                symbol: symbol.symbol.clone(),
            });
        }
    }
    Ok(result)
}

struct Input<'a> {
    source: AuthoredSource<'a>,
    references: Vec<Reference>,
}

struct Compiled {
    plugin: usize,
    symbol: SymbolId,
    source: Rva,
    selected: SelectedInstructions,
    indirect: Vec<(usize, Register)>,
    slot: u32,
    rva: u32,
    body: Vec<u8>,
    report: FunctionReport,
}

struct PlacedData {
    plugin: usize,
    source: Rva,
    section: NewSection,
}

pub struct AuthoredSource<'a> {
    plugin: &'a Plugin,
    module: Module,
    source_positions: BTreeMap<SymbolId, Rva>,
    retired: BTreeSet<usize>,
    boundaries: BTreeSet<u32>,
    signatures: BTreeMap<SymbolId, &'a FnSignature>,
}

pub struct AuthoredFunction<'a> {
    pub symbol: &'a kamy_pe::module::CodeSymbol,
    pub function: kamy_core::Function,
    pub references: Vec<OperandReference>,
}

impl<'a> AuthoredSource<'a> {
    pub fn new(plugin: &'a Plugin) -> anyhow::Result<Self> {
        let pe = PeFile::parse(&plugin.module.image)
            .with_context(|| format!("parsing plugin {}", plugin.name))?;
        ensure!(
            pe.is_dll() && pe.subsystem() != 1,
            "plugin {} is not a user-mode specialized DLL",
            plugin.name
        );
        let mut module = pe.to_module();
        module.symbols = plugin.module.symbols.clone();
        let source_positions: BTreeMap<_, _> = module
            .symbols
            .iter()
            .map(|symbol| (symbol.id.clone(), symbol.rva))
            .collect();
        ensure!(
            source_positions.len() == module.symbols.len(),
            "plugin {} has duplicate compiler symbol identities",
            plugin.name
        );
        ensure!(
            !plugin.module.code.is_empty(),
            "plugin {} has no authored functions",
            plugin.name
        );
        let mut previous_end = 0;
        let mut previous_start = None;
        let mut code: Vec<_> = plugin.module.code.iter().collect();
        code.sort_by_key(|symbol| symbol.start);
        for symbol in code {
            ensure!(
                previous_start != Some(symbol.start),
                "plugin {} has ambiguous authored code symbols at local RVA {}",
                plugin.name,
                symbol.start
            );
            ensure!(
                symbol.start.get() >= previous_end && symbol.end > symbol.start,
                "plugin {} has overlapping/empty authored function {}",
                plugin.name,
                symbol.name
            );
            let section = module
                .section_at(symbol.start)
                .context("authored function outside module")?;
            ensure!(
                section.flags.execute
                    && symbol.end.get() <= add(section.rva.get(), section.virtual_size)?,
                "plugin {} function {} crosses executable storage",
                plugin.name,
                symbol.name
            );
            ensure!(
                source_positions.get(&symbol.symbol) == Some(&symbol.start),
                "plugin {} function {} has no compiler symbol binding",
                plugin.name,
                symbol.name
            );
            previous_end = symbol.end.get();
            previous_start = Some(symbol.start);
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
        let retired = retired_sections(&pe, &module)
            .with_context(|| format!("plugin {} directories", plugin.name))?;
        Ok(Self {
            plugin,
            module,
            source_positions,
            retired,
            boundaries: plugin
                .module
                .code
                .iter()
                .flat_map(|symbol| [symbol.start.get(), symbol.end.get()])
                .collect(),
            signatures: plugin
                .module
                .code
                .iter()
                .map(|symbol| (symbol.symbol.clone(), &symbol.signature))
                .collect(),
        })
    }

    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Select an exact compiler entry in source-local coordinates. Without a
    /// host, host-image-base expressions remain unbound symbolic references.
    pub fn function_at(
        &self,
        rva: Rva,
        host: Option<&Module>,
    ) -> anyhow::Result<AuthoredFunction<'_>> {
        let mut matches = self
            .plugin
            .module
            .code
            .iter()
            .filter(|symbol| symbol.start == rva);
        let symbol = matches.next().with_context(|| {
            format!(
                "plugin {} has no authored code symbol at local RVA {rva}",
                self.plugin.name
            )
        })?;
        ensure!(
            matches.next().is_none(),
            "plugin {} has ambiguous authored code symbols at local RVA {rva}",
            self.plugin.name
        );
        let function = kamy_disasm::recover_function(
            &self.module,
            symbol.start,
            &self.boundaries,
            &BTreeSet::new(),
        );
        ensure!(
            !function.blocks.is_empty()
                && function
                    .blocks
                    .iter()
                    .all(|block| block.start >= symbol.start && block.end <= symbol.end),
            "plugin {}::{} has control flow outside its authored range",
            self.plugin.name,
            symbol.name
        );
        let references = operand_references(self.plugin, self, symbol, host)
            .with_context(|| format!("plugin {}::{} operands", self.plugin.name, symbol.name))?;
        Ok(AuthoredFunction {
            symbol,
            function,
            references,
        })
    }
}

impl CallingConvLookup for AuthoredSource<'_> {
    fn lookup(&self, _: u64) -> Option<FnSignature> {
        None
    }
    fn lookup_symbol(&self, symbol: &SymbolId) -> Option<FnSignature> {
        if let Some(signature) = self.signatures.get(symbol) {
            return Some((*signature).clone());
        }
        let expression =
            canonical_expression(SymbolicExpression::symbol(symbol.clone()), self.plugin).ok()?;
        let SymbolicExpression::Symbol { symbol, addend: 0 } = expression else {
            return None;
        };
        self.signatures
            .get(&symbol)
            .map(|signature| (*signature).clone())
    }
}

pub(crate) struct Plan<'a> {
    plugins: &'a [Plugin],
    inputs: Vec<Input<'a>>,
    compiled: Vec<Compiled>,
    data: Vec<PlacedData>,
    bindings: BTreeMap<SymbolId, u64>,
    placements: Vec<Placement>,
    base: u64,
    alignment: u32,
    mode: EntryMode,
    dll: bool,
    original_entry: Option<Rva>,
    has_table: bool,
    code_name: String,
    metadata_name: String,
    loader_rva: u32,
    loader: Vec<u8>,
    startup_rva: u32,
    startup: Vec<u8>,
    table_rva: u32,
    table_end: u32,
    table: Vec<u8>,
    relocations: Vec<Relocation>,
    pinned_host: BTreeSet<Rva>,
}

impl<'a> Plan<'a> {
    pub(crate) fn prepare(
        pe: &PeFile,
        host: &Module,
        opts: &Options,
        transform: &mut dyn FnMut(
            &SymbolId,
            &mut IrFunction,
            f32,
        ) -> anyhow::Result<TransformOutcome>,
        injection: Injection<'a>,
    ) -> anyhow::Result<Self> {
        let Injection { plugins, mode } = injection;
        planned_functions(plugins)?;
        if !plugins.is_empty() {
            ensure!(
                pe.subsystem() != 1,
                "SDK module injection is prohibited for kernel images"
            );
            ensure!(
                host.entry_point.is_some(),
                "SDK module injection requires an original entry point"
            );
        }
        let has_table = !plugins.is_empty()
            && (mode == EntryMode::InitTable
                || plugins.iter().any(|plugin| {
                    plugin
                        .module
                        .data
                        .iter()
                        .any(|symbol| is_bound(&symbol.name))
                }));
        let mut plan = Self {
            plugins,
            inputs: Vec::new(),
            compiled: Vec::new(),
            data: Vec::new(),
            bindings: BTreeMap::new(),
            placements: Vec::new(),
            base: host.image_base,
            alignment: pe.section_alignment(),
            mode,
            dll: pe.is_dll(),
            original_entry: host.entry_point,
            has_table,
            code_name: opts.code_section.clone(),
            metadata_name: opts.metadata_section.clone(),
            loader_rva: 0,
            loader: Vec::new(),
            startup_rva: 0,
            startup: Vec::new(),
            table_rva: 0,
            table_end: 0,
            table: Vec::new(),
            relocations: Vec::new(),
            pinned_host: BTreeSet::new(),
        };
        for (index, plugin) in plugins.iter().enumerate() {
            let source = AuthoredSource::new(plugin)?;
            let module = &source.module;
            let retired = &source.retired;
            let source_positions = &source.source_positions;
            let mut references = Vec::new();
            for reference in &plugin.module.references {
                let source = reference_source(source_positions, reference)?;
                let section = module
                    .sections
                    .iter()
                    .position(|section| section.contains(source))
                    .context("authored reference source outside storage")?;
                if retired.contains(&section) || module.sections[section].flags.execute {
                    continue;
                }
                let mut reference = reference.clone();
                reference.expression = canonical_expression(reference.expression, plugin)?;
                validate_code_expression(&reference.expression, plugin)?;
                reference.expression = identify_host_object(reference.expression, host)?;
                pin_interior_host(&reference.expression, host, &mut plan.pinned_host);
                references.push(reference);
            }
            for symbol in &plugin.module.data {
                let section = module
                    .section_at(symbol.start)
                    .context("authored data outside module")?;
                ensure!(
                    !section.flags.execute
                        && add(symbol.start.get(), symbol.size)?
                            <= add(section.rva.get(), section.virtual_size)?,
                    "plugin {} data {} crosses its storage",
                    plugin.name,
                    symbol.name
                );
                ensure!(
                    module
                        .symbols
                        .iter()
                        .any(|binding| binding.id == symbol.symbol && binding.rva == symbol.start),
                    "plugin {} data {} has no compiler symbol binding",
                    plugin.name,
                    symbol.name
                );
                if is_bound(&symbol.name) {
                    ensure!(
                        symbol.size == 8
                            && add(symbol.start.get() - section.rva.get(), symbol.size)?
                                <= u32::try_from(section.data.len())?,
                        "plugin {} SDK bound {} requires initialized pointer-sized storage; rebuild with the current kamy-sdk",
                        plugin.name,
                        symbol.name
                    );
                }
            }
            let mut fields = Vec::with_capacity(plugin.module.references.len());
            for reference in &plugin.module.references {
                let source = reference_source(source_positions, reference)?;
                let section_index = module
                    .sections
                    .iter()
                    .position(|section| section.contains(source))
                    .context("reference outside storage")?;
                if retired.contains(&section_index) {
                    continue;
                }
                let section = &module.sections[section_index];
                let end = add(source.get(), reference.field.width())?;
                ensure!(
                    end <= add(section.rva.get(), section.virtual_size)?,
                    "plugin {} reference crosses storage",
                    plugin.name
                );
                if section.flags.execute {
                    ensure!(
                        plugin
                            .module
                            .code
                            .iter()
                            .any(|symbol| symbol.start <= source && end <= symbol.end.get()),
                        "plugin {} reference has no authored function owner",
                        plugin.name
                    );
                }
                fields.push((source.get(), end));
            }
            fields.sort_unstable();
            ensure!(
                fields.windows(2).all(|pair| pair[0].1 <= pair[1].0),
                "plugin {} has overlapping authored reference fields",
                plugin.name
            );
            for (section_index, section) in module.sections.iter().enumerate() {
                if section.virtual_size == 0
                    || section.flags.execute
                    || retired.contains(&section_index)
                {
                    continue;
                }
                let initialized = section.data.len().min(section.virtual_size as usize);
                plan.data.push(PlacedData {
                    plugin: index,
                    source: section.rva,
                    section: NewSection {
                        name: opts.metadata_section.clone(),
                        rva: Rva::ZERO,
                        virtual_size: section.virtual_size,
                        flags: section.flags,
                        data: section.data[..initialized].to_vec(),
                    },
                });
            }
            plan.inputs.push(Input { source, references });
        }
        for (index, plugin) in plugins.iter().enumerate() {
            let input = &plan.inputs[index];
            for symbol in &plugin.module.code {
                let prepared = input.source.function_at(symbol.start, Some(host))?;
                let selected = opts
                    .selected_symbols
                    .as_ref()
                    .is_none_or(|symbols| symbols.contains(&symbol.symbol));
                let mut identity =
                    |_: &SymbolId, _: &mut IrFunction, _: f32| Ok(TransformOutcome::default());
                let callback = if selected {
                    &mut *transform
                } else {
                    &mut identity
                };
                let mut lowered = match crate::ssa_instructions(
                    &input.source.module,
                    host,
                    &prepared.function,
                    &symbol.symbol,
                    &prepared.references,
                    &input.source,
                    callback,
                ) {
                    Ok(lowered) => lowered,
                    Err(LoweringError::Rejected(reason)) => bail!(
                        "plugin {}::{} cannot pass SSA/codegen: {reason:?}",
                        plugin.name,
                        symbol.name
                    ),
                    Err(LoweringError::Callback(error)) => return Err(error),
                };
                plan.pinned_host.extend(lowered.pinned_host.iter().copied());
                ensure!(
                    !lowered.selected.instructions.is_empty(),
                    "plugin {}::{} generated no code",
                    plugin.name,
                    symbol.name
                );
                lowered
                    .selected
                    .instructions
                    .insert(0, Instruction::with(Code::Endbr64));
                for reference in &mut lowered.selected.references {
                    reference.instruction += 1;
                }
                let indirect = crate::translation::instrument(&mut lowered.selected.instructions)
                    .with_context(|| {
                    format!(
                        "plugin {}::{} indirect references",
                        plugin.name, symbol.name
                    )
                })?;
                plan.compiled.push(Compiled {
                    plugin: index,
                    symbol: symbol.symbol.clone(),
                    source: symbol.start,
                    selected: lowered.selected,
                    indirect,
                    slot: 1,
                    rva: 0,
                    body: Vec::new(),
                    report: FunctionReport {
                        symbol: symbol.symbol.clone(),
                        selected,
                        eligible: true,
                        lowered: true,
                        transformed: lowered.transformed,
                        intensity: lowered.intensity,
                        allocation: Some(lowered.allocation),
                    },
                });
            }
        }
        Ok(plan)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
    pub(crate) fn pins(&self, rva: Rva) -> bool {
        self.pinned_host.contains(&rva)
    }
    pub(crate) fn helper_registers(&self) -> impl Iterator<Item = Register> + '_ {
        self.compiled
            .iter()
            .flat_map(|function| function.indirect.iter().map(|&(_, register)| register))
    }

    pub(crate) fn place(
        &mut self,
        start: u32,
        host: &BTreeMap<Rva, Rva>,
        helpers: &BTreeMap<u32, (Register, u32)>,
    ) -> anyhow::Result<u32> {
        if self.is_empty() {
            return Ok(start);
        }
        let original = self.original_entry.context("missing original entry")?;
        let original = host.get(&original).copied().unwrap_or(original);
        let mut cursor = crate::align_up(start, self.alignment)?;
        for placed in &mut self.data {
            cursor = crate::align_up(cursor, self.alignment)?;
            placed.section.rva = Rva::new(cursor);
            cursor = add(cursor, placed.section.virtual_size)?;
        }
        let code_start = crate::align_up(cursor, self.alignment)?;
        for iteration in 0..4096 {
            self.bindings.clear();
            for placed in &self.data {
                for symbol in &self.plugins[placed.plugin].module.symbols {
                    if self.plugins[placed.plugin]
                        .module
                        .bindings
                        .contains_key(&symbol.id)
                    {
                        continue;
                    }
                    if placed.source <= symbol.rva
                        && symbol.rva.get() < add(placed.source.get(), placed.section.virtual_size)?
                    {
                        self.bindings.insert(
                            symbol.id.clone(),
                            va(
                                self.base,
                                add(
                                    placed.section.rva.get(),
                                    symbol.rva.get() - placed.source.get(),
                                )?,
                            )?,
                        );
                    }
                }
            }
            cursor = code_start;
            for function in &mut self.compiled {
                cursor = crate::align_up(cursor, crate::FUNCTION_ALIGN)?;
                function.rva = cursor;
                self.bindings
                    .insert(function.symbol.clone(), va(self.base, cursor)?);
                cursor = add(cursor, function.slot)?;
            }
            for plugin in self.plugins {
                for symbol in plugin.module.bindings.keys() {
                    let expression =
                        canonical_expression(SymbolicExpression::symbol(symbol.clone()), plugin)?;
                    // Interior code labels and retired metadata have no post-SSA storage map.
                    if validate_code_expression(&expression, plugin).is_err() {
                        continue;
                    }
                    let Some(value) = expression.evaluate(|root| {
                        self.bindings
                            .get(root)
                            .copied()
                            .or_else(|| crate::resolve_host(root, host, self.base))
                    }) else {
                        continue;
                    };
                    self.bindings.insert(
                        symbol.clone(),
                        u64::try_from(value).context("authored alias exceeds address space")?,
                    );
                }
            }
            self.loader_rva = crate::align_up(cursor, crate::FUNCTION_ALIGN)?;
            let entries = self
                .plugins
                .iter()
                .enumerate()
                .map(|(index, plugin)| {
                    self.compiled
                        .iter()
                        .find(|function| {
                            function.plugin == index && function.source == plugin.module.entry
                        })
                        .map(|function| function.rva)
                        .context("module entry has no final placement")
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let probe = entry_loader(
                self.base,
                self.loader_rva,
                &entries,
                original,
                self.dll,
                self.mode,
                0..0,
            )?;
            let loader_end = add(self.loader_rva, u32::try_from(probe.len())?)?;
            self.startup_rva = crate::align_up(loader_end, crate::FUNCTION_ALIGN)?;
            self.startup = if self.has_table && !self.dll {
                startup_thunk(self.base, self.startup_rva, original)?
            } else {
                Vec::new()
            };
            let code_end = if self.startup.is_empty() {
                loader_end
            } else {
                add(self.startup_rva, u32::try_from(self.startup.len())?)?
            };
            self.table_rva = crate::align_up(code_end, self.alignment)?;
            let count = if self.has_table {
                self.plugins
                    .len()
                    .checked_add(usize::from(!self.dll))
                    .context("table count overflow")?
            } else {
                0
            };
            self.table_end = add(
                self.table_rva,
                u32::try_from(count.checked_mul(8).context("table size overflow")?)?,
            )?;
            self.loader = entry_loader(
                self.base,
                self.loader_rva,
                &entries,
                original,
                self.dll,
                self.mode,
                self.table_rva..self.table_end,
            )?;
            ensure!(
                self.loader.len() == probe.len(),
                "entry loader size depends on table placement"
            );
            let mut grew = false;
            for function in &mut self.compiled {
                kamy_codegen::bind_references(&mut function.selected, self.base, |symbol| {
                    self.bindings
                        .get(symbol)
                        .copied()
                        .or_else(|| crate::resolve_host(symbol, host, self.base))
                })
                .with_context(|| {
                    format!(
                        "binding plugin {} symbol {:?}",
                        self.plugins[function.plugin].name, function.symbol
                    )
                })?;
                for &(index, register) in &function.indirect {
                    let rva = helpers
                        .get(&(register as u32))
                        .context("missing authored indirect translator")?
                        .1;
                    function.selected.instructions[index].set_near_branch64(va(self.base, rva)?);
                }
                function.body = kamy_codegen::relocate(
                    &function.selected.instructions,
                    va(self.base, function.rva)?,
                )
                .with_context(|| {
                    format!(
                        "encoding plugin {} symbol {:?}",
                        self.plugins[function.plugin].name, function.symbol
                    )
                })?;
                let size = u32::try_from(function.body.len())?;
                if size > function.slot {
                    function.slot = size;
                    grew = true;
                }
            }
            if grew {
                ensure!(
                    iteration < 4095,
                    "module layout failed to converge after 4096 monotone iterations"
                );
                continue;
            }
            self.table.clear();
            self.relocations.clear();
            if self.has_table {
                for entry in entries
                    .into_iter()
                    .chain((!self.dll).then_some(self.startup_rva))
                {
                    self.relocations.push(Relocation {
                        rva: Rva::new(add(self.table_rva, u32::try_from(self.table.len())?)?),
                        kind: RelocKind::Dir64,
                    });
                    self.table
                        .extend_from_slice(&va(self.base, entry)?.to_le_bytes());
                }
            }
            self.rebase_data(host)?;
            self.record_placements()?;
            return Ok(if self.has_table {
                self.table_end
            } else {
                code_end
            });
        }
        unreachable!()
    }

    fn rebase_data(&mut self, host: &BTreeMap<Rva, Rva>) -> anyhow::Result<()> {
        for placed in &mut self.data {
            let plugin = &self.plugins[placed.plugin];
            let source_end = add(placed.source.get(), placed.section.virtual_size)?;
            for reference in &self.inputs[placed.plugin].references {
                let source = reference_source(
                    &self.inputs[placed.plugin].source.source_positions,
                    reference,
                )?;
                if source < placed.source || source.get() >= source_end {
                    continue;
                }
                if plugin
                    .module
                    .data
                    .iter()
                    .any(|symbol| is_bound(&symbol.name) && symbol.start == source)
                {
                    continue;
                }
                let offset = usize::try_from(source.get() - placed.source.get())?;
                let end = offset
                    .checked_add(reference.field.width() as usize)
                    .context("reference size overflow")?;
                ensure!(
                    end <= placed.section.virtual_size as usize,
                    "plugin {} reference crosses data storage",
                    plugin.name
                );
                ensure!(
                    end <= placed.section.data.len(),
                    "plugin {} reference {:?} requires initialized data storage; rebuild the module producer",
                    plugin.name,
                    reference.source
                );
                let value = reference
                    .expression
                    .evaluate(|symbol| {
                        self.bindings
                            .get(symbol)
                            .copied()
                            .or_else(|| crate::resolve_host(symbol, host, self.base))
                    })
                    .with_context(|| {
                        format!(
                            "plugin {} reference {:?} has no final target",
                            plugin.name, reference.source
                        )
                    })?;
                reference
                    .field
                    .encode_into(
                        value,
                        va(self.base, add(placed.section.rva.get(), offset as u32)?)?,
                        self.base,
                        &mut placed.section.data[offset..end],
                    )
                    .with_context(|| {
                        format!(
                            "plugin {} reference {:?} exceeds {:?} range",
                            plugin.name, reference.source, reference.field
                        )
                    })?;
                if reference.field == LinkField::Absolute64
                    && matches!(reference.expression, SymbolicExpression::Symbol { .. })
                {
                    self.relocations.push(Relocation {
                        rva: Rva::new(add(placed.section.rva.get(), offset as u32)?),
                        kind: RelocKind::Dir64,
                    });
                }
            }
            for symbol in plugin
                .module
                .data
                .iter()
                .filter(|symbol| is_bound(&symbol.name))
            {
                if symbol.start < placed.source || symbol.start.get() >= source_end {
                    continue;
                }
                ensure!(
                    symbol.size == 8,
                    "plugin {} SDK bound {} is not pointer-sized",
                    plugin.name,
                    symbol.name
                );
                let offset = usize::try_from(symbol.start.get() - placed.source.get())?;
                let end = offset.checked_add(8).context("bound offset overflow")?;
                ensure!(
                    end <= placed.section.virtual_size as usize,
                    "SDK bound crosses data storage"
                );
                ensure!(
                    end <= placed.section.data.len(),
                    "plugin {} SDK bound {} requires initialized data storage; rebuild with the current kamy-sdk",
                    plugin.name,
                    symbol.name
                );
                let target = if symbol.name == "SYMBOL_init_table_start" {
                    self.table_rva
                } else {
                    self.table_end
                };
                placed.section.data[offset..end]
                    .copy_from_slice(&va(self.base, target)?.to_le_bytes());
                self.relocations.push(Relocation {
                    rva: Rva::new(add(placed.section.rva.get(), offset as u32)?),
                    kind: RelocKind::Dir64,
                });
            }
        }
        Ok(())
    }

    fn record_placements(&mut self) -> anyhow::Result<()> {
        self.placements.clear();
        for function in &self.compiled {
            self.placements.push(Placement {
                symbol: function.symbol.clone(),
                source_rva: Some(function.source),
                rva: Rva::new(function.rva),
                size: u32::try_from(function.body.len())?,
                ownership: Ownership::Generated,
            });
        }
        for placed in &self.data {
            for symbol in &self.plugins[placed.plugin].module.symbols {
                if let Some(&target) = self.bindings.get(&symbol.id) {
                    if placed.source <= symbol.rva
                        && symbol.rva.get() < add(placed.source.get(), placed.section.virtual_size)?
                        && va(self.base, placed.section.rva.get())? <= target
                        && target
                            < va(
                                self.base,
                                add(placed.section.rva.get(), placed.section.virtual_size)?,
                            )?
                    {
                        let size = self.plugins[placed.plugin]
                            .module
                            .data
                            .iter()
                            .find(|data| data.symbol == symbol.id)
                            .map_or(
                                placed.section.virtual_size
                                    - (symbol.rva.get() - placed.source.get()),
                                |data| data.size,
                            );
                        self.placements.push(Placement {
                            symbol: symbol.id.clone(),
                            source_rva: Some(symbol.rva),
                            rva: Rva::new(u32::try_from(target - self.base)?),
                            size,
                            ownership: Ownership::Generated,
                        });
                    }
                }
            }
        }
        for (name, rva, size) in [
            ("entry-loader", self.loader_rva, self.loader.len()),
            ("startup", self.startup_rva, self.startup.len()),
            ("init-table", self.table_rva, self.table.len()),
        ] {
            if size != 0 {
                self.placements.push(Placement {
                    symbol: SymbolId::Generated { name: name.into() },
                    source_rva: None,
                    rva: Rva::new(rva),
                    size: u32::try_from(size)?,
                    ownership: Ownership::Generated,
                });
            }
        }
        for (index, input) in self.inputs.iter().enumerate() {
            for &retired in &input.source.retired {
                let section = &input.source.module.sections[retired];
                for symbol in &self.plugins[index].module.symbols {
                    if section.contains(symbol.rva) {
                        self.placements.push(Placement {
                            symbol: symbol.id.clone(),
                            source_rva: Some(symbol.rva),
                            rva: symbol.rva,
                            size: section.virtual_size - (symbol.rva.get() - section.rva.get()),
                            ownership: Ownership::Retired,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn emit(
        &mut self,
        sections: &mut Vec<NewSection>,
        relocations: &mut Vec<Relocation>,
        xdata: &mut Vec<u8>,
        entries: &mut Vec<(u32, u32, u32)>,
        xdata_rva: u32,
    ) -> anyhow::Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let code_rva = self.compiled.first().context("no module code")?.rva;
        let mut code = Vec::new();
        for function in &self.compiled {
            ensure!(
                function.body.len() <= function.slot as usize,
                "module body exceeds reserved slot"
            );
            crate::append_code(&mut code, code_rva, function.rva, &function.body)?;
            append_generated_unwind(
                self.base,
                xdata,
                entries,
                xdata_rva,
                function.rva,
                &function.body,
            )
            .with_context(|| format!("reconstructing unwind for {:?}", function.symbol))?;
        }
        crate::append_code(&mut code, code_rva, self.loader_rva, &self.loader)?;
        append_generated_unwind(
            self.base,
            xdata,
            entries,
            xdata_rva,
            self.loader_rva,
            &self.loader,
        )
        .context("reconstructing entry-loader unwind")?;
        if !self.startup.is_empty() {
            crate::append_code(&mut code, code_rva, self.startup_rva, &self.startup)?;
            append_generated_unwind(
                self.base,
                xdata,
                entries,
                xdata_rva,
                self.startup_rva,
                &self.startup,
            )
            .context("reconstructing startup-thunk unwind")?;
        }
        sections.extend(self.data.drain(..).map(|placed| placed.section));
        sections.push(crate::section(self.code_name.clone(), code_rva, true, code));
        if self.has_table {
            sections.push(crate::section(
                self.metadata_name.clone(),
                self.table_rva,
                false,
                std::mem::take(&mut self.table),
            ));
        }
        relocations.append(&mut self.relocations);
        Ok(())
    }

    pub(crate) fn entry_point(&self) -> Option<Rva> {
        (!self.is_empty()).then_some(Rva::new(self.loader_rva))
    }

    pub(crate) fn finish_report(&self, report: &mut Report) {
        report.placements.extend(self.placements.iter().cloned());
        report
            .address_map
            .extend(self.bindings.iter().filter_map(|(symbol, &target)| {
                u32::try_from(target.checked_sub(self.base)?)
                    .ok()
                    .map(|rva| (symbol.clone(), Rva::new(rva)))
            }));
        for function in &self.compiled {
            report.moved.push(function.symbol.clone());
            report.ssa_lowered_symbols.push(function.symbol.clone());
            report.functions.push(function.report.clone());
        }
        report.ssa_lowered = report.ssa_lowered_symbols.len();
    }
}

fn is_bound(name: &str) -> bool {
    matches!(name, "SYMBOL_init_table_start" | "SYMBOL_init_table_end")
}

fn reference_source(
    positions: &BTreeMap<SymbolId, Rva>,
    reference: &Reference,
) -> anyhow::Result<Rva> {
    let source = positions.get(&reference.source).with_context(|| {
        format!(
            "authored reference source {:?}+0x{:x} has no compiler symbol",
            reference.source, reference.offset
        )
    })?;
    Ok(Rva::new(add(source.get(), reference.offset)?))
}

fn operand_references(
    plugin: &Plugin,
    input: &AuthoredSource<'_>,
    symbol: &kamy_pe::module::CodeSymbol,
    host: Option<&Module>,
) -> anyhow::Result<Vec<OperandReference>> {
    let module = &input.module;
    let mut result = Vec::new();
    let section = module
        .section_at(symbol.start)
        .context("authored function has no storage")?;
    let bytes = module
        .bytes_at(symbol.start)
        .and_then(|bytes| bytes.get(..(symbol.end.get() - symbol.start.get()) as usize))
        .context("truncated authored function")?;
    let mut decoder = Decoder::with_ip(
        64,
        bytes,
        va(module.image_base, symbol.start.get())?,
        DecoderOptions::NONE,
    );
    let mut matched = BTreeSet::new();
    let mut fields = BTreeMap::new();
    for (index, reference) in plugin.module.references.iter().enumerate() {
        let source = reference_source(&input.source_positions, reference)?;
        if symbol.start <= source && source < symbol.end {
            ensure!(
                fields.insert(source, (index, reference)).is_none(),
                "duplicate authored field at {source}"
            );
        }
    }
    while decoder.can_decode() {
        let instruction = decoder.decode();
        let constants = decoder.get_constant_offsets(&instruction);
        let instruction_rva = u32::try_from(instruction.ip() - module.image_base)?;
        let next_rva = u32::try_from(instruction.next_ip() - module.image_base)?;
        for (&source, &(index, reference)) in
            fields.range(Rva::new(instruction_rva)..Rva::new(next_rva))
        {
            let displacement = instruction_rva.checked_add(constants.displacement_offset() as u32);
            let immediate = instruction_rva.checked_add(constants.immediate_offset() as u32);
            let operand =
                if constants.displacement_size() != 0 && displacement == Some(source.get()) {
                    ensure!(
                        instruction.is_ip_rel_memory_operand(),
                        "authored address displacement is not RIP-relative"
                    );
                    (0..instruction.op_count())
                        .find(|&operand| instruction.op_kind(operand) == OpKind::Memory)
                        .context("missing memory operand")?
                } else if constants.immediate_size() != 0 && immediate == Some(source.get()) {
                    (0..instruction.op_count())
                        .find(|&operand| {
                            matches!(
                                instruction.op_kind(operand),
                                OpKind::Immediate64
                                    | OpKind::Immediate32
                                    | OpKind::Immediate32to64
                                    | OpKind::NearBranch64
                            )
                        })
                        .context("missing immediate operand")?
                } else {
                    continue;
                };
            ensure!(
                reference.field.width() as usize
                    == if displacement == Some(source.get()) {
                        constants.displacement_size()
                    } else {
                        constants.immediate_size()
                    },
                "authored field width disagrees with its instruction operand"
            );
            let mut reference = reference.clone();
            if let LinkField::Relative32 { bias } = reference.field {
                let origin = va(module.image_base, add(source.get(), 4 + u32::from(bias))?)?;
                let correction =
                    i64::try_from(i128::from(instruction.next_ip()) - i128::from(origin))?;
                reference.expression = reference
                    .expression
                    .with_addend(correction)
                    .context("authored RIP addend overflow")?;
            }
            reference.expression = canonical_expression(reference.expression, plugin)?;
            validate_code_expression(&reference.expression, plugin)?;
            if let Some(host) = host {
                reference.expression = identify_host_object(reference.expression, host)?;
            }
            if reference.field == LinkField::ImageRelative32 {
                reference.expression = match reference.expression {
                    SymbolicExpression::Symbol { symbol, addend } => {
                        SymbolicExpression::Difference {
                            left: symbol,
                            right: SymbolId::HostImageBase,
                            addend,
                        }
                    }
                    SymbolicExpression::Difference { .. } => {
                        bail!("image-relative composite operand needs an unsupported third symbol")
                    }
                };
                reference.field = LinkField::Absolute64;
            }
            reference.source = symbol.symbol.clone();
            reference.offset = source.get() - symbol.start.get();
            result.push(OperandReference {
                instruction: Rva::new(instruction_rva),
                operand,
                reference,
            });
            ensure!(
                matched.insert(index),
                "authored reference matches multiple operands"
            );
        }
    }
    for (&source, &(index, _)) in &fields {
        ensure!(
            matched.contains(&index),
            "plugin {} function {} reference {} is not an exact instruction operand",
            plugin.name,
            symbol.name,
            source
        );
    }
    ensure!(
        section.flags.execute,
        "authored function storage is not executable"
    );
    Ok(result)
}

fn canonical_expression(
    expression: SymbolicExpression,
    plugin: &Plugin,
) -> anyhow::Result<SymbolicExpression> {
    fn root(symbol: SymbolId, plugin: &Plugin) -> anyhow::Result<(SymbolId, i64)> {
        let mut symbol = symbol;
        let mut offset = 0i64;
        for _ in 0..=plugin.module.bindings.len() {
            let Some(binding) = plugin.module.bindings.get(&symbol) else {
                return Ok((symbol, offset));
            };
            let SymbolicExpression::Symbol {
                symbol: target,
                addend,
            } = binding
            else {
                bail!(
                    "plugin {} alias {:?} is not a storage binding",
                    plugin.name,
                    symbol
                );
            };
            offset = offset
                .checked_add(*addend)
                .context("authored alias addend overflow")?;
            symbol = target.clone();
        }
        bail!("plugin {} has cyclic authored symbol bindings", plugin.name)
    }
    match expression {
        SymbolicExpression::Symbol { symbol, addend } => {
            let (symbol, offset) = root(symbol, plugin)?;
            let addend = addend
                .checked_add(offset)
                .context("authored expression addend overflow")?;
            Ok(SymbolicExpression::Symbol { symbol, addend })
        }
        SymbolicExpression::Difference {
            left,
            right,
            addend,
        } => {
            let (left, left_offset) = root(left, plugin)?;
            let (right, right_offset) = root(right, plugin)?;
            ensure!(
                (left_offset == 0
                    || !plugin
                        .module
                        .code
                        .iter()
                        .any(|function| function.symbol == left))
                    && (right_offset == 0
                        || !plugin
                            .module
                            .code
                            .iter()
                            .any(|function| function.symbol == right)),
                "plugin {} has unsupported interior code labels in a difference",
                plugin.name
            );
            let addend = addend
                .checked_add(left_offset)
                .and_then(|value| value.checked_sub(right_offset))
                .context("authored difference addend overflow")?;
            Ok(SymbolicExpression::Difference {
                left,
                right,
                addend,
            })
        }
    }
}

fn validate_code_expression(
    expression: &SymbolicExpression,
    plugin: &Plugin,
) -> anyhow::Result<()> {
    if let SymbolicExpression::Symbol { symbol, addend } = expression {
        ensure!(
            *addend == 0
                || !plugin
                    .module
                    .code
                    .iter()
                    .any(|function| function.symbol == *symbol),
            "plugin {} has an unsupported interior code expression",
            plugin.name
        );
    }
    Ok(())
}

pub(crate) fn identify_host_object(
    expression: SymbolicExpression,
    host: &Module,
) -> anyhow::Result<SymbolicExpression> {
    if let SymbolicExpression::Symbol {
        symbol: SymbolId::HostImageBase,
        addend,
    } = &expression
    {
        if let Ok(rva) = u32::try_from(*addend) {
            if let Some(function) = host.functions.iter().find(|function| {
                function
                    .blocks
                    .iter()
                    .any(|block| block.start.get() <= rva && rva < block.end.get())
            }) {
                return SymbolicExpression::symbol(SymbolId::Host {
                    rva: function.entry,
                })
                .with_addend(i64::from(rva) - i64::from(function.entry.get()))
                .context("host object offset overflow");
            }
        }
    }
    Ok(expression)
}

pub(crate) fn pin_interior_host(
    expression: &SymbolicExpression,
    host: &Module,
    pinned: &mut BTreeSet<Rva>,
) {
    let mut visit = |symbol: &SymbolId, addend: i64| {
        if let SymbolId::Host { rva } = symbol {
            if let Some(function) = host.functions.iter().find(|function| {
                function.entry == *rva
                    || function
                        .blocks
                        .iter()
                        .any(|block| block.start <= *rva && *rva < block.end)
            }) {
                if *rva != function.entry || addend != 0 {
                    pinned.insert(function.entry);
                }
            }
        }
    };
    match expression {
        SymbolicExpression::Symbol { symbol, addend } => visit(symbol, *addend),
        SymbolicExpression::Difference {
            left,
            right,
            addend,
        } => {
            visit(left, *addend);
            visit(right, 0);
        }
    }
}

fn retired_sections(pe: &PeFile, module: &Module) -> anyhow::Result<BTreeSet<usize>> {
    let mut retired = BTreeSet::new();
    for index in 0..16 {
        let Some((rva, size)) = pe.data_directory(index) else {
            continue;
        };
        if rva == Rva::ZERO && size == 0 {
            continue;
        }
        ensure!(
            matches!(index, 3 | 5),
            "unsupported authored module directory {index}; imports/TLS require producer support"
        );
        let section = module
            .sections
            .iter()
            .position(|section| section.contains(rva))
            .context("module directory outside storage")?;
        let record = &module.sections[section];
        ensure!(
            !record.flags.execute && rva == record.rva && size <= record.virtual_size,
            "module directory {index} is not dedicated storage"
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
            .context("invalid module unwind")?;
        ensure!(
            header & 0xf8 == 0,
            "module function {} uses unsupported language/chained unwind",
            function.begin
        );
    }
    Ok(retired)
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
    use iced_x86::Mnemonic;
    use kamy_core::ir::{AbiValue, Gpr, PhysReg, Win64Default};
    use kamy_core::{ReferenceOrigin, Symbol, SymbolKind};
    use kamy_pe::module::{CodeSymbol, DataSymbol};

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
        named_plugin("example", code)
    }

    fn id(module: &str, name: &str) -> SymbolId {
        SymbolId::Authored {
            module: module.into(),
            symbol: name.into(),
        }
    }

    fn named_plugin(name: &str, code: &[u8]) -> Plugin {
        let function = id(name, "coff:fixture:symbol:1:init");
        let data = id(name, "coff:fixture:section:2:piece:0");
        let readonly = id(name, "coff:fixture:section:3:piece:0");
        Plugin {
            name: name.into(),
            module: AuthoredModule {
                identity: name.into(),
                image: fixture(code, true),
                entry: Rva::new(0x1000),
                bindings: BTreeMap::new(),
                symbols: vec![
                    Symbol {
                        id: function.clone(),
                        name: "init".into(),
                        rva: Rva::new(0x1000),
                        kind: SymbolKind::Function,
                    },
                    Symbol {
                        id: data,
                        name: "data".into(),
                        rva: Rva::new(0x2000),
                        kind: SymbolKind::Data,
                    },
                    Symbol {
                        id: readonly,
                        name: "readonly".into(),
                        rva: Rva::new(0x3000),
                        kind: SymbolKind::Data,
                    },
                ],
                code: vec![CodeSymbol {
                    symbol: function,
                    name: "init".into(),
                    start: Rva::new(0x1000),
                    end: Rva::new(0x1000 + code.len() as u32),
                    signature: FnSignature {
                        args: [Gpr::Rcx, Gpr::Rdx, Gpr::R8]
                            .into_iter()
                            .map(|reg| AbiValue::register(PhysReg::Gpr(reg)))
                            .collect(),
                        returns: vec![AbiValue::register(PhysReg::Gpr(Gpr::Rax))],
                        clobbers: vec![
                            PhysReg::Gpr(Gpr::Rax),
                            PhysReg::Gpr(Gpr::Rcx),
                            PhysReg::Gpr(Gpr::Rdx),
                        ],
                        noreturn: false,
                    },
                }],
                data: Vec::new(),
                references: Vec::new(),
            },
        }
    }

    fn reference(
        source: SymbolId,
        offset: u32,
        target: SymbolId,
        addend: i64,
        field: LinkField,
    ) -> Reference {
        Reference {
            source,
            offset,
            expression: SymbolicExpression::Symbol {
                symbol: target,
                addend,
            },
            field,
            origin: ReferenceOrigin::Authored,
        }
    }

    #[test]
    fn authored_source_preserves_exact_operands_and_native_abi_without_a_host() {
        use kamy_core::ir::{AbiClass, XmmReg};

        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&BASE.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&(BASE + 0x2007).to_le_bytes());
        code.push(0xc3);
        let mut plugin = plugin(&code);
        let function = plugin.module.code[0].symbol.clone();
        let data = plugin.module.symbols[1].id.clone();
        let alias = id(&plugin.name, "callback-alias");
        plugin
            .module
            .bindings
            .insert(alias.clone(), SymbolicExpression::symbol(function.clone()));
        plugin.module.code[0].signature.args.push(AbiValue {
            class: AbiClass::Float,
            bits: 64,
            ..AbiValue::register(PhysReg::Xmm(XmmReg::Xmm1))
        });
        plugin.module.code[0].signature.returns.push(AbiValue {
            class: AbiClass::Float,
            bits: 64,
            ..AbiValue::register(PhysReg::Xmm(XmmReg::Xmm0))
        });
        plugin.module.references.extend([
            reference(
                function.clone(),
                2,
                SymbolId::HostImageBase,
                0,
                LinkField::Absolute64,
            ),
            reference(function.clone(), 12, data.clone(), 7, LinkField::Absolute64),
        ]);
        let source = AuthoredSource::new(&plugin).unwrap();
        let prepared = source.function_at(Rva::new(0x1000), None).unwrap();
        assert_eq!(prepared.symbol.symbol, function);
        assert_eq!(prepared.function.entry, Rva::new(0x1000));
        assert!(prepared.function.blocks.iter().all(|block| {
            block.start >= prepared.symbol.start && block.end <= prepared.symbol.end
        }));
        assert_eq!(prepared.references.len(), 2);
        assert_eq!(prepared.references[0].instruction, Rva::new(0x1000));
        assert_eq!(prepared.references[0].operand, 1);
        assert_eq!(
            prepared.references[0].reference.expression,
            SymbolicExpression::symbol(SymbolId::HostImageBase)
        );
        assert_eq!(prepared.references[1].reference.source, function);
        assert_eq!(prepared.references[1].reference.offset, 12);
        assert_eq!(
            prepared.references[1].reference.expression,
            SymbolicExpression::Symbol {
                symbol: data,
                addend: 7,
            }
        );
        assert_eq!(
            source.lookup_symbol(&alias),
            Some(prepared.symbol.signature.clone())
        );
        assert_eq!(source.lookup(BASE + 0x1000), None);
        assert_eq!(source.lookup_symbol(&id(&plugin.name, "unknown")), None);
    }

    #[test]
    fn authored_source_reports_missing_and_ambiguous_local_entries() {
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        let source = AuthoredSource::new(&plugin).unwrap();
        assert!(source.function_at(Rva::new(0x1001), None).is_err());
        plugin.module.code.push(plugin.module.code[0].clone());
        assert!(AuthoredSource::new(&plugin).is_err());
    }

    fn add_bounds(plugin: &mut Plugin) {
        for (name, offset) in [("SYMBOL_init_table_start", 0), ("SYMBOL_init_table_end", 8)] {
            let symbol = id(&plugin.name, name);
            plugin.module.symbols.push(Symbol {
                id: symbol.clone(),
                name: name.into(),
                rva: Rva::new(0x2000 + offset),
                kind: SymbolKind::Data,
            });
            plugin.module.data.push(DataSymbol {
                symbol,
                name: name.into(),
                start: Rva::new(0x2000 + offset),
                size: 8,
            });
        }
    }

    fn link(
        pe: &PeFile,
        host: &Module,
        plugins: &[Plugin],
        mode: EntryMode,
    ) -> anyhow::Result<(Vec<u8>, Report)> {
        crate::protect(
            pe,
            host,
            &host.functions,
            &Options::default(),
            &Win64Default,
            &mut |_, _, _| Ok(TransformOutcome::default()),
            Injection { plugins, mode },
        )
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
    fn exact_movabs_operand_preserves_equal_valued_integer() {
        let pointer = BASE + 0x2000;
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&pointer.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&pointer.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x01, 0x48, 0x89, 0x51, 8, 0x31, 0xc0, 0xc3]);
        let mut plugin = plugin(&code);
        plugin.module.references.push(reference(
            plugin.module.code[0].symbol.clone(),
            2,
            plugin.module.symbols[1].id.clone(),
            0,
            LinkField::Absolute64,
        ));
        let original = plugin.module.image.clone();
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let plugins = [plugin];
        let planned = planned_functions(&plugins).unwrap();
        let (image, report) = link(&pe, &host, &plugins, EntryMode::Inline).unwrap();
        assert_eq!(plugins[0].module.image, original);
        let output = PeFile::parse(&image).unwrap().to_module();
        let entry = report.address_map[&planned[0].symbol];
        let data = report.address_map[&plugins[0].module.symbols[1].id];
        let instructions: Vec<_> = Decoder::with_ip(
            64,
            output.bytes_at(entry).unwrap(),
            BASE + u64::from(entry.get()),
            DecoderOptions::NONE,
        )
        .into_iter()
        .take_while(|instruction| instruction.mnemonic() != Mnemonic::Ret)
        .collect();
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction.mnemonic() == Mnemonic::Lea
                    && instruction.ip_rel_memory_address() == BASE + u64::from(data.get()))
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction.code() == Code::Mov_r64_imm64
                    && instruction.immediate64() == pointer)
        );
    }

    #[test]
    fn authored_image_base_signed_offsets_and_module_interiors_are_source_qualified() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        for addend in [0, -2, 0x2345, 0x1_1000, 0x1_2000] {
            for absolute in [false, true] {
                let (mut code, offset, field) = if absolute {
                    let mut code = vec![0x48, 0xb8];
                    code.extend_from_slice(&BASE.checked_add_signed(addend).unwrap().to_le_bytes());
                    (code, 2, LinkField::Absolute64)
                } else {
                    let mut code = vec![0x48, 0x8d, 0x05];
                    code.extend_from_slice(&i32::try_from(addend - 0x1007).unwrap().to_le_bytes());
                    (code, 3, LinkField::Relative32 { bias: 0 })
                };
                code.extend_from_slice(&[0x48, 0x89, 0x01]);
                let local_offset = code.len() as u32 + 3;
                code.extend_from_slice(&[0x48, 0x8d, 0x05]);
                code.extend_from_slice(
                    &i32::try_from(0x2008i64 - i64::from(0x1000 + local_offset + 4))
                        .unwrap()
                        .to_le_bytes(),
                );
                code.extend_from_slice(&[0x48, 0x89, 0x41, 8, 0x31, 0xc0, 0xc3]);
                let mut plugin = plugin(&code);
                let function = plugin.module.code[0].symbol.clone();
                let data = plugin.module.symbols[1].id.clone();
                plugin.module.references.extend([
                    reference(
                        function.clone(),
                        offset,
                        SymbolId::HostImageBase,
                        addend,
                        field,
                    ),
                    reference(
                        function.clone(),
                        local_offset,
                        data.clone(),
                        8,
                        LinkField::Relative32 { bias: 0 },
                    ),
                ]);
                let plugins = [plugin];
                let mut callbacks = Vec::new();
                let (image, report) = crate::protect(
                    &pe,
                    &host,
                    &[],
                    &Options::default(),
                    &Win64Default,
                    &mut |symbol, _, _| {
                        callbacks.push(symbol.clone());
                        Ok(TransformOutcome::default())
                    },
                    Injection {
                        plugins: &plugins,
                        mode: EntryMode::Inline,
                    },
                )
                .unwrap();
                assert!(callbacks.iter().all(|symbol| *symbol == function));
                let output = PeFile::parse(&image).unwrap().to_module();
                let entry = report.address_map[&function];
                for slide in [0, 0x1234_0000] {
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
                    assert!(pointers.contains(
                        &(BASE + slide + u64::from(report.address_map[&data].get()) + 8)
                    ));
                }
            }
        }
    }

    #[test]
    fn signed_rel32_addends_keep_trailing_immediate_bias() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        for (host_base, addend, interior) in [(true, -2, 0), (false, 0x10, 0), (false, -0x10, 0x20)]
        {
            let target = if host_base { 0 } else { 0x2000 + interior };
            let mut code = vec![0x31, 0xc0, 0x66, 0x81, 0x3d];
            code.extend_from_slice(
                &i32::try_from(i64::from(target) + addend - 0x1009)
                    .unwrap()
                    .to_le_bytes(),
            );
            code.extend_from_slice(&[0x4d, 0x5a, 0x0f, 0x95, 0xc0, 0xc3]);
            let mut plugin = plugin(&code);
            let target = if host_base {
                SymbolId::HostImageBase
            } else if interior == 0 {
                plugin.module.symbols[1].id.clone()
            } else {
                let target = id("example", "coff:fixture:symbol:7:data-interior");
                plugin.module.symbols.push(Symbol {
                    id: target.clone(),
                    name: "data-interior".into(),
                    rva: Rva::new(0x2000 + interior),
                    kind: SymbolKind::Data,
                });
                plugin.module.bindings.insert(
                    target.clone(),
                    SymbolicExpression::Symbol {
                        symbol: plugin.module.symbols[1].id.clone(),
                        addend: i64::from(interior),
                    },
                );
                target
            };
            plugin.module.references.push(reference(
                plugin.module.code[0].symbol.clone(),
                5,
                target.clone(),
                addend,
                LinkField::Relative32 { bias: 0 },
            ));
            let plugins = [plugin];
            let (image, report) = link(&pe, &host, &plugins, EntryMode::Inline).unwrap();
            let output = PeFile::parse(&image).unwrap().to_module();
            let entry = report.address_map[&plugins[0].module.code[0].symbol];
            let expected = if host_base {
                BASE
            } else {
                (BASE + u64::from(report.address_map[&target].get()))
                    .checked_add_signed(addend + 2)
                    .unwrap()
            };
            let references: Vec<_> = Decoder::with_ip(
                64,
                output.bytes_at(entry).unwrap(),
                BASE + u64::from(entry.get()),
                DecoderOptions::NONE,
            )
            .into_iter()
            .take_while(|instruction| instruction.mnemonic() != Mnemonic::Ret)
            .filter(|instruction| instruction.is_ip_rel_memory_operand())
            .map(|instruction| instruction.ip_rel_memory_address())
            .collect();
            assert!(references.contains(&expected));
        }
    }

    #[test]
    fn data_fixups_bounds_and_directory_contributions_share_final_placement() {
        let pe = PeFile::parse(&fixture(&[0x31, 0xc0, 0xc3], false)).unwrap();
        let host = pe.to_module();
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        add_bounds(&mut plugin);
        let source = plugin.module.symbols[1].id.clone();
        let readonly = plugin.module.symbols[2].id.clone();
        let function = plugin.module.code[0].symbol.clone();
        plugin.module.references.extend([
            reference(
                source.clone(),
                16,
                function.clone(),
                0,
                LinkField::Absolute64,
            ),
            reference(
                source.clone(),
                24,
                readonly.clone(),
                0,
                LinkField::ImageRelative32,
            ),
            reference(
                source.clone(),
                32,
                SymbolId::HostImageBase,
                0x1_1000,
                LinkField::Absolute64,
            ),
            reference(
                source.clone(),
                40,
                SymbolId::HostImageBase,
                0x2345,
                LinkField::ImageRelative32,
            ),
            reference(
                source.clone(),
                44,
                SymbolId::HostImageBase,
                0x1_2000,
                LinkField::Relative32 { bias: 0 },
            ),
            reference(
                source.clone(),
                48,
                SymbolId::HostImageBase,
                -2,
                LinkField::Absolute64,
            ),
        ]);
        let plugins = [plugin];
        let (image, report) = link(&pe, &host, &plugins, EntryMode::InitTable).unwrap();
        let output_pe = PeFile::parse(&image).unwrap();
        let output = output_pe.to_module();
        let data_rva = report.address_map[&source];
        let data = output.bytes_at(data_rva).unwrap();
        let read64 = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        assert_eq!(read64(8) - read64(0), 16);
        assert_eq!(
            read64(16),
            BASE + u64::from(report.address_map[&function].get())
        );
        assert_eq!(read64(32), BASE + 0x1_1000);
        assert_eq!(read64(48), BASE - 2);
        assert_eq!(
            u32::from_le_bytes(data[24..28].try_into().unwrap()),
            report.address_map[&readonly].get()
        );
        assert_eq!(u32::from_le_bytes(data[40..44].try_into().unwrap()), 0x2345);
        assert_eq!(
            (BASE + u64::from(data_rva.get()) + 48).checked_add_signed(i64::from(
                i32::from_le_bytes(data[44..48].try_into().unwrap())
            )),
            Some(BASE + 0x1_2000)
        );
        let exception = report
            .directories
            .iter()
            .find(|directory| directory.index == 3)
            .unwrap();
        assert_eq!(
            output_pe.data_directory(3),
            Some((exception.rva, exception.size))
        );
        assert_eq!(
            exception
                .contributions
                .iter()
                .map(|range| (range.rva, range.size))
                .collect::<Vec<_>>(),
            output_pe
                .runtime_functions()
                .iter()
                .map(|range| (range.begin, range.end.get() - range.begin.get()))
                .collect::<Vec<_>>()
        );
        let relocations = report
            .directories
            .iter()
            .find(|directory| directory.index == 5)
            .unwrap();
        let fields: BTreeSet<_> = relocations
            .contributions
            .iter()
            .map(|range| range.rva)
            .collect();
        assert_eq!(
            fields,
            output
                .relocations
                .iter()
                .filter(|relocation| relocation.kind == RelocKind::Dir64)
                .map(|relocation| relocation.rva)
                .collect()
        );
        for offset in [0, 8, 16, 32, 48] {
            assert!(fields.contains(&Rva::new(data_rva.get() + offset)));
        }
        let startup = report.address_map[&SymbolId::Generated {
            name: "startup".into(),
        }];
        let instructions: Vec<_> = Decoder::with_ip(
            64,
            output.bytes_at(startup).unwrap(),
            BASE + u64::from(startup.get()),
            DecoderOptions::NONE,
        )
        .into_iter()
        .take(2)
        .collect();
        assert_eq!(instructions[1].near_branch_target(), BASE + 0x1000);
    }

    #[test]
    fn duplicate_source_rvas_and_compiler_symbols_do_not_alias_module_instances() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let mut plugins = [
            named_plugin("first", &[0x31, 0xc0, 0xc3]),
            named_plugin("second", &[0x31, 0xc0, 0xc3]),
        ];
        for plugin in &mut plugins {
            plugin.module.references.push(reference(
                plugin.module.symbols[1].id.clone(),
                0,
                plugin.module.code[0].symbol.clone(),
                0,
                LinkField::Absolute64,
            ));
            plugin.module.image[0x608..0x610].copy_from_slice(&(BASE + 0x1000).to_le_bytes());
        }
        let planned = planned_functions(&plugins).unwrap();
        assert_ne!(planned[0].symbol, planned[1].symbol);
        let (first, report) = link(&pe, &host, &plugins, EntryMode::InitTable).unwrap();
        let (second, _) = link(&pe, &host, &plugins, EntryMode::InitTable).unwrap();
        assert_eq!(first, second);
        assert_ne!(
            report.address_map[&planned[0].symbol],
            report.address_map[&planned[1].symbol]
        );
        assert!(report.functions.iter().all(|function| function.lowered
            && !function.transformed
            && function.intensity == 0.0));
        let output = PeFile::parse(&first).unwrap().to_module();
        for plugin in &plugins {
            let data = report.address_map[&plugin.module.symbols[1].id];
            let bytes = output.bytes_at(data).unwrap();
            assert_eq!(
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                BASE + u64::from(report.address_map[&plugin.module.code[0].symbol].get())
            );
            assert_eq!(
                u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                BASE + 0x1000
            );
            assert!(
                !output
                    .relocations
                    .iter()
                    .any(|relocation| relocation.rva.get() == data.get() + 8)
            );
        }
    }

    #[test]
    fn dll_init_table_excludes_original_entry_and_preserves_bool_tail_return() {
        let mut image = fixture(&[0xb8, 1, 0, 0, 0, 0xc3], true);
        put32(&mut image, 0xa8, 0x1000);
        let pe = PeFile::parse(&image).unwrap();
        let host = pe.to_module();
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        add_bounds(&mut plugin);
        let (image, report) = link(&pe, &host, &[plugin], EntryMode::InitTable).unwrap();
        let output = PeFile::parse(&image).unwrap().to_module();
        let table = report
            .placements
            .iter()
            .find(|placement| {
                placement.symbol
                    == (SymbolId::Generated {
                        name: "init-table".into(),
                    })
            })
            .unwrap();
        assert_eq!(table.size, 8);
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
    fn zero_fill_storage_preserves_virtual_size_permissions_and_no_raw_bytes() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        put32(&mut plugin.module.image, 0x188 + 40 + 16, 0);
        put32(&mut plugin.module.image, 0x188 + 40 + 20, 0);
        let data = plugin.module.symbols[1].id.clone();
        let (image, report) = link(&pe, &host, &[plugin], EntryMode::Inline).unwrap();
        let output = PeFile::parse(&image).unwrap();
        let module = output.to_module();
        let section = module.section_at(report.address_map[&data]).unwrap();
        assert_eq!(section.virtual_size, 128);
        assert!(section.flags.read && section.flags.write && !section.flags.execute);
        let header = output
            .section_headers()
            .iter()
            .find(|header| header.rva == section.rva.get())
            .unwrap();
        assert_eq!(header.raw_size, 0);
    }

    fn plugin_with_large_bss() -> Plugin {
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        put32(&mut plugin.module.image, 0x188 + 40 + 8, 0x2018);
        put32(&mut plugin.module.image, 0x188 + 2 * 40 + 12, 0x5000);
        put32(&mut plugin.module.image, 0xd0, 0x6000);
        plugin.module.symbols[2].rva = Rva::new(0x5000);
        let bss = id(&plugin.name, "large-bss");
        plugin.module.symbols.push(Symbol {
            id: bss.clone(),
            name: "large-bss".into(),
            rva: Rva::new(0x2018),
            kind: SymbolKind::Data,
        });
        plugin.module.data.push(DataSymbol {
            symbol: bss,
            name: "large-bss".into(),
            start: Rva::new(0x2018),
            size: 8192,
        });
        add_bounds(&mut plugin);
        plugin
    }

    #[test]
    fn later_linker_bound_cells_preserve_large_bss_virtual_tail_and_aliases() {
        for dll in [false, true] {
            for mode in [EntryMode::Inline, EntryMode::InitTable] {
                let mut host_image = fixture(&[0x31, 0xc0, 0xc3], dll);
                put32(&mut host_image, 0xa8, 0x1000);
                let pe = PeFile::parse(&host_image).unwrap();
                let host = pe.to_module();
                let mut plugin = plugin_with_large_bss();
                let source = plugin.module.symbols[1].id.clone();
                let readonly = plugin.module.symbols[2].id.clone();
                let bss = plugin.module.data[0].symbol.clone();
                let interior = id(&plugin.name, "bss-interior");
                let one_past = id(&plugin.name, "bss-one-past");
                for (alias, offset) in [(interior.clone(), 37), (one_past.clone(), 8192)] {
                    plugin.module.symbols.push(Symbol {
                        id: alias.clone(),
                        name: format!("bss+{offset}"),
                        rva: Rva::new(0x2018 + offset),
                        kind: SymbolKind::Data,
                    });
                    plugin.module.bindings.insert(
                        alias,
                        SymbolicExpression::Symbol {
                            symbol: bss.clone(),
                            addend: i64::from(offset),
                        },
                    );
                }
                plugin.module.references.extend([
                    reference(
                        source.clone(),
                        16,
                        interior.clone(),
                        0,
                        LinkField::Absolute64,
                    ),
                    reference(
                        readonly.clone(),
                        0,
                        one_past.clone(),
                        0,
                        LinkField::Absolute64,
                    ),
                ]);
                let (image, report) = link(&pe, &host, &[plugin], mode).unwrap();
                let output = PeFile::parse(&image).unwrap();
                let output_module = output.to_module();
                let data_rva = report.address_map[&source].get();
                let bss_rva = report.address_map[&bss].get();
                let section = output
                    .section_headers()
                    .iter()
                    .find(|section| section.rva == data_rva)
                    .unwrap();
                assert_eq!(section.virtual_size, 24 + 8192);
                assert_eq!(section.raw_size, 0x200);
                assert_eq!(section.characteristics & 0xe000_0000, 0xc000_0000);
                assert_eq!(bss_rva, data_rva + 24);
                assert_eq!(bss_rva + 8192, section.rva + section.virtual_size);
                assert!(bss_rva + 8192 > section.rva + section.raw_size);
                assert_eq!(report.address_map[&interior].get(), bss_rva + 37);
                assert_eq!(report.address_map[&one_past].get(), bss_rva + 8192);
                let read_pointer = |rva| {
                    u64::from_le_bytes(
                        output_module.bytes_at(Rva::new(rva)).unwrap()[..8]
                            .try_into()
                            .unwrap(),
                    )
                };
                assert_eq!(read_pointer(data_rva + 16), BASE + u64::from(bss_rva + 37));
                assert_eq!(
                    read_pointer(report.address_map[&readonly].get()),
                    BASE + u64::from(bss_rva + 8192)
                );
                let table = report
                    .placements
                    .iter()
                    .find(|placement| {
                        placement.symbol
                            == (SymbolId::Generated {
                                name: "init-table".into(),
                            })
                    })
                    .unwrap();
                assert_eq!(read_pointer(data_rva), BASE + u64::from(table.rva.get()));
                assert_eq!(
                    read_pointer(data_rva + 8),
                    BASE + u64::from(table.rva.get() + table.size)
                );
                let relocations = &output_module.relocations;
                for field in [
                    data_rva,
                    data_rva + 8,
                    data_rva + 16,
                    report.address_map[&readonly].get(),
                ] {
                    assert!(relocations.iter().any(|relocation| {
                        relocation.rva.get() == field && relocation.kind == RelocKind::Dir64
                    }));
                }
            }
        }
    }

    #[test]
    fn initialized_writes_cannot_extend_raw_storage_across_bss() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        for bound_cell in [false, true] {
            let mut plugin = plugin_with_large_bss();
            if bound_cell {
                let bound = plugin
                    .module
                    .data
                    .iter_mut()
                    .find(|data| is_bound(&data.name))
                    .unwrap();
                bound.start = Rva::new(0x4010);
                plugin
                    .module
                    .symbols
                    .iter_mut()
                    .find(|symbol| symbol.id == bound.symbol)
                    .unwrap()
                    .rva = bound.start;
            } else {
                plugin.module.references.push(reference(
                    plugin.module.symbols[1].id.clone(),
                    0x2010,
                    plugin.module.code[0].symbol.clone(),
                    0,
                    LinkField::Absolute64,
                ));
            }
            let error = format!(
                "{:#}",
                link(&pe, &host, &[plugin], EntryMode::Inline)
                    .err()
                    .unwrap()
            );
            assert!(error.contains("initialized"), "{error}");
            assert!(error.contains("example"), "{error}");
            assert!(error.contains("rebuild"), "{error}");
        }
    }

    #[test]
    fn kernel_injection_fails_before_transformation() {
        let mut image = fixture(&[0xc3], false);
        put16(&mut image, 0xdc, 1);
        let pe = PeFile::parse(&image).unwrap();
        let host = pe.to_module();
        let error = crate::protect(
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
    fn image_relative_signed_overflow_fails_contextually() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        for addend in [-1, i64::from(u32::MAX) + 1] {
            let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
            plugin.module.references.push(reference(
                plugin.module.symbols[1].id.clone(),
                0,
                SymbolId::HostImageBase,
                addend,
                LinkField::ImageRelative32,
            ));
            let error = link(&pe, &host, &[plugin], EntryMode::Inline)
                .err()
                .unwrap();
            let message = format!("{error:#}");
            assert!(message.contains("plugin example reference") && message.contains("range"));
        }
    }

    #[test]
    fn inline_pic_dll_keeps_empty_relocations_consistent() {
        let mut bytes = fixture(&[0xb8, 1, 0, 0, 0, 0xc3], true);
        put32(&mut bytes, 0xa8, 0x1000);
        let pe = PeFile::parse(&bytes).unwrap();
        let (image, _) = link(
            &pe,
            &pe.to_module(),
            &[plugin(&[0x31, 0xc0, 0xc3])],
            EntryMode::Inline,
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

    fn host_function(entry: u32, end: u32) -> kamy_core::Function {
        kamy_core::Function {
            entry: Rva::new(entry),
            blocks: vec![kamy_core::BasicBlock {
                start: Rva::new(entry),
                end: Rva::new(end),
                successors: Vec::new(),
                terminator: kamy_core::Terminator::Return,
            }],
        }
    }

    #[test]
    fn authored_host_object_retargets_mover_without_touching_equal_integer() {
        for arithmetic in [false, true] {
            let pe = PeFile::parse(&fixture(&[0x31, 0xc0, 0xc3], false)).unwrap();
            let mut host = pe.to_module();
            host.functions.push(host_function(0x1000, 0x1003));
            let mut code = vec![0x48, 0xb8];
            let raw = if arithmetic { BASE } else { BASE + 0x1000 };
            code.extend_from_slice(&raw.to_le_bytes());
            if arithmetic {
                code.extend_from_slice(&[0x48, 0x05, 0x00, 0x10, 0x00, 0x00]);
            }
            code.extend_from_slice(&[0x48, 0x89, 0x01, 0x48, 0xba]);
            code.extend_from_slice(&(BASE + 0x1000).to_le_bytes());
            code.extend_from_slice(&[0x48, 0x89, 0x51, 8, 0x31, 0xc0, 0xc3]);
            let mut plugin = plugin(&code);
            plugin.module.references.push(reference(
                plugin.module.code[0].symbol.clone(),
                2,
                SymbolId::HostImageBase,
                if arithmetic { 0 } else { 0x1000 },
                LinkField::Absolute64,
            ));
            let function = plugin.module.code[0].symbol.clone();
            let (image, report) = link(&pe, &host, &[plugin], EntryMode::Inline).unwrap();
            let moved = report.address_map[&SymbolId::Host {
                rva: Rva::new(0x1000),
            }];
            assert_ne!(moved, Rva::new(0x1000));
            let output = PeFile::parse(&image).unwrap().to_module();
            let entry = report.address_map[&function];
            for slide in [0, 0x1234_0000] {
                let instructions: Vec<_> = Decoder::with_ip(
                    64,
                    output.bytes_at(entry).unwrap(),
                    BASE + slide + u64::from(entry.get()),
                    DecoderOptions::NONE,
                )
                .into_iter()
                .take_while(|instruction| instruction.mnemonic() != Mnemonic::Ret)
                .collect();
                assert!(
                    instructions
                        .iter()
                        .any(|instruction| instruction.mnemonic() == Mnemonic::Lea
                            && instruction.ip_rel_memory_address()
                                == BASE + slide + u64::from(moved.get()))
                );
                assert!(
                    instructions
                        .iter()
                        .any(|instruction| instruction.code() == Code::Mov_r64_imm64
                            && instruction.immediate64() == BASE + 0x1000)
                );
            }
        }
    }

    #[test]
    fn retained_host_and_lowered_sources_share_one_active_exception_table() {
        let mut code = vec![0x90; 0x11];
        code[..3].copy_from_slice(&[0x31, 0xc0, 0xc3]);
        code[0x10] = 0xc3;
        let mut bytes = fixture(&code, false);
        put32(&mut bytes, 0x108 + 3 * 8, 0x3000);
        put32(&mut bytes, 0x10c + 3 * 8, 24);
        put32(&mut bytes, 0x188 + 2 * 40 + 8, 24);
        bytes[0x600] = 1;
        for (offset, value) in [
            (0x800, 0x1000),
            (0x804, 0x1003),
            (0x808, 0x2000),
            (0x80c, 0x1010),
            (0x810, 0x1011),
            (0x814, 0x2000),
        ] {
            put32(&mut bytes, offset, value);
        }
        let pe = PeFile::parse(&bytes).unwrap();
        let mut host = pe.to_module();
        host.functions = vec![host_function(0x1000, 0x1003), host_function(0x1010, 0x1011)];
        let plugins = [plugin(&[0x31, 0xc0, 0xc3])];
        let opts = Options {
            selected_symbols: Some(
                [
                    SymbolId::Host {
                        rva: Rva::new(0x1000),
                    },
                    plugins[0].module.code[0].symbol.clone(),
                ]
                .into_iter()
                .collect(),
            ),
            ..Options::default()
        };
        for injected in [false, true] {
            let (image, report) = crate::protect(
                &pe,
                &host,
                &host.functions,
                &opts,
                &Win64Default,
                &mut |_, _, _| Ok(TransformOutcome::default()),
                Injection {
                    plugins: if injected { &plugins } else { &[] },
                    mode: EntryMode::InitTable,
                },
            )
            .unwrap();
            let output = PeFile::parse(&image).unwrap();
            let active = report
                .directories
                .iter()
                .find(|directory| directory.index == 3)
                .unwrap();
            let tables: Vec<_> = report
                .placements
                .iter()
                .filter(|placement| {
                    placement.ownership == Ownership::Generated
                        && placement.symbol
                            == (SymbolId::Generated {
                                name: "directory-3".into(),
                            })
                })
                .collect();
            assert_eq!(tables.len(), 1);
            assert_eq!((tables[0].rva, tables[0].size), (active.rva, active.size));
            assert_eq!(output.data_directory(3), Some((active.rva, active.size)));
            assert!(active.contributions.iter().any(
                |range| range.rva == Rva::new(0x1010) && range.ownership == Ownership::Resident
            ));
            assert!(active.contributions.iter().any(|range| range.symbol
                == (SymbolId::Host {
                    rva: Rva::new(0x1000)
                })
                && range.ownership == Ownership::Generated));
            assert_eq!(
                active
                    .contributions
                    .iter()
                    .any(|range| matches!(range.symbol, SymbolId::Authored { .. })),
                injected
            );
            assert_eq!(active.contributions.len(), output.runtime_functions().len());
            assert!(
                output
                    .runtime_functions()
                    .windows(2)
                    .all(|pair| pair[0].end <= pair[1].begin)
            );
            assert!(
                report
                    .placements
                    .iter()
                    .any(|placement| placement.rva == Rva::new(0x3000)
                        && placement.ownership == Ownership::Retired)
            );
        }
    }

    #[test]
    fn image_relative_instruction_is_a_scalar_difference_not_a_pointer() {
        let code = [0xb8, 0x00, 0x20, 0x00, 0x00, 0x89, 0x01, 0x31, 0xc0, 0xc3];
        let mut plugin = plugin(&code);
        let function = plugin.module.code[0].symbol.clone();
        let data = plugin.module.symbols[1].id.clone();
        plugin.module.references.push(reference(
            function.clone(),
            1,
            data.clone(),
            0,
            LinkField::ImageRelative32,
        ));
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let (image, report) = link(&pe, &pe.to_module(), &[plugin], EntryMode::Inline).unwrap();
        let output = PeFile::parse(&image).unwrap().to_module();
        let entry = report.address_map[&function];
        let target = u64::from(report.address_map[&data].get());
        let instructions: Vec<_> = Decoder::with_ip(
            64,
            output.bytes_at(entry).unwrap(),
            BASE + u64::from(entry.get()),
            DecoderOptions::NONE,
        )
        .into_iter()
        .take_while(|instruction| instruction.mnemonic() != Mnemonic::Ret)
        .collect();
        assert!(
            instructions
                .iter()
                .any(|instruction| match instruction.op1_kind() {
                    OpKind::Immediate64 => instruction.immediate64() == target,
                    OpKind::Immediate32 => u64::from(instruction.immediate32()) == target,
                    _ => false,
                })
        );
        assert!(
            !instructions
                .iter()
                .any(|instruction| instruction.mnemonic() == Mnemonic::Lea
                    && instruction.ip_rel_memory_address() == BASE + target)
        );
    }

    #[test]
    fn authored_alias_bindings_and_negative_differences_preserve_storage_identity() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        let storage = plugin.module.symbols[1].id.clone();
        let readonly = plugin.module.symbols[2].id.clone();
        let alias = id("example", "coff:fixture:symbol:9:one-past");
        plugin.module.symbols.push(Symbol {
            id: alias.clone(),
            name: "one-past".into(),
            rva: Rva::new(0x2080),
            kind: SymbolKind::Data,
        });
        plugin.module.bindings.insert(
            alias.clone(),
            SymbolicExpression::Symbol {
                symbol: storage.clone(),
                addend: 128,
            },
        );
        plugin.module.references.push(reference(
            storage.clone(),
            0,
            alias.clone(),
            -8,
            LinkField::Absolute64,
        ));
        plugin.module.references.push(Reference {
            source: storage.clone(),
            offset: 8,
            expression: SymbolicExpression::Difference {
                left: storage.clone(),
                right: readonly.clone(),
                addend: -7,
            },
            field: LinkField::Absolute64,
            origin: ReferenceOrigin::Authored,
        });
        let (image, report) = link(&pe, &pe.to_module(), &[plugin], EntryMode::Inline).unwrap();
        let output = PeFile::parse(&image).unwrap().to_module();
        let data = report.address_map[&storage];
        assert_eq!(report.address_map[&alias].get(), data.get() + 128);
        let bytes = output.bytes_at(data).unwrap();
        assert_eq!(
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            BASE + u64::from(data.get()) + 120
        );
        let expected = i64::from(data.get()) - i64::from(report.address_map[&readonly].get()) - 7;
        assert_eq!(
            i64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            expected
        );
        assert!(
            output
                .relocations
                .iter()
                .any(|relocation| relocation.rva == data && relocation.kind == RelocKind::Dir64)
        );
        assert!(
            !output
                .relocations
                .iter()
                .any(|relocation| relocation.rva.get() == data.get() + 8)
        );
    }

    #[test]
    fn module_selection_does_not_remove_required_identity_lowering() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let plugins = [plugin(&[0x31, 0xc0, 0xc3])];
        let opts = Options {
            selected_symbols: Some(BTreeSet::new()),
            ..Options::default()
        };
        let (_, report) = crate::protect(
            &pe,
            &host,
            &[],
            &opts,
            &Win64Default,
            &mut |_, _, _| panic!("unselected semantic callback must not run"),
            Injection {
                plugins: &plugins,
                mode: EntryMode::Inline,
            },
        )
        .unwrap();
        assert_eq!(report.ssa_lowered, 1);
        assert!(report.functions.iter().all(|function| !function.selected
            && function.eligible
            && function.lowered
            && !function.transformed
            && function.intensity == 0.0));
    }

    #[test]
    fn layout_overflow_fails_without_neighbor_storage() {
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let plugins = [plugin(&[0x31, 0xc0, 0xc3])];
        let mut plan = Plan::prepare(
            &pe,
            &host,
            &Options::default(),
            &mut |_, _, _| Ok(TransformOutcome::default()),
            Injection {
                plugins: &plugins,
                mode: EntryMode::Inline,
            },
        )
        .unwrap();
        let error = plan
            .place(u32::MAX - 15, &BTreeMap::new(), &BTreeMap::new())
            .unwrap_err();
        assert!(format!("{error:#}").contains("overflow"));
    }

    #[test]
    fn distant_symbolic_pointer_rejects_encoding_with_source_context() {
        let addend = 0x10_0000_0000i64;
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&BASE.checked_add_signed(addend).unwrap().to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x01, 0x31, 0xc0, 0xc3]);
        let mut plugin = plugin(&code);
        plugin.module.references.push(reference(
            plugin.module.code[0].symbol.clone(),
            2,
            SymbolId::HostImageBase,
            addend,
            LinkField::Absolute64,
        ));
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let error = link(&pe, &pe.to_module(), &[plugin], EntryMode::Inline)
            .err()
            .unwrap();
        let message = format!("{error:#}");
        assert!(
            message.contains("encoding plugin example") && message.contains("instruction encode")
        );
    }

    #[test]
    fn overlapping_authored_fields_fail_before_any_transform() {
        let mut plugin = plugin(&[0x31, 0xc0, 0xc3]);
        let data = plugin.module.symbols[1].id.clone();
        plugin.module.references.extend([
            reference(
                data.clone(),
                0,
                SymbolId::HostImageBase,
                0,
                LinkField::Absolute64,
            ),
            reference(
                data,
                4,
                SymbolId::HostImageBase,
                0,
                LinkField::ImageRelative32,
            ),
        ]);
        let pe = PeFile::parse(&fixture(&[0xc3], false)).unwrap();
        let host = pe.to_module();
        let error = crate::protect(
            &pe,
            &host,
            &[],
            &Options::default(),
            &Win64Default,
            &mut |_, _, _| panic!("overlapping reference transform must not run"),
            Injection {
                plugins: &[plugin],
                mode: EntryMode::Inline,
            },
        )
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("overlapping authored reference fields")
        );
    }

    #[test]
    fn unresolved_host_base_computation_keeps_host_targets_resident() {
        let pe = PeFile::parse(&fixture(&[0x31, 0xc0, 0xc3], false)).unwrap();
        let mut host = pe.to_module();
        host.functions.push(host_function(0x1000, 0x1003));
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&BASE.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x01, 0xd0, 0x48, 0x89, 0x01, 0x31, 0xc0, 0xc3]);
        let mut plugin = plugin(&code);
        plugin.module.references.push(reference(
            plugin.module.code[0].symbol.clone(),
            2,
            SymbolId::HostImageBase,
            0,
            LinkField::Absolute64,
        ));
        let (image, report) = link(&pe, &host, &[plugin], EntryMode::Inline).unwrap();
        let source = SymbolId::Host {
            rva: Rva::new(0x1000),
        };
        assert!(!report.moved.contains(&source));
        assert!(
            report
                .rejected
                .iter()
                .any(|(symbol, reason)| *symbol == source
                    && *reason == kamy_core::RejectionReason::InvalidReference)
        );
        let output = PeFile::parse(&image).unwrap().to_module();
        assert_eq!(
            &output.bytes_at(Rva::new(0x1000)).unwrap()[..3],
            &[0x31, 0xc0, 0xc3]
        );
    }

    #[test]
    fn certificate_and_overlay_keep_final_file_coordinates_out_of_image_maps() {
        let mut bytes = fixture(&[0xc3], false);
        let certificate_offset = bytes.len() as u32;
        let certificate = [16, 0, 0, 0, 0, 2, 2, 0, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4];
        bytes.extend_from_slice(&certificate);
        bytes.extend_from_slice(b"retained-overlay");
        put32(&mut bytes, 0x108 + 4 * 8, certificate_offset);
        put32(&mut bytes, 0x10c + 4 * 8, certificate.len() as u32);
        let pe = PeFile::parse(&bytes).unwrap();
        let (image, report) = link(
            &pe,
            &pe.to_module(),
            &[plugin(&[0x31, 0xc0, 0xc3])],
            EntryMode::Inline,
        )
        .unwrap();
        let directory = report
            .directories
            .iter()
            .find(|directory| directory.index == 4)
            .unwrap();
        assert_eq!(directory.rva, Rva::ZERO);
        let offset = directory.file_offset.unwrap() as usize;
        assert_ne!(offset, certificate_offset as usize);
        assert_eq!(&image[offset..offset + certificate.len()], &certificate);
        assert!(image.ends_with(b"retained-overlay"));
        assert!(
            directory.contributions.iter().all(
                |source| source.source_rva.is_none() && source.ownership == Ownership::Retained
            )
        );
        assert!(!report.address_map.contains_key(&SymbolId::Generated {
            name: "certificate".into()
        }));
    }
}
