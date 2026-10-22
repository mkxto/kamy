use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail, ensure};
use kamy_core::ir::{
    AbiClass, AbiLocation, AbiPassing, AbiValue, FnSignature, Gpr, PhysReg, X86Flag, XmmReg,
    win64_volatiles,
};

#[derive(Clone, Debug)]
pub(super) struct CompilerMetadata {
    pub version: String,
    pub ir: String,
    pub machine: String,
}

#[derive(Clone, Debug)]
struct ValueType {
    class: AbiClass,
    bits: u16,
    size: u64,
    align: u32,
    pieces: Vec<ValueType>,
    repeat: usize,
}

impl ValueType {
    fn scalar(class: AbiClass, bits: u16) -> Self {
        let size = u64::from(bits).div_ceil(8);
        Self {
            class,
            bits,
            size,
            align: u32::try_from(size.next_power_of_two().min(16)).unwrap_or(16),
            pieces: Vec::new(),
            repeat: 1,
        }
    }

    fn flatten(&self, output: &mut Vec<(AbiClass, u16)>) -> anyhow::Result<()> {
        for _ in 0..self.repeat {
            if self.pieces.is_empty() {
                if self.bits != 0 {
                    ensure!(
                        output.len() < 64,
                        "LLVM direct ABI exceeds 64 scalar pieces"
                    );
                    output.push((self.class, self.bits));
                }
            } else {
                for piece in &self.pieces {
                    piece.flatten(output)?;
                }
            }
        }
        Ok(())
    }
}

struct Definition {
    args: Vec<(AbiClass, u16, AbiPassing)>,
    returns: Vec<(AbiClass, u16)>,
    noreturn: bool,
    requires_call_mask: bool,
}

fn split_top(text: &str, delimiter: char) -> anyhow::Result<Vec<&str>> {
    let mut depth = 0i32;
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut result = Vec::new();
    for (index, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            continue;
        }
        match ch {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            _ => {}
        }
        ensure!(depth >= 0, "unbalanced LLVM ABI record");
        if ch == delimiter && depth == 0 {
            result.push(text[start..index].trim());
            start = index + ch.len_utf8();
        }
    }
    ensure!(depth == 0 && !quoted, "unterminated LLVM ABI record");
    if !text[start..].trim().is_empty() {
        result.push(text[start..].trim());
    }
    Ok(result)
}

fn identifier(text: &str) -> anyhow::Result<(String, &str)> {
    if let Some(quoted) = text.strip_prefix('"') {
        let end = quoted.find('"').context("unterminated LLVM symbol")?;
        ensure!(
            !quoted[..end].contains('\\'),
            "escaped LLVM symbol names are unsupported"
        );
        Ok((quoted[..end].to_owned(), &quoted[end + 1..]))
    } else {
        let end = text
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '-')))
            .unwrap_or(text.len());
        ensure!(end != 0, "missing LLVM symbol identity");
        Ok((text[..end].to_owned(), &text[end..]))
    }
}

fn parse_type<'a>(
    text: &'a str,
    named: &BTreeMap<String, String>,
    depth: u8,
) -> anyhow::Result<(ValueType, &'a str)> {
    ensure!(
        depth < 32,
        "recursive LLVM aggregate ABI type is unsupported"
    );
    let text = text.trim_start();
    for (name, class, bits) in [
        ("double", AbiClass::Float, 64),
        ("float", AbiClass::Float, 32),
        ("ptr", AbiClass::Pointer, 64),
        ("void", AbiClass::Integer, 0),
    ] {
        if let Some(rest) = text
            .strip_prefix(name)
            .filter(|r| r.is_empty() || !r.starts_with(|c: char| c.is_ascii_alphanumeric()))
        {
            ensure!(
                !rest.trim_start().starts_with("addrspace"),
                "non-default LLVM address spaces are unsupported"
            );
            return Ok((ValueType::scalar(class, bits), rest));
        }
    }
    if let Some(integer) = text.strip_prefix('i') {
        let length = integer.bytes().take_while(u8::is_ascii_digit).count();
        if length != 0 {
            let bits: u16 = integer[..length].parse()?;
            ensure!(
                matches!(bits, 1 | 8 | 16 | 32 | 64),
                "unsupported LLVM integer ABI width i{bits}"
            );
            return Ok((
                ValueType::scalar(AbiClass::Integer, bits),
                &integer[length..],
            ));
        }
    }
    if let Some(rest) = text.strip_prefix('%') {
        let (name, rest) = identifier(rest)?;
        let definition = named
            .get(&name)
            .with_context(|| format!("unknown LLVM aggregate type %{name}"))?;
        let (ty, trailing) = parse_type(definition, named, depth + 1)?;
        ensure!(
            trailing.trim().is_empty(),
            "unsupported LLVM named aggregate definition"
        );
        return Ok((ty, rest));
    }
    let packed = text.starts_with("<{");
    if text.starts_with('{') || packed {
        let opening = if packed { 2 } else { 1 };
        let closing = if packed { "}>" } else { "}" };
        let mut nesting = 1i32;
        let mut end = None;
        for (index, ch) in text[opening..].char_indices() {
            if ch == '{' {
                nesting += 1;
            }
            if ch == '}' {
                nesting -= 1;
            }
            if nesting == 0 {
                end = Some(opening + index);
                break;
            }
        }
        let end = end.context("unterminated LLVM aggregate type")?;
        ensure!(text[end..].starts_with(closing), "invalid packed LLVM type");
        let mut pieces = Vec::new();
        let mut size = 0u64;
        let mut align = 1u32;
        for member in split_top(&text[opening..end], ',')? {
            let (ty, rest) = parse_type(member, named, depth + 1)?;
            ensure!(rest.trim().is_empty(), "unsupported LLVM aggregate member");
            let member_align = if packed { 1 } else { ty.align };
            size = size
                .checked_add(u64::from(member_align) - 1)
                .context("LLVM aggregate size overflow")?
                / u64::from(member_align)
                * u64::from(member_align);
            size = size
                .checked_add(ty.size)
                .context("LLVM aggregate size overflow")?;
            align = align.max(member_align);
            pieces.push(ty);
        }
        size = size
            .checked_add(u64::from(align) - 1)
            .context("LLVM aggregate size overflow")?
            / u64::from(align)
            * u64::from(align);
        return Ok((
            ValueType {
                class: AbiClass::Integer,
                bits: 0,
                size,
                align,
                pieces,
                repeat: 1,
            },
            &text[end + closing.len()..],
        ));
    }
    if let Some(array) = text.strip_prefix('[') {
        let (count, element) = array
            .split_once(" x ")
            .context("unsupported LLVM array ABI type")?;
        let count: usize = count.trim().parse()?;
        ensure!(
            count <= 4096,
            "LLVM aggregate ABI array exceeds supported bound"
        );
        let (element, rest) = parse_type(element, named, depth + 1)?;
        let rest = rest
            .trim_start()
            .strip_prefix(']')
            .context("unterminated LLVM array type")?;
        let size = element
            .size
            .checked_mul(u64::try_from(count)?)
            .context("LLVM array size overflow")?;
        return Ok((
            ValueType {
                class: AbiClass::Integer,
                bits: 0,
                size,
                align: element.align,
                pieces: vec![element],
                repeat: count,
            },
            rest,
        ));
    }
    bail!("unsupported LLVM ABI type: {text}")
}

fn definitions(ir: &str) -> anyhow::Result<BTreeMap<String, Definition>> {
    ensure!(
        ir.lines()
            .any(|l| l.trim() == "target triple = \"x86_64-pc-windows-msvc\""),
        "authored ABI requires the x86_64-pc-windows-msvc compiler target"
    );
    ensure!(ir.lines().any(|l| l.trim() == "target datalayout = \"e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128\""), "unsupported LLVM authored aggregate data layout");
    let mut named = BTreeMap::new();
    let mut attributes = BTreeMap::new();
    for line in ir.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix('%') {
            if let Some((name, ty)) = rest.split_once(" = type ") {
                named.insert(name.trim_matches('"').to_owned(), ty.to_owned());
            }
        }
        if let Some(rest) = line.strip_prefix("attributes #") {
            if let Some((number, value)) = rest.split_once(" = ") {
                attributes.insert(number, value);
            }
        }
    }
    let mut result = BTreeMap::new();
    for line in ir
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("define "))
    {
        let (prefix, symbol) = line
            .strip_prefix("define ")
            .unwrap()
            .split_once('@')
            .context("LLVM function lacks symbol")?;
        let requires_call_mask = prefix.split_whitespace().any(|w| w == "fastcc");
        ensure!(
            !prefix
                .split_whitespace()
                .any(|w| (w.ends_with("cc") && !matches!(w, "ccc" | "fastcc")) || w == "cc"),
            "unsupported LLVM authored calling convention: {prefix}"
        );
        let (name, after_name) = identifier(symbol)?;
        let args_text = after_name
            .strip_prefix('(')
            .context("LLVM function lacks argument list")?;
        let mut depth = 1i32;
        let mut end = None;
        for (index, ch) in args_text.char_indices() {
            if ch == '(' {
                depth += 1;
            }
            if ch == ')' {
                depth -= 1;
            }
            if depth == 0 {
                end = Some(index);
                break;
            }
        }
        let end = end.context("multiline LLVM function headers are unsupported")?;
        let suffix = &args_text[end + 1..];
        let mut attrs = suffix.to_owned();
        for word in suffix
            .split_whitespace()
            .filter_map(|w| w.strip_prefix('#'))
        {
            attrs.push_str(
                attributes
                    .get(word)
                    .context("missing LLVM attribute group")?,
            );
        }
        ensure!(
            !attrs.contains("preserve_") && !attrs.contains("no_caller_saved_registers"),
            "unsupported LLVM authored preservation contract for {name}"
        );
        let mut ret_type = None;
        for (offset, _) in prefix
            .char_indices()
            .filter(|(i, _)| *i == 0 || prefix.as_bytes()[i - 1].is_ascii_whitespace())
        {
            if let Ok((ty, rest)) = parse_type(&prefix[offset..], &named, 0) {
                if rest.trim().is_empty() {
                    ret_type = Some(ty);
                    break;
                }
            }
        }
        let ret_type =
            ret_type.with_context(|| format!("unsupported LLVM return ABI for {name}"))?;
        let mut returns = Vec::new();
        ret_type.flatten(&mut returns)?;
        let mut args = Vec::new();
        for argument in split_top(&args_text[..end], ',')? {
            ensure!(
                argument != "...",
                "variadic authored ABI is unsupported for {name}"
            );
            let (ty, rest) = parse_type(argument, &named, 0)
                .with_context(|| format!("argument ABI for {name}"))?;
            let mut passing = AbiPassing::Direct;
            for (attribute, sret) in [("sret(", true), ("byval(", false)] {
                if let Some((_, payload)) = rest.split_once(attribute) {
                    ensure!(
                        ty.class == AbiClass::Pointer,
                        "indirect aggregate ABI is not a pointer"
                    );
                    let (aggregate, tail) = parse_type(payload, &named, 0)?;
                    ensure!(
                        tail.trim_start().starts_with(')'),
                        "malformed indirect aggregate ABI"
                    );
                    let mut words = rest.split_whitespace();
                    let align = if words.any(|word| word == "align") {
                        words
                            .next()
                            .context("missing LLVM indirect aggregate alignment")?
                            .parse::<u32>()
                            .context("invalid LLVM indirect aggregate alignment")?
                    } else {
                        aggregate.align
                    };
                    ensure!(
                        align.is_power_of_two() && aggregate.size != 0,
                        "invalid indirect aggregate layout"
                    );
                    passing = if sret {
                        AbiPassing::Sret {
                            size: aggregate.size,
                            align,
                        }
                    } else {
                        AbiPassing::Indirect {
                            size: aggregate.size,
                            align,
                        }
                    };
                }
            }
            ensure!(
                !rest.contains("inalloca")
                    && !rest.contains("preallocated")
                    && !rest.contains("inreg")
                    && !rest.contains("nest")
                    && !rest.contains("swift"),
                "unsupported LLVM argument lowering attribute for {name}"
            );
            let mut pieces = Vec::new();
            ty.flatten(&mut pieces)?;
            for (class, bits) in pieces {
                args.push((class, bits, passing));
            }
        }
        ensure!(
            result
                .insert(
                    name.clone(),
                    Definition {
                        args,
                        returns,
                        requires_call_mask,
                        noreturn: attrs
                            .split(|c: char| !c.is_ascii_alphanumeric())
                            .any(|w| w == "noreturn")
                    }
                )
                .is_none(),
            "duplicate LLVM function definition {name}"
        );
    }
    ensure!(
        !result.is_empty(),
        "LLVM module contains no authored function definitions"
    );
    Ok(result)
}

fn register(text: &str) -> anyhow::Result<PhysReg> {
    let text = text.trim().trim_start_matches('$');
    let text = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("");
    let gpr = match text {
        "rax" | "eax" | "ax" | "al" => Some(Gpr::Rax),
        "rcx" | "ecx" | "cx" | "cl" => Some(Gpr::Rcx),
        "rdx" | "edx" | "dx" | "dl" => Some(Gpr::Rdx),
        "r8" | "r8d" | "r8w" | "r8b" => Some(Gpr::R8),
        "r9" | "r9d" | "r9w" | "r9b" => Some(Gpr::R9),
        "rbx" | "ebx" | "bx" | "bl" => Some(Gpr::Rbx),
        "rsi" | "esi" | "si" | "sil" => Some(Gpr::Rsi),
        "rdi" | "edi" | "di" | "dil" => Some(Gpr::Rdi),
        "r10" | "r10d" | "r10w" | "r10b" => Some(Gpr::R10),
        "r11" | "r11d" | "r11w" | "r11b" => Some(Gpr::R11),
        _ => None,
    };
    if let Some(gpr) = gpr {
        return Ok(PhysReg::Gpr(gpr));
    }
    if let Some(index) = text.strip_prefix("xmm") {
        let index: usize = index.parse().context("invalid compiler XMM ABI register")?;
        return Ok(PhysReg::Xmm(
            *XmmReg::ALL
                .get(index)
                .context("unsupported compiler XMM ABI register")?,
        ));
    }
    bail!("unsupported compiler ABI register ${text}")
}

fn register_list(text: &str) -> anyhow::Result<Vec<PhysReg>> {
    text.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| register(s.split_whitespace().next().unwrap_or("")))
        .collect()
}

fn value(
    location: AbiLocation,
    ty: (AbiClass, u16),
    passing: AbiPassing,
) -> anyhow::Result<AbiValue> {
    if let AbiLocation::Register(reg) = location {
        ensure!(
            matches!(
                (reg, ty.0),
                (PhysReg::Gpr(_), AbiClass::Integer | AbiClass::Pointer)
                    | (PhysReg::Xmm(_), AbiClass::Float | AbiClass::Vector)
            ),
            "compiler register class differs from LLVM ABI type"
        );
    }
    Ok(AbiValue {
        location,
        class: ty.0,
        bits: ty.1,
        passing,
    })
}

pub(super) fn signatures(
    metadata: &CompilerMetadata,
    callback: Option<&str>,
) -> anyhow::Result<BTreeMap<String, FnSignature>> {
    ensure!(
        metadata.version.split('-').next() == Some("22.1.2"),
        "unsupported LLVM ABI dump version {}; rebuild with matching LLVM 22.1.2 tools",
        metadata.version
    );
    let definitions = definitions(&metadata.ir)?;
    if let Some(name) = callback {
        let declared = definitions
            .get(name)
            .context("selected SDK callback lacks an LLVM definition")?;
        ensure!(
            !declared.requires_call_mask
                && !declared.noreturn
                && declared.args.as_slice() == [(AbiClass::Pointer, 64, AbiPassing::Direct); 3]
                && declared.returns == [(AbiClass::Integer, 32)],
            "declared SDK callback differs from kamy_sdk::Entry"
        );
    }
    let mut output = BTreeMap::new();
    let mut tails = Vec::new();
    let mut call_clobbers: BTreeMap<String, Vec<PhysReg>> = BTreeMap::new();
    for line in metadata
        .machine
        .lines()
        .filter(|l| l.contains("CALL64pcrel32 ") || l.contains("TCRETURNdi64 "))
    {
        let target = line
            .split_once('@')
            .context("compiler direct call lacks symbol identity")?
            .1;
        let (target, _) = identifier(target)?;
        let mask = line
            .split_once("<regmask")
            .context("compiler call lacks an authoritative preservation mask")?
            .1
            .split_once('>')
            .context("unterminated compiler preservation mask")?
            .0;
        ensure!(
            !mask.contains("...") && !mask.contains("more"),
            "truncated compiler preservation mask; producer MUST use -print-regmask-num-regs=-1"
        );
        let preserved: BTreeSet<_> = mask
            .split_whitespace()
            .map(|s| s.trim_start_matches('$'))
            .collect();
        let mut clobbers = Vec::new();
        for reg in Gpr::ALL {
            if reg == Gpr::Rsp {
                continue;
            }
            let name = format!("{reg:?}").to_ascii_lowercase();
            if !preserved.contains(name.as_str()) {
                clobbers.push(PhysReg::Gpr(reg));
            }
        }
        for reg in XmmReg::ALL {
            let name = format!("{reg:?}").to_ascii_lowercase();
            if !preserved.contains(name.as_str()) {
                clobbers.push(PhysReg::Xmm(reg));
            }
        }
        clobbers.extend(X86Flag::ALL.into_iter().map(PhysReg::Flag));
        if let Some(previous) = call_clobbers.insert(target.clone(), clobbers.clone()) {
            ensure!(
                previous == clobbers,
                "inconsistent native call preservation contract for {target}"
            );
        }
    }
    for block in metadata
        .machine
        .split("# Machine code for function ")
        .skip(1)
    {
        let (header, body) = block
            .split_once('\n')
            .context("truncated compiler machine function")?;
        let (name, _) = header
            .rsplit_once(": ")
            .context("malformed compiler machine function header")?;
        let end_marker = format!("# End machine code for function {name}.");
        let body = body
            .split_once(&end_marker)
            .context("truncated compiler machine function body")?
            .0;
        let definition = definitions
            .get(name)
            .with_context(|| format!("native machine function {name} lacks an LLVM contract"))?;
        let registers = body
            .lines()
            .find_map(|l| l.strip_prefix("Function Live Ins: "))
            .map(register_list)
            .transpose()?
            .unwrap_or_default();
        let mut stack = Vec::new();
        for line in body
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("fi#-") && l.contains(", fixed,"))
        {
            let offset = line
                .split_once("at location [SP")
                .context("fixed compiler argument lacks stack location")?
                .1
                .split_once(']')
                .context("unterminated compiler stack location")?
                .0;
            let offset = if offset.is_empty() {
                0
            } else {
                offset.parse::<i32>()?
            };
            ensure!(
                offset >= 40,
                "unsupported fixed compiler stack object at callee RSP{offset:+}"
            );
            stack.push(offset);
        }
        stack.sort_unstable();
        let args = if callback == Some(name) {
            let expected = [Gpr::Rcx, Gpr::Rdx, Gpr::R8];
            ensure!(
                stack.is_empty()
                    && registers
                        .iter()
                        .all(|r| expected.iter().any(|g| *r == PhysReg::Gpr(*g))),
                "native SDK callback has inputs incompatible with its declared Entry ABI"
            );
            expected
                .into_iter()
                .map(|reg| {
                    value(
                        AbiLocation::Register(PhysReg::Gpr(reg)),
                        (AbiClass::Pointer, 64),
                        AbiPassing::Direct,
                    )
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        } else if definition.noreturn && registers.is_empty() && stack.is_empty() {
            Vec::new()
        } else {
            ensure!(
                registers.len() + stack.len() == definition.args.len(),
                "compiler argument location/type count mismatch for {name}: {} register + {} stack versus {} typed pieces",
                registers.len(),
                stack.len(),
                definition.args.len()
            );
            let locations = registers.into_iter().map(AbiLocation::Register).chain(
                stack
                    .into_iter()
                    .map(|offset| AbiLocation::Stack { offset }),
            );
            locations
                .zip(&definition.args)
                .map(|(location, &(class, bits, passing))| value(location, (class, bits), passing))
                .collect::<anyhow::Result<Vec<_>>>()?
        };
        let mut return_registers: Option<Vec<PhysReg>> = None;
        let mut tail_target = None;
        for line in body.lines().map(str::trim) {
            if let Some(ret) = line
                .strip_prefix("RET ")
                .or_else(|| line.strip_prefix("RET64 "))
            {
                let (_, operands) = ret.split_once(',').unwrap_or((ret, ""));
                let regs = register_list(operands)?;
                if let Some(previous) = &return_registers {
                    ensure!(
                        *previous == regs,
                        "inconsistent compiler return registers for {name}"
                    );
                }
                return_registers = Some(regs);
            }
            if let Some(tail) = line.split("TCRETURNdi64 ").nth(1) {
                let target = tail
                    .trim_start()
                    .strip_prefix('@')
                    .context("unsupported indirect authored tail ABI")?;
                tail_target = Some(identifier(target)?.0);
            }
        }
        let mut return_types = definition.returns.clone();
        if return_types.is_empty() && return_registers.as_ref().is_some_and(|r| r.len() == 1) {
            ensure!(
                args.iter()
                    .any(|a| matches!(a.passing, AbiPassing::Sret { .. })),
                "untyped compiler return for {name}"
            );
            return_types.push((AbiClass::Pointer, 64));
        }
        let returns = if let Some(regs) = return_registers {
            ensure!(
                regs.len() == return_types.len(),
                "compiler return location/type count mismatch for {name}"
            );
            regs.into_iter()
                .zip(return_types)
                .map(|(reg, ty)| value(AbiLocation::Register(reg), ty, AbiPassing::Direct))
                .collect::<anyhow::Result<Vec<_>>>()?
        } else if definition.noreturn {
            Vec::new()
        } else if let Some(target) = tail_target {
            tails.push((name.to_owned(), target, return_types));
            Vec::new()
        } else {
            bail!("compiler function {name} has no authoritative return boundary");
        };
        ensure!(
            !definition.requires_call_mask || call_clobbers.contains_key(name),
            "compiler nondefault calling convention for {name} lacks a captured native preservation mask"
        );
        let clobbers = call_clobbers
            .get(name)
            .cloned()
            .unwrap_or_else(win64_volatiles);
        ensure!(
            output
                .insert(
                    name.to_owned(),
                    FnSignature {
                        args,
                        returns,
                        clobbers,
                        noreturn: definition.noreturn
                    }
                )
                .is_none(),
            "duplicate compiler machine contract for {name}"
        );
    }
    for _ in 0..=tails.len() {
        if tails.is_empty() {
            break;
        }
        let mut remaining = Vec::new();
        for (name, target, types) in tails {
            let Some(signature) = output
                .get(&target)
                .filter(|s| !s.returns.is_empty() || types.is_empty())
                .cloned()
            else {
                remaining.push((name, target, types));
                continue;
            };
            ensure!(
                signature
                    .returns
                    .iter()
                    .map(|v| (v.class, v.bits))
                    .eq(types),
                "tail-call return ABI differs for {name}"
            );
            output.get_mut(&name).unwrap().returns = signature.returns;
        }
        tails = remaining;
    }
    ensure!(tails.is_empty(), "unresolved compiler tail-return ABI");
    ensure!(
        output.len() == definitions.len(),
        "compiler dump omitted authored function contracts"
    );
    Ok(output)
}

pub(super) fn validate_callback(signature: &FnSignature) -> anyhow::Result<()> {
    let registers = [Gpr::Rcx, Gpr::Rdx, Gpr::R8];
    ensure!(
        !signature.noreturn && signature.args.len() == registers.len(),
        "SDK callback MUST return and accept the three original Win64 entry pointers"
    );
    for (value, register) in signature.args.iter().zip(registers) {
        ensure!(
            value.location == AbiLocation::Register(PhysReg::Gpr(register))
                && value.class == AbiClass::Pointer
                && value.bits == 64
                && value.passing == AbiPassing::Direct,
            "SDK callback argument ABI differs from kamy_sdk::Entry"
        );
    }
    ensure!(
        signature.returns.len() == 1
            && signature.returns[0]
                == AbiValue {
                    location: AbiLocation::Register(PhysReg::Gpr(Gpr::Rax)),
                    class: AbiClass::Integer,
                    bits: 32,
                    passing: AbiPassing::Direct,
                },
        "SDK callback MUST return a 32-bit integer status in RAX"
    );
    Ok(())
}
