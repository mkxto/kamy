//! Offline generator for the Win32 calling-convention DB (grilling D14).
//!
//! Reads a `Windows.Win32.winmd` (ECMA-335) and emits a compact binary table
//! of `name -> (register-arg classes, return class)` for every non-variadic
//! Win32 free function whose signature lowers soundly to the Win64 register
//! ABI. The table is consumed by `kamy-core` via `include_bytes!`.
//!
//! Soundness rules (a wrong narrowing miscompiles; when unsure we omit the
//! function so the caller keeps the four-argument Win64 default):
//! - Argument register class: a by-value `f32`/`f64` occupies the positional
//!   XMM register; every other argument (ints, pointers, handles, by-value
//!   aggregates — passed in a GPR or by reference) occupies the positional GPR.
//! - Return class: void / RAX (int, pointer, enum, <=8-byte single-field
//!   wrapper struct) / XMM0 (float). A return larger than 8 bytes may introduce
//!   a hidden RCX result pointer that shifts every argument register, so such
//!   functions are omitted.
//! - Variadic functions are omitted (a caller may pass more register arguments
//!   than the fixed prototype declares).

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use windows_metadata::reader::{File, Index, Item, TypeCategory};
use windows_metadata::{MethodCallAttributes, Type};

/// X64 architecture bit for `Index::new_for_architecture`.
const ARCH_X64: i32 = 2;
const MAGIC: &[u8; 4] = b"KCC1";

#[derive(Clone, Copy, PartialEq, Eq)]
struct Packed {
    arg_regs: u8,
    float_mask: u8,
    ret: u8,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let winmd = args.next().context("usage: win32cc-gen <winmd> <out.bin>")?;
    let out = args.next().context("usage: win32cc-gen <winmd> <out.bin>")?;

    let file = File::read(&winmd).with_context(|| format!("reading winmd {winmd}"))?;
    let index = Index::new_for_architecture(vec![file], ARCH_X64);

    // None marks an ambiguous name (same export, divergent signatures); omit it.
    let mut map: BTreeMap<String, Option<Packed>> = BTreeMap::new();
    let (mut scanned, mut variadic, mut bailed) = (0usize, 0usize, 0usize);

    for (_ns, name, item) in index.iter_items() {
        let Item::Fn(method) = item else { continue };
        scanned += 1;
        let sig = method.signature(&[]);
        if sig.flags.contains(MethodCallAttributes::VARARG) {
            variadic += 1;
            continue;
        }
        let Some(ret) = classify_ret(&sig.return_type, &index, 0) else {
            bailed += 1;
            continue;
        };
        let arg_regs = sig.types.len().min(4);
        let mut float_mask = 0u8;
        for (i, ty) in sig.types.iter().take(arg_regs).enumerate() {
            if is_float(ty) {
                float_mask |= 1 << i;
            }
        }
        let packed = Packed {
            arg_regs: arg_regs as u8,
            float_mask,
            ret,
        };
        map.entry(name.to_string())
            .and_modify(|e| {
                if *e != Some(packed) {
                    *e = None;
                }
            })
            .or_insert(Some(packed));
    }

    let entries: Vec<(&String, Packed)> = map
        .iter()
        .filter_map(|(k, v)| v.map(|p| (k, p)))
        .collect();

    let mut blob = Vec::new();
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, p) in &entries {
        let bytes = name.as_bytes();
        if bytes.len() > u8::MAX as usize {
            continue;
        }
        blob.push(bytes.len() as u8);
        blob.extend_from_slice(bytes);
        blob.push(p.arg_regs);
        blob.push(p.float_mask);
        blob.push(p.ret);
        blob.push(0); // flags (noreturn reserved)
    }

    std::fs::write(&out, &blob).with_context(|| format!("writing {out}"))?;
    eprintln!(
        "scanned {scanned} fns: emitted {} ({} bytes), variadic {variadic}, bailed {bailed}",
        entries.len(),
        blob.len()
    );
    if entries.is_empty() {
        bail!("no entries emitted; metadata layout unexpected");
    }
    Ok(())
}

fn is_float(ty: &Type) -> bool {
    matches!(ty, Type::F32 | Type::F64)
}

/// Return class code: 0 = void, 1 = RAX (int/pointer class), 2 = XMM0 (float).
/// `None` means bail (omit the function).
fn classify_ret(ty: &Type, index: &Index, depth: u32) -> Option<u8> {
    Some(match ty {
        Type::Void => 0,
        Type::F32 | Type::F64 => 2,
        Type::Bool
        | Type::Char
        | Type::I8
        | Type::U8
        | Type::I16
        | Type::U16
        | Type::I32
        | Type::U32
        | Type::I64
        | Type::U64
        | Type::ISize
        | Type::USize
        | Type::PtrMut(..)
        | Type::PtrConst(..)
        | Type::String
        | Type::Object
        | Type::ClassName(_) => 1,
        Type::ValueName(tn) => return classify_value_ret(&tn.namespace, &tn.name, index, depth),
        _ => return None,
    })
}

fn classify_value_ret(namespace: &str, name: &str, index: &Index, depth: u32) -> Option<u8> {
    if depth > 4 {
        return None;
    }
    let td = index.get(namespace, name).next()?;
    match td.category() {
        TypeCategory::Enum => Some(1),
        TypeCategory::Struct => {
            let fields: Vec<_> = td.fields().collect();
            if fields.len() != 1 {
                return None;
            }
            let fty = fields[0].ty();
            let size = scalar_size(&fty, index, depth + 1)?;
            if size > 8 {
                return None;
            }
            Some(if is_float(&fty) { 2 } else { 1 })
        }
        _ => None,
    }
}

/// Byte size of a scalar/wrapper type, or `None` when it cannot be resolved to a
/// single <=8-byte value (caller then bails).
fn scalar_size(ty: &Type, index: &Index, depth: u32) -> Option<u64> {
    Some(match ty {
        Type::Bool | Type::I8 | Type::U8 => 1,
        Type::Char | Type::I16 | Type::U16 => 2,
        Type::I32 | Type::U32 | Type::F32 => 4,
        Type::I64 | Type::U64 | Type::F64 | Type::ISize | Type::USize => 8,
        Type::PtrMut(..) | Type::PtrConst(..) | Type::String | Type::Object | Type::ClassName(_) => {
            8
        }
        Type::ValueName(tn) => {
            if depth > 4 {
                return None;
            }
            let td = index.get(&tn.namespace, &tn.name).next()?;
            match td.category() {
                TypeCategory::Enum => td
                    .underlying_type()
                    .and_then(|u| scalar_size(&u, index, depth + 1))
                    .unwrap_or(4),
                TypeCategory::Struct => {
                    let fields: Vec<_> = td.fields().collect();
                    if fields.len() != 1 {
                        return None;
                    }
                    scalar_size(&fields[0].ty(), index, depth + 1)?
                }
                _ => return None,
            }
        }
        _ => return None,
    })
}
