use std::collections::HashMap;
use std::sync::LazyLock;

use super::phys::{Gpr, PhysReg, X86Flag, XmmReg};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiClass {
    Integer,
    Float,
    Vector,
    Pointer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiLocation {
    Register(PhysReg),
    /// Byte offset from the callee entry RSP, including the return address.
    Stack {
        offset: i32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiPassing {
    Direct,
    Indirect { size: u64, align: u32 },
    Sret { size: u64, align: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbiValue {
    pub location: AbiLocation,
    pub class: AbiClass,
    pub bits: u16,
    pub passing: AbiPassing,
}

impl AbiValue {
    pub fn register(reg: PhysReg) -> Self {
        let (class, bits) = match reg {
            PhysReg::Xmm(_) => (AbiClass::Vector, 128),
            _ => (AbiClass::Integer, 64),
        };
        Self {
            location: AbiLocation::Register(reg),
            class,
            bits,
            passing: AbiPassing::Direct,
        }
    }

    pub fn register_location(&self) -> Option<PhysReg> {
        match self.location {
            AbiLocation::Register(reg) => Some(reg),
            AbiLocation::Stack { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FnSignature {
    pub args: Vec<AbiValue>,
    pub returns: Vec<AbiValue>,
    pub clobbers: Vec<PhysReg>,
    pub noreturn: bool,
}

pub trait CallingConvLookup {
    fn lookup(&self, target_va: u64) -> Option<FnSignature>;
    fn lookup_symbol(&self, _symbol: &crate::symbol::SymbolId) -> Option<FnSignature> {
        None
    }
}

/// The four Win64 integer-argument registers, in positional order.
const WIN64_ARG_GPRS: [Gpr; 4] = [Gpr::Rcx, Gpr::Rdx, Gpr::R8, Gpr::R9];

/// The four Win64 floating-point argument registers, in positional order.
const WIN64_ARG_XMMS: [XmmReg; 4] = [XmmReg::Xmm0, XmmReg::Xmm1, XmmReg::Xmm2, XmmReg::Xmm3];

/// The volatile set is independent of the argument and return shape.
pub fn win64_volatiles() -> Vec<PhysReg> {
    use Gpr::*;
    use XmmReg::*;
    vec![
        PhysReg::Gpr(Rax),
        PhysReg::Gpr(Rcx),
        PhysReg::Gpr(Rdx),
        PhysReg::Gpr(R8),
        PhysReg::Gpr(R9),
        PhysReg::Gpr(R10),
        PhysReg::Gpr(R11),
        PhysReg::Xmm(Xmm0),
        PhysReg::Xmm(Xmm1),
        PhysReg::Xmm(Xmm2),
        PhysReg::Xmm(Xmm3),
        PhysReg::Xmm(Xmm4),
        PhysReg::Xmm(Xmm5),
        PhysReg::Flag(X86Flag::Cf),
        PhysReg::Flag(X86Flag::Pf),
        PhysReg::Flag(X86Flag::Af),
        PhysReg::Flag(X86Flag::Zf),
        PhysReg::Flag(X86Flag::Sf),
        PhysReg::Flag(X86Flag::Of),
    ]
}

/// A Win64 signature with `int_args` integer-class arguments (capped at the
/// four register slots), the RAX return, and the full volatile clobber set.
fn win64_sig(int_args: usize, noreturn: bool) -> FnSignature {
    FnSignature {
        args: WIN64_ARG_GPRS
            .iter()
            .take(int_args.min(WIN64_ARG_GPRS.len()))
            .map(|g| AbiValue::register(PhysReg::Gpr(*g)))
            .collect(),
        returns: vec![AbiValue::register(PhysReg::Gpr(Gpr::Rax))],
        clobbers: win64_volatiles(),
        noreturn,
    }
}

/// Conservative integer-call contract for unresolved host calls. Authored calls
/// require a compiler-produced contract instead.
pub struct Win64Default;

impl Win64Default {
    pub fn default_signature() -> FnSignature {
        win64_sig(WIN64_ARG_GPRS.len(), false)
    }
}

impl CallingConvLookup for Win64Default {
    fn lookup(&self, _target_va: u64) -> Option<FnSignature> {
        Some(Self::default_signature())
    }
}

/// CRT functions with a fixed Win64 register-argument shape. The C runtime
/// (`msvcrt`/`ucrt`) is not part of Win32 metadata, so these are curated. An
/// entry must never undercount the register arguments — an undercount leaves
/// the real argument register unpinned and miscompiles the call. Variadic CRT
/// functions (`printf`, `sprintf`, …) and float-returning ones (`atof`,
/// `strtod`, the `<math.h>` surface — their result is in XMM0, which
/// the curated integer-only table cannot classify) are intentionally absent.
fn crt_signature(name: &str) -> Option<FnSignature> {
    let (int_args, noreturn) = match name {
        "abort" => (0, true),
        "exit" | "_exit" | "_Exit" | "quick_exit" => (1, true),
        "malloc" | "free" | "strlen" | "wcslen" | "puts" | "putchar" | "_strdup" | "_wcsdup"
        | "fflush" | "fclose" | "rewind" | "ftell" | "atoi" | "atol" | "atoll" | "_atoi64"
        | "tolower" | "toupper" | "isdigit" | "isalpha" | "isspace" | "isalnum"
        | "__acrt_iob_func" => (1, false),
        "calloc" | "realloc" | "strcmp" | "wcscmp" | "strcpy" | "wcscpy" | "strcat" | "wcscat"
        | "strchr" | "strrchr" | "strstr" | "fopen" | "_wfopen" | "fputs" => (2, false),
        "memcpy" | "memmove" | "memset" | "memcmp" | "memchr" | "strncmp" | "wcsncmp"
        | "strncpy" | "wcsncpy" | "strncat" | "fgets" | "fseek" | "strtol" | "strtoul" => {
            (3, false)
        }
        "fwrite" | "fread" => (4, false),
        _ => return None,
    };
    Some(win64_sig(int_args, noreturn))
}

/// Precise Win64 signature for a named import: the curated CRT table first (the
/// C runtime is outside Win32 metadata), then the generated Win32 metadata DB
/// (grilling D14). Unknown names fall back to the four-argument Win64 default
/// at the call site.
pub fn win64_import_signature(name: &str) -> Option<FnSignature> {
    if let Some(sig) = crt_signature(name) {
        return Some(sig);
    }
    IMPORT_DB.get(name).map(packed_to_signature)
}

// ── Win32 metadata DB (grilling D14) ─────────────────────────────────────────

/// Compact `name -> packed signature` table generated offline from
/// `Windows.Win32.winmd` by `tools/win32cc-gen`. Embedded so the shipping
/// binary needs no external metadata file, and decoded once into a shared map
/// (D14: parse once, share across jobs).
static WIN32_DB: &[u8] = include_bytes!("../../data/win32cc.bin");
static IMPORT_DB: LazyLock<HashMap<Box<str>, PackedSig>> =
    LazyLock::new(|| decode_import_db(WIN32_DB));

#[derive(Clone, Copy)]
struct PackedSig {
    /// Register-argument slots used (0..=4).
    arg_regs: u8,
    /// Bit `i` set => argument slot `i` is a floating-point (XMM) register.
    float_mask: u8,
    /// 0 = void, 1 = RAX (integer/pointer class), 2 = XMM0 (float).
    ret: u8,
}

/// Decode the `KCC1` blob. Malformed or truncated input yields an empty table,
/// so the engine simply keeps the Win64 default for every call.
fn decode_import_db(bytes: &[u8]) -> HashMap<Box<str>, PackedSig> {
    let mut map = HashMap::new();
    if bytes.len() < 8 || &bytes[..4] != b"KCC1" {
        return map;
    }
    let count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let mut off = 8;
    for _ in 0..count {
        let Some(&len) = bytes.get(off) else { break };
        off += 1;
        let Some(name) = bytes.get(off..off + len as usize) else {
            break;
        };
        off += len as usize;
        let Some(fields) = bytes.get(off..off + 4) else {
            break;
        };
        off += 4;
        if let Ok(name) = std::str::from_utf8(name) {
            map.insert(
                name.into(),
                PackedSig {
                    arg_regs: fields[0],
                    float_mask: fields[1],
                    ret: fields[2],
                },
            );
        }
    }
    map
}

fn packed_to_signature(p: &PackedSig) -> FnSignature {
    let n = (p.arg_regs as usize).min(WIN64_ARG_GPRS.len());
    let args = (0..n)
        .map(|i| {
            if p.float_mask & (1 << i) != 0 {
                AbiValue {
                    class: AbiClass::Float,
                    bits: 64,
                    ..AbiValue::register(PhysReg::Xmm(WIN64_ARG_XMMS[i]))
                }
            } else {
                AbiValue::register(PhysReg::Gpr(WIN64_ARG_GPRS[i]))
            }
        })
        .collect();
    let returns = match p.ret {
        0 => Vec::new(),
        2 => vec![AbiValue {
            class: AbiClass::Float,
            bits: 64,
            ..AbiValue::register(PhysReg::Xmm(XmmReg::Xmm0))
        }],
        _ => vec![AbiValue::register(PhysReg::Gpr(Gpr::Rax))],
    };
    FnSignature {
        args,
        returns,
        clobbers: win64_volatiles(),
        noreturn: false,
    }
}

/// Calling-convention lookup backed by a precomputed `target VA → signature`
/// map (import slots and import thunks resolved to [`win64_import_signature`]),
/// falling back to the Win64 default for every unresolved target — including
/// the `0` address an unresolvable indirect call passes.
pub struct MapCallConv {
    by_va: HashMap<u64, FnSignature>,
    default: FnSignature,
}

impl MapCallConv {
    pub fn new(by_va: HashMap<u64, FnSignature>) -> Self {
        Self {
            by_va,
            default: Win64Default::default_signature(),
        }
    }

    pub fn len(&self) -> usize {
        self.by_va.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_va.is_empty()
    }
}

impl CallingConvLookup for MapCallConv {
    fn lookup(&self, target_va: u64) -> Option<FnSignature> {
        Some(
            self.by_va
                .get(&target_va)
                .cloned()
                .unwrap_or_else(|| self.default.clone()),
        )
    }
}
