//! Jump-table recovery (D24 layer 2, research.md §10.5).
//!
//! A per-function use-def DAG is matched against the canonical switch-dispatch
//! template with petgraph VF2 subgraph isomorphism. Register identity, constants
//! and RIP-relative operands are ignored; plain `mov`/`movsxd`/`movzx` register
//! copies are collapsed so allocator and scheduling variance do not defeat the
//! match. The entry count comes from the index bound (`cmp imm`+1 or an
//! `and` mask `2^k`); unbounded tables are rejected, and every recovered target
//! is cross-checked to land inside the function body. Ambiguity is never
//! guessed — detection fails and the `jmp reg` stays `Indirect`.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use kamy_core::{Module, Rva};
use petgraph::algo::subgraph_isomorphisms_iter;
use petgraph::graph::DiGraph;

const MAX_ENTRIES: u64 = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Lea,
    TableLoad,
    AddBase,
    Jmp,
    Other,
}

/// Canonical x86-64 switch dispatch (both MSVC module-base and LLVM
/// table-relative forms collapse to this shape):
///
/// ```text
/// Lea ───▶ TableLoad ───▶ AddBase ───▶ Jmp
///   └───────────────────────▲
/// ```
fn template() -> (DiGraph<Kind, ()>, [usize; 4]) {
    let mut g = DiGraph::<Kind, ()>::new();
    let lea = g.add_node(Kind::Lea);
    let load = g.add_node(Kind::TableLoad);
    let add = g.add_node(Kind::AddBase);
    let jmp = g.add_node(Kind::Jmp);
    g.add_edge(lea, load, ());
    g.add_edge(lea, add, ());
    g.add_edge(load, add, ());
    g.add_edge(add, jmp, ());
    (g, [lea.index(), load.index(), add.index(), jmp.index()])
}

fn gpr64(r: Register) -> Option<Register> {
    r.is_gpr().then(|| r.full_register())
}

fn is_indirect_reg_jmp(i: &Instruction) -> bool {
    i.mnemonic() == Mnemonic::Jmp && i.op0_kind() == OpKind::Register
}

fn is_reg_copy(i: &Instruction) -> bool {
    matches!(
        i.mnemonic(),
        Mnemonic::Mov | Mnemonic::Movsxd | Mnemonic::Movzx
    ) && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Register
}

fn is_table_load(i: &Instruction) -> bool {
    matches!(
        i.mnemonic(),
        Mnemonic::Mov | Mnemonic::Movsxd | Mnemonic::Movzx
    ) && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Memory
        && i.memory_index() != Register::None
        && i.memory_index_scale() == 4
}

struct Dag {
    g: DiGraph<Kind, ()>,
    iidx: Vec<usize>,
}

/// Build the register use-def DAG. `mov reg,reg` and register-form
/// `movsxd`/`movzx` are collapsed (def propagated, no node) per §10.5.
fn build_dag(instrs: &[Instruction]) -> Dag {
    use std::collections::HashMap;
    let mut g = DiGraph::<Kind, ()>::new();
    let mut iidx: Vec<usize> = Vec::new();
    let mut last_def: HashMap<Register, petgraph::graph::NodeIndex> = HashMap::new();

    let push = |g: &mut DiGraph<Kind, ()>, iidx: &mut Vec<usize>, kind: Kind, i: usize| {
        let n = g.add_node(kind);
        debug_assert_eq!(n.index(), iidx.len());
        iidx.push(i);
        n
    };

    for (i, ins) in instrs.iter().enumerate() {
        if is_indirect_reg_jmp(ins) {
            let n = push(&mut g, &mut iidx, Kind::Jmp, i);
            if let Some(src) = gpr64(ins.op0_register()).and_then(|r| last_def.get(&r)) {
                g.add_edge(*src, n, ());
            }
            continue;
        }
        if is_reg_copy(ins) {
            let (Some(d), Some(s)) = (gpr64(ins.op0_register()), gpr64(ins.op1_register())) else {
                continue;
            };
            match last_def.get(&s).copied() {
                Some(n) => {
                    last_def.insert(d, n);
                }
                None => {
                    last_def.remove(&d);
                }
            }
            continue;
        }
        if ins.mnemonic() == Mnemonic::Lea && ins.op0_kind() == OpKind::Register {
            let Some(d) = gpr64(ins.op0_register()) else {
                continue;
            };
            let kind = if ins.memory_base() == Register::RIP && ins.memory_index() == Register::None
            {
                Kind::Lea
            } else {
                Kind::Other
            };
            let n = push(&mut g, &mut iidx, kind, i);
            last_def.insert(d, n);
            continue;
        }
        if is_table_load(ins) {
            let Some(d) = gpr64(ins.op0_register()) else {
                continue;
            };
            let n = push(&mut g, &mut iidx, Kind::TableLoad, i);
            if let Some(b) = gpr64(ins.memory_base())
                .and_then(|r| last_def.get(&r))
                .copied()
            {
                g.add_edge(b, n, ());
            }
            last_def.insert(d, n);
            continue;
        }
        if ins.mnemonic() == Mnemonic::Add
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
        {
            let (Some(d), Some(s)) = (gpr64(ins.op0_register()), gpr64(ins.op1_register())) else {
                continue;
            };
            let n = push(&mut g, &mut iidx, Kind::AddBase, i);
            if let Some(a) = last_def.get(&d).copied() {
                g.add_edge(a, n, ());
            }
            if let Some(b) = last_def.get(&s).copied() {
                g.add_edge(b, n, ());
            }
            last_def.insert(d, n);
            continue;
        }
        if ins.op0_kind() == OpKind::Register {
            if let Some(d) = gpr64(ins.op0_register()) {
                let n = push(&mut g, &mut iidx, Kind::Other, i);
                last_def.insert(d, n);
            }
        }
    }

    Dag { g, iidx }
}

/// Index-bound entry count: an `and idx, 2^k-1` mask (count `2^k`) or a
/// `cmp idx, imm` bound (count `imm+1`). `None` → unbounded → reject (§10.5).
fn imm_reg_op(ins: &Instruction, index: Register) -> Option<u64> {
    use OpKind::{
        Immediate8, Immediate8to16, Immediate8to32, Immediate8to64, Immediate16, Immediate32,
        Immediate32to64, Immediate64,
    };
    let is_imm = matches!(
        ins.op1_kind(),
        Immediate8
            | Immediate8to16
            | Immediate8to32
            | Immediate8to64
            | Immediate16
            | Immediate32
            | Immediate32to64
            | Immediate64
    );
    (ins.op0_kind() == OpKind::Register && is_imm && gpr64(ins.op0_register()) == Some(index))
        .then(|| ins.immediate(1))
}

fn bound_count(instrs: &[Instruction], index: Register) -> Option<u64> {
    for ins in instrs {
        match ins.mnemonic() {
            Mnemonic::And => {
                if let Some(mask) = imm_reg_op(ins, index) {
                    if mask > 0 && mask & (mask + 1) == 0 {
                        return Some(mask + 1);
                    }
                }
            }
            Mnemonic::Cmp | Mnemonic::Sub => {
                if let Some(imm) = imm_reg_op(ins, index) {
                    return imm.checked_add(1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Recover every confident jump table in the function body `[lo, hi)`. Each
/// result pairs the exclusive end RVA of the dispatching `jmp reg` with the
/// recovered `SwitchTable`; the Vec is empty when nothing recovers. Ambiguous
/// or out-of-range matches are skipped individually — a guess is never emitted.
pub(crate) fn detect_switch(
    module: &Module,
    instrs: &[Instruction],
    lo: u32,
    hi: u32,
) -> Vec<(u32, kamy_core::SwitchTable)> {
    let mut out: Vec<(u32, kamy_core::SwitchTable)> = Vec::new();
    if !instrs.iter().any(is_indirect_reg_jmp) {
        return out;
    }
    let dag = build_dag(instrs);
    let (pat, [p_lea, p_load, _p_add, p_jmp]) = template();

    let mut nm = |a: &Kind, b: &Kind| a == b;
    let mut em = |_: &(), _: &()| true;
    let pat_ref = &pat;
    let dag_ref = &dag.g;
    let Some(iters) = subgraph_isomorphisms_iter(&pat_ref, &dag_ref, &mut nm, &mut em) else {
        return out;
    };

    for map in iters {
        let lea = &instrs[dag.iidx[map[p_lea]]];
        let load = &instrs[dag.iidx[map[p_load]]];
        let jmp = &instrs[dag.iidx[map[p_jmp]]];

        // `lea reg,[rip+d]` resolves to the absolute base VA; the table sits at
        // base + the load displacement; each case target is base + entry.
        let base_va = lea.memory_displacement64();
        let table_va = base_va.wrapping_add(load.memory_displacement64());
        let signed = load.mnemonic() == Mnemonic::Movsxd;
        let base_is_image = !signed;
        let Some(index) = gpr64(load.memory_index()) else {
            continue;
        };
        let Some(count) = bound_count(instrs, index) else {
            continue;
        };
        if count == 0 || count > MAX_ENTRIES {
            continue;
        }

        // MSVC module-base entries are measured from the image base; a base that
        // is not the image base is ambiguous, so recover nothing for it.
        if base_is_image && base_va != module.image_base {
            continue;
        }

        let Some(table_rva) = table_va
            .checked_sub(module.image_base)
            .and_then(|v| u32::try_from(v).ok())
        else {
            continue;
        };
        let Some(data) = module.bytes_at(Rva::new(table_rva)) else {
            continue;
        };
        let Some(need) = (count as usize).checked_mul(4) else {
            continue;
        };
        if data.len() < need {
            continue;
        }

        // Every slot in table order, duplicates preserved (`len == count`).
        let mut entries = Vec::with_capacity(count as usize);
        let mut ok = true;
        for k in 0..count as usize {
            let o = k * 4;
            let raw = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
            let delta = if signed {
                i64::from(raw as i32)
            } else {
                i64::from(raw)
            };
            let tgt_va = (base_va as i64).wrapping_add(delta) as u64;
            let Some(tgt_rva) = tgt_va
                .checked_sub(module.image_base)
                .and_then(|v| u32::try_from(v).ok())
            else {
                ok = false;
                break;
            };
            if tgt_rva < lo || tgt_rva >= hi {
                ok = false;
                break;
            }
            entries.push(Rva::new(tgt_rva));
        }
        if !ok {
            continue;
        }

        let jmp_end = (jmp.ip() - module.image_base) as u32 + jmp.len() as u32;
        // A dispatch may match several isomorphisms; keep the first valid table.
        if out.iter().any(|(end, _)| *end == jmp_end) {
            continue;
        }

        // LLVM retargets the `lea`; MSVC retargets the table load.
        let dispatch = if base_is_image { load } else { lea };
        let dispatch_rva = Rva::new((dispatch.ip() - module.image_base) as u32);

        out.push((
            jmp_end,
            kamy_core::SwitchTable {
                dispatch_rva,
                table_rva: Rva::new(table_rva),
                base_va,
                base_is_image,
                count: count as u32,
                entries,
            },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};
    use kamy_core::{Machine, Section, SectionFlags};

    const BASE: u64 = 0x1_4000_0000;

    fn module_with_table(tbl_rva: u32, data: Vec<u8>) -> Module {
        Module {
            image_base: BASE,
            machine: Machine::X64,
            entry_point: None,
            sections: vec![Section {
                name: ".rdata".into(),
                rva: Rva::new(tbl_rva),
                virtual_size: data.len() as u32,
                data,
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: false,
                },
            }],
            symbols: vec![],
            relocations: vec![],
            functions: vec![],
        }
    }

    fn decode(code: &[u8]) -> Vec<Instruction> {
        let mut d = Decoder::with_ip(64, code, BASE + 0x1000, DecoderOptions::NONE);
        let mut v = Vec::new();
        while d.can_decode() {
            v.push(d.decode());
        }
        v
    }

    // table-relative i32 deltas at rva 0x2000; four targets at 0x1013..0x1022.
    const TABLE: [u8; 16] = [
        0x13, 0xF0, 0xFF, 0xFF, 0x18, 0xF0, 0xFF, 0xFF, 0x1D, 0xF0, 0xFF, 0xFF, 0x22, 0xF0, 0xFF,
        0xFF,
    ];
    const EXPECT: [u32; 4] = [0x1013, 0x1018, 0x101D, 0x1022];

    #[test]
    fn recovers_mask_bounded_table() {
        // and ecx,3; lea rdx,[rip+0xff6]; movsxd rcx,[rdx+rcx*4]; add rcx,rdx; jmp rcx
        let code = [
            0x83, 0xE1, 0x03, 0x48, 0x8D, 0x15, 0xF6, 0x0F, 0x00, 0x00, 0x48, 0x63, 0x0C, 0x8A,
            0x48, 0x01, 0xD1, 0xFF, 0xE1,
        ];
        let m = module_with_table(0x2000, TABLE.to_vec());
        let tables = detect_switch(&m, &decode(&code), 0x1000, 0x1100);
        assert_eq!(tables.len(), 1);
        let (jmp_end, table) = &tables[0];
        assert_eq!(*jmp_end, 0x1013);
        assert_eq!(table.entries.len() as u32, table.count);
        assert!(!table.base_is_image);
        let mut got: Vec<u32> = table.entries.iter().map(|r| r.get()).collect();
        got.sort_unstable();
        got.dedup();
        assert_eq!(got, EXPECT);
    }

    #[test]
    fn recovers_cmp_bounded_table() {
        // cmp ecx,3; lea rdx,[rip+0xff6]; movsxd rcx,[rdx+rcx*4]; add rcx,rdx; jmp rcx
        let code = [
            0x83, 0xF9, 0x03, 0x48, 0x8D, 0x15, 0xF6, 0x0F, 0x00, 0x00, 0x48, 0x63, 0x0C, 0x8A,
            0x48, 0x01, 0xD1, 0xFF, 0xE1,
        ];
        let m = module_with_table(0x2000, TABLE.to_vec());
        let tables = detect_switch(&m, &decode(&code), 0x1000, 0x1100);
        assert_eq!(tables.len(), 1);
        let (_, table) = &tables[0];
        assert_eq!(table.entries.len() as u32, table.count);
        assert!(!table.base_is_image);
        let mut got: Vec<u32> = table.entries.iter().map(|r| r.get()).collect();
        got.sort_unstable();
        got.dedup();
        assert_eq!(got, EXPECT);
    }

    #[test]
    fn preserves_duplicate_entries() {
        // same mask-bounded dispatch; table slots repeat two targets: t0,t1,t0,t1
        let code = [
            0x83, 0xE1, 0x03, 0x48, 0x8D, 0x15, 0xF6, 0x0F, 0x00, 0x00, 0x48, 0x63, 0x0C, 0x8A,
            0x48, 0x01, 0xD1, 0xFF, 0xE1,
        ];
        let dup = vec![
            0x13, 0xF0, 0xFF, 0xFF, 0x18, 0xF0, 0xFF, 0xFF, 0x13, 0xF0, 0xFF, 0xFF, 0x18, 0xF0,
            0xFF, 0xFF,
        ];
        let m = module_with_table(0x2000, dup);
        let tables = detect_switch(&m, &decode(&code), 0x1000, 0x1100);
        assert_eq!(tables.len(), 1);
        let (_, table) = &tables[0];
        assert_eq!(table.count, 4);
        let got: Vec<u32> = table.entries.iter().map(|r| r.get()).collect();
        assert_eq!(got, [0x1013, 0x1018, 0x1013, 0x1018]);
        let mut distinct = got.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct, [0x1013, 0x1018]);
    }

    #[test]
    fn unbounded_table_rejected() {
        // no cmp/and bound on the index -> reject (never guess, §10.5)
        let code = [
            0x48, 0x8D, 0x15, 0xF6, 0x0F, 0x00, 0x00, 0x48, 0x63, 0x0C, 0x8A, 0x48, 0x01, 0xD1,
            0xFF, 0xE1,
        ];
        let m = module_with_table(0x2000, TABLE.to_vec());
        assert!(detect_switch(&m, &decode(&code), 0x1000, 0x1100).is_empty());
    }

    #[test]
    fn out_of_range_target_rejected() {
        // hi clamped below the targets -> cross-check fails -> reject
        let code = [
            0x83, 0xE1, 0x03, 0x48, 0x8D, 0x15, 0xF6, 0x0F, 0x00, 0x00, 0x48, 0x63, 0x0C, 0x8A,
            0x48, 0x01, 0xD1, 0xFF, 0xE1,
        ];
        let m = module_with_table(0x2000, TABLE.to_vec());
        assert!(detect_switch(&m, &decode(&code), 0x1000, 0x1010).is_empty());
    }
}
