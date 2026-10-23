use std::collections::{BTreeMap, BTreeSet, HashMap};

use iced_x86::{Code, Instruction, MemoryOperand, Register};
use kamy_core::ir::{
    AbiClass, AbiLocation, AbiPassing, AbiValue, FnSignature, Gpr, MapCallConv, PhysReg,
    win64_volatiles,
};
use kamy_core::{Module, Rva, SymbolId};
use kamy_link::module::{EntryMode, Injection};
use kamy_link::{Options, Report, TransformOutcome};
use kamy_pe::PeFile;
use kamy_transforms::MbaPass;
use kamy_transforms::mba::{MbaBitwidths, MbaConfig, MbaSemantics};

const BASE: u64 = 0x1_4000_0000;
const ENTRY: u32 = 0x1000;
const TOUCH: u32 = 0x1200;
const MIX: u32 = 0x1300;
const RECURSIVE: u32 = 0x1400;

fn slot(offset: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, offset)
}

fn instruction_label(index: usize) -> u64 {
    // BlockEncoder matches targets against source IPs, including external calls.
    0x8000_0000_0000_0000 + index as u64 * 16
}

fn encode(rva: u32, mut instructions: Vec<Instruction>) -> Vec<u8> {
    for (index, instruction) in instructions.iter_mut().enumerate() {
        instruction.set_ip(instruction_label(index));
    }
    kamy_codegen::relocate(&instructions, BASE + u64::from(rva)).unwrap()
}

fn stack_caller() -> Vec<u8> {
    use Register::*;
    let mut code = vec![
        Instruction::with1(Code::Push_r64, RBX).unwrap(),
        Instruction::with1(Code::Push_r64, R12).unwrap(),
        Instruction::with2(Code::Sub_rm64_imm8, RSP, 0x78i32).unwrap(),
    ];
    // Two pushes and 0x78 local bytes put entry RSP at current RSP+0x88.
    for (register, offset) in [(RCX, 0x40), (RDX, 0x48), (R8, 0x50), (R9, 0x58)] {
        code.push(Instruction::with2(Code::Mov_rm64_r64, slot(offset), register).unwrap());
    }
    for (source, destination) in [(0xb0, 0x60), (0xb8, 0x68)] {
        code.push(Instruction::with2(Code::Mov_r64_rm64, RAX, slot(source)).unwrap());
        code.push(Instruction::with2(Code::Mov_rm64_r64, slot(destination), RAX).unwrap());
    }
    code.extend([
        Instruction::with2(Code::Mov_rm64_r64, slot(0x90), RCX).unwrap(),
        Instruction::with2(Code::Lea_r64_m, RBX, slot(0x40)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, RCX, RBX).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(TOUCH)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, R12, RAX).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, RCX, RBX).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(TOUCH)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, slot(0x70), RAX).unwrap(),
    ]);
    for (register, offset) in [(RCX, 0x40), (RDX, 0x48), (R8, 0x50), (R9, 0x58)] {
        code.push(Instruction::with2(Code::Mov_r64_rm64, register, slot(offset)).unwrap());
    }
    for (source, destination) in [(0x60, 32), (0x68, 40)] {
        code.push(Instruction::with2(Code::Mov_r64_rm64, RAX, slot(source)).unwrap());
        code.push(Instruction::with2(Code::Mov_rm64_r64, slot(destination), RAX).unwrap());
    }
    code.extend([
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(MIX)).unwrap(),
        Instruction::with3(Code::Imul_r64_rm64_imm8, R12, R12, 13i32).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, RAX, R12).unwrap(),
        Instruction::with2(Code::Add_r64_rm64, RAX, slot(0x70)).unwrap(),
        Instruction::with2(Code::Add_r64_rm64, RAX, slot(0x90)).unwrap(),
        Instruction::with2(Code::Add_r64_rm64, RAX, MemoryOperand::with_base(RBX)).unwrap(),
        Instruction::with2(Code::Add_rm64_imm8, RSP, 0x78i32).unwrap(),
        Instruction::with1(Code::Pop_r64, R12).unwrap(),
        Instruction::with1(Code::Pop_r64, RBX).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    encode(ENTRY, code)
}

fn touch() -> Vec<u8> {
    use Register::*;
    encode(
        TOUCH,
        vec![
            Instruction::with2(Code::Add_rm64_imm8, MemoryOperand::with_base(RCX), 19i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(RCX)).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RAX, 7i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    )
}

fn mix() -> Vec<u8> {
    use Register::*;
    encode(
        MIX,
        vec![
            Instruction::with2(Code::Mov_r64_rm64, RAX, RCX).unwrap(),
            Instruction::with3(Code::Imul_r64_rm64_imm8, RDX, RDX, 3i32).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, RDX).unwrap(),
            Instruction::with3(Code::Imul_r64_rm64_imm8, R8, R8, 5i32).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, R8, R9).unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, RAX, R8).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, slot(40)).unwrap(),
            Instruction::with3(Code::Imul_r64_rm64_imm8, R10, R10, 7i32).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, R10).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, slot(48)).unwrap(),
            Instruction::with3(Code::Imul_r64_rm64_imm8, R10, R10, 11i32).unwrap(),
            Instruction::with2(Code::Sub_rm64_r64, RAX, R10).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    )
}

fn recursive() -> Vec<u8> {
    use Register::*;
    let label = instruction_label;
    encode(
        RECURSIVE,
        vec![
            Instruction::with1(Code::Push_r64, RBX).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 64i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, RBX, RCX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, slot(32), RDX).unwrap(),
            Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap(),
            Instruction::with_branch(Code::Je_rel32_64, label(11)).unwrap(),
            Instruction::with1(Code::Dec_rm64, RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RDX, 3i32).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(RECURSIVE)).unwrap(),
            Instruction::with_branch(Code::Jmp_rel32_64, label(13)).unwrap(),
            Instruction::with(Code::Nopd),
            Instruction::with3(Code::Imul_r64_rm64_imm8, RAX, RDX, 17i32).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RAX, 3i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, slot(32)).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, R10, RBX).unwrap(),
            Instruction::with3(Code::Imul_r64_rm64_imm8, R10, R10, 5i32).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, R10).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, slot(32)).unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, R10, RBX).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, R10).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 64i32).unwrap(),
            Instruction::with1(Code::Pop_r64, RBX).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    )
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn fixture(functions: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = vec![0; 0x1400];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 1);
    put16(&mut bytes, 0x94, 0xf0);
    put16(&mut bytes, 0x96, 0x22);
    put16(&mut bytes, 0x98, 0x20b);
    put32(&mut bytes, 0xa8, ENTRY);
    bytes[0xb0..0xb8].copy_from_slice(&BASE.to_le_bytes());
    put32(&mut bytes, 0xb8, 0x1000);
    put32(&mut bytes, 0xbc, 0x200);
    put32(&mut bytes, 0xd0, 0x2000);
    put32(&mut bytes, 0xd4, 0x400);
    put16(&mut bytes, 0xdc, 3);
    bytes[0xe0..0xe8].copy_from_slice(&0x10_0000u64.to_le_bytes());
    bytes[0xe8..0xf0].copy_from_slice(&0x1000u64.to_le_bytes());
    put32(&mut bytes, 0x104, 16);
    bytes[0x188..0x18d].copy_from_slice(b".text");
    put32(&mut bytes, 0x190, 0x1000);
    put32(&mut bytes, 0x194, 0x1000);
    put32(&mut bytes, 0x198, 0x1000);
    put32(&mut bytes, 0x19c, 0x400);
    put32(&mut bytes, 0x1ac, 0x6000_0020);
    for (rva, code) in functions {
        let offset = 0x400 + (*rva - ENTRY) as usize;
        bytes[offset..offset + code.len()].copy_from_slice(code);
    }
    bytes
}

fn module(pe: &PeFile, starts: &[u32]) -> Module {
    let mut module = pe.to_module();
    let starts: BTreeSet<_> = starts.iter().copied().collect();
    module.functions = starts
        .iter()
        .map(|start| {
            kamy_disasm::recover_function(&module, Rva::new(*start), &starts, &BTreeSet::new())
        })
        .collect();
    module
}

fn signature(count: usize) -> FnSignature {
    FnSignature {
        args: (0..count)
            .map(|index| {
                if index < 4 {
                    AbiValue::register(PhysReg::Gpr([Gpr::Rcx, Gpr::Rdx, Gpr::R8, Gpr::R9][index]))
                } else {
                    AbiValue {
                        location: AbiLocation::Stack {
                            offset: 40 + (index as i32 - 4) * 8,
                        },
                        class: AbiClass::Integer,
                        bits: 64,
                        passing: AbiPassing::Direct,
                    }
                }
            })
            .collect(),
        returns: vec![AbiValue::register(PhysReg::Gpr(Gpr::Rax))],
        clobbers: win64_volatiles(),
        noreturn: false,
    }
}

fn protect(bytes: &[u8], starts: &[u32], mba: bool, precise_stack: bool) -> (Vec<u8>, Report) {
    let pe = PeFile::parse(bytes).unwrap();
    let module = module(&pe, starts);
    let cc = MapCallConv::new(HashMap::from([
        (BASE + u64::from(ENTRY), signature(6)),
        (BASE + u64::from(TOUCH), signature(1)),
        (
            BASE + u64::from(MIX),
            signature(if precise_stack { 6 } else { 4 }),
        ),
        (BASE + u64::from(RECURSIVE), signature(2)),
    ]));
    let mut invocations: BTreeMap<SymbolId, Vec<f32>> = BTreeMap::new();
    let result = kamy_link::protect(
        &pe,
        &module,
        &module.functions,
        &Options::default(),
        &cc,
        &mut |symbol, function, intensity| {
            invocations
                .entry(symbol.clone())
                .or_default()
                .push(intensity);
            let mut transformed = false;
            if mba {
                for (seed, add, sub, xor) in
                    [(0x1234, true, true, false), (0x5678, false, false, true)]
                {
                    transformed |= MbaPass {
                        config: MbaConfig {
                            iterations: 2,
                            probability: 100,
                            semantics: MbaSemantics { add, sub, xor },
                            bitwidths: MbaBitwidths {
                                bit8: true,
                                bit16: true,
                                bit32: true,
                                bit64: true,
                            },
                        },
                        seed,
                    }
                    .run_with_intensity(function, intensity);
                }
            }
            Ok(TransformOutcome { transformed })
        },
        Injection {
            plugins: &[],
            mode: EntryMode::Inline,
        },
    )
    .unwrap();
    for intensities in invocations.values() {
        assert_eq!(
            intensities,
            &[1.0],
            "a selected body MUST NOT retry at reduced intensity"
        );
    }
    result
}

fn retain(name: &str, original: &[u8], lowered: &[u8]) {
    if let Some(directory) = std::env::var_os("KAMY_MEMORY_FRAME_WITNESS_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(format!("{name}-before.exe")), original).unwrap();
        std::fs::write(directory.join(format!("{name}-after.exe")), lowered).unwrap();
    }
}

#[test]
fn full_link_preserves_incoming_home_local_aliases_and_six_argument_calls() {
    let caller = stack_caller();
    let targets: Vec<_> = iced_x86::Decoder::with_ip(
        64,
        &caller,
        BASE + u64::from(ENTRY),
        iced_x86::DecoderOptions::NONE,
    )
    .into_iter()
    .filter(|instruction| instruction.flow_control() == iced_x86::FlowControl::Call)
    .map(|instruction| instruction.near_branch_target())
    .collect();
    assert_eq!(
        targets,
        [TOUCH, TOUCH, MIX].map(|rva| BASE + u64::from(rva))
    );
    let original = fixture(&[(ENTRY, caller), (TOUCH, touch()), (MIX, mix())]);
    for (mba, precise_stack) in [(false, true), (true, true), (false, false), (true, false)] {
        let (lowered, report) = protect(&original, &[ENTRY, TOUCH, MIX], mba, precise_stack);
        let name = match (mba, precise_stack) {
            (false, true) => "stack-identity",
            (true, true) => "stack-mba",
            (false, false) => "stack-unknown-identity",
            (true, false) => "stack-unknown-mba",
        };
        retain(name, &original, &lowered);
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        for entry in [ENTRY, TOUCH, MIX] {
            let symbol = SymbolId::Host {
                rva: Rva::new(entry),
            };
            assert!(report.ssa_lowered_symbols.contains(&symbol));
            let function = report
                .functions
                .iter()
                .find(|function| function.symbol == symbol)
                .unwrap();
            assert_eq!(function.transformed, mba);
            assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 });
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&lowered);
            let before: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
            let after: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 = unsafe {
                core::mem::transmute(output.at(report.address_map[&SymbolId::Host {
                    rva: Rva::new(ENTRY),
                }]))
            };
            for arguments in [
                [2, 3, 5, 7, 11, 13],
                [17, 23, 29, 31, 37, 41],
                [u64::MAX - 47, 2, 3, 4, 5, 6],
            ] {
                let [a, b, c, d, e, f] = arguments;
                let expected = stack_oracle(arguments);
                assert_eq!(unsafe { before(a, b, c, d, e, f) }, expected);
                assert_eq!(unsafe { after(a, b, c, d, e, f) }, expected);
            }
        }
    }
    assert_eq!(stack_oracle([2, 3, 5, 7, 11, 13]), 404);
}

fn stack_oracle([a, b, c, d, e, f]: [u64; 6]) -> u64 {
    let object = a.wrapping_add(38);
    let mixed = (object.wrapping_add(b.wrapping_mul(3)) ^ c.wrapping_mul(5).wrapping_add(d))
        .wrapping_add(e.wrapping_mul(7))
        .wrapping_sub(f.wrapping_mul(11));
    mixed
        .wrapping_add(a.wrapping_add(26).wrapping_mul(13))
        .wrapping_add(a.wrapping_add(45))
        .wrapping_add(a)
        .wrapping_add(object)
}

#[test]
fn full_link_mba_preserves_phi_pointer_differences_and_comparisons() {
    use Register::*;
    let code = encode(
        ENTRY,
        vec![
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 72i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, RDX, RSP).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, RAX, RDX).unwrap(),
            Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap(),
            Instruction::with_branch(Code::Je_rel32_64, instruction_label(6)).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RAX, slot(88)).unwrap(),
            Instruction::with2(Code::Cmp_rm64_r64, RAX, RDX).unwrap(),
            Instruction::with1(Code::Setb_rm8, R8L).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, R8D, R8L).unwrap(),
            Instruction::with2(Code::Sub_rm64_r64, RAX, RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, R8).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 72i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    );
    let original = fixture(&[(ENTRY, code)]);
    for mba in [false, true] {
        let (lowered, report) = protect(&original, &[ENTRY], mba, true);
        retain(
            if mba {
                "pointer-coordinates-mba"
            } else {
                "pointer-coordinates-identity"
            },
            &original,
            &lowered,
        );
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        let symbol = SymbolId::Host {
            rva: Rva::new(ENTRY),
        };
        assert!(report.ssa_lowered_symbols.contains(&symbol));
        let function = report
            .functions
            .iter()
            .find(|function| function.symbol == symbol)
            .unwrap();
        assert_eq!(function.transformed, mba);
        assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 });
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&lowered);
            let before: unsafe extern "system" fn(u64) -> u64 =
                unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
            let after: unsafe extern "system" fn(u64) -> u64 =
                unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
            for (selector, expected) in [(0, 0), (1, 88), (7, 88)] {
                assert_eq!(unsafe { before(selector) }, expected);
                assert_eq!(unsafe { after(selector) }, expected);
            }
        }
    }
}

fn selected_coordinates(
    condition: Option<u64>,
    branch: bool,
    nested: bool,
    incoming_first: bool,
    arithmetic_first: bool,
    overlap_store: bool,
) -> Vec<u8> {
    use Register::*;
    let mut code = vec![Instruction::with2(Code::Sub_rm64_imm8, RSP, 24i32).unwrap()];
    if let Some(condition) = condition {
        code.push(Instruction::with2(Code::Mov_r64_imm64, RCX, condition).unwrap());
    }
    // Initialize both LOW objects from the real incoming arguments, independently of selection.
    for (source, destination) in [(64, 8), (72, 16)] {
        code.push(Instruction::with2(Code::Mov_r64_rm64, R10, slot(source)).unwrap());
        code.push(Instruction::with2(Code::Mov_rm64_r64, slot(destination), R10).unwrap());
    }
    let start = if incoming_first { 64 } else { 8 };
    code.push(Instruction::with2(Code::Lea_r64_m, RAX, slot(start)).unwrap());
    code.push(Instruction::with2(Code::Lea_r64_m, RDX, slot(start + 8)).unwrap());
    let shift = if incoming_first { -56 } else { 56 };
    if arithmetic_first {
        for register in [RAX, RDX] {
            code.push(Instruction::with2(Code::Add_rm64_imm8, register, shift).unwrap());
        }
    }
    code.push(Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap());
    if branch {
        let landing = code.len() + 2;
        code.push(Instruction::with_branch(Code::Je_rel32_64, instruction_label(landing)).unwrap());
        code.push(Instruction::with2(Code::Mov_r64_rm64, RAX, RDX).unwrap());
    } else {
        code.push(Instruction::with2(Code::Cmovne_r64_rm64, RAX, RDX).unwrap());
    }
    if nested {
        code.push(Instruction::with2(Code::Mov_r64_rm64, R11, RAX).unwrap());
        let first = start
            + if arithmetic_first {
                i64::from(shift)
            } else {
                0
            };
        code.push(Instruction::with2(Code::Lea_r64_m, R10, slot(first)).unwrap());
        code.push(Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap());
        code.push(Instruction::with2(Code::Cmove_r64_rm64, R11, R10).unwrap());
        code.push(Instruction::with2(Code::Mov_r64_rm64, RAX, R11).unwrap());
    }
    if !arithmetic_first {
        code.push(Instruction::with2(Code::Add_rm64_imm8, RAX, shift).unwrap());
    }
    if overlap_store {
        code.push(
            Instruction::with2(Code::Mov_r64_rm64, R10, MemoryOperand::with_base(RAX)).unwrap(),
        );
        code.push(
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(RAX), R10).unwrap(),
        );
        code.push(
            Instruction::with2(
                Code::Mov_rm32_imm32,
                MemoryOperand::with_base_displ(RAX, 4),
                0xaabb_ccddu32,
            )
            .unwrap(),
        );
    }
    code.extend([
        Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(RAX)).unwrap(),
        // A scalar payload forces genuine requested MBA, rather than only pointer rematerialization.
        Instruction::with2(Code::Add_rm64_imm8, RAX, 7i32).unwrap(),
        Instruction::with2(Code::Add_rm64_imm8, RSP, 24i32).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    encode(ENTRY, code)
}

fn mixed_zone_selected_coordinates() -> Vec<u8> {
    use Register::*;
    encode(
        ENTRY,
        vec![
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 24i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, slot(64)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, slot(0), R10).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, slot(72)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, slot(64), R10).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RAX, slot(8)).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RDX, slot(72)).unwrap(),
            Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap(),
            Instruction::with2(Code::Cmovne_r64_rm64, RAX, RDX).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm8, RAX, 8i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(RAX)).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RAX, 7i32).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 24i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    )
}

#[test]
fn finite_select_phi_coordinates_execute_in_identity_and_requested_mba() {
    let cases = [
        ("select", None, false, false, false, false, false),
        ("select-zero", Some(0), false, false, false, false, false),
        ("select-one", Some(1), false, false, false, false, false),
        ("phi", None, true, false, false, false, false),
        ("nested-copy", None, false, true, false, false, false),
        ("arithmetic-before", None, false, false, false, true, false),
        ("incoming-to-low", None, false, false, true, false, false),
        ("phi-incoming-to-low", None, true, true, true, false, false),
        (
            "incoming-overlap-store",
            None,
            false,
            true,
            false,
            false,
            true,
        ),
        ("low-overlap-store", None, true, false, true, false, true),
    ];
    let cases = cases
        .into_iter()
        .map(
            |(name, constant, branch, nested, incoming, arithmetic_first, overlap)| {
                (
                    name,
                    selected_coordinates(
                        constant,
                        branch,
                        nested,
                        incoming,
                        arithmetic_first,
                        overlap,
                    ),
                    constant,
                    overlap,
                )
            },
        )
        .chain(std::iter::once((
            "mixed-zones",
            mixed_zone_selected_coordinates(),
            None,
            false,
        )));
    for (name, code, constant, overlap) in cases {
        let original = fixture(&[(ENTRY, code)]);
        for mba in [false, true] {
            let (lowered, report) = protect(&original, &[ENTRY], mba, true);
            retain(
                &format!("select-{name}-{}", if mba { "mba" } else { "identity" }),
                &original,
                &lowered,
            );
            assert!(report.rejected.is_empty(), "{name}: {:?}", report.rejected);
            let symbol = SymbolId::Host {
                rva: Rva::new(ENTRY),
            };
            assert!(report.ssa_lowered_symbols.contains(&symbol), "{name}");
            let function = report
                .functions
                .iter()
                .find(|function| function.symbol == symbol)
                .unwrap();
            assert_eq!(function.transformed, mba, "{name}");
            assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 }, "{name}");
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let input = native::MappedImage::new(&original);
                let output = native::MappedImage::new(&lowered);
                let before: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                    unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
                let after: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                    unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
                for condition in [0, 1, 7] {
                    let e = 0x1122_3344_5566_7788u64;
                    let f = 0x8877_6655_4433_2211u64;
                    let selected = if constant.unwrap_or(condition) == 0 {
                        e
                    } else {
                        f
                    };
                    let expected = if overlap {
                        (selected & 0xffff_ffff) | 0xaabb_ccdd_0000_0000
                    } else {
                        selected
                    }
                    .wrapping_add(7);
                    assert_eq!(
                        unsafe { before(condition, 0, 0, 0, e, f) },
                        expected,
                        "original {name}"
                    );
                    assert_eq!(
                        unsafe { after(condition, 0, 0, 0, e, f) },
                        expected,
                        "{name} mba={mba}"
                    );
                }
            }
        }
    }
}

#[test]
fn selected_frame_index_proof_survives_requested_mba_and_final_zone_crossing() {
    use Register::*;
    for constant_first in [false, true] {
        let mut code = vec![
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 24i32).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RAX, slot(8)).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RDX, slot(16)).unwrap(),
            Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap(),
            Instruction::with2(Code::Cmovne_r64_rm64, RAX, RDX).unwrap(),
            Instruction::with2(Code::And_rm64_imm8, R8, 7i32).unwrap(),
        ];
        let constant = Instruction::with2(Code::Add_rm64_imm8, RAX, 56i32).unwrap();
        let index = Instruction::with2(Code::Add_rm64_r64, RAX, R8).unwrap();
        code.extend(if constant_first {
            [constant, index]
        } else {
            [index, constant]
        });
        code.extend([
            Instruction::with2(Code::Movzx_r32_rm8, EAX, MemoryOperand::with_base(RAX)).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RAX, 7i32).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 24i32).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let original = fixture(&[(ENTRY, encode(ENTRY, code))]);
        for mba in [false, true] {
            let (lowered, report) = protect(&original, &[ENTRY], mba, true);
            retain(
                &format!("select-index-constant-first-{constant_first}-mba-{mba}"),
                &original,
                &lowered,
            );
            assert!(report.rejected.is_empty(), "{:?}", report.rejected);
            let symbol = SymbolId::Host {
                rva: Rva::new(ENTRY),
            };
            assert!(report.ssa_lowered_symbols.contains(&symbol));
            let function = report
                .functions
                .iter()
                .find(|function| function.symbol == symbol)
                .unwrap();
            assert_eq!(function.transformed, mba);
            assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 });
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let input = native::MappedImage::new(&original);
                let output = native::MappedImage::new(&lowered);
                let before: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                    unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
                let after: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                    unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
                for condition in [0, 1] {
                    for index in 0..8 {
                        let e = 0x1122_3344_5566_7788u64;
                        let f = 0x8877_6655_4433_2211u64;
                        let selected = if condition == 0 { e } else { f };
                        let expected = u64::from(selected.to_le_bytes()[index as usize]) + 7;
                        assert_eq!(unsafe { before(condition, 0, index, 0, e, f) }, expected);
                        assert_eq!(unsafe { after(condition, 0, index, 0, e, f) }, expected);
                    }
                }
            }
        }
    }
}

#[test]
fn selected_frame_alternatives_split_final_zones_without_invented_crossing() {
    use Register::*;
    let original = fixture(&[(
        ENTRY,
        encode(
            ENTRY,
            vec![
                Instruction::with2(Code::Sub_rm64_imm8, RSP, 40i32).unwrap(),
                // Initialize E-8 and E+8 from independent fifth and sixth Win64 arguments.
                Instruction::with2(Code::Mov_r64_rm64, R10, slot(80)).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, slot(32), R10).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, R10, slot(88)).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, slot(48), R10).unwrap(),
                // Select E-32 or E-16 before shifting: the only final addresses are E-8/E+8.
                // Each eight-byte access is valid; no access starts between these alternatives.
                Instruction::with2(Code::Lea_r64_m, RAX, slot(8)).unwrap(),
                Instruction::with2(Code::Lea_r64_m, RDX, slot(24)).unwrap(),
                Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap(),
                Instruction::with2(Code::Cmovne_r64_rm64, RAX, RDX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm8, RAX, 24i32).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(RAX)).unwrap(),
                // Keep genuine scalar MBA work without changing the exact ledger witness below.
                Instruction::with2(Code::Add_rm64_imm8, RAX, 7i32).unwrap(),
                Instruction::with2(Code::Add_rm64_imm8, RSP, 40i32).unwrap(),
                Instruction::with(Code::Retnq),
            ],
        ),
    )]);
    for mba in [false, true] {
        let (lowered, report) = protect(&original, &[ENTRY], mba, true);
        retain(
            if mba {
                "select-split-final-zones-mba"
            } else {
                "select-split-final-zones-identity"
            },
            &original,
            &lowered,
        );
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        let symbol = SymbolId::Host {
            rva: Rva::new(ENTRY),
        };
        assert!(report.ssa_lowered_symbols.contains(&symbol));
        let function = report
            .functions
            .iter()
            .find(|function| function.symbol == symbol)
            .unwrap();
        assert!(function.selected && function.eligible && function.lowered);
        assert_eq!(function.transformed, mba);
        assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 });
        assert_eq!(
            report
                .functions
                .iter()
                .filter(|function| function.transformed)
                .count(),
            usize::from(mba),
            "requested MBA must transform the selected body, not silently fall back"
        );
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&lowered);
            let before: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
            let after: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
            for (fifth, sixth) in [
                (0x1122_3344_5566_7788u64, 0x8877_6655_4433_2211u64),
                (u64::MAX - 3, 0x1020_3040_5060_7080),
            ] {
                for condition in [0, 1, 7] {
                    let selected = if condition == 0 { fifth } else { sixth };
                    let expected = selected.wrapping_add(7);
                    assert_eq!(
                        unsafe { before(condition, 0, 0, 0, fifth, sixth) },
                        expected,
                        "original condition={condition}"
                    );
                    assert_eq!(
                        unsafe { after(condition, 0, 0, 0, fifth, sixth) },
                        expected,
                        "protected condition={condition} mba={mba}"
                    );
                }
            }
        }
    }
}

#[test]
fn exact_six_argument_select_ledger_witness_lowers_in_both_profiles() {
    use Register::*;
    let original = fixture(&[(
        ENTRY,
        encode(
            ENTRY,
            vec![
                Instruction::with2(Code::Sub_rm64_imm8, RSP, 24i32).unwrap(),
                Instruction::with2(Code::Lea_r64_m, RAX, slot(8)).unwrap(),
                Instruction::with2(Code::Lea_r64_m, RDX, slot(16)).unwrap(),
                Instruction::with2(Code::Test_rm64_r64, RCX, RCX).unwrap(),
                Instruction::with2(Code::Cmovne_r64_rm64, RAX, RDX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm8, RAX, 56i32).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(RAX)).unwrap(),
                Instruction::with2(Code::Add_rm64_imm8, RSP, 24i32).unwrap(),
                Instruction::with(Code::Retnq),
            ],
        ),
    )]);
    for mba in [false, true] {
        let (lowered, report) = protect(&original, &[ENTRY], mba, true);
        retain(
            if mba {
                "select-ledger-mba"
            } else {
                "select-ledger-identity"
            },
            &original,
            &lowered,
        );
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        let symbol = SymbolId::Host {
            rva: Rva::new(ENTRY),
        };
        assert!(report.ssa_lowered_symbols.contains(&symbol));
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&lowered);
            let before: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
            let after: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
            for (condition, expected) in [(0, 0x1122_3344_5566_7788), (1, 0x8877_6655_4433_2211)] {
                assert_eq!(
                    unsafe {
                        before(
                            condition,
                            0,
                            0,
                            0,
                            0x1122_3344_5566_7788,
                            0x8877_6655_4433_2211,
                        )
                    },
                    expected
                );
                assert_eq!(
                    unsafe {
                        after(
                            condition,
                            0,
                            0,
                            0,
                            0x1122_3344_5566_7788,
                            0x8877_6655_4433_2211,
                        )
                    },
                    expected
                );
            }
        }
    }
}

#[test]
fn selected_frame_flags_and_successive_call_results_compose() {
    use Register::*;
    let caller = encode(
        ENTRY,
        vec![
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 72i32).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(TOUCH)).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm8, RAX, 7i32).unwrap(),
            Instruction::with2(Code::Test_rm64_r64, RAX, RAX).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RAX, slot(40)).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RDX, slot(48)).unwrap(),
            Instruction::with2(Code::Cmovne_r64_rm64, RAX, RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RAX, 72i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, MemoryOperand::with_base(RAX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, slot(48), R10).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, RCX, 0u64).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(TOUCH)).unwrap(),
            Instruction::with2(Code::Add_r64_rm64, RAX, slot(48)).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 72i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    );
    let callee = encode(
        TOUCH,
        vec![
            Instruction::with2(Code::Mov_r64_rm64, RAX, RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RAX, 7i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    );
    let original = fixture(&[(ENTRY, caller), (TOUCH, callee)]);
    for mba in [false, true] {
        let (lowered, report) = protect(&original, &[ENTRY, TOUCH], mba, true);
        retain(
            if mba {
                "select-calls-mba"
            } else {
                "select-calls-identity"
            },
            &original,
            &lowered,
        );
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        for entry in [ENTRY, TOUCH] {
            assert!(report.ssa_lowered_symbols.contains(&SymbolId::Host {
                rva: Rva::new(entry)
            }));
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&lowered);
            let before: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
            let after: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 = unsafe {
                core::mem::transmute(output.at(report.address_map[&SymbolId::Host {
                    rva: Rva::new(ENTRY),
                }]))
            };
            for (condition, expected) in [(0, 0x1122_3344_5566_778fu64), (1, 0x8877_6655_4433_2218)]
            {
                assert_eq!(
                    unsafe {
                        before(
                            condition,
                            0,
                            0,
                            0,
                            0x1122_3344_5566_7788,
                            0x8877_6655_4433_2211,
                        )
                    },
                    expected
                );
                assert_eq!(
                    unsafe {
                        after(
                            condition,
                            0,
                            0,
                            0,
                            0x1122_3344_5566_7788,
                            0x8877_6655_4433_2211,
                        )
                    },
                    expected
                );
            }
        }
    }
}

#[test]
fn full_link_self_recursion_preserves_live_original_locals() {
    let original = fixture(&[(ENTRY, vec![0xc3]), (RECURSIVE, recursive())]);
    for mba in [false, true] {
        let (lowered, report) = protect(&original, &[RECURSIVE], mba, true);
        retain(
            if mba {
                "recursive-mba"
            } else {
                "recursive-identity"
            },
            &original,
            &lowered,
        );
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        let symbol = SymbolId::Host {
            rva: Rva::new(RECURSIVE),
        };
        assert!(report.ssa_lowered_symbols.contains(&symbol));
        let function = report
            .functions
            .iter()
            .find(|function| function.symbol == symbol)
            .unwrap();
        assert_eq!(function.transformed, mba);
        assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 });
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&lowered);
            let before: unsafe extern "system" fn(u64, u64) -> u64 =
                unsafe { core::mem::transmute(input.at(Rva::new(RECURSIVE))) };
            let after: unsafe extern "system" fn(u64, u64) -> u64 =
                unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
            for (depth, seed) in [(0, 17), (1, 17), (7, 23), (64, 17), (96, 5)] {
                let expected = recursive_oracle(depth, seed);
                assert_eq!(unsafe { before(depth, seed) }, expected);
                assert_eq!(unsafe { after(depth, seed) }, expected);
            }
        }
    }
    assert_eq!(recursive_oracle(64, 17), 57994);
}

fn recursive_oracle(depth: u64, seed: u64) -> u64 {
    let mut result = seed
        .wrapping_add(depth.wrapping_mul(3))
        .wrapping_mul(17)
        .wrapping_add(3);
    for level in (0..=depth).rev() {
        let remaining = depth - level;
        let local = seed.wrapping_add(level.wrapping_mul(3));
        result = result
            .wrapping_add(local.wrapping_add(remaining).wrapping_mul(5))
            .wrapping_add(local ^ remaining);
    }
    result
}

#[test]
fn inferred_leaf_xmm_input_and_return_survive_real_calls() {
    use Register::*;
    let caller = encode(
        ENTRY,
        vec![
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 56i32).unwrap(),
            Instruction::with2(Code::Movups_xmmm128_xmm, slot(32), XMM6).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, RAX, 3.25f64.to_bits()).unwrap(),
            Instruction::with2(Code::Movq_xmm_rm64, XMM0, RAX).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(TOUCH)).unwrap(),
            Instruction::with2(Code::Movaps_xmm_xmmm128, XMM6, XMM0).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, RAX, (-7.0f64).to_bits()).unwrap(),
            Instruction::with2(Code::Movq_xmm_rm64, XMM0, RAX).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(TOUCH)).unwrap(),
            Instruction::with2(Code::Addsd_xmm_xmmm64, XMM0, XMM6).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, RAX, 2.5f64.to_bits()).unwrap(),
            Instruction::with2(Code::Movq_xmm_rm64, XMM1, RAX).unwrap(),
            Instruction::with2(Code::Mulsd_xmm_xmmm64, XMM0, XMM1).unwrap(),
            Instruction::with2(Code::Movups_xmm_xmmm128, XMM6, slot(32)).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 56i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    );
    let original = fixture(&[(ENTRY, caller), (TOUCH, vec![0xc3])]);
    let pe = PeFile::parse(&original).unwrap();
    let module = module(&pe, &[ENTRY, TOUCH]);
    let cc = kamy_link::build_callconv(&pe, &module).unwrap();
    let (lowered, report) = kamy_link::protect(
        &pe,
        &module,
        &module.functions,
        &Options::default(),
        &cc,
        &mut |_, _, intensity| {
            assert_eq!(intensity, 1.0);
            Ok(TransformOutcome::default())
        },
        Injection {
            plugins: &[],
            mode: EntryMode::Inline,
        },
    )
    .unwrap();
    retain("inferred-floating", &original, &lowered);
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    for entry in [ENTRY, TOUCH] {
        assert!(report.ssa_lowered_symbols.contains(&SymbolId::Host {
            rva: Rva::new(entry)
        }));
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let input = native::MappedImage::new(&original);
        let output = native::MappedImage::new(&lowered);
        let before: unsafe extern "system" fn() -> f64 =
            unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
        let after: unsafe extern "system" fn() -> f64 = unsafe {
            core::mem::transmute(output.at(report.address_map[&SymbolId::Host {
                rva: Rva::new(ENTRY),
            }]))
        };
        assert_eq!(unsafe { before() }.to_bits(), (-9.375f64).to_bits());
        assert_eq!(unsafe { after() }.to_bits(), (-9.375f64).to_bits());
    }
}

#[test]
fn unwind_allocation_scalar_matching_code_address_is_not_a_pointer() {
    use Register::*;
    let code = encode(
        TOUCH,
        vec![
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 16i32).unwrap(),
            Instruction::with3(Code::Imul_r64_rm64_imm8, RAX, RDX, 2i32).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RAX, 9i32).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 16i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    );
    let end = TOUCH + code.len() as u32;
    let mut original = fixture(&[(TOUCH, code)]);
    original.resize(0x1800, 0);
    put16(&mut original, 0x86, 3);
    put32(&mut original, 0xa8, TOUCH);
    put32(&mut original, 0xd0, 0x4000);
    put32(&mut original, 0x120, 0x3000);
    put32(&mut original, 0x124, 12);
    for (header, name, rva, size, raw) in [
        (0x1b0, b".xdata".as_slice(), 0x2000, 8, 0x1400),
        (0x1d8, b".pdata".as_slice(), 0x3000, 12, 0x1600),
    ] {
        original[header..header + name.len()].copy_from_slice(name);
        put32(&mut original, header + 8, size);
        put32(&mut original, header + 12, rva);
        put32(&mut original, header + 16, 0x200);
        put32(&mut original, header + 20, raw);
        put32(&mut original, header + 36, 0x4000_0040);
    }
    original[0x1400..0x1408].copy_from_slice(&[1, 4, 1, 0, 4, 0x12, 0, 0]);
    put32(&mut original, 0x1600, TOUCH);
    put32(&mut original, 0x1604, end);
    put32(&mut original, 0x1608, 0x2000);
    let pe = PeFile::parse(&original).unwrap();
    let module = module(&pe, &[TOUCH]);
    let metadata = pe.metadata_references().unwrap();
    for (source, target) in [(0x3000, TOUCH), (0x3004, end), (0x3008, 0x2000)] {
        assert!(metadata.references.contains(&kamy_core::HostReference {
            source: Rva::new(source),
            target: Rva::new(target),
            kind: kamy_core::ReferenceKind::Unwind,
        }));
    }
    let references = kamy_analysis::build_reference_model(&module, &metadata).unwrap();
    assert!(references.is_resolved(Rva::new(TOUCH)));
    let (lowered, report) = kamy_link::protect(
        &pe,
        &module,
        &module.functions,
        &Options::default(),
        &kamy_core::ir::Win64Default,
        &mut |_, _, _| Ok(TransformOutcome::default()),
        Injection {
            plugins: &[],
            mode: EntryMode::Inline,
        },
    )
    .unwrap();
    retain("unwind-scalar", &original, &lowered);
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    let symbol = SymbolId::Host {
        rva: Rva::new(TOUCH),
    };
    assert!(report.ssa_lowered_symbols.contains(&symbol));
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let input = native::MappedImage::new(&original);
        let output = native::MappedImage::new(&lowered);
        let before: unsafe extern "system" fn(u64, u64) -> u64 =
            unsafe { core::mem::transmute(input.at(Rva::new(TOUCH))) };
        let after: unsafe extern "system" fn(u64, u64) -> u64 =
            unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
        assert_eq!(unsafe { before(17, 23) }, 72);
        assert_eq!(unsafe { after(17, 23) }, 72);
    }
    let mut adjacent = original.clone();
    put32(&mut adjacent, 0x1b8, 12);
    put32(&mut adjacent, 0x1408, 0x1204);
    let adjacent_pe = PeFile::parse(&adjacent).unwrap();
    let mut adjacent_module = adjacent_pe.to_module();
    adjacent_module.functions = module.functions.clone();
    let metadata = adjacent_pe.metadata_references().unwrap();
    let references = kamy_analysis::build_reference_model(&adjacent_module, &metadata).unwrap();
    let unresolved = &references.functions[&Rva::new(TOUCH)].unresolved;
    assert!(unresolved.contains(&kamy_core::HostReference {
        source: Rva::new(0x2008),
        target: Rva::new(0x1204),
        kind: kamy_core::ReferenceKind::Opaque,
    }));
    let (_, report) = kamy_link::protect(
        &adjacent_pe,
        &adjacent_module,
        &adjacent_module.functions,
        &Options::default(),
        &kamy_core::ir::Win64Default,
        &mut |_, _, _| Ok(TransformOutcome::default()),
        Injection {
            plugins: &[],
            mode: EntryMode::Inline,
        },
    )
    .unwrap();
    assert!(report.ssa_lowered_symbols.is_empty());
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].1.tag(), "SymbolizationUncertain");
}

#[test]
fn mixed_memory_phi_cycles_transfer_flags_widths_constants_and_frame_addresses() {
    use kamy_core::ir::{
        BlockId, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, Phi, ValueId,
    };
    fn value(
        func: &mut IrFunction,
        block: usize,
        op: IrOp,
        args: &[ValueId],
        ty: IrType,
    ) -> ValueId {
        let dest = func.alloc_value();
        func.blocks[block].insts.push(Inst {
            dest: Some(dest),
            op,
            args: args.to_vec(),
            ty,
        });
        dest
    }
    fn store(func: &mut IrFunction, block: usize, address: ValueId, source: ValueId, ty: IrType) {
        func.blocks[block].insts.push(Inst {
            dest: None,
            op: IrOp::Store,
            args: vec![address, source],
            ty,
        });
    }
    for reverse in [false, true] {
        let mut func = IrFunction {
            entry: BlockId(0),
            next_value: 0,
            blocks: (0..4)
                .map(|id| IrBlock {
                    id: BlockId(id),
                    phis: vec![],
                    insts: vec![],
                    term: IrTerminator::Ret,
                })
                .collect(),
        };
        let input = value(&mut func, 0, IrOp::Undef, &[], IrType::I64);
        let rounds = value(&mut func, 0, IrOp::Undef, &[], IrType::I64);
        let output = value(&mut func, 0, IrOp::Undef, &[], IrType::I64);
        let zero = value(&mut func, 0, IrOp::Const(0), &[], IrType::I64);
        let one = value(&mut func, 0, IrOp::Const(1), &[], IrType::I64);
        let mut lanes = Vec::new();
        let mut seeds = Vec::new();
        let mut types = Vec::new();
        for ty in [
            IrType::I8,
            IrType::I16,
            IrType::I32,
            IrType::I64,
            IrType::I128,
        ] {
            for lane in 0..3 {
                let offset = value(
                    &mut func,
                    0,
                    IrOp::Const(seeds.len() as u64 * 16),
                    &[],
                    IrType::I64,
                );
                let address = value(&mut func, 0, IrOp::Add, &[input, offset], IrType::I64);
                let loaded = value(&mut func, 0, IrOp::Load, &[address], ty);
                let initial = if ty == IrType::I8 {
                    value(&mut func, 0, IrOp::IsZero, &[loaded], IrType::I8)
                } else {
                    loaded
                };
                seeds.push(if ty == IrType::I8 {
                    if lane == 1 { 0x21 } else { 0 }
                } else {
                    0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128
                        ^ (lane as u128 * 0x0102_0304_0506_0708)
                });
                lanes.push((func.alloc_value(), initial));
                types.push(ty);
            }
        }
        // Rematerialized literal sources exercise the same initial edge as memory and flags.
        for seed in [17u64, 23, 31] {
            let initial = value(&mut func, 0, IrOp::Const(seed), &[], IrType::I64);
            lanes.push((func.alloc_value(), initial));
            types.push(IrType::I64);
        }
        // Frame-address sources initialize a distinct three-cycle; consumers load the objects.
        for (delta, seed) in [(-8, 41), (-16, 43), (-24, 47)] {
            let pointer = value(&mut func, 0, IrOp::FrameAddress(delta), &[], IrType::I64);
            let initial = value(&mut func, 0, IrOp::Const(seed), &[], IrType::I64);
            store(&mut func, 0, pointer, initial, IrType::I64);
            lanes.push((func.alloc_value(), pointer));
            types.push(IrType::I64);
        }
        let counter = func.alloc_value();
        let next = value(&mut func, 2, IrOp::Add, &[counter, one], IrType::I64);
        func.blocks[1].phis.push(Phi {
            dest: counter,
            ty: IrType::I64,
            args: vec![(BlockId(0), zero), (BlockId(2), next)],
        });
        for (index, &(dest, initial)) in lanes.iter().enumerate() {
            let source = lanes[index / 3 * 3 + (index % 3 + 1) % 3].0;
            func.blocks[1].phis.push(Phi {
                dest,
                ty: types[index],
                args: vec![(BlockId(0), initial), (BlockId(2), source)],
            });
        }
        if reverse {
            func.blocks[1].phis.reverse();
        }
        let condition = value(
            &mut func,
            1,
            IrOp::BorrowSub,
            &[counter, rounds],
            IrType::I8,
        );
        func.blocks[0].term = IrTerminator::Jump(BlockId(1));
        func.blocks[1].term = IrTerminator::Branch {
            cond: condition,
            taken: BlockId(2),
            not_taken: BlockId(3),
        };
        func.blocks[2].term = IrTerminator::Jump(BlockId(1));
        for (index, &(lane, _)) in lanes.iter().enumerate() {
            let offset = value(
                &mut func,
                3,
                IrOp::Const(index as u64 * 16),
                &[],
                IrType::I64,
            );
            let address = value(&mut func, 3, IrOp::Add, &[output, offset], IrType::I64);
            let transferred = if index >= 18 {
                value(&mut func, 3, IrOp::Load, &[lane], IrType::I64)
            } else {
                lane
            };
            store(&mut func, 3, address, transferred, types[index]);
        }
        let returned = value(&mut func, 3, IrOp::Copy, &[counter], IrType::I64);
        func.blocks[3].insts.push(Inst {
            dest: None,
            op: IrOp::Use,
            args: vec![returned],
            ty: IrType::I64,
        });
        let pins = HashMap::from([
            (input, PhysReg::Gpr(Gpr::Rcx)),
            (rounds, PhysReg::Gpr(Gpr::Rdx)),
            (output, PhysReg::Gpr(Gpr::R8)),
            (returned, PhysReg::Gpr(Gpr::Rax)),
        ]);
        let alloc = kamy_codegen::allocate_registers(&func, &Default::default(), &pins).unwrap();
        let selected = kamy_codegen::select_instructions(&func, &alloc);
        let code = kamy_codegen::relocate(&selected.instructions, BASE + u64::from(ENTRY)).unwrap();
        let image = fixture(&[(ENTRY, code)]);
        if let Some(directory) = std::env::var_os("KAMY_MEMORY_FRAME_WITNESS_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join(format!("phi-mixed-reverse-{reverse}.exe")),
                &image,
            )
            .unwrap();
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let mapped = native::MappedImage::new(&image);
            let run: unsafe extern "system" fn(*const u128, u64, *mut u128) -> u64 =
                unsafe { core::mem::transmute(mapped.at(Rva::new(ENTRY))) };
            let mut expected = seeds.clone();
            for (index, value) in expected.iter_mut().enumerate() {
                let bits = types[index].bits();
                if bits < 128 {
                    *value &= (1u128 << bits) - 1;
                }
                if index < 3 {
                    *value = u128::from(*value == 0);
                }
            }
            expected.extend([17, 23, 31, 41, 43, 47]);
            for rounds in [0, 1, 2, 3, 17, 64] {
                let mut actual = vec![0u128; lanes.len()];
                assert_eq!(
                    unsafe { run(seeds.as_ptr(), rounds, actual.as_mut_ptr()) },
                    rounds
                );
                let mut rotated = expected.clone();
                for group in rotated.chunks_mut(3) {
                    group.rotate_left(rounds as usize % 3);
                }
                assert_eq!(actual, rotated, "reverse={reverse} rounds={rounds}");
            }
        }
    }
}

fn rejected_frames() -> &'static [(&'static str, &'static [u8])] {
    &[
        (
            "FrameDynamic",
            &[
                0x55, 0x48, 0x89, 0xe5, 0x48, 0x29, 0xcc, 0x48, 0x89, 0xec, 0x5d, 0xc3,
            ],
        ),
        (
            "FrameConflict",
            &[
                0x55, 0x48, 0x89, 0xe5, 0x48, 0x85, 0xc9, 0x74, 0x04, 0x48, 0x83, 0xec, 0x20, 0x48,
                0x89, 0xec, 0x5d, 0xc3,
            ],
        ),
        (
            "FrameResourceLimit",
            &[
                0x48, 0x81, 0xec, 0, 0, 0, 1, 0x48, 0x81, 0xc4, 0, 0, 0, 1, 0xc3,
            ],
        ),
    ]
}

#[test]
fn dynamic_conflicting_and_excessive_frames_fail_specifically() {
    for &(tag, code) in rejected_frames() {
        let original = fixture(&[(ENTRY, code.to_vec())]);
        let (lowered, report) = protect(&original, &[ENTRY], false, true);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].1.tag(), tag);
        assert!(report.ssa_lowered_symbols.is_empty());
        assert!(report.functions.iter().all(|function| !function.lowered));
        let output = PeFile::parse(&lowered).unwrap().to_module();
        assert_eq!(
            &output.bytes_at(Rva::new(ENTRY)).unwrap()[..code.len()],
            code
        );
    }
}

#[test]
fn mandatory_authored_unprovable_frames_do_not_return_partial_images() {
    let host = PeFile::parse(&fixture(&[(ENTRY, vec![0xc3])])).unwrap();
    let module = host.to_module();
    for &(tag, code) in rejected_frames() {
        let mut image = fixture(&[(ENTRY, code.to_vec())]);
        put16(&mut image, 0x96, 0x2022);
        let symbol = SymbolId::Authored {
            module: "negative_frame".into(),
            symbol: "required_frame".into(),
        };
        let plugin = kamy_link::module::Plugin {
            name: "negative_frame".into(),
            module: kamy_pe::module::AuthoredModule {
                identity: "negative_frame".into(),
                image,
                entry: Rva::new(ENTRY),
                bindings: BTreeMap::new(),
                symbols: vec![kamy_core::Symbol {
                    id: symbol.clone(),
                    name: "required_frame".into(),
                    rva: Rva::new(ENTRY),
                    kind: kamy_core::SymbolKind::Function,
                }],
                code: vec![kamy_pe::module::CodeSymbol {
                    symbol,
                    name: "required_frame".into(),
                    start: Rva::new(ENTRY),
                    end: Rva::new(ENTRY + code.len() as u32),
                    signature: signature(1),
                }],
                data: Vec::new(),
                references: Vec::new(),
            },
        };
        let result = kamy_link::protect(
            &host,
            &module,
            &[],
            &Options::default(),
            &kamy_core::ir::Win64Default,
            &mut |_, _, _| Ok(TransformOutcome::default()),
            Injection {
                plugins: &[plugin],
                mode: EntryMode::Inline,
            },
        );
        let error = result
            .err()
            .expect("a mandatory failed body MUST NOT produce a rebuilt image");
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("negative_frame::required_frame"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains(tag), "{diagnostic}");
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod native {
    use super::{PeFile, Rva};
    use core::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            kind: u32,
            protection: u32,
        ) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
        fn VirtualProtect(address: *mut c_void, size: usize, protection: u32, old: *mut u32)
        -> i32;
        fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
    }

    pub(super) struct MappedImage(*mut c_void);

    impl MappedImage {
        pub(super) fn new(bytes: &[u8]) -> Self {
            let pe = PeFile::parse(bytes).unwrap();
            let module = pe.to_module();
            assert!(
                module.relocations.is_empty(),
                "fixture code MUST remain image-base independent"
            );
            let size = module
                .sections
                .iter()
                .map(|section| section.rva.get() + section.virtual_size)
                .max()
                .unwrap() as usize;
            let address = unsafe { VirtualAlloc(core::ptr::null_mut(), size, 0x3000, 4) };
            assert!(!address.is_null());
            let image = Self(address);
            unsafe {
                for section in &module.sections {
                    core::ptr::copy_nonoverlapping(
                        section.data.as_ptr(),
                        address.cast::<u8>().add(section.rva.get() as usize),
                        section.data.len(),
                    );
                }
                let mut old = 0;
                assert_ne!(VirtualProtect(address, size, 0x20, &mut old), 0);
                assert_ne!(FlushInstructionCache(GetCurrentProcess(), address, size), 0);
            }
            image
        }

        pub(super) fn at(&self, rva: Rva) -> *mut c_void {
            unsafe { self.0.cast::<u8>().add(rva.get() as usize).cast() }
        }
    }

    impl Drop for MappedImage {
        fn drop(&mut self) {
            assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0);
        }
    }
}
