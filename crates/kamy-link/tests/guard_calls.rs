use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, MemoryOperand, Register};
use kamy_core::ir::{AbiValue, CallingConvLookup, Gpr, IrOp, PhysReg, Win64Default};
use kamy_core::{Module, RejectionReason, Rva, SymbolId};
use kamy_link::module::{EntryMode, Injection};
use kamy_link::{Options, Ownership, TransformOutcome};
use kamy_pe::PeFile;
use kamy_transforms::MbaPass;
use kamy_transforms::mba::{MbaBitwidths, MbaConfig, MbaSemantics};

const BASE: u64 = 0x1_4000_0000;
const ENTRY: u32 = 0x1000;
const THUNK: u32 = 0x1200;
const DISPATCH: u32 = 0x1240;
const TARGET: u32 = 0x1300;
const SECOND_TARGET: u32 = 0x1400;
const CONFIG: u32 = 0x2000;
const DISPATCH_SLOT: u32 = 0x2100;
const DECOY_SLOT: u32 = 0x2108;

fn label(index: usize) -> u64 {
    // Encoder-local IPs MUST be disjoint from real image targets.
    0x8000_0000_0000_0000 + index as u64 * 16
}

fn encode(rva: u32, mut instructions: Vec<Instruction>) -> Vec<u8> {
    for (index, instruction) in instructions.iter_mut().enumerate() {
        instruction.set_ip(label(index));
    }
    kamy_codegen::relocate(&instructions, BASE + u64::from(rva)).unwrap()
}

fn stack(offset: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, offset)
}

fn rip(rva: u32) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RIP, (BASE + u64::from(rva)) as i64)
}

fn caller(indirect: bool) -> Vec<u8> {
    use Register::*;
    let mut code = vec![
        Instruction::with2(Code::Sub_rm64_imm8, RSP, 56i32).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, R10, stack(96)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, stack(32), R10).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, R10, stack(104)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, stack(40), R10).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, stack(48), RDX).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(RCX)).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, RCX, 7u64).unwrap(),
        Instruction::with2(Code::Movq_xmm_rm64, XMM0, RCX).unwrap(),
        Instruction::with2(Code::Movq_xmm_rm64, XMM1, RDX).unwrap(),
        Instruction::with2(Code::Movq_xmm_rm64, XMM2, R8).unwrap(),
        Instruction::with2(Code::Movq_xmm_rm64, XMM3, R9).unwrap(),
        Instruction::with2(Code::Test_rm64_r64, RAX, RAX).unwrap(),
        Instruction::with_branch(Code::Je_rel32_64, label(21)).unwrap(),
    ];
    code.push(if indirect {
        Instruction::with1(Code::Call_rm64, rip(DISPATCH_SLOT)).unwrap()
    } else {
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(THUNK)).unwrap()
    });
    code.extend([
        Instruction::with2(Code::Movq_rm64_xmm, RDX, XMM0).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, RAX, RDX).unwrap(),
        Instruction::with2(Code::Add_r64_rm64, RAX, stack(48)).unwrap(),
        Instruction::with2(Code::Add_rm64_imm8, RSP, 56i32).unwrap(),
        Instruction::with(Code::Retnq),
        Instruction::with(Code::Nopd),
        Instruction::with2(Code::Mov_r64_imm64, RAX, 0x55u64).unwrap(),
        Instruction::with2(Code::Add_rm64_imm8, RSP, 56i32).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    encode(ENTRY, code)
}

fn target(rva: u32, bias: i32) -> Vec<u8> {
    use Register::*;
    let mut code = vec![Instruction::with2(Code::Mov_r64_rm64, RAX, RCX).unwrap()];
    for (register, weight) in [(RDX, 3), (R8, 5), (R9, 7)] {
        code.extend([
            Instruction::with3(Code::Imul_r64_rm64_imm8, R10, register, weight).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, R10).unwrap(),
        ]);
    }
    for (offset, weight) in [(40, 11), (48, 13)] {
        code.extend([
            Instruction::with2(Code::Mov_r64_rm64, R10, stack(offset)).unwrap(),
            Instruction::with3(Code::Imul_r64_rm64_imm8, R10, R10, weight).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, RAX, R10).unwrap(),
        ]);
    }
    code.push(Instruction::with2(Code::Add_rm64_imm32, RAX, bias).unwrap());
    code.push(Instruction::with2(Code::Movq_rm64_xmm, R10, XMM0).unwrap());
    for register in [XMM1, XMM2, XMM3] {
        code.extend([
            Instruction::with2(Code::Movq_rm64_xmm, R11, register).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, R10, R11).unwrap(),
        ]);
    }
    code.push(Instruction::with2(Code::Movq_xmm_rm64, XMM0, R10).unwrap());
    for register in [RCX, RDX, R8, R9, R10, R11] {
        code.push(Instruction::with2(Code::Xor_rm64_r64, register, register).unwrap());
    }
    for register in [XMM1, XMM2, XMM3, XMM4, XMM5] {
        code.push(Instruction::with2(Code::Pxor_xmm_xmmm128, register, register).unwrap());
    }
    code.push(Instruction::with(Code::Retnq));
    encode(rva, code)
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn file_offset(rva: u32) -> usize {
    0x400 + (rva - ENTRY) as usize
}

fn fixture(indirect: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x2400];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 2);
    put16(&mut bytes, 0x94, 0xf0);
    put16(&mut bytes, 0x96, 0x22);
    put16(&mut bytes, 0x98, 0x20b);
    put32(&mut bytes, 0xa8, ENTRY);
    bytes[0xb0..0xb8].copy_from_slice(&BASE.to_le_bytes());
    put32(&mut bytes, 0xb8, 0x1000);
    put32(&mut bytes, 0xbc, 0x200);
    put32(&mut bytes, 0xd0, 0x3000);
    put32(&mut bytes, 0xd4, 0x400);
    put16(&mut bytes, 0xdc, 3);
    put16(&mut bytes, 0xde, 0x4000);
    bytes[0xe0..0xe8].copy_from_slice(&0x10_0000u64.to_le_bytes());
    bytes[0xe8..0xf0].copy_from_slice(&0x1000u64.to_le_bytes());
    put32(&mut bytes, 0x104, 16);
    for (index, rva, size) in [(5, 0x2200, 16), (10, CONFIG, 148)] {
        put32(&mut bytes, 0x108 + index * 8, rva);
        put32(&mut bytes, 0x10c + index * 8, size);
    }
    for (header, name, rva, flags) in [
        (0x188, b".text".as_slice(), 0x1000, 0x6000_0020),
        (0x1b0, b".data".as_slice(), 0x2000, 0xc000_0040),
    ] {
        bytes[header..header + name.len()].copy_from_slice(name);
        put32(&mut bytes, header + 8, 0x1000);
        put32(&mut bytes, header + 12, rva);
        put32(&mut bytes, header + 16, 0x1000);
        put32(&mut bytes, header + 20, file_offset(rva) as u32);
        put32(&mut bytes, header + 36, flags);
    }
    let thunk = encode(
        THUNK,
        vec![
            Instruction::with(Code::Endbr64),
            Instruction::with1(Code::Jmp_rm64, rip(DISPATCH_SLOT)).unwrap(),
        ],
    );
    for (rva, code) in [
        (ENTRY, caller(indirect)),
        (THUNK, thunk),
        (DISPATCH, vec![0xff, 0xe0]),
        (TARGET, target(TARGET, 0)),
        (SECOND_TARGET, target(SECOND_TARGET, 101)),
    ] {
        let offset = file_offset(rva);
        bytes[offset..offset + code.len()].copy_from_slice(&code);
    }
    put32(&mut bytes, file_offset(CONFIG), 148);
    put32(&mut bytes, file_offset(CONFIG + 144), 0x100);
    for (field, target) in [
        (CONFIG + 120, DISPATCH_SLOT),
        (DISPATCH_SLOT, DISPATCH),
        (DECOY_SLOT, DISPATCH),
    ] {
        let offset = file_offset(field);
        bytes[offset..offset + 8].copy_from_slice(&(BASE + u64::from(target)).to_le_bytes());
    }
    put32(&mut bytes, file_offset(0x2200), CONFIG);
    put32(&mut bytes, file_offset(0x2204), 16);
    for (index, offset) in [0x78, 0x100, 0x108, 0].into_iter().enumerate() {
        put16(
            &mut bytes,
            file_offset(0x2208) + index * 2,
            if offset == 0 { 0 } else { 0xa000 | offset },
        );
    }
    bytes
}

fn module(pe: &PeFile) -> Module {
    let mut module = pe.to_module();
    let starts = BTreeSet::from([ENTRY, THUNK, TARGET, SECOND_TARGET]);
    module.functions = starts
        .iter()
        .map(|&rva| {
            kamy_disasm::recover_function(&module, Rva::new(rva), &starts, &BTreeSet::new())
        })
        .collect();
    module
}

#[test]
fn metadata_owns_dispatch_contract_not_the_slot_contents() {
    let mut bytes = fixture(false);
    let check = file_offset(CONFIG + 112);
    bytes[check..check + 8].copy_from_slice(&(BASE + u64::from(DECOY_SLOT)).to_le_bytes());
    let pe = PeFile::parse(&bytes).unwrap();
    let module = module(&pe);
    assert_eq!(
        pe.guard_cf_dispatch_slot().unwrap(),
        Some(Rva::new(DISPATCH_SLOT))
    );
    assert!(
        module
            .symbols
            .iter()
            .all(|symbol| symbol.kind != kamy_core::SymbolKind::Import)
    );
    let cc = kamy_link::build_callconv(&pe, &module).unwrap();
    let mut expected = Win64Default::default_signature();
    expected
        .args
        .push(AbiValue::register(PhysReg::Gpr(Gpr::Rax)));
    for rva in [DISPATCH_SLOT, THUNK] {
        assert_eq!(cc.lookup(BASE + u64::from(rva)), Some(expected.clone()));
    }
    for rva in [DECOY_SLOT, DISPATCH] {
        assert_eq!(
            cc.lookup(BASE + u64::from(rva)),
            Some(Win64Default::default_signature())
        );
    }
    let mut malformed = bytes;
    let offset = file_offset(CONFIG + 120);
    malformed[offset..offset + 8].copy_from_slice(&1u64.to_le_bytes());
    let pe = PeFile::parse(&malformed).unwrap();
    assert!(kamy_link::build_callconv(&pe, &module).is_err());
}

#[test]
fn nontransparent_guard_thunks_do_not_inherit_the_forwarding_contract() {
    let mut bytes = fixture(false);
    let thunk = encode(
        THUNK,
        vec![
            Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 1i32).unwrap(),
            Instruction::with1(Code::Jmp_rm64, rip(DISPATCH_SLOT)).unwrap(),
        ],
    );
    let offset = file_offset(THUNK);
    bytes[offset..offset + thunk.len()].copy_from_slice(&thunk);
    let pe = PeFile::parse(&bytes).unwrap();
    let module = module(&pe);
    let cc = kamy_link::build_callconv(&pe, &module).unwrap();
    assert!(
        !cc.lookup(BASE + u64::from(THUNK))
            .unwrap()
            .args
            .iter()
            .any(|argument| { argument.register_location() == Some(PhysReg::Gpr(Gpr::Rax)) })
    );
}

#[test]
fn guard_dispatch_keeps_loaded_target_through_flag_scratch_and_stack_forwarding() {
    for (indirect, mba) in [(false, false), (false, true), (true, false), (true, true)] {
        let original = fixture(indirect);
        let pe = PeFile::parse(&original).unwrap();
        let module = module(&pe);
        let cc = kamy_link::build_callconv(&pe, &module).unwrap();
        let caller = module
            .functions
            .iter()
            .find(|function| function.entry == Rva::new(ENTRY))
            .unwrap();
        let mut lifted = kamy_lift::lift_function(&module, caller, &cc, &[]);
        assert!(!lifted.unsupported);
        kamy_lift::ssa::construct_ssa(&mut lifted).unwrap();
        let instructions: BTreeMap<_, _> = lifted
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|instruction| instruction.dest.map(|dest| (dest, instruction)))
            .collect();
        let call = lifted
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find(|instruction| {
                matches!(
                    instruction.op,
                    IrOp::Call { .. } | IrOp::CallIndirect { .. }
                )
            })
            .unwrap();
        let mut target = *call
            .args
            .iter()
            .find(|value| lifted.reg_pins.get(*value) == Some(&PhysReg::Gpr(Gpr::Rax)))
            .expect("RAX MUST be an explicit guard-call dependency");
        while let IrOp::Copy = instructions[&target].op {
            target = instructions[&target].args[0];
        }
        assert!(matches!(instructions[&target].op, IrOp::Load));
        let mut invocations: BTreeMap<SymbolId, Vec<f32>> = BTreeMap::new();
        let (protected, report) = kamy_link::protect(
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
                assert_eq!(intensity, 1.0);
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
        let thunk_symbol = SymbolId::Host {
            rva: Rva::new(THUNK),
        };
        assert_eq!(
            report.rejected,
            [(thunk_symbol.clone(), RejectionReason::ResolvableIndirect)]
        );
        assert_eq!(report.ssa_lowered, 3);
        assert_eq!(report.moved.len(), 3);
        assert_eq!(invocations.len(), 3);
        for rva in [ENTRY, TARGET, SECOND_TARGET] {
            let symbol = SymbolId::Host { rva: Rva::new(rva) };
            assert!(report.ssa_lowered_symbols.contains(&symbol));
            assert!(report.moved.contains(&symbol));
            assert_ne!(report.address_map[&symbol], Rva::new(rva));
            assert_eq!(invocations[&symbol], [1.0]);
            let function = report
                .functions
                .iter()
                .find(|function| function.symbol == symbol)
                .unwrap();
            assert!(function.selected && function.eligible && function.lowered);
            assert_eq!(function.transformed, mba);
            assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 });
        }
        let thunk = report
            .functions
            .iter()
            .find(|function| function.symbol == thunk_symbol)
            .unwrap();
        assert!(!thunk.lowered && !thunk.transformed);
        assert!(thunk.allocation.is_none());
        assert_eq!(report.address_map[&thunk_symbol], Rva::new(THUNK));
        let placements: Vec<_> = report
            .placements
            .iter()
            .filter(|placement| placement.symbol == thunk_symbol)
            .collect();
        assert_eq!(placements.len(), 1);
        assert_eq!(placements[0].ownership, Ownership::Resident);
        assert_eq!(placements[0].rva, Rva::new(THUNK));
        let output_pe = PeFile::parse(&protected).unwrap();
        assert_eq!(
            output_pe.guard_cf_dispatch_slot().unwrap(),
            Some(Rva::new(DISPATCH_SLOT))
        );
        let output_module = output_pe.to_module();
        let mut decoder = Decoder::with_ip(
            64,
            output_module.bytes_at(Rva::new(THUNK)).unwrap(),
            BASE + u64::from(THUNK),
            DecoderOptions::NONE,
        );
        assert_eq!(decoder.decode().code(), Code::Endbr64);
        let dispatch = decoder.decode();
        assert_eq!(dispatch.code(), Code::Jmp_rm64);
        assert_eq!(dispatch.memory_base(), Register::RIP);
        assert_eq!(
            dispatch.ip_rel_memory_address(),
            BASE + u64::from(DISPATCH_SLOT)
        );
        let translator_symbol = SymbolId::Generated {
            name: format!("translation-{:?}", Register::RAX).into(),
        };
        let translator_rva = report.address_map[&translator_symbol];
        let translators: Vec<_> = report
            .placements
            .iter()
            .filter(|placement| placement.symbol == translator_symbol)
            .collect();
        assert_eq!(translators.len(), 1);
        assert_eq!(translators[0].ownership, Ownership::Generated);
        assert_eq!(translators[0].source_rva, None);
        assert_eq!(translators[0].rva, translator_rva);
        let dispatch_slot = output_pe.guard_cf_dispatch_slot().unwrap().unwrap();
        let pointer = output_module.bytes_at(dispatch_slot).unwrap();
        assert_eq!(
            u64::from_le_bytes(pointer[..8].try_into().unwrap()),
            output_module.image_base + u64::from(translator_rva.get())
        );
        let mut translator = Decoder::with_ip(
            64,
            &output_module.bytes_at(translator_rva).unwrap()[..translators[0].size as usize],
            output_module.image_base + u64::from(translator_rva.get()),
            DecoderOptions::NONE,
        );
        assert_eq!(translator.decode().code(), Code::Endbr64);
        let source = translator.decode();
        assert_eq!(source.code(), Code::Mov_r64_rm64);
        assert_eq!(source.op0_register(), Register::R11);
        assert_eq!(source.op1_register(), Register::RAX);
        assert_eq!(
            &output_module.bytes_at(Rva::new(DECOY_SLOT)).unwrap()[..8],
            &module.bytes_at(Rva::new(DECOY_SLOT)).unwrap()[..8]
        );
        assert_eq!(
            u16::from_le_bytes(protected[0xde..0xe0].try_into().unwrap()) & 0x4000,
            0
        );
        #[cfg(all(target_arch = "x86_64", any(windows, target_os = "linux")))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&protected);
            let before: unsafe extern "win64" fn(*const usize, u64, u64, u64, u64, u64) -> u64 =
                unsafe { core::mem::transmute(input.at(Rva::new(ENTRY))) };
            let after: unsafe extern "win64" fn(*const usize, u64, u64, u64, u64, u64) -> u64 = unsafe {
                core::mem::transmute(output.at(report.address_map[&SymbolId::Host {
                    rva: Rva::new(ENTRY),
                }]))
            };
            for (rva, bias) in [(TARGET, 0), (SECOND_TARGET, 101)] {
                for [b, c, d, e, f] in [[3, 5, 7, 11, 13], [17, 23, 29, 31, 37]] {
                    let expected =
                        7 + 3 * b + 5 * c + 7 * d + 11 * e + 13 * f + bias + 7 + b + c + d + b;
                    let original_pointer = input.at(Rva::new(rva)) as usize;
                    // The protected call receives an old RVA, so its shared translator MUST resolve it.
                    let protected_pointer = output.at(Rva::new(rva)) as usize;
                    assert_eq!(
                        unsafe { before(&original_pointer, b, c, d, e, f) },
                        expected
                    );
                    assert_eq!(
                        unsafe { after(&protected_pointer, b, c, d, e, f) },
                        expected
                    );
                }
            }
            let null = 0;
            assert_eq!(unsafe { before(&null, 1, 2, 3, 4, 5) }, 0x55);
            assert_eq!(unsafe { after(&null, 1, 2, 3, 4, 5) }, 0x55);
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(windows, target_os = "linux")))]
mod native {
    use super::{PeFile, Rva};
    use core::ffi::c_void;

    #[cfg(windows)]
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

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            size: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, size: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, size: usize) -> i32;
    }

    pub(super) struct MappedImage {
        address: *mut c_void,
        size: usize,
    }

    impl MappedImage {
        pub(super) fn new(bytes: &[u8]) -> Self {
            let module = PeFile::parse(bytes).unwrap().to_module();
            let size = module
                .sections
                .iter()
                .map(|section| section.rva.get() + section.virtual_size)
                .max()
                .unwrap() as usize;
            #[cfg(windows)]
            let address = unsafe { VirtualAlloc(core::ptr::null_mut(), size, 0x3000, 4) };
            #[cfg(target_os = "linux")]
            let address = unsafe { mmap(core::ptr::null_mut(), size, 3, 0x22, -1, 0) };
            assert!(!address.is_null() && address as usize != usize::MAX);
            let image = Self { address, size };
            unsafe {
                for section in &module.sections {
                    core::ptr::copy_nonoverlapping(
                        section.data.as_ptr(),
                        address.cast::<u8>().add(section.rva.get() as usize),
                        section.data.len(),
                    );
                }
                for relocation in &module.relocations {
                    match relocation.kind {
                        kamy_core::RelocKind::Absolute => {}
                        kamy_core::RelocKind::Dir64 => {
                            let pointer = image.at(relocation.rva).cast::<u64>();
                            pointer.write_unaligned(
                                pointer
                                    .read_unaligned()
                                    .wrapping_sub(module.image_base)
                                    .wrapping_add(address as u64),
                            );
                        }
                        kind => panic!("unsupported fixture relocation {kind:?}"),
                    }
                }
                #[cfg(windows)]
                {
                    let mut old = 0;
                    assert_ne!(VirtualProtect(address, image.size, 0x20, &mut old), 0);
                    assert_ne!(
                        FlushInstructionCache(GetCurrentProcess(), address, image.size),
                        0
                    );
                }
                #[cfg(target_os = "linux")]
                assert_eq!(mprotect(address, image.size, 5), 0);
            }
            image
        }

        pub(super) fn at(&self, rva: Rva) -> *mut c_void {
            unsafe { self.address.cast::<u8>().add(rva.get() as usize).cast() }
        }
    }

    impl Drop for MappedImage {
        fn drop(&mut self) {
            #[cfg(windows)]
            assert_ne!(unsafe { VirtualFree(self.address, 0, 0x8000) }, 0);
            #[cfg(target_os = "linux")]
            assert_eq!(unsafe { munmap(self.address, self.size) }, 0);
        }
    }
}
