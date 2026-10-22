use std::collections::{BTreeMap, BTreeSet, HashMap};

use iced_x86::{Code, Instruction, MemoryOperand, Register};
use kamy_core::ir::{AbiValue, FnSignature, Gpr, MapCallConv, PhysReg, win64_volatiles};
use kamy_core::{Module, Rva, SymbolId};
use kamy_link::module::{EntryMode, Injection};
use kamy_link::{Options, Report, TransformOutcome};
use kamy_pe::PeFile;
use kamy_transforms::MbaPass;
use kamy_transforms::mba::{MbaBitwidths, MbaConfig, MbaSemantics};

const BASE: u64 = 0x1_4000_0000;
const ENTRY: u32 = 0x1000;
const MINIMAL: u32 = 0x1400;
const RETURNED: u32 = 0x1600;
const LATER: u32 = 0x1700;
const STARTS: [u32; 4] = [ENTRY, MINIMAL, RETURNED, LATER];

fn slot(offset: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, offset)
}

fn label(index: usize) -> u64 {
    // BlockEncoder resolves branch labels against source IPs, including external calls.
    0x8000_0000_0000_0000 + index as u64 * 16
}

fn encode(rva: u32, mut instructions: Vec<Instruction>) -> Vec<u8> {
    for (index, instruction) in instructions.iter_mut().enumerate() {
        instruction.set_ip(label(index));
    }
    kamy_codegen::relocate(&instructions, BASE + u64::from(rva)).unwrap()
}

fn minimal() -> Vec<u8> {
    use Register::*;
    encode(
        MINIMAL,
        vec![
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 72i32).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RCX, slot(64)).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(RETURNED)).unwrap(),
            Instruction::with2(Code::Lea_r64_m, RDX, slot(64)).unwrap(),
            Instruction::with2(Code::Cmp_rm64_r64, RAX, RDX).unwrap(),
            Instruction::with1(Code::Sete_rm8, AL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, EAX, AL).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 72i32).unwrap(),
            Instruction::with(Code::Retnq),
        ],
    )
}

fn status(code: &mut Vec<Instruction>, condition: Code, bit: u32) {
    use Register::*;
    code.extend([
        Instruction::with1(condition, AL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, EAX, AL).unwrap(),
    ]);
    if bit != 0 {
        code.push(Instruction::with2(Code::Shl_rm64_imm8, RAX, bit).unwrap());
    }
    code.push(Instruction::with2(Code::Or_rm64_r64, R8, RAX).unwrap());
}

fn caller() -> Vec<u8> {
    use Register::*;
    let mut code = vec![
        Instruction::with2(Code::Sub_rm64_imm8, RSP, 72i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, slot(32), RCX).unwrap(),
        Instruction::with2(Code::Mov_rm64_imm32, slot(64), 0x1234i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_imm32, slot(56), 0x5678i32).unwrap(),
        Instruction::with2(Code::Lea_r64_m, RCX, slot(64)).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(RETURNED)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, slot(40), RAX).unwrap(),
        Instruction::with2(Code::Lea_r64_m, RCX, slot(56)).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(RETURNED)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, slot(48), RAX).unwrap(),
        Instruction::with2(Code::Cmp_rm64_imm8, slot(32), 0i32).unwrap(),
    ];
    let branch = code.len();
    code.push(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap());
    code.push(Instruction::with2(Code::Mov_r64_rm64, R10, slot(40)).unwrap());
    let jump = code.len();
    code.push(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap());
    let known = code.len();
    code.push(Instruction::with2(Code::Lea_r64_m, R10, slot(64)).unwrap());
    let join = code.len();
    code[branch].set_near_branch64(label(known));
    code[jump].set_near_branch64(label(join));
    code.extend([
        Instruction::with2(Code::Mov_r64_rm64, R11, R10).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, slot(40), R11).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, RCX, R11).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(RETURNED)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, slot(40), RAX).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, RCX, slot(32)).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, BASE + u64::from(LATER)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, R10, slot(40)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, R11, slot(48)).unwrap(),
        Instruction::with2(Code::Lea_r64_m, R9, slot(64)).unwrap(),
        Instruction::with2(Code::Lea_r64_m, RCX, slot(56)).unwrap(),
        Instruction::with2(Code::Xor_rm32_r32, R8D, R8D).unwrap(),
        Instruction::with2(Code::Cmp_rm64_r64, R10, R9).unwrap(),
    ]);
    status(&mut code, Code::Sete_rm8, 0);
    code.push(Instruction::with2(Code::Cmp_rm64_r64, R9, R10).unwrap());
    status(&mut code, Code::Sete_rm8, 1);
    code.push(Instruction::with2(Code::Cmp_rm64_r64, R10, RCX).unwrap());
    status(&mut code, Code::Setne_rm8, 2);
    code.extend([
        Instruction::with2(
            Code::Lea_r64_m,
            RAX,
            MemoryOperand::with_base_displ(R10, -8),
        )
        .unwrap(),
        Instruction::with2(Code::Cmp_rm64_r64, RAX, RCX).unwrap(),
    ]);
    status(&mut code, Code::Sete_rm8, 3);
    code.extend([
        Instruction::with2(Code::Mov_r64_rm64, RAX, R10).unwrap(),
        Instruction::with2(Code::Sub_rm64_r64, RAX, RCX).unwrap(),
        Instruction::with2(Code::Cmp_rm64_imm8, RAX, 8i32).unwrap(),
    ]);
    status(&mut code, Code::Sete_rm8, 4);
    code.extend([
        Instruction::with2(Code::Mov_r64_rm64, RAX, RCX).unwrap(),
        Instruction::with2(Code::Sub_rm64_r64, RAX, R10).unwrap(),
        Instruction::with2(Code::Cmp_rm64_imm8, RAX, -8i32).unwrap(),
    ]);
    status(&mut code, Code::Sete_rm8, 5);
    code.push(Instruction::with2(Code::Cmp_rm64_r64, R11, RCX).unwrap());
    status(&mut code, Code::Sete_rm8, 6);
    code.extend([
        Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(R10)).unwrap(),
        Instruction::with2(Code::Cmp_rm64_imm32, RAX, 0x1234i32).unwrap(),
    ]);
    status(&mut code, Code::Sete_rm8, 7);
    code.extend([
        Instruction::with2(Code::Mov_r64_rm64, RAX, MemoryOperand::with_base(R11)).unwrap(),
        Instruction::with2(Code::Cmp_rm64_imm32, RAX, 0x5678i32).unwrap(),
    ]);
    status(&mut code, Code::Sete_rm8, 8);
    code.extend([
        Instruction::with2(Code::Lea_r64_m, RAX, slot(88)).unwrap(),
        Instruction::with2(Code::Sub_rm64_r64, RAX, R9).unwrap(),
        Instruction::with2(Code::Cmp_rm64_imm8, RAX, 24i32).unwrap(),
    ]);
    status(&mut code, Code::Sete_rm8, 9);
    code.extend([
        Instruction::with2(Code::Lea_r64_m, RDX, slot(88)).unwrap(),
        Instruction::with2(Code::Cmp_rm64_r64, RCX, RDX).unwrap(),
    ]);
    status(&mut code, Code::Setb_rm8, 10);
    code.push(Instruction::with2(Code::Cmp_rm64_r64, RCX, R10).unwrap());
    status(&mut code, Code::Setb_rm8, 11);
    code.push(Instruction::with2(Code::Cmp_rm64_r64, R10, RCX).unwrap());
    status(&mut code, Code::Setae_rm8, 12);
    code.push(Instruction::with2(Code::Cmp_rm64_r64, R9, R10).unwrap());
    status(&mut code, Code::Setbe_rm8, 13);
    code.push(Instruction::with2(Code::Cmp_rm64_r64, R10, R9).unwrap());
    status(&mut code, Code::Setae_rm8, 14);
    code.extend([
        Instruction::with2(Code::Mov_r64_rm64, RAX, R8).unwrap(),
        Instruction::with2(Code::Add_rm64_imm8, RSP, 72i32).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    encode(ENTRY, code)
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn fixture() -> Vec<u8> {
    use Register::*;
    let functions = [
        (ENTRY, caller()),
        (MINIMAL, minimal()),
        (
            RETURNED,
            encode(
                RETURNED,
                vec![
                    Instruction::with2(Code::Mov_r64_rm64, RAX, RCX).unwrap(),
                    Instruction::with(Code::Retnq),
                ],
            ),
        ),
        (
            LATER,
            encode(
                LATER,
                vec![
                    Instruction::with3(Code::Imul_r64_rm64_imm8, RAX, RCX, 13i32).unwrap(),
                    Instruction::with2(Code::Sub_rm64_imm8, RAX, 9i32).unwrap(),
                    Instruction::with(Code::Retnq),
                ],
            ),
        ),
    ];
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
        let offset = 0x400 + (rva - ENTRY) as usize;
        bytes[offset..offset + code.len()].copy_from_slice(&code);
    }
    bytes
}

fn module(pe: &PeFile) -> Module {
    let mut module = pe.to_module();
    let starts: BTreeSet<_> = STARTS.into_iter().collect();
    module.functions = STARTS
        .into_iter()
        .map(|start| {
            kamy_disasm::recover_function(&module, Rva::new(start), &starts, &BTreeSet::new())
        })
        .collect();
    module
}

fn protect(bytes: &[u8], mba: bool) -> (Vec<u8>, Report) {
    let pe = PeFile::parse(bytes).unwrap();
    let module = module(&pe);
    let signature = FnSignature {
        args: vec![AbiValue::register(PhysReg::Gpr(Gpr::Rcx))],
        returns: vec![AbiValue::register(PhysReg::Gpr(Gpr::Rax))],
        clobbers: win64_volatiles(),
        noreturn: false,
    };
    let cc = MapCallConv::new(HashMap::from(
        STARTS.map(|rva| (BASE + u64::from(rva), signature.clone())),
    ));
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
            assert_eq!(intensity, 1.0);
            if *symbol
                == (SymbolId::Host {
                    rva: Rva::new(MINIMAL),
                })
            {
                assert!(function.blocks.iter().all(|block| {
                    block
                        .insts
                        .iter()
                        .all(|inst| !matches!(inst.op, kamy_core::ir::IrOp::FrameLogical))
                }));
            }
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
    for start in STARTS {
        assert_eq!(
            invocations[&SymbolId::Host {
                rva: Rva::new(start)
            }],
            [1.0],
            "every selected body MUST lower once at the requested intensity"
        );
    }
    result
}

#[test]
fn full_link_preserves_call_returned_frame_aliases_and_scalar_coordinates() {
    let original = fixture();
    for mba in [false, true] {
        let (lowered, report) = protect(&original, mba);
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        for start in STARTS {
            let symbol = SymbolId::Host {
                rva: Rva::new(start),
            };
            assert!(report.ssa_lowered_symbols.contains(&symbol));
            let function = report
                .functions
                .iter()
                .find(|function| function.symbol == symbol)
                .unwrap();
            assert!(function.selected && function.eligible && function.lowered);
            if [ENTRY, MINIMAL, LATER].contains(&start) {
                assert_eq!(function.transformed, mba);
                assert_eq!(function.intensity, if mba { 1.0 } else { 0.0 });
            }
        }
        if let Some(directory) = std::env::var_os("KAMY_MEMORY_FRAME_WITNESS_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            let name = if mba { "mba" } else { "identity" };
            std::fs::write(
                directory.join(format!("frame-call-alias-{name}-before.exe")),
                &original,
            )
            .unwrap();
            std::fs::write(
                directory.join(format!("frame-call-alias-{name}-after.exe")),
                &lowered,
            )
            .unwrap();
        }
        #[cfg(all(
            target_arch = "x86_64",
            any(windows, target_os = "linux", target_os = "macos")
        ))]
        {
            let input = native::MappedImage::new(&original);
            let output = native::MappedImage::new(&lowered);
            for (start, expected) in [(MINIMAL, 1), (ENTRY, 32767)] {
                let symbol = SymbolId::Host {
                    rva: Rva::new(start),
                };
                let before: unsafe extern "win64" fn(u64) -> u64 =
                    unsafe { core::mem::transmute(input.at(Rva::new(start))) };
                let after: unsafe extern "win64" fn(u64) -> u64 =
                    unsafe { core::mem::transmute(output.at(report.address_map[&symbol])) };
                for selector in [0, 1, 7, u64::MAX] {
                    assert_eq!(unsafe { before(selector) }, expected, "original {start:#x}");
                    assert_eq!(
                        unsafe { after(selector) },
                        expected,
                        "lowered {start:#x}, mba={mba}"
                    );
                }
            }
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(windows, target_os = "linux", target_os = "macos")
))]
mod native {
    use super::{PeFile, Rva};
    use core::ffi::c_void;

    #[cfg(windows)]
    mod platform {
        use super::c_void;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn VirtualAlloc(
                address: *mut c_void,
                size: usize,
                kind: u32,
                protection: u32,
            ) -> *mut c_void;
            fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
            fn VirtualProtect(
                address: *mut c_void,
                size: usize,
                protection: u32,
                old: *mut u32,
            ) -> i32;
            fn FlushInstructionCache(
                process: *mut c_void,
                address: *const c_void,
                size: usize,
            ) -> i32;
            fn GetCurrentProcess() -> *mut c_void;
        }

        pub(super) unsafe fn allocate(size: usize) -> *mut c_void {
            let address = unsafe { VirtualAlloc(core::ptr::null_mut(), size, 0x3000, 4) };
            assert!(!address.is_null());
            address
        }

        pub(super) unsafe fn executable(address: *mut c_void, size: usize) {
            let mut old = 0;
            unsafe {
                assert_ne!(VirtualProtect(address, size, 0x20, &mut old), 0);
                assert_ne!(FlushInstructionCache(GetCurrentProcess(), address, size), 0);
            }
        }

        pub(super) unsafe fn release(address: *mut c_void, _size: usize) {
            assert_ne!(unsafe { VirtualFree(address, 0, 0x8000) }, 0);
        }
    }

    #[cfg(unix)]
    mod platform {
        use super::c_void;

        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                size: usize,
                protection: i32,
                flags: i32,
                descriptor: i32,
                offset: i64,
            ) -> *mut c_void;
            fn mprotect(address: *mut c_void, size: usize, protection: i32) -> i32;
            fn munmap(address: *mut c_void, size: usize) -> i32;
        }

        pub(super) unsafe fn allocate(size: usize) -> *mut c_void {
            let anonymous = if cfg!(target_os = "macos") {
                0x1000
            } else {
                0x20
            };
            let address = unsafe { mmap(core::ptr::null_mut(), size, 3, 2 | anonymous, -1, 0) };
            assert_ne!(address as usize, usize::MAX);
            address
        }

        pub(super) unsafe fn executable(address: *mut c_void, size: usize) {
            assert_eq!(unsafe { mprotect(address, size, 5) }, 0);
        }

        pub(super) unsafe fn release(address: *mut c_void, size: usize) {
            assert_eq!(unsafe { munmap(address, size) }, 0);
        }
    }

    pub(super) struct MappedImage {
        address: *mut c_void,
        size: usize,
    }

    impl MappedImage {
        pub(super) fn new(bytes: &[u8]) -> Self {
            let module = PeFile::parse(bytes).unwrap().to_module();
            assert!(module.relocations.is_empty());
            let size = module
                .sections
                .iter()
                .map(|section| section.rva.get() + section.virtual_size)
                .max()
                .unwrap() as usize;
            let address = unsafe { platform::allocate(size) };
            let image = Self { address, size };
            unsafe {
                for section in &module.sections {
                    core::ptr::copy_nonoverlapping(
                        section.data.as_ptr(),
                        address.cast::<u8>().add(section.rva.get() as usize),
                        section.data.len(),
                    );
                }
                platform::executable(address, size);
            }
            image
        }

        pub(super) fn at(&self, rva: Rva) -> *mut c_void {
            unsafe { self.address.cast::<u8>().add(rva.get() as usize).cast() }
        }
    }

    impl Drop for MappedImage {
        fn drop(&mut self) {
            unsafe { platform::release(self.address, self.size) };
        }
    }
}
