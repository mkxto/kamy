use kamy_analysis::{ReferenceModel, build_reference_model};
use kamy_core::{
    BasicBlock, Function, Machine, Module, ReferenceKind, RelocKind, Relocation, Rva, Section,
    SectionFlags, Terminator,
};

const IMAGE_BASE: u64 = 0x1_4000_0000;
const TARGET: u32 = 0x1000;
const CONTROL: u32 = 0x1100;
const CALLER: u32 = 0x1200;
const DATA: u32 = 0x2000;

fn function(entry: u32, end: u32, terminator: Terminator) -> Function {
    Function {
        entry: Rva::new(entry),
        blocks: vec![BasicBlock {
            start: Rva::new(entry),
            end: Rva::new(end),
            successors: Vec::new(),
            terminator,
        }],
    }
}

fn module(caller: &[u8], terminator: Terminator, data: Vec<u8>) -> Module {
    let mut code = vec![0xcc; (CALLER - TARGET) as usize + caller.len()];
    code[..2].copy_from_slice(&[0x90, 0xc3]);
    code[(CONTROL - TARGET) as usize] = 0xc3;
    code[(CALLER - TARGET) as usize..].copy_from_slice(caller);
    Module {
        image_base: IMAGE_BASE,
        machine: Machine::X64,
        entry_point: None,
        sections: vec![
            Section {
                name: ".text".into(),
                rva: Rva::new(TARGET),
                virtual_size: code.len() as u32,
                data: code,
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
            Section {
                name: ".rdata".into(),
                rva: Rva::new(DATA),
                virtual_size: data.len() as u32,
                data,
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: false,
                },
            },
        ],
        symbols: Vec::new(),
        relocations: Vec::new(),
        functions: vec![
            function(TARGET, TARGET + 2, Terminator::Return),
            function(CONTROL, CONTROL + 1, Terminator::Return),
            function(CALLER, CALLER + caller.len() as u32, terminator),
        ],
    }
}

fn assert_target_pinned(model: &ReferenceModel, source: u32, target: u32) {
    assert!(!model.is_resolved(Rva::new(TARGET)));
    assert!(
        model.functions[&Rva::new(TARGET)]
            .unresolved
            .iter()
            .any(|reference| {
                reference.source == Rva::new(source) && reference.target == Rva::new(target)
            }),
        "missing unresolved reference from {source:#x} to {target:#x}"
    );
    assert!(model.is_resolved(Rva::new(CONTROL)));
}

#[test]
fn unsupported_highlow_does_not_hide_a_qword_pointer_to_code_interior() {
    let mut module = module(
        &[0xc3],
        Terminator::Return,
        (IMAGE_BASE + u64::from(TARGET + 1)).to_le_bytes().to_vec(),
    );
    module.relocations.push(Relocation {
        rva: Rva::new(DATA),
        kind: RelocKind::HighLow,
    });

    let model = build_reference_model(&module, &[]).unwrap();

    assert_target_pinned(&model, DATA, TARGET + 1);
}

#[test]
fn reading_entry_bytes_pins_code_but_materializing_the_entry_address_does_not() {
    // lea rax,[rip-0x207]; ret
    let address = module(
        &[0x48, 0x8d, 0x05, 0xf9, 0xfd, 0xff, 0xff, 0xc3],
        Terminator::Return,
        Vec::new(),
    );
    let address_model = build_reference_model(&address, &[]).unwrap();
    assert!(address_model.is_resolved(Rva::new(TARGET)));
    assert!(address_model.is_resolved(Rva::new(CONTROL)));
    assert!(address_model.references.iter().any(|reference| {
        reference.source == Rva::new(CALLER)
            && reference.target == Rva::new(TARGET)
            && reference.kind == ReferenceKind::RipRelative
    }));

    // movzx eax,byte ptr [rip-0x207]; ret
    let read = module(
        &[0x0f, 0xb6, 0x05, 0xf9, 0xfd, 0xff, 0xff, 0xc3],
        Terminator::Return,
        Vec::new(),
    );
    let read_model = build_reference_model(&read, &[]).unwrap();

    assert_target_pinned(&read_model, CALLER, TARGET);
}

#[test]
fn absolute_moffs64_read_of_code_interior_pins_its_target() {
    let mut caller = vec![0x48, 0xa1];
    caller.extend_from_slice(&(IMAGE_BASE + u64::from(TARGET + 1)).to_le_bytes());
    caller.push(0xc3);
    let module = module(&caller, Terminator::Return, Vec::new());

    let model = build_reference_model(&module, &[]).unwrap();

    assert_target_pinned(&model, CALLER, TARGET + 1);
}

#[test]
fn image_base_plus_rva_indirect_jump_pins_the_destination_function() {
    let module = module(
        &[
            0x48, 0x8d, 0x05, 0xf9, 0xed, 0xff, 0xff, // lea rax,[rip+__ImageBase]
            0xba, 0x01, 0x10, 0x00, 0x00, // mov edx,0x1001
            0x48, 0x01, 0xd0, // add rax,rdx
            0xff, 0xe0, // jmp rax
        ],
        Terminator::Unknown,
        Vec::new(),
    );

    let model = build_reference_model(&module, &[]).unwrap();

    assert_target_pinned(&model, CALLER + 7, TARGET + 1);
}
