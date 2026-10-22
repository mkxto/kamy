use super::*;
use kamy_core::{ReferenceOrigin, SymbolicExpression};

fn empty_compiler() -> abi::CompilerMetadata {
    abi::CompilerMetadata {
        version: "22.1.2".to_owned(),
        ir: "target triple = \"x86_64-pc-windows-msvc\"\ntarget datalayout = \"e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128\"\ndefine void @entry() {\n ret void\n}\n".to_owned(),
        machine: "# Machine code for function entry: NoVRegs\n RET 0\n# End machine code for function entry.\n".to_owned(),
    }
}

fn compiler() -> abi::CompilerMetadata {
    let mut compiler = empty_compiler();
    compiler.ir = compiler.ir.replace(
        "define void @entry() {\n ret void",
        "define i32 @entry(ptr %first, ptr %second, ptr %third) {\n ret i32 0",
    );
    compiler.machine = "# Machine code for function entry: NoVRegs\nFunction Live Ins: $rcx, $rdx, $r8\n RET 0, $eax\n# End machine code for function entry.\n".to_owned();
    compiler
}

fn compiler_symbol(index: u32, name: &str) -> SymbolId {
    SymbolId::Authored {
        module: "fixture".into(),
        symbol: format!("coff:0:symbol:{index}:{name}").into(),
    }
}

fn storage_symbol(section: u32) -> SymbolId {
    SymbolId::Authored {
        module: "fixture".into(),
        symbol: format!("coff:0:section:{section}:piece:0").into(),
    }
}

fn expression(symbol: SymbolId, addend: i64) -> SymbolicExpression {
    SymbolicExpression::Symbol { symbol, addend }
}

const BASE: u64 = 0x0000_0001_8000_0000;
const RELATIVE_TYPES: [(object::pe::RelocationType, u8); 6] = [
    (object::pe::IMAGE_REL_AMD64_REL32, 0),
    (object::pe::IMAGE_REL_AMD64_REL32_1, 1),
    (object::pe::IMAGE_REL_AMD64_REL32_2, 2),
    (object::pe::IMAGE_REL_AMD64_REL32_3, 3),
    (object::pe::IMAGE_REL_AMD64_REL32_4, 4),
    (object::pe::IMAGE_REL_AMD64_REL32_5, 5),
];

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn object(typ: object::pe::RelocationType, relocation_offset: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 240];
    put16(&mut bytes, 0, 0x8664);
    put16(&mut bytes, 2, 3);
    put32(&mut bytes, 8, 182);
    put32(&mut bytes, 12, 3);
    for (index, (name, size, pointer, flags)) in [
        (b".text".as_slice(), 16, 140, 0x6050_0020),
        (b".data".as_slice(), 16, 156, 0xc040_0040),
        (b".bss".as_slice(), 16, 0, 0xc030_0080),
    ]
    .into_iter()
    .enumerate()
    {
        let section = 20 + index * 40;
        bytes[section..section + name.len()].copy_from_slice(name);
        put32(&mut bytes, section + 16, size);
        put32(&mut bytes, section + 20, pointer);
        put32(&mut bytes, section + 36, flags);
    }
    put32(&mut bytes, 60 + 24, 172);
    put16(&mut bytes, 60 + 32, 1);
    bytes[140] = 0xc3;
    put32(&mut bytes, 172, relocation_offset);
    put32(&mut bytes, 176, 1);
    put16(&mut bytes, 180, typ.0);
    let width = if typ == object::pe::IMAGE_REL_AMD64_ADDR64 {
        8
    } else {
        4
    };
    if relocation_offset as usize + width <= 16 {
        let start = 156 + relocation_offset as usize;
        bytes[start..start + width].copy_from_slice(&8u64.to_le_bytes()[..width]);
    }
    for (index, (name, offset, section, kind)) in [
        (b"entry".as_slice(), 0, 1, 0x20),
        (b"value".as_slice(), 0, 2, 0),
        (b"state".as_slice(), 0, 3, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let symbol = 182 + index * 18;
        bytes[symbol..symbol + name.len()].copy_from_slice(name);
        put32(&mut bytes, symbol + 8, offset);
        put16(&mut bytes, symbol + 12, section);
        put16(&mut bytes, symbol + 14, kind);
        bytes[symbol + 16] = 2;
    }
    put32(&mut bytes, 236, 4);
    bytes
}

fn placements() -> Vec<Placement> {
    (1..=3)
        .map(|section| Placement {
            object: 0,
            section,
            offset: 0,
            size: 16,
            rva: section * 0x1000,
        })
        .collect()
}

fn fixture(
    typ: object::pe::RelocationType,
    relocation_offset: u32,
    placements: &[Placement],
) -> Vec<u8> {
    let provenance = object(typ, relocation_offset);
    let metadata = encode(0x1000, &[provenance], placements, &compiler()).unwrap();
    let absolute = typ == object::pe::IMAGE_REL_AMD64_ADDR64;
    let mut text = vec![0u8; 16];
    text[0] = 0xc3;
    let mut data = vec![0u8; 16];
    if relocation_offset as usize + if absolute { 8 } else { 4 } <= data.len() {
        let offset = relocation_offset as usize;
        if absolute {
            data[offset..offset + 8].copy_from_slice(&(BASE + 0x2008).to_le_bytes());
        } else if typ == object::pe::IMAGE_REL_AMD64_ADDR32NB {
            put32(&mut data, offset, 0x2008);
        } else if let Some((_, bias)) = RELATIVE_TYPES
            .iter()
            .find(|(candidate, _)| *candidate == typ)
        {
            let displacement =
                0x2008i64 - (0x2000 + i64::from(relocation_offset) + 4 + i64::from(*bias));
            put32(&mut data, offset, displacement as i32 as u32);
        }
    }
    let mut reloc = vec![0u8; 12];
    put32(&mut reloc, 0, 0x2000);
    put32(&mut reloc, 4, 12);
    put16(&mut reloc, 8, 0xa000 | relocation_offset as u16);
    let mut sections = vec![
        (".text", 0x1000, 16, text, 0x6000_0020u32),
        (".data", 0x2000, 16, data, 0xc000_0040),
        (".bss", 0x3000, 16, Vec::new(), 0xc000_0080),
    ];
    if absolute {
        sections.push((".reloc", 0x4000, 12, reloc, 0x4200_0040));
    }
    sections.push((
        ".kmod",
        0x5000,
        metadata.len() as u32,
        metadata,
        0x4000_0040,
    ));
    let mut bytes = vec![0u8; 0x400];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, sections.len() as u16);
    put16(&mut bytes, 0x94, 0xf0);
    put16(&mut bytes, 0x96, 0x2022);
    let opt = 0x98;
    put16(&mut bytes, opt, 0x20b);
    bytes[opt + 24..opt + 32].copy_from_slice(&BASE.to_le_bytes());
    put32(&mut bytes, opt + 32, 0x1000);
    put32(&mut bytes, opt + 36, 0x200);
    put32(&mut bytes, opt + 56, 0x6000);
    put32(&mut bytes, opt + 60, 0x400);
    put16(&mut bytes, opt + 68, 2);
    put16(&mut bytes, opt + 70, 0x160);
    put32(&mut bytes, opt + 108, 16);
    if absolute {
        put32(&mut bytes, opt + 112 + 5 * 8, 0x4000);
        put32(&mut bytes, opt + 116 + 5 * 8, 12);
    }
    for (index, (name, rva, virtual_size, data, flags)) in sections.into_iter().enumerate() {
        let header = opt + 0xf0 + index * 40;
        bytes[header..header + name.len()].copy_from_slice(name.as_bytes());
        put32(&mut bytes, header + 8, virtual_size);
        put32(&mut bytes, header + 12, rva);
        put32(&mut bytes, header + 36, flags);
        if !data.is_empty() {
            let raw_pointer = bytes.len();
            let raw_size = (data.len() + 0x1ff) & !0x1ff;
            put32(&mut bytes, header + 16, raw_size as u32);
            put32(&mut bytes, header + 20, raw_pointer as u32);
            bytes.extend_from_slice(&data);
            bytes.resize(raw_pointer + raw_size, 0);
        }
    }
    bytes
}

#[test]
fn embedded_coff_preserves_function_data_bss_and_absolute_reference() {
    let bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &placements());
    let module = AuthoredModule::parse(&bytes, "fixture").unwrap();
    assert_eq!(module.image, bytes);
    assert_eq!(module.entry, Rva::new(0x1000));
    assert_eq!(
        module.code,
        vec![CodeSymbol {
            symbol: compiler_symbol(0, "entry"),
            signature: abi::signatures(&compiler(), Some("entry"))
                .unwrap()
                .remove("entry")
                .unwrap(),
            name: "entry".to_owned(),
            start: Rva::new(0x1000),
            end: Rva::new(0x1010)
        }]
    );
    assert!(
        module
            .data
            .iter()
            .any(|s| s.name == "value" && s.start == Rva::new(0x2000) && s.size == 16)
    );
    assert!(
        module
            .data
            .iter()
            .any(|s| s.name == "state" && s.start == Rva::new(0x3000) && s.size == 16)
    );
    assert_eq!(
        module.references,
        vec![Reference {
            source: storage_symbol(2),
            offset: 0,
            expression: expression(compiler_symbol(1, "value"), 8),
            field: LinkField::Absolute64,
            origin: ReferenceOrigin::Authored,
        }]
    );
}

#[test]
fn sdk_bounds_require_native_initialized_storage_even_when_bss_is_file_backed() {
    for name in ["SYMBOL_init_table_start", "SYMBOL_init_table_end"] {
        for initialized in [false, true] {
            let mut original = object(object::pe::IMAGE_REL_AMD64_ADDR32NB, 0);
            put16(&mut original, 60 + 32, 0);
            original[156..172].fill(0);
            let symbol = 182 + if initialized { 18 } else { 36 };
            original[symbol..symbol + 8].fill(0);
            put32(&mut original, symbol + 4, 4);
            original.extend_from_slice(name.as_bytes());
            original.push(0);
            put32(&mut original, 236, (5 + name.len()) as u32);
            let section = if initialized { 2 } else { 3 };
            put32(&mut original, 20 + (section - 1) * 40 + 16, 8);
            let mut placed = placements();
            placed[section - 1].size = 8;
            let mut bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR32NB, 0, &placements());
            bytes[0x600..0x610].fill(0);
            let bss = 0x188 + 2 * 40;
            let raw_pointer = bytes.len() as u32;
            put32(&mut bytes, bss + 16, 0x200);
            put32(&mut bytes, bss + 20, raw_pointer);
            bytes.resize(bytes.len() + 0x200, 0);
            let pe = PeFile::parse(&bytes).unwrap();
            let signatures = abi::signatures(&compiler(), Some("entry")).unwrap();
            let result = coff::describe(&pe, &[original], &placed, 0x1000, "fixture", &signatures);
            if initialized {
                let module = result.unwrap();
                assert!(
                    module
                        .data
                        .iter()
                        .any(|symbol| symbol.name == name && symbol.size == 8)
                );
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(name), "{error}");
                assert!(
                    error.contains("initialized pointer-sized native storage"),
                    "{error}"
                );
                assert!(error.contains("rebuild"), "{error}");
            }
        }
    }
}

#[test]
fn every_amd64_relative_bias_and_image_relative_field_round_trips() {
    for (typ, bias) in RELATIVE_TYPES {
        let bytes = fixture(typ, 12, &placements());
        let module = AuthoredModule::parse(&bytes, "fixture").unwrap();
        assert_eq!(
            module.references[0].expression,
            expression(compiler_symbol(1, "value"), 8)
        );
        assert_eq!(module.references[0].field, LinkField::Relative32 { bias });
    }
    let module = AuthoredModule::parse(
        &fixture(object::pe::IMAGE_REL_AMD64_ADDR32NB, 12, &placements()),
        "fixture",
    )
    .unwrap();
    assert_eq!(module.references[0].field, LinkField::ImageRelative32);
    assert_eq!(
        module.references[0].expression,
        expression(compiler_symbol(1, "value"), 8)
    );
}

#[test]
fn metadata_decoder_rejects_unknown_version_and_malformed_lengths() {
    let good = encode(
        0x1000,
        &[object(object::pe::IMAGE_REL_AMD64_ADDR64, 0)],
        &placements(),
        &compiler(),
    )
    .unwrap();
    for length in [0, 7, 8, 12, 28, good.len() - 1] {
        assert!(decode(&good[..length]).is_err());
    }
    let mut wrong = good.clone();
    put32(&mut wrong, 8, VERSION + 1);
    assert!(decode(&wrong).is_err());
    let mut wrong = good.clone();
    put32(&mut wrong, 20, u32::MAX);
    assert!(decode(&wrong).is_err());
    let mut wrong = good;
    put32(&mut wrong, HEADER_SIZE, u32::MAX);
    assert!(decode(&wrong).is_err());
}

#[test]
fn missing_overlapping_and_out_of_range_contributions_fail() {
    let mut missing = placements();
    missing.pop();
    assert!(
        AuthoredModule::parse(
            &fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &missing),
            "fixture"
        )
        .is_err()
    );
    let mut duplicate = placements();
    duplicate.push(duplicate[0]);
    assert!(
        AuthoredModule::parse(
            &fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &duplicate),
            "fixture"
        )
        .is_err()
    );
    let mut overflow = placements();
    overflow[0].rva = u32::MAX - 4;
    assert!(
        AuthoredModule::parse(
            &fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &overflow),
            "fixture"
        )
        .is_err()
    );
}

#[test]
fn relocation_fields_must_fit_the_compiler_contribution() {
    assert!(
        AuthoredModule::parse(
            &fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 9, &placements()),
            "fixture"
        )
        .is_err()
    );
    assert!(
        AuthoredModule::parse(
            &fixture(object::pe::IMAGE_REL_AMD64_REL32, 13, &placements()),
            "fixture"
        )
        .is_err()
    );
    assert!(
        AuthoredModule::parse(
            &fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 8, &placements()),
            "fixture"
        )
        .is_ok()
    );
}

#[test]
fn linked_target_and_nonrelocated_bytes_must_match_embedded_provenance() {
    let mut bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &placements());
    let data_pointer = u32_at(&bytes, 0x98 + 0xf0 + 40 + 20).unwrap() as usize;
    bytes[data_pointer..data_pointer + 8].copy_from_slice(&(BASE + 0x2009).to_le_bytes());
    assert!(AuthoredModule::parse(&bytes, "fixture").is_err());
    let mut bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &placements());
    let text_pointer = u32_at(&bytes, 0x98 + 0xf0 + 20).unwrap() as usize;
    bytes[text_pointer] = 0x90;
    assert!(AuthoredModule::parse(&bytes, "fixture").is_err());
}

#[test]
fn unsupported_coff_relocation_fails_contextually() {
    let error = AuthoredModule::parse(
        &fixture(object::pe::IMAGE_REL_AMD64_ADDR32, 0, &placements()),
        "fixture",
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("unsupported AMD64 COFF relocation"));
}

#[test]
fn loader_relocations_must_exactly_match_coff_provenance() {
    let mut bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &placements());
    let reloc_pointer = u32_at(&bytes, 0x98 + 0xf0 + 3 * 40 + 20).unwrap() as usize;
    put16(&mut bytes, reloc_pointer + 8, 0xa008);
    assert!(AuthoredModule::parse(&bytes, "fixture").is_err());
}

#[test]
fn directories_cannot_share_application_storage() {
    let mut bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &placements());
    put32(&mut bytes, 0x98 + 112 + 3 * 8, 0x2000);
    put32(&mut bytes, 0x98 + 116 + 3 * 8, 12);
    assert!(AuthoredModule::parse(&bytes, "fixture").is_err());
}

fn imagebase_fixture(
    typ: object::pe::RelocationType,
    relocation_offset: u32,
    addend: i64,
    target: i64,
) -> Vec<u8> {
    let bytes = fixture(typ, relocation_offset, &placements());
    let pe = PeFile::parse(&bytes).unwrap();
    let mut original = object(typ, relocation_offset);
    original[200..208].fill(0);
    put32(&mut original, 204, 4);
    put32(&mut original, 208, 0);
    put16(&mut original, 212, 0);
    put32(&mut original, 236, 16);
    original.extend_from_slice(b"__ImageBase\0");
    let absolute = typ == object::pe::IMAGE_REL_AMD64_ADDR64;
    let width = if absolute { 8 } else { 4 };
    let mut patches = Vec::new();
    if relocation_offset as usize + width <= 16 {
        let start = 156 + relocation_offset as usize;
        original[start..start + width].copy_from_slice(&addend.to_le_bytes()[..width]);
        let value = if absolute {
            u64::try_from(i128::from(BASE) + i128::from(target))
                .unwrap()
                .to_le_bytes()
                .to_vec()
        } else if typ == object::pe::IMAGE_REL_AMD64_ADDR32NB {
            (target as u32).to_le_bytes().to_vec()
        } else {
            let bias = RELATIVE_TYPES
                .iter()
                .find(|(candidate, _)| *candidate == typ)
                .unwrap()
                .1;
            let displacement =
                target - (0x2000 + i64::from(relocation_offset) + 4 + i64::from(bias));
            (displacement as i32).to_le_bytes().to_vec()
        };
        patches.push(crate::BytePatch {
            rva: Rva::new(0x2000 + relocation_offset),
            bytes: value,
        });
    }
    let metadata = encode(0x1000, &[original], &placements(), &compiler()).unwrap();
    pe.rebuild(&crate::PeEdits {
        section_updates: vec![crate::SectionUpdate {
            index: if absolute { 4 } else { 3 },
            data: Some(metadata),
            ..crate::SectionUpdate::default()
        }],
        patches,
        ..crate::PeEdits::default()
    })
    .unwrap()
}

#[test]
fn imagebase_addends_remain_distinct_from_module_storage() {
    let types = [
        (object::pe::IMAGE_REL_AMD64_ADDR64, LinkField::Absolute64),
        (
            object::pe::IMAGE_REL_AMD64_ADDR32NB,
            LinkField::ImageRelative32,
        ),
    ]
    .into_iter()
    .chain(
        RELATIVE_TYPES
            .into_iter()
            .map(|(typ, bias)| (typ, LinkField::Relative32 { bias })),
    );
    for (typ, kind) in types {
        for addend in [0, 4, 0x2008, 0x21180, i64::from(i32::MAX)] {
            let bytes = imagebase_fixture(typ, 0, addend, addend);
            let module = AuthoredModule::parse(&bytes, "fixture").unwrap();
            assert_eq!(
                module.references,
                vec![Reference {
                    source: storage_symbol(2),
                    offset: 0,
                    expression: expression(SymbolId::HostImageBase, addend),
                    field: kind,
                    origin: ReferenceOrigin::Authored,
                }]
            );
        }
    }
    for (typ, addend) in [
        (object::pe::IMAGE_REL_AMD64_ADDR64, -2),
        (object::pe::IMAGE_REL_AMD64_ADDR64, i64::from(u32::MAX) + 1),
        (object::pe::IMAGE_REL_AMD64_ADDR64, i64::MAX),
        (object::pe::IMAGE_REL_AMD64_ADDR64, -(BASE as i64)),
        (object::pe::IMAGE_REL_AMD64_ADDR32NB, i64::from(u32::MAX)),
    ] {
        let bytes = imagebase_fixture(typ, 0, addend, addend);
        let module = AuthoredModule::parse(&bytes, "fixture").unwrap();
        assert_eq!(
            module.references[0].expression,
            expression(SymbolId::HostImageBase, addend)
        );
    }
    for (typ, _) in RELATIVE_TYPES {
        let bytes = imagebase_fixture(typ, 0, -2, -2);
        let module = AuthoredModule::parse(&bytes, "fixture").unwrap();
        let reference = &module.references[0];
        assert_eq!(
            reference.expression,
            expression(SymbolId::HostImageBase, -2)
        );
        let lowest = i64::from(i32::MIN)
            + 0x2004
            + i64::from(match reference.field {
                LinkField::Relative32 { bias } => bias,
                _ => unreachable!(),
            });
        let bytes = imagebase_fixture(typ, 0, lowest, lowest);
        assert_eq!(
            AuthoredModule::parse(&bytes, "fixture").unwrap().references[0].expression,
            expression(SymbolId::HostImageBase, lowest)
        );
        assert!(
            AuthoredModule::parse(
                &imagebase_fixture(typ, 0, lowest - 1, lowest - 1),
                "fixture"
            )
            .is_err()
        );
    }
}

#[test]
fn imagebase_addends_retain_compiler_provenance_and_range_checks() {
    for typ in [
        object::pe::IMAGE_REL_AMD64_ADDR64,
        object::pe::IMAGE_REL_AMD64_ADDR32NB,
    ]
    .into_iter()
    .chain(RELATIVE_TYPES.into_iter().map(|(typ, _)| typ))
    {
        let bytes = imagebase_fixture(typ, 0, 0x21180, 0x21181);
        let error = AuthoredModule::parse(&bytes, "fixture").unwrap_err();
        assert!(format!("{error:#}").contains("compiler symbol/addend provenance"));
        if typ == object::pe::IMAGE_REL_AMD64_ADDR32NB {
            let error =
                AuthoredModule::parse(&imagebase_fixture(typ, 0, 0, -1), "fixture").unwrap_err();
            assert!(format!("{error:#}").contains("compiler symbol/addend provenance"));
        }
        let last_offset = if typ == object::pe::IMAGE_REL_AMD64_ADDR64 {
            8
        } else {
            12
        };
        assert!(
            AuthoredModule::parse(&imagebase_fixture(typ, last_offset, 4, 4), "fixture").is_ok()
        );
        let error =
            AuthoredModule::parse(&imagebase_fixture(typ, last_offset + 1, 4, 4), "fixture")
                .unwrap_err();
        assert!(format!("{error:#}").contains("crosses contribution boundary"));
    }
    let bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR32NB, 0, &placements());
    let pe = PeFile::parse(&bytes).unwrap();
    let mut original = object(object::pe::IMAGE_REL_AMD64_ADDR32NB, 0);
    put32(&mut original, 156, u32::MAX);
    let metadata = encode(0x1000, &[original], &placements(), &compiler()).unwrap();
    let packed = pe
        .rebuild(&crate::PeEdits {
            section_updates: vec![crate::SectionUpdate {
                index: 3,
                data: Some(metadata),
                ..crate::SectionUpdate::default()
            }],
            patches: vec![crate::BytePatch {
                rva: Rva::new(0x2000),
                bytes: 0x1fffu32.to_le_bytes().to_vec(),
            }],
            ..crate::PeEdits::default()
        })
        .unwrap();
    let error = AuthoredModule::parse(&packed, "fixture").unwrap_err();
    assert!(format!("{error:#}").contains("compiler symbol/addend provenance"));
    let mut bytes = imagebase_fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, 0, 0);
    let data_pointer = u32_at(&bytes, 0x98 + 0xf0 + 40 + 20).unwrap() as usize;
    bytes[data_pointer..data_pointer + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let error = AuthoredModule::parse(&bytes, "fixture").unwrap_err();
    assert!(format!("{error:#}").contains("exceeds signed expression range"));
}

#[test]
fn trailing_immediate_bias_preserves_imagebase_and_local_symbol_expressions() {
    for image_base in [true, false] {
        let typ = object::pe::IMAGE_REL_AMD64_REL32;
        let bytes = fixture(typ, 5, &placements());
        let pe = PeFile::parse(&bytes).unwrap();
        let mut original = object(typ, 5);
        put32(&mut original, 20 + 24, 172);
        put16(&mut original, 20 + 32, 1);
        put32(&mut original, 60 + 24, 0);
        put16(&mut original, 60 + 32, 0);
        original[156..172].fill(0);
        let mut code = vec![
            0x31, 0xc0, 0x66, 0x81, 0x3d, 0xfe, 0xff, 0xff, 0xff, 0x4d, 0x5a, 0x0f, 0x95, 0xc0,
            0xc3, 0,
        ];
        original[140..156].copy_from_slice(&code);
        if image_base {
            original[200..208].fill(0);
            put32(&mut original, 204, 4);
            put32(&mut original, 208, 0);
            put16(&mut original, 212, 0);
            put32(&mut original, 236, 16);
            original.extend_from_slice(b"__ImageBase\0");
        }
        let symbol_rva = if image_base { 0i64 } else { 0x2000 };
        let displacement = i32::try_from(symbol_rva - 2 - 0x1009).unwrap();
        code[5..9].copy_from_slice(&displacement.to_le_bytes());
        let metadata = encode(0x1000, &[original], &placements(), &compiler()).unwrap();
        let packed = pe
            .rebuild(&crate::PeEdits {
                section_updates: vec![crate::SectionUpdate {
                    index: 3,
                    data: Some(metadata),
                    ..crate::SectionUpdate::default()
                }],
                patches: vec![
                    crate::BytePatch {
                        rva: Rva::new(0x1000),
                        bytes: code,
                    },
                    crate::BytePatch {
                        rva: Rva::new(0x2000),
                        bytes: vec![0; 16],
                    },
                ],
                ..crate::PeEdits::default()
            })
            .unwrap();
        let module = AuthoredModule::parse(&packed, "fixture").unwrap();
        assert_eq!(
            module.references,
            vec![Reference {
                source: compiler_symbol(0, "entry"),
                offset: 5,
                expression: expression(
                    if image_base {
                        SymbolId::HostImageBase
                    } else {
                        compiler_symbol(1, "value")
                    },
                    -2
                ),
                field: LinkField::Relative32 { bias: 0 },
                origin: ReferenceOrigin::Authored,
            }]
        );
        let linked = PeFile::parse(&packed).unwrap();
        let instruction = linked.slice_at_rva(0x1000).unwrap();
        let displacement = i32::from_le_bytes(instruction[5..9].try_into().unwrap());
        assert_eq!(0x100bi64 + i64::from(displacement), symbol_rva);
        assert_eq!(&instruction[9..11], &[0x4d, 0x5a]);
    }
}

#[test]
fn split_contribution_boundaries_choose_the_following_piece() {
    let pieces = [
        Placement {
            object: 0,
            section: 1,
            offset: 0,
            size: 12,
            rva: 0x400c,
        },
        Placement {
            object: 0,
            section: 1,
            offset: 12,
            size: 12,
            rva: 0x4000,
        },
    ];
    assert_eq!(coff::locate(&pieces, 0, 1, 12, 0).unwrap(), 0x4000);
    assert_eq!(coff::locate(&pieces, 0, 1, 24, 0).unwrap(), 0x400c);
    assert!(coff::locate(&pieces, 0, 1, 10, 4).is_err());
}

#[test]
fn module_instance_identity_is_not_a_source_rva_namespace() {
    let bytes = fixture(object::pe::IMAGE_REL_AMD64_ADDR64, 0, &placements());
    let left = AuthoredModule::parse(&bytes, "left").unwrap();
    let right = AuthoredModule::parse(&bytes, "right").unwrap();
    assert_eq!(left.code[0].start, right.code[0].start);
    assert_ne!(left.code[0].symbol, right.code[0].symbol);
    assert_ne!(
        left.references[0].expression,
        right.references[0].expression
    );
    assert_ne!(left.references[0].source, right.references[0].source);
}

#[test]
fn compiler_abi_serialization_round_trips_scalar_float_and_split_aggregate() {
    use kamy_core::ir::{AbiClass, AbiLocation, Gpr, PhysReg, XmmReg};
    let mut metadata = empty_compiler();
    metadata.ir = metadata.ir.replace("define void @entry() {\n ret void\n}", "define { i64, double } @entry(i64 %integer, double %real) {\n ret { i64, double } zeroinitializer\n}");
    metadata.machine = "# Machine code for function entry: NoVRegs\nFunction Live Ins: $rcx, $xmm1\n RET 0, $rax, $xmm0\n# End machine code for function entry.\n".to_owned();
    let original = object(object::pe::IMAGE_REL_AMD64_ADDR64, 0);
    let encoded = encode(0x1000, &[original], &placements(), &metadata).unwrap();
    let decoded = decode(&encoded).unwrap();
    let signatures = abi::signatures(&decoded.compiler, None).unwrap();
    let signature = &signatures["entry"];
    assert_eq!(signature.args.len(), 2);
    assert_eq!(
        (signature.args[0].class, signature.args[0].bits),
        (AbiClass::Integer, 64)
    );
    assert_eq!(
        signature.args[1].location,
        AbiLocation::Register(PhysReg::Xmm(XmmReg::Xmm1))
    );
    assert_eq!(signature.args[1].class, AbiClass::Float);
    assert_eq!(
        signature.returns[0].location,
        AbiLocation::Register(PhysReg::Gpr(Gpr::Rax))
    );
    assert_eq!(
        signature.returns[1].location,
        AbiLocation::Register(PhysReg::Xmm(XmmReg::Xmm0))
    );
    assert_eq!(signature.returns[1].class, AbiClass::Float);
}

#[test]
fn compiler_abi_retains_stack_hidden_sret_and_indirect_layout() {
    use kamy_core::ir::{AbiLocation, AbiPassing};
    let mut metadata = empty_compiler();
    metadata.ir = metadata.ir.replace("define void @entry()", "define void @entry(ptr sret([3 x i64]) align 8 %result, ptr byval([3 x i64]) align 8 %input, i64 %third, i64 %fourth, i64 %fifth)");
    metadata.machine = "# Machine code for function entry: NoVRegs\nFrame Objects:\n  fi#-1: size=8, align=8, fixed, at location [SP+40]\nFunction Live Ins: $rcx, $rdx, $r8, $r9\n RET 0, $rax\n# End machine code for function entry.\n".to_owned();
    let signatures = abi::signatures(&metadata, None).unwrap();
    let signature = &signatures["entry"];
    assert_eq!(
        signature.args[0].passing,
        AbiPassing::Sret { size: 24, align: 8 }
    );
    assert_eq!(
        signature.args[1].passing,
        AbiPassing::Indirect { size: 24, align: 8 }
    );
    assert_eq!(
        signature.args[4].location,
        AbiLocation::Stack { offset: 40 }
    );
    assert_eq!(signature.returns.len(), 1);
}

#[test]
fn compiler_abi_rejects_unknown_malformed_and_unsupported_records() {
    let good = empty_compiler();
    for replacement in [
        "define i128 @entry()",
        "define x86_vectorcallcc void @entry()",
        "define void @entry(...)",
        "define void @entry(ptr addrspace(1) %value)",
    ] {
        let mut metadata = good.clone();
        metadata.ir = metadata.ir.replace("define void @entry()", replacement);
        assert!(abi::signatures(&metadata, None).is_err());
    }
    for machine in [
        "",
        "# Machine code for function unknown: NoVRegs\n RET 0\n# End machine code for function unknown.\n",
        "# Machine code for function entry: NoVRegs\n RET 0\n",
        "# Machine code for function entry: NoVRegs\nFunction Live Ins: $ymm0\n RET 0\n# End machine code for function entry.\n",
    ] {
        let mut metadata = good.clone();
        metadata.machine = machine.to_owned();
        assert!(abi::signatures(&metadata, None).is_err());
    }
    let mut unknown = good;
    unknown.version = "23.0.0".to_owned();
    assert!(abi::signatures(&unknown, None).is_err());
}

#[test]
fn obsolete_artifact_schema_requires_rebuilding_the_plugin() {
    let mut bytes = encode(
        0x1000,
        &[object(object::pe::IMAGE_REL_AMD64_ADDR64, 0)],
        &placements(),
        &compiler(),
    )
    .unwrap();
    put32(&mut bytes, 8, 1);
    assert!(
        decode(&bytes)
            .unwrap_err()
            .to_string()
            .contains("rebuild the Rust plugin")
    );
}

#[test]
fn unused_entry_pointers_are_validated_from_declared_sdk_boundary() {
    use kamy_core::ir::{AbiLocation, Gpr, PhysReg};
    for liveins in [
        "",
        "Function Live Ins: $rdx\n",
        "Function Live Ins: $rcx, $r8\n",
    ] {
        let mut metadata = compiler();
        metadata.machine = format!(
            "# Machine code for function entry: NoVRegs\n{liveins} RET 0, $eax\n# End machine code for function entry.\n"
        );
        let signatures = abi::signatures(&metadata, Some("entry")).unwrap();
        let signature = &signatures["entry"];
        abi::validate_callback(signature).unwrap();
        assert_eq!(
            signature.args[1].location,
            AbiLocation::Register(PhysReg::Gpr(Gpr::Rdx))
        );
    }
    let mut metadata = compiler();
    metadata.machine = metadata.machine.replace("$rcx, $rdx, $r8", "$r9");
    assert!(abi::signatures(&metadata, Some("entry")).is_err());
    let mut metadata = compiler();
    metadata.ir = metadata.ir.replace("ptr %second", "i64 %second");
    assert!(abi::signatures(&metadata, Some("entry")).is_err());
}

#[test]
fn native_fastcc_masks_and_unused_noreturn_inputs_are_explicit() {
    use kamy_core::ir::{Gpr, PhysReg, X86Flag};
    let mut metadata = empty_compiler();
    metadata.ir.push_str("\ndefine internal fastcc i64 @callee(i64 %value) {\n ret i64 %value\n}\ndefine void @aborter(ptr %unused) noreturn {\n unreachable\n}\n");
    metadata.machine = "# Machine code for function entry: NoVRegs\n CALL64pcrel32 @callee, <regmask $rbx $rsp $rbp $rsi $rdi $r12 $r13 $r14 $r15 $xmm6 $xmm7 $xmm8 $xmm9 $xmm10 $xmm11 $xmm12 $xmm13 $xmm14 $xmm15>, implicit $rcx, implicit-def $rax\n RET 0\n# End machine code for function entry.\n# Machine code for function callee: NoVRegs\nFunction Live Ins: $rcx\n RET 0, $rax\n# End machine code for function callee.\n# Machine code for function aborter: NoVRegs\n INT 41\n# End machine code for function aborter.\n".to_owned();
    let signatures = abi::signatures(&metadata, None).unwrap();
    assert!(
        signatures["callee"]
            .clobbers
            .contains(&PhysReg::Gpr(Gpr::Rax))
    );
    assert!(
        !signatures["callee"]
            .clobbers
            .contains(&PhysReg::Gpr(Gpr::Rbx))
    );
    assert!(
        signatures["callee"]
            .clobbers
            .contains(&PhysReg::Flag(X86Flag::Of))
    );
    assert!(signatures["aborter"].noreturn);
    assert!(signatures["aborter"].args.is_empty());
    metadata.machine = metadata.machine.replace("$xmm15>", "and 4 more...>");
    assert!(abi::signatures(&metadata, None).is_err());
}

#[test]
fn one_past_compiler_symbols_retain_their_original_storage_owner() {
    let typ = object::pe::IMAGE_REL_AMD64_ADDR64;
    let bytes = fixture(typ, 0, &placements());
    let pe = PeFile::parse(&bytes).unwrap();
    let mut original = object(typ, 0);
    put32(&mut original, 208, 16);
    let metadata = encode(0x1000, &[original], &placements(), &compiler()).unwrap();
    let packed = pe
        .rebuild(&crate::PeEdits {
            section_updates: vec![crate::SectionUpdate {
                index: 4,
                data: Some(metadata),
                ..Default::default()
            }],
            patches: vec![crate::BytePatch {
                rva: Rva::new(0x2000),
                bytes: (BASE + 0x2018).to_le_bytes().to_vec(),
            }],
            ..Default::default()
        })
        .unwrap();
    let module = AuthoredModule::parse(&packed, "fixture").unwrap();
    assert_eq!(
        module.bindings[&compiler_symbol(1, "value")],
        expression(storage_symbol(2), 16)
    );
    assert_eq!(
        module.references[0].expression,
        expression(compiler_symbol(1, "value"), 8)
    );
    assert!(!module.bindings.contains_key(&module.code[0].symbol));
    assert!(!module.bindings.contains_key(&storage_symbol(2)));
}

#[test]
fn equal_numeric_literal_does_not_acquire_pointer_provenance() {
    let typ = object::pe::IMAGE_REL_AMD64_ADDR64;
    let bytes = fixture(typ, 0, &placements());
    let pe = PeFile::parse(&bytes).unwrap();
    let literal = (BASE + 0x2008).to_le_bytes();
    let mut original = object(typ, 0);
    original[164..172].copy_from_slice(&literal);
    let metadata = encode(0x1000, &[original], &placements(), &compiler()).unwrap();
    let packed = pe
        .rebuild(&crate::PeEdits {
            section_updates: vec![crate::SectionUpdate {
                index: 4,
                data: Some(metadata),
                ..Default::default()
            }],
            patches: vec![crate::BytePatch {
                rva: Rva::new(0x2008),
                bytes: literal.to_vec(),
            }],
            ..Default::default()
        })
        .unwrap();
    let module = AuthoredModule::parse(&packed, "fixture").unwrap();
    assert_eq!(module.references.len(), 1);
    assert_eq!(module.references[0].offset, 0);
    assert_eq!(
        module.references[0].expression,
        expression(compiler_symbol(1, "value"), 8)
    );
}
