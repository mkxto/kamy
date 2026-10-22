use std::collections::BTreeMap;

use kamy_core::{HostReference, ReferenceKind, RelocKind, Relocation, Rva};
use kamy_pe::PeFile;

const IMAGE_BASE: u64 = 0x140000000;
const PE_OFFSET: usize = 0x80;
const OPTIONAL_HEADER: usize = PE_OFFSET + 24;
const SECTION_TABLE: usize = OPTIONAL_HEADER + 0xf0;
const LOAD_CONFIG: u32 = 0x3000;
const TABLE: u32 = 0x5080;
const ORIGINAL: u32 = 0x1100;
const ALTERNATE: u32 = 0x1200;
const PATCH: u32 = 0x1301;
const TARGET: u32 = 0x1400;
const UNRELATED: u32 = 0x1500;
const OVERRIDE_SIZE: u32 = 32;
const PAYLOAD_SIZE: u32 = 4 + OVERRIDE_SIZE + 8 + 24;

#[derive(Clone, Copy, Debug)]
enum Locator {
    Va,
    SectionRelative,
}

struct Fixture {
    bytes: Vec<u8>,
    version: u32,
}

impl Fixture {
    fn new(version: u32, locator: Locator) -> Self {
        let mut fixture = Self {
            bytes: vec![0; 0x3400],
            version,
        };
        fixture.bytes[..2].copy_from_slice(b"MZ");
        fixture.file32(0x3c, PE_OFFSET as u32);
        fixture.bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        fixture.file16(PE_OFFSET + 4, 0x8664);
        fixture.file16(PE_OFFSET + 6, 3);
        fixture.file16(PE_OFFSET + 20, 0xf0);
        fixture.file16(PE_OFFSET + 22, 0x2022);
        fixture.file16(OPTIONAL_HEADER, 0x20b);
        fixture.file32(OPTIONAL_HEADER + 16, ORIGINAL);
        fixture.file64(OPTIONAL_HEADER + 24, IMAGE_BASE);
        fixture.file32(OPTIONAL_HEADER + 32, 0x1000);
        fixture.file32(OPTIONAL_HEADER + 36, 0x200);
        fixture.file32(OPTIONAL_HEADER + 56, 0x6000);
        fixture.file32(OPTIONAL_HEADER + 60, 0x400);
        fixture.file32(OPTIONAL_HEADER + 108, 16);
        fixture.directory(3, 0x3200, 5 * 12);
        fixture.directory(10, LOAD_CONFIG, 0x140);
        fixture.section(0, b".text", 0x1000, 0x400, 0x60000020);
        fixture.section(1, b".rdata", 0x3000, 0x1400, 0x40000040);
        fixture.section(2, b".reloc", 0x5000, 0x2400, 0x42000040);
        fixture.put32(LOAD_CONFIG, 0x140);
        match locator {
            Locator::Va => fixture.put64(LOAD_CONFIG + 192, IMAGE_BASE + u64::from(TABLE)),
            Locator::SectionRelative => {
                fixture.put32(LOAD_CONFIG + 224, TABLE - 0x5000);
                fixture.put16(LOAD_CONFIG + 228, 3);
            }
        }
        for (index, begin) in [ORIGINAL, ALTERNATE, 0x1300, TARGET, UNRELATED]
            .into_iter()
            .enumerate()
        {
            let runtime = 0x3200 + index as u32 * 12;
            fixture.put32(runtime, begin);
            fixture.put32(runtime + 4, begin + 0x20);
            fixture.put32(runtime + 8, 0x3280);
            fixture.bytes[Self::offset(begin)] = 0xc3;
        }
        fixture.bytes[Self::offset(0x3280)] = 1;
        fixture.bytes[Self::offset(PATCH - 1)] = 0xe8;
        fixture.put32(PATCH, TARGET - (PATCH + 4));
        fixture.put32(TABLE, version);
        fixture.put32(TABLE + 4, fixture.header_size() + PAYLOAD_SIZE);
        match version {
            1 => {
                fixture.put64(TABLE + 8, 7);
                fixture.put32(TABLE + 16, PAYLOAD_SIZE);
            }
            2 => {
                fixture.put32(TABLE + 8, fixture.header_size());
                fixture.put32(TABLE + 12, PAYLOAD_SIZE);
                fixture.put64(TABLE + 16, 7);
            }
            _ => unreachable!(),
        }
        let payload = fixture.payload();
        fixture.put32(payload, OVERRIDE_SIZE);
        fixture.put32(payload + 4, ORIGINAL);
        fixture.put32(payload + 8, 0);
        fixture.put32(payload + 12, 4);
        fixture.put32(payload + 16, 12);
        fixture.put32(payload + 20, ALTERNATE);
        fixture.put32(payload + 24, PATCH & !0xfff);
        fixture.put32(payload + 28, 12);
        fixture.put16(payload + 32, 0x1000 | (PATCH & 0xfff) as u16);
        let bdd = payload + 4 + OVERRIDE_SIZE;
        fixture.put32(bdd, 1);
        fixture.put32(bdd + 4, 24);
        fixture.put16(bdd + 8, 1);
        fixture.put16(bdd + 10, 2);
        for node in [bdd + 16, bdd + 24] {
            fixture.put16(node, u16::MAX);
            fixture.put16(node + 2, u16::MAX);
        }
        fixture
    }

    fn offset(rva: u32) -> usize {
        match rva {
            0x1000..=0x1fff => 0x400 + (rva - 0x1000) as usize,
            0x3000..=0x3fff => 0x1400 + (rva - 0x3000) as usize,
            0x5000..=0x5fff => 0x2400 + (rva - 0x5000) as usize,
            0x90000000..=0x90000fff => 0x3400 + (rva - 0x90000000) as usize,
            _ => panic!("fixture RVA {rva:#x} is not mapped"),
        }
    }

    fn file16(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn file32(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn file64(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put16(&mut self, rva: u32, value: u16) {
        self.file16(Self::offset(rva), value);
    }

    fn put32(&mut self, rva: u32, value: u32) {
        self.file32(Self::offset(rva), value);
    }

    fn put64(&mut self, rva: u32, value: u64) {
        self.file64(Self::offset(rva), value);
    }

    fn directory(&mut self, index: usize, rva: u32, size: u32) {
        let field = OPTIONAL_HEADER + 112 + index * 8;
        self.file32(field, rva);
        self.file32(field + 4, size);
    }

    fn section(&mut self, index: usize, name: &[u8], rva: u32, raw: u32, flags: u32) {
        let header = SECTION_TABLE + index * 40;
        self.bytes[header..header + name.len()].copy_from_slice(name);
        self.file32(header + 8, 0x1000);
        self.file32(header + 12, rva);
        self.file32(header + 16, 0x1000);
        self.file32(header + 20, raw);
        self.file32(header + 36, flags);
    }

    fn base_relocations(&mut self, entries: &[u16]) {
        let base = 0x5400;
        let size = 8 + entries.len() as u32 * 2;
        self.directory(5, base, size);
        self.put32(base, 0x3000);
        self.put32(base + 4, size);
        for (index, entry) in entries.iter().enumerate() {
            self.put16(base + 8 + index as u32 * 2, *entry);
        }
    }

    fn header_size(&self) -> u32 {
        match self.version {
            1 => 12,
            2 => 24,
            _ => unreachable!(),
        }
    }

    fn payload(&self) -> u32 {
        TABLE + 8 + self.header_size()
    }

    fn payload_size(&mut self, size: u32) {
        let field = match self.version {
            1 => TABLE + 16,
            2 => TABLE + 12,
            _ => unreachable!(),
        };
        self.put32(field, size);
        self.put32(TABLE + 4, self.header_size() + size);
    }

    fn references(&self) -> anyhow::Result<Vec<HostReference>> {
        PeFile::parse(&self.bytes)
            .expect("synthetic PE32+ headers must parse")
            .metadata_references()
            .map(|metadata| metadata.references)
    }
}

fn assert_localized(fixture: &Fixture, target: u32) {
    let references = fixture
        .references()
        .expect("valid function override metadata");
    for expected in [ORIGINAL, ALTERNATE, PATCH, target] {
        assert!(
            references.iter().any(|reference| {
                reference.kind == ReferenceKind::Opaque && reference.target == Rva::new(expected)
            }),
            "missing opaque target {expected:#x}"
        );
    }
    assert!(references.iter().any(|reference| {
        reference.kind == ReferenceKind::Unwind && reference.target == Rva::new(UNRELATED)
    }));
    assert!(!references.iter().any(|reference| {
        reference.kind == ReferenceKind::Opaque
            && (UNRELATED..UNRELATED + 0x20).contains(&reference.target.get())
    }));
}

#[test]
fn va_based_v1_function_override_localizes_opaque_references() {
    assert_localized(&Fixture::new(1, Locator::Va), TARGET);
}

#[test]
fn section_relative_v1_function_override_localizes_opaque_references() {
    assert_localized(&Fixture::new(1, Locator::SectionRelative), TARGET);
}

#[test]
fn va_based_v2_function_override_localizes_opaque_references() {
    assert_localized(&Fixture::new(2, Locator::Va), TARGET);
}

#[test]
fn section_relative_v2_function_override_localizes_opaque_references() {
    assert_localized(&Fixture::new(2, Locator::SectionRelative), TARGET);
}

#[test]
fn rel32_targets_are_signed() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::SectionRelative);
        let target = 0x1080;
        fixture.bytes[Fixture::offset(target)] = 0xc3;
        let displacement = i64::from(target) - i64::from(PATCH + 4);
        fixture.put32(PATCH, (displacement as i32) as u32);
        assert_localized(&fixture, target);
    }
}

#[test]
fn invalid_section_relative_locator_indices_are_rejected() {
    for section in [0, 4, u16::MAX] {
        let mut fixture = Fixture::new(1, Locator::SectionRelative);
        fixture.put16(LOAD_CONFIG + 228, section);
        assert!(fixture.references().is_err(), "section ordinal {section}");
    }
}

#[test]
fn invalid_section_relative_locator_offsets_are_rejected() {
    for offset in [0x1000, u32::MAX] {
        let mut fixture = Fixture::new(1, Locator::SectionRelative);
        fixture.put32(LOAD_CONFIG + 224, offset);
        assert!(fixture.references().is_err(), "section offset {offset:#x}");
    }
}

#[test]
fn partial_section_relative_locator_is_rejected() {
    let mut fixture = Fixture::new(1, Locator::SectionRelative);
    fixture.put32(LOAD_CONFIG, 230);
    assert!(fixture.references().is_err());
}

#[test]
fn partial_dynamic_record_headers_are_rejected() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::Va);
        fixture.put32(TABLE + 4, fixture.header_size() - 1);
        assert!(fixture.references().is_err(), "table version {version}");
    }
}

#[test]
fn partial_dynamic_record_payloads_are_rejected() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::Va);
        fixture.put32(TABLE + 4, fixture.header_size() + PAYLOAD_SIZE - 1);
        assert!(fixture.references().is_err(), "table version {version}");
    }
}

#[test]
fn partial_function_override_headers_are_rejected() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::Va);
        fixture.put32(fixture.payload(), 15);
        assert!(fixture.references().is_err(), "table version {version}");
    }
}

#[test]
fn invalid_alternate_rva_sizes_are_rejected() {
    for version in [1, 2] {
        for size in [1, 2, 3, 5, u32::MAX] {
            let mut fixture = Fixture::new(version, Locator::Va);
            fixture.put32(fixture.payload() + 12, size);
            assert!(
                fixture.references().is_err(),
                "table version {version}, RVA size {size}"
            );
        }
    }
}

#[test]
fn invalid_function_base_relocation_sizes_are_rejected() {
    for version in [1, 2] {
        for size in [1, 7, 10, 13, u32::MAX] {
            let mut fixture = Fixture::new(version, Locator::Va);
            fixture.put32(fixture.payload() + 16, size);
            assert!(
                fixture.references().is_err(),
                "table version {version}, base relocation size {size}"
            );
        }
    }
}

#[test]
fn invalid_base_relocation_block_sizes_are_rejected() {
    for version in [1, 2] {
        for size in [0, 7, 9, 10, 16, u32::MAX] {
            let mut fixture = Fixture::new(version, Locator::Va);
            fixture.put32(fixture.payload() + 28, size);
            assert!(
                fixture.references().is_err(),
                "table version {version}, block size {size}"
            );
        }
    }
}

#[test]
fn rel32_target_overflow_is_rejected_instead_of_wrapping_to_mapped_code() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::Va);
        fixture.bytes.resize(0x4400, 0);
        fixture.file16(PE_OFFSET + 6, 4);
        fixture.file32(OPTIONAL_HEADER + 56, 0x90001000);
        fixture.section(3, b".high", 0x90000000, 0x3400, 0x60000020);
        fixture.put32(fixture.payload() + 24, 0x90000000);
        fixture.put16(fixture.payload() + 32, 0x1001);
        fixture.put32(0x90000001, 0x700010fb);
        assert!(fixture.references().is_err(), "table version {version}");
    }
}

#[test]
fn rel32_target_underflow_is_rejected() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::Va);
        fixture.put32(PATCH, i32::MIN as u32);
        assert!(fixture.references().is_err(), "table version {version}");
    }
}

#[test]
fn invalid_bdd_offsets_are_rejected() {
    for version in [1, 2] {
        for offset in [1, 4, 8, 32, u32::MAX] {
            let mut fixture = Fixture::new(version, Locator::Va);
            fixture.put32(fixture.payload() + 8, offset);
            assert!(
                fixture.references().is_err(),
                "table version {version}, BDD offset {offset}"
            );
        }
    }
}

#[test]
fn partial_bdd_headers_are_rejected() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::Va);
        fixture.payload_size(4 + OVERRIDE_SIZE + 7);
        assert!(fixture.references().is_err(), "table version {version}");
    }
}

#[test]
fn partial_bdd_nodes_are_rejected() {
    for version in [1, 2] {
        let mut fixture = Fixture::new(version, Locator::Va);
        fixture.put32(fixture.payload() + 4 + OVERRIDE_SIZE + 4, 23);
        assert!(fixture.references().is_err(), "table version {version}");
    }
}

#[test]
fn terminal_word_aligned_base_relocation_block_preserves_fixup_rewrites() {
    let mut fixture = Fixture::new(1, Locator::Va);
    fixture.directory(10, 0, 0);
    fixture.base_relocations(&[0xa400, 0x3408, 0]);
    fixture.put64(0x3400, IMAGE_BASE + u64::from(ORIGINAL));
    fixture.put32(0x3408, 0x12345678);
    let pe = PeFile::parse(&fixture.bytes).unwrap();
    pe.metadata_references().unwrap();
    let fixup = |rva, kind| Relocation {
        rva: Rva::new(rva),
        kind,
    };
    assert_eq!(
        pe.to_module().relocations,
        vec![
            fixup(0x3400, RelocKind::Dir64),
            fixup(0x3408, RelocKind::HighLow),
            fixup(0x3000, RelocKind::Absolute),
        ]
    );
    let replacement = Rva::new(0x1600);
    let edits = pe
        .rebase_references(&BTreeMap::from([(Rva::new(ORIGINAL), replacement)]))
        .unwrap();
    assert!(edits.patches.iter().any(|patch| {
        patch.rva == Rva::new(0x3400)
            && patch.bytes == (IMAGE_BASE + u64::from(replacement.get())).to_le_bytes()
    }));
    assert_eq!(
        edits.relocations,
        vec![
            fixup(0x3400, RelocKind::Dir64),
            fixup(0x3408, RelocKind::HighLow),
        ]
    );
}

#[test]
fn malformed_base_relocation_blocks_fail_at_the_pe_producer() {
    for size in [0, 1, 6, 7, 9, 11, 13, 16, u32::MAX] {
        let mut fixture = Fixture::new(1, Locator::Va);
        fixture.base_relocations(&[0xa400, 0]);
        fixture.put32(0x5404, size);
        let error = PeFile::parse(&fixture.bytes)
            .err()
            .expect("invalid block size");
        assert!(
            format!("{error:#}").contains("base relocation"),
            "size {size}"
        );
    }
    for size in [1, 7, 10, 13] {
        let mut fixture = Fixture::new(1, Locator::Va);
        fixture.base_relocations(&[0xa400, 0]);
        fixture.directory(5, 0x5400, size);
        assert!(
            PeFile::parse(&fixture.bytes).is_err(),
            "directory size {size}"
        );
    }
}

#[test]
fn invalid_base_relocation_directory_extents_are_rejected() {
    for (rva, size) in [
        (0, 12),
        (0x5400, 0),
        (0x5402, 12),
        (0x6000, 12),
        (0xffff_fffc, 8),
        (0x5ff8, 12),
    ] {
        let mut fixture = Fixture::new(1, Locator::Va);
        fixture.base_relocations(&[0xa400, 0]);
        fixture.put32(0x5ff8, 0x3000);
        fixture.put32(0x5ffc, 12);
        fixture.directory(5, rva, size);
        assert!(
            PeFile::parse(&fixture.bytes).is_err(),
            "directory {rva:#x}+{size:#x}"
        );
    }
    let mut fixture = Fixture::new(1, Locator::Va);
    fixture.base_relocations(&[0xa400, 0]);
    fixture.bytes.truncate(Fixture::offset(0x540a));
    assert!(PeFile::parse(&fixture.bytes).is_err());
}

#[test]
fn unknown_base_relocation_entry_contracts_are_rejected() {
    for kind in [1, 2, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15] {
        let mut fixture = Fixture::new(1, Locator::Va);
        fixture.base_relocations(&[(kind << 12) | 0x400, 0]);
        let error = PeFile::parse(&fixture.bytes)
            .err()
            .expect("unsupported relocation type");
        assert!(
            format!("{error:#}").contains("unsupported base relocation type"),
            "type {kind}"
        );
    }
}

#[test]
fn base_relocation_pages_and_subsequent_headers_require_alignment() {
    let mut fixture = Fixture::new(1, Locator::Va);
    fixture.base_relocations(&[0xa400, 0]);
    fixture.put32(0x5400, 0x3001);
    assert!(PeFile::parse(&fixture.bytes).is_err());

    let mut fixture = Fixture::new(1, Locator::Va);
    fixture.base_relocations(&[0]);
    fixture.put32(0x540a, 0x3000);
    fixture.put32(0x540e, 8);
    fixture.directory(5, 0x5400, 18);
    let error = PeFile::parse(&fixture.bytes)
        .err()
        .expect("unaligned second block");
    assert!(format!("{error:#}").contains("unaligned base relocation block header"));
}

#[test]
fn overflowing_base_relocation_fields_are_rejected() {
    for entry in [0x3ffd, 0xaff9] {
        let mut fixture = Fixture::new(1, Locator::Va);
        fixture.base_relocations(&[entry, 0]);
        fixture.put32(0x5400, 0xffff_f000);
        let error = PeFile::parse(&fixture.bytes)
            .err()
            .expect("overflowing fixup field");
        assert!(format!("{error:#}").contains("base relocation field overflows RVA space"));
    }
}
