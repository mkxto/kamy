use anyhow::{Context, ensure};
use kamy_core::Rva;

use crate::imports::{ImportSymbol, checked_imports};
use crate::{BytePatch, DirectoryUpdate, PeFile};

pub struct RebuiltImports {
    pub bytes: Vec<u8>,
    pub directory: DirectoryUpdate,
    pub iat_patches: Vec<BytePatch>,
}

impl PeFile {
    /// Rebuilds unbound imports while retaining every original IAT slot.
    /// The caller must clear the Bound Import directory when a blob is returned.
    pub fn rebuild_import_directory(
        &self,
        section_rva: Rva,
    ) -> anyhow::Result<Option<RebuiltImports>> {
        let Some(&(base, size)) = self.data_directories.get(1).filter(|&&(rva, _)| rva != 0) else {
            return Ok(None);
        };
        let libraries = checked_imports(self, base, size)?;
        let descriptor_size = libraries
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(20))
            .context("import descriptor size overflow")?;
        let mut blob = vec![0; descriptor_size];
        let mut patches = Vec::new();
        for (index, library) in libraries.iter().enumerate() {
            while blob.len() % 8 != 0 {
                blob.push(0);
            }
            let lookup_rva = blob_rva(section_rva, blob.len())?;
            let lookup_offset = blob.len();
            let lookup_size = library
                .symbols
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(8))
                .context("import lookup size overflow")?;
            blob.resize(
                blob.len()
                    .checked_add(lookup_size)
                    .context("import blob size overflow")?,
                0,
            );
            let name_rva = blob_rva(section_rva, blob.len())?;
            blob.extend_from_slice(&library.name);
            blob.push(0);
            let mut iat_data = Vec::with_capacity(lookup_size);
            for (slot, symbol) in library.symbols.iter().enumerate() {
                let value = match symbol {
                    ImportSymbol::Ordinal(ordinal) => 0x8000_0000_0000_0000 | u64::from(*ordinal),
                    ImportSymbol::Named { hint, name } => {
                        if blob.len() % 2 != 0 {
                            blob.push(0);
                        }
                        let rva = blob_rva(section_rva, blob.len())?;
                        blob.extend_from_slice(&hint.to_le_bytes());
                        blob.extend_from_slice(name);
                        blob.push(0);
                        u64::from(rva)
                    }
                };
                blob[lookup_offset + slot * 8..lookup_offset + slot * 8 + 8]
                    .copy_from_slice(&value.to_le_bytes());
                iat_data.extend_from_slice(&value.to_le_bytes());
            }
            iat_data.extend_from_slice(&0u64.to_le_bytes());
            patches.push(BytePatch {
                rva: Rva::new(library.first_thunk),
                bytes: iat_data,
            });
            let descriptor = &mut blob[index * 20..index * 20 + 20];
            descriptor[..4].copy_from_slice(&lookup_rva.to_le_bytes());
            descriptor[12..16].copy_from_slice(&name_rva.to_le_bytes());
            descriptor[16..20].copy_from_slice(&library.first_thunk.to_le_bytes());
        }
        blob_rva(section_rva, blob.len())?;
        ensure!(
            section_rva != Rva::ZERO,
            "rebuilt import directory RVA is zero"
        );
        Ok(Some(RebuiltImports {
            bytes: blob,
            directory: DirectoryUpdate {
                index: 1,
                rva: section_rva,
                size: u32::try_from(descriptor_size).context("import directory size overflow")?,
            },
            iat_patches: patches,
        }))
    }
}

fn blob_rva(base: Rva, offset: usize) -> anyhow::Result<u32> {
    base.get()
        .checked_add(u32::try_from(offset).context("import blob offset overflow")?)
        .context("import blob RVA overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PeFile {
        let mut pe = PeFile {
            bytes: vec![0; 0x500],
            image_base: 0x140000000,
            entry_point: 0,
            sections: vec![crate::SectionRecord {
                name: ".idata".into(),
                rva: 0x1000,
                virtual_size: 0x500,
                raw_size: 0x500,
                raw_pointer: 0,
                characteristics: 0x40000040,
            }],
            data_directories: vec![(0, 0); 16],
            relocations: Vec::new(),
            pdata_begins: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
        };
        pe.data_directories[1] = (0x1000, 60);
        for (offset, value) in [
            (0, 0x1100u32),
            (4, 42),
            (8, 17),
            (12, 0x1080),
            (16, 0x1180),
            (20, 0x1120),
            (32, 0x1090),
            (36, 0x11a0),
        ] {
            pe.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        pe.bytes[0x80..0x86].copy_from_slice(b"a.dll\0");
        pe.bytes[0x90..0x96].copy_from_slice(b"b.dll\0");
        pe.bytes[0x200..0x208].copy_from_slice(b"\x07\0Entry\0");
        for (offset, value) in [
            (0x100, 0x1200u64),
            (0x108, 0x800000000000002a),
            (0x120, 0x1200),
            (0x180, 0x1200),
            (0x188, 0x800000000000002a),
            (0x1a0, 0x1200),
        ] {
            pe.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        pe
    }

    #[test]
    fn rebuilds_multiple_libraries_shared_names_and_ordinals_with_stable_iat() {
        let mut pe = fixture();
        pe.bytes[0x180..0x188].copy_from_slice(&0x7ffb12345678u64.to_le_bytes());
        let RebuiltImports {
            bytes: blob,
            directory,
            iat_patches: patches,
        } = pe
            .rebuild_import_directory(Rva::new(0x3000))
            .unwrap()
            .unwrap();
        assert_eq!(directory.index, 1);
        assert_eq!(directory.size, 60);
        assert_eq!(
            patches
                .iter()
                .map(|patch| patch.rva.get())
                .collect::<Vec<_>>(),
            [0x1180, 0x11a0]
        );
        assert_eq!(&blob[4..12], &[0; 8]);
        assert_eq!(&blob[40..60], &[0; 20]);
        let mut rebuilt = fixture();
        for patch in patches {
            let offset = (patch.rva.get() - 0x1000) as usize;
            rebuilt.bytes[offset..offset + patch.bytes.len()].copy_from_slice(&patch.bytes);
        }
        let raw = rebuilt.bytes.len() as u32;
        rebuilt.sections.push(crate::SectionRecord {
            name: ".meta".into(),
            rva: 0x3000,
            virtual_size: blob.len() as u32,
            raw_size: blob.len() as u32,
            raw_pointer: raw,
            characteristics: 0x40000040,
        });
        rebuilt.bytes.extend_from_slice(&blob);
        let libraries = checked_imports(&rebuilt, 0x3000, 60).unwrap();
        assert_eq!(libraries.len(), 2);
        assert_eq!(libraries[0].name, b"a.dll");
        assert!(
            matches!(libraries[0].symbols[0], ImportSymbol::Named { hint: 7, ref name } if name == b"Entry")
        );
        assert!(matches!(libraries[0].symbols[1], ImportSymbol::Ordinal(42)));
        assert!(
            matches!(libraries[1].symbols[0], ImportSymbol::Named { hint: 7, ref name } if name == b"Entry")
        );
    }

    #[test]
    fn handles_oft_zero_and_rejects_bound_names_without_lookup() {
        let mut pe = fixture();
        pe.bytes[..4].fill(0);
        assert!(pe.rebuild_import_directory(Rva::new(0x3000)).is_ok());
        pe.bytes[0x180..0x188].copy_from_slice(&0x7ffb12345678u64.to_le_bytes());
        let error = format!(
            "{:#}",
            pe.rebuild_import_directory(Rva::new(0x3000)).err().unwrap()
        );
        assert!(error.contains("OFT=0"));
        assert!(error.contains("0x1180"));
        assert!(error.contains("0x7ffb12345678"));
    }

    #[test]
    fn rejects_truncated_records_strings_and_unterminated_arrays() {
        let mut pe = fixture();
        pe.data_directories[1].1 = 59;
        assert!(pe.rebuild_import_directory(Rva::new(0x3000)).is_err());
        pe.data_directories[1].1 = 60;
        pe.bytes[0..4].copy_from_slice(&0x14fcu32.to_le_bytes());
        assert!(pe.rebuild_import_directory(Rva::new(0x3000)).is_err());
        let mut pe = fixture();
        pe.bytes[12..16].copy_from_slice(&0x14ffu32.to_le_bytes());
        pe.bytes[0x4ff] = b'x';
        assert!(pe.rebuild_import_directory(Rva::new(0x3000)).is_err());
        let mut pe = fixture();
        pe.bytes[40] = 1;
        assert!(pe.rebuild_import_directory(Rva::new(0x3000)).is_err());
    }
}
