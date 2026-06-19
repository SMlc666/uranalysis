use urloader::{load, Architecture, ImageClass, ImageFormat};

fn minimal_pe32_plus_x86_64() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84usize;
    bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

    let opt = coff + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    bytes[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());

    let text = opt + 0xf0;
    write_section(
        &mut bytes,
        text,
        b".text\0\0\0",
        0x1000,
        0x200,
        0x200,
        0x200,
        0x6000_0020,
    );
    write_section(
        &mut bytes,
        text + 40,
        b".rdata\0\0",
        0x2000,
        0x200,
        0x200,
        0x400,
        0x4000_0040,
    );
    bytes[0x200..0x204].copy_from_slice(&[0x48, 0x31, 0xc0, 0xc3]);
    bytes[0x400..0x405].copy_from_slice(b"hello");
    bytes
}

fn pe32_plus_x86_64_with_imports_and_relocs() -> Vec<u8> {
    let mut bytes = minimal_pe32_plus_x86_64();

    let coff = 0x84usize;
    let opt = coff + 20;

    let idata_va = 0x3000u32;
    let idata_raw = 0x600u32;
    let reloc_va = 0x4000u32;
    let reloc_raw = 0x700u32;

    let text = opt + 0xf0;
    write_section(
        &mut bytes,
        text + 80,
        b".idata\0\0",
        idata_va,
        0x100,
        0x100,
        idata_raw,
        0x4000_0040,
    );
    write_section(
        &mut bytes,
        text + 120,
        b".reloc\0\0",
        reloc_va,
        0x100,
        0x100,
        reloc_raw,
        0x4200_0040,
    );

    bytes[coff + 2..coff + 4].copy_from_slice(&4u16.to_le_bytes());

    bytes.resize(0x800, 0);

    let import_dir = opt + 112 + (8 * 1);
    bytes[import_dir..import_dir + 4].copy_from_slice(&idata_va.to_le_bytes());
    bytes[import_dir + 4..import_dir + 8].copy_from_slice(&0x40u32.to_le_bytes());
    let reloc_dir = opt + 112 + (8 * 5);
    bytes[reloc_dir..reloc_dir + 4].copy_from_slice(&reloc_va.to_le_bytes());
    bytes[reloc_dir + 4..reloc_dir + 8].copy_from_slice(&0x0cu32.to_le_bytes());

    let desc = idata_raw as usize;
    bytes[desc..desc + 4].copy_from_slice(&(idata_va + 0x28).to_le_bytes());
    bytes[desc + 12..desc + 16].copy_from_slice(&(idata_va + 0x40).to_le_bytes());
    bytes[desc + 16..desc + 20].copy_from_slice(&(idata_va + 0x28).to_le_bytes());

    let thunk = (idata_raw + 0x28) as usize;
    bytes[thunk..thunk + 8].copy_from_slice(&(idata_va as u64 + 0x50).to_le_bytes());
    bytes[thunk + 8..thunk + 16].copy_from_slice(&0u64.to_le_bytes());

    let dll = (idata_raw + 0x40) as usize;
    bytes[dll..dll + 12].copy_from_slice(b"KERNEL32.dll");
    bytes[dll + 12] = 0;

    let ibn = (idata_raw + 0x50) as usize;
    bytes[ibn..ibn + 2].copy_from_slice(&0u16.to_le_bytes());
    bytes[ibn + 2..ibn + 13].copy_from_slice(b"ExitProcess");
    bytes[ibn + 13] = 0;

    let reloc = reloc_raw as usize;
    bytes[reloc..reloc + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[reloc + 4..reloc + 8].copy_from_slice(&0x0cu32.to_le_bytes());
    bytes[reloc + 8..reloc + 10].copy_from_slice(&0xa010u16.to_le_bytes());
    bytes[reloc + 10..reloc + 12].copy_from_slice(&0u16.to_le_bytes());

    bytes
}

fn minimal_pe32_plus_x86_64_with_pdata() -> Vec<u8> {
    let mut bytes = minimal_pe32_plus_x86_64();

    let coff = 0x84usize;
    let opt = coff + 20;
    let pdata_va = 0x5000u32;
    let pdata_raw = 0x780u32;
    let text = opt + 0xf0;

    write_section(
        &mut bytes,
        text + 80,
        b".pdata\0\0",
        pdata_va,
        0x100,
        0x80,
        pdata_raw,
        0x4000_0040,
    );
    bytes[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes());

    let exception_dir = opt + 112 + (8 * 3);
    bytes[exception_dir..exception_dir + 4].copy_from_slice(&pdata_va.to_le_bytes());
    bytes[exception_dir + 4..exception_dir + 8].copy_from_slice(&0x0cu32.to_le_bytes());

    let pdata = pdata_raw as usize;
    bytes[pdata..pdata + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[pdata + 4..pdata + 8].copy_from_slice(&0x1010u32.to_le_bytes());
    bytes[pdata + 8..pdata + 12].copy_from_slice(&0x5100u32.to_le_bytes());

    bytes
}

#[allow(clippy::too_many_arguments)]
fn write_section(
    bytes: &mut [u8],
    off: usize,
    name: &[u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
) {
    bytes[off..off + 8].copy_from_slice(name);
    bytes[off + 8..off + 12].copy_from_slice(&virtual_size.to_le_bytes());
    bytes[off + 12..off + 16].copy_from_slice(&virtual_address.to_le_bytes());
    bytes[off + 16..off + 20].copy_from_slice(&raw_size.to_le_bytes());
    bytes[off + 20..off + 24].copy_from_slice(&raw_ptr.to_le_bytes());
    bytes[off + 36..off + 40].copy_from_slice(&characteristics.to_le_bytes());
}

#[test]
fn loads_minimal_pe32_plus_x86_64_sections() {
    let image = load(&minimal_pe32_plus_x86_64()).unwrap();

    assert_eq!(image.format, ImageFormat::Pe);
    assert_eq!(image.architecture, Architecture::X86_64);
    assert_eq!(image.class, ImageClass::Bits64);
    assert_eq!(image.image_base, 0x140000000);
    assert_eq!(image.entry, 0x140001000);
    assert_eq!(image.sections.len(), 2);
    assert_eq!(image.sections[0].name, ".text");
    assert_eq!(image.sections[0].addr, 0x140001000);
    assert_eq!(image.sections[0].offset, 0x200);
    assert_eq!(image.sections[0].permissions, "r-x");
    assert_eq!(image.sections[1].name, ".rdata");
    assert_eq!(image.sections[1].addr, 0x140002000);
    assert_eq!(image.sections[1].permissions, "r--");
    assert_eq!(image.rva_to_offset(0x1000), Some(0x200));
    assert_eq!(image.va_to_offset(0x140001000), Some(0x200));
    assert_eq!(
        image.bytes_at(0x140001000, 4),
        Some(&[0x48, 0x31, 0xc0, 0xc3][..])
    );
}

#[test]
fn rejects_out_of_bounds_pe_pointer() {
    let mut bytes = minimal_pe32_plus_x86_64();
    bytes[0x3c..0x40].copy_from_slice(&0x900u32.to_le_bytes());
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("truncated pe signature"), "{err}");
}

#[test]
fn rejects_missing_pe_signature() {
    let mut bytes = minimal_pe32_plus_x86_64();
    bytes[0x80..0x84].copy_from_slice(b"PX\0\0");
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("missing PE signature"), "{err}");
}

#[test]
fn rejects_truncated_optional_header() {
    let mut bytes = minimal_pe32_plus_x86_64();
    let coff = 0x84usize;
    bytes[coff + 16..coff + 18].copy_from_slice(&0x800u16.to_le_bytes());
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("truncated optional header"), "{err}");
}

#[test]
fn rejects_unsupported_optional_header_magic() {
    let mut bytes = minimal_pe32_plus_x86_64();
    let opt = 0x84usize + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x999u16.to_le_bytes());
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("unsupported optional header magic"), "{err}");
}

#[test]
fn rejects_section_raw_range_outside_file() {
    let mut bytes = minimal_pe32_plus_x86_64();
    let text = 0x84usize + 20 + 0xf0;
    bytes[text + 20..text + 24].copy_from_slice(&0x700u32.to_le_bytes());
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("section raw range"), "{err}");
}

#[test]
fn analysis_view_normalizes_pe_imports_and_relocations() {
    let bytes = pe32_plus_x86_64_with_imports_and_relocs();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert!(view.capabilities.has_imports || view.capabilities.has_relocations);
    assert!(view.imports.iter().any(|import| import.name.as_deref() == Some("ExitProcess")));
    assert!(view.relocations.iter().any(|reloc| reloc.addr == 0x140001010));
}

#[test]
fn analysis_view_surfaces_pe_unwind_ranges_when_pdata_exists() {
    let bytes = minimal_pe32_plus_x86_64_with_pdata();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert!(view.capabilities.has_unwind_ranges);
    assert!(view.unwind.is_some());
}
