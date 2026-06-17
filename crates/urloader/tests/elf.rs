use urloader::{load, LoadError};
use urloader::{Architecture, Endian, ImageClass, ImageFormat, LoadProfile};

#[test]
fn rejects_unknown_binary_magic() {
    let err = load(b"not a binary").unwrap_err();
    assert!(matches!(err, LoadError::UnknownFormat));
}

fn minimal_elf64_aarch64_executable() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1000];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&0x400080u64.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
    bytes[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let ph = 0x40usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes
}

fn minimal_elf64_x86_64_executable() -> Vec<u8> {
    let mut bytes = minimal_elf64_aarch64_executable();
    bytes[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    bytes
}

#[test]
fn loads_minimal_elf64_aarch64_executable_segments() {
    let image = load(&minimal_elf64_aarch64_executable()).unwrap();

    assert_eq!(image.format, ImageFormat::Elf);
    assert_eq!(image.architecture, Architecture::Aarch64);
    assert_eq!(image.class, ImageClass::Bits64);
    assert_eq!(image.endian, Endian::Little);
    assert_eq!(image.profile, LoadProfile::Executable);
    assert_eq!(image.entry, 0x400080);
    assert_eq!(image.image_base, 0);
    assert_eq!(image.segments.len(), 1);
    assert_eq!(image.segments[0].vaddr, 0x400000);
    assert_eq!(image.segments[0].file_offset, 0);
    assert_eq!(image.segments[0].file_size, 0x1000);
    assert_eq!(image.segments[0].mem_size, 0x1000);
    assert_eq!(image.segments[0].permissions, "r-x");
    assert_eq!(image.va_to_offset(0x400080), Some(0x80));
    assert_eq!(image.executable_ranges(), vec![(0x400000, 0x401000)]);
    assert_eq!(
        image.bytes_at(0x400080, 4),
        Some(&[0xc0, 0x03, 0x5f, 0xd6][..])
    );
}

#[test]
fn loads_minimal_elf64_x86_64_executable_metadata() {
    let image = load(&minimal_elf64_x86_64_executable()).unwrap();

    assert_eq!(image.format, ImageFormat::Elf);
    assert_eq!(image.architecture, Architecture::X86_64);
    assert_eq!(image.class, ImageClass::Bits64);
    assert_eq!(image.endian, Endian::Little);
    assert_eq!(image.entry, 0x400080);
}

fn elf_with_sections_and_symbols() -> Vec<u8> {
    let mut bytes = minimal_elf64_aarch64_executable();
    bytes.resize(0x1400, 0);

    let shoff = 0x1000u64;
    bytes[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
    bytes[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x3c..0x3e].copy_from_slice(&5u16.to_le_bytes());
    bytes[0x3e..0x40].copy_from_slice(&4u16.to_le_bytes());

    let shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0main\0dyn_func\0";
    bytes[0x300..0x300 + shstr.len()].copy_from_slice(shstr);

    write_shdr(&mut bytes, 1, 1, 1, 0x6, 0x400080, 0x80, 4, 0, 0, 4, 0);
    write_shdr(&mut bytes, 2, 7, 2, 0, 0, 0x400, 24, 3, 1, 8, 24);
    write_shdr(
        &mut bytes,
        3,
        15,
        3,
        0,
        0,
        0x300,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    );
    write_shdr(
        &mut bytes,
        4,
        23,
        3,
        0,
        0,
        0x300,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    );

    let sym = 0x400usize;
    bytes[sym..sym + 4].copy_from_slice(&33u32.to_le_bytes());
    bytes[sym + 4] = 0x12;
    bytes[sym + 8..sym + 16].copy_from_slice(&0x400080u64.to_le_bytes());
    bytes[sym + 16..sym + 24].copy_from_slice(&4u64.to_le_bytes());
    bytes
}

#[allow(clippy::too_many_arguments)]
fn write_shdr(
    bytes: &mut [u8],
    index: usize,
    name: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
) {
    let off = 0x1000 + index * 64;
    bytes[off..off + 4].copy_from_slice(&name.to_le_bytes());
    bytes[off + 4..off + 8].copy_from_slice(&sh_type.to_le_bytes());
    bytes[off + 8..off + 16].copy_from_slice(&flags.to_le_bytes());
    bytes[off + 16..off + 24].copy_from_slice(&addr.to_le_bytes());
    bytes[off + 24..off + 32].copy_from_slice(&offset.to_le_bytes());
    bytes[off + 32..off + 40].copy_from_slice(&size.to_le_bytes());
    bytes[off + 40..off + 44].copy_from_slice(&link.to_le_bytes());
    bytes[off + 44..off + 48].copy_from_slice(&info.to_le_bytes());
    bytes[off + 48..off + 56].copy_from_slice(&addralign.to_le_bytes());
    bytes[off + 56..off + 64].copy_from_slice(&entsize.to_le_bytes());
}

#[test]
fn loads_elf_sections_and_symbols() {
    let image = load(&elf_with_sections_and_symbols()).unwrap();

    assert!(image.sections.iter().any(|section| {
        section.name == ".text" && section.addr == 0x400080 && section.offset == 0x80
    }));
    assert!(image.symbols.iter().any(|symbol| {
        symbol.name == "main"
            && symbol.addr == 0x400080
            && symbol.size == 4
            && symbol.kind == "Func"
            && symbol.is_export
            && !symbol.is_import
    }));
}

#[test]
fn loads_nobits_section_without_file_backing() {
    let mut bytes = minimal_elf64_aarch64_executable();
    bytes.resize(0x1100, 0);

    let shoff = 0x1000u64;
    bytes[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
    bytes[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x3c..0x3e].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes());

    write_shdr(
        &mut bytes, 1, 0, 8, 0x3, 0x600000, 0x2000, 0x1000, 0, 0, 8, 0,
    );

    let image = load(&bytes).unwrap();

    assert!(image
        .sections
        .iter()
        .any(|section| section.addr == 0x600000 && section.offset == 0x2000));
}

#[test]
fn rejects_unsupported_elf_class() {
    let mut bytes = minimal_elf64_aarch64_executable();
    bytes[4] = 1;
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("unsupported class"), "{err}");
}

#[test]
fn rejects_unsupported_elf_machine() {
    let mut bytes = minimal_elf64_aarch64_executable();
    bytes[0x12..0x14].copy_from_slice(&999u16.to_le_bytes());
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("unsupported machine"), "{err}");
}

#[test]
fn rejects_truncated_elf_header() {
    let err = load(b"\x7fELF").unwrap_err().to_string();
    assert!(err.contains("truncated header"), "{err}");
}

#[test]
fn rejects_out_of_bounds_elf_program_header() {
    let mut bytes = minimal_elf64_aarch64_executable();
    bytes[0x20..0x28].copy_from_slice(&0x2000u64.to_le_bytes());
    let err = load(&bytes).unwrap_err().to_string();
    assert!(err.contains("truncated program header"), "{err}");
}
