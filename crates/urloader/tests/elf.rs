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
