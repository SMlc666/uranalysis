pub fn minimal_elf64_aarch64_executable() -> Vec<u8> {
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
    bytes[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let ph = 0x40usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes
}

#[allow(dead_code)]
pub fn minimal_pe32_plus_x86_64() -> Vec<u8> {
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

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
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
