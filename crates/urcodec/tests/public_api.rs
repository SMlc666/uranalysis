use urcodec::{Architecture, DecodeOptions, Decoder, Endian};

#[test]
fn decoder_constructs_for_aarch64_little_endian() {
    let decoder = Decoder::new(
        Architecture::Aarch64,
        DecodeOptions {
            endian: Endian::Little,
        },
    )
    .expect("AArch64 little-endian decoder should be supported");

    assert_eq!(decoder.architecture(), Architecture::Aarch64);
}

#[test]
fn decoder_constructs_for_x86_64_little_endian() {
    let decoder = Decoder::new(
        Architecture::X86_64,
        DecodeOptions {
            endian: Endian::Little,
        },
    )
    .expect("x86-64 little-endian decoder should be supported");

    assert_eq!(decoder.architecture(), Architecture::X86_64);
}

#[test]
fn decoded_instruction_carries_architecture_identity() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let decoded = decoder
        .decode_one(&0xd65f03c0u32.to_le_bytes(), 0x400080)
        .unwrap();

    assert_eq!(decoded.architecture, Architecture::Aarch64);
    assert_eq!(decoded.form.as_deref(), Some("aarch64.ret"));
}
