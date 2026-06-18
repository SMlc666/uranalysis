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
