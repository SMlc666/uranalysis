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

#[test]
fn form_registries_expose_layout_and_matcher_metadata() {
    let x86_ret = urcodec::arch::x86_64::forms::all_forms()
        .iter()
        .find(|form| form.id().local_name() == "ret")
        .expect("x86 ret form should exist");
    assert!(matches!(
        x86_ret.decode_layout(),
        urcodec::form::DecodeLayout::ByteStream(_)
    ));
    assert!(!x86_ret.matchers().is_empty());

    let aarch64_ret = urcodec::arch::aarch64::forms::all_forms()
        .iter()
        .find(|form| form.id().local_name() == "ret")
        .expect("aarch64 ret form should exist");
    assert!(matches!(
        aarch64_ret.decode_layout(),
        urcodec::form::DecodeLayout::FixedWidthBits { width: 32 }
    ));
    assert!(!aarch64_ret.fields().is_empty());
}

#[test]
fn decoder_encoder_and_parser_share_runtime_for_aarch64_ret() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder =
        urcodec::Encoder::new(Architecture::Aarch64, urcodec::EncodeOptions::default()).unwrap();
    let parser =
        urcodec::TextParser::new(Architecture::Aarch64, urcodec::TextOptions::default()).unwrap();

    let bytes = 0xd65f03c0u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400080).unwrap();
    assert_eq!(decoded.form.as_deref(), Some("aarch64.ret"));
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret", 0x400080).unwrap();
    assert_eq!(parsed.form.as_deref(), Some("aarch64.ret"));
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn decoder_encoder_and_parser_share_runtime_for_x86_ret() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder =
        urcodec::Encoder::new(Architecture::X86_64, urcodec::EncodeOptions::default()).unwrap();
    let parser =
        urcodec::TextParser::new(Architecture::X86_64, urcodec::TextOptions::default()).unwrap();

    let bytes = [0xc3];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(decoded.form.as_deref(), Some("x86_64.ret"));
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret", 0x401000).unwrap();
    assert_eq!(parsed.form.as_deref(), Some("x86_64.ret"));
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
