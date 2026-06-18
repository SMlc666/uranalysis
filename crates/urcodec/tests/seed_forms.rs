use urcodec::{
    Architecture, DecodeOptions, Decoder, EncodeOptions, Encoder, TextOptions, TextParser,
};

#[test]
fn x86_ret_roundtrips_through_decode_encode_and_text() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let decoded = decoder.decode_one(&[0xc3], 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), vec![0xc3]);

    let parsed = parser.parse_one("ret", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), vec![0xc3]);
}

#[test]
fn aarch64_ret_roundtrips_through_decode_encode_and_text() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xd65f03c0u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400080).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret", 0x400080).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn seed_form_ids_are_exposed_once_per_architecture() {
    let x86_forms = urcodec::arch::x86_64::forms::all_forms();
    let aarch64_forms = urcodec::arch::aarch64::forms::all_forms();

    assert_eq!(
        x86_forms
            .iter()
            .filter(|form| form.id().local_name() == "ret")
            .count(),
        1
    );
    assert_eq!(
        aarch64_forms
            .iter()
            .filter(|form| form.id().local_name() == "ret")
            .count(),
        1
    );
}

#[test]
fn x86_call_rel32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let decoded = decoder
        .decode_one(&[0xe8, 0x05, 0x00, 0x00, 0x00], 0x401000)
        .unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "call 0x40100a");
    assert_eq!(
        encoder.encode_one(&decoded).unwrap(),
        vec![0xe8, 0x05, 0x00, 0x00, 0x00]
    );

    let parsed = parser.parse_one("call 0x40100a", 0x401000).unwrap();
    assert_eq!(
        encoder.encode_one(&parsed).unwrap(),
        vec![0xe8, 0x05, 0x00, 0x00, 0x00]
    );
}

#[test]
fn aarch64_b_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x14000004u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "b 0x400110");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("b 0x400110", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
