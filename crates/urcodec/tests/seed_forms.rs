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
