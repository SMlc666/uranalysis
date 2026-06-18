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

#[test]
fn aarch64_bl_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x94000004u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "bl 0x400110");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("bl 0x400110", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_b_cond_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x54000060u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "b.eq 0x40010c");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("b.eq 0x40010c", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_cbnz_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xb5000061u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cbnz x1, 0x40010c");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cbnz x1, 0x40010c", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_jmp_short_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let decoded = decoder.decode_one(&[0xeb, 0x05], 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "jmp 0x401007");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), vec![0xeb, 0x05]);

    let parsed = parser.parse_one("jmp 0x401007", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), vec![0xeb, 0x05]);
}

#[test]
fn x86_jne_near_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let decoded = decoder
        .decode_one(&[0x0f, 0x85, 0xfa, 0x00, 0x00, 0x00], 0x401000)
        .unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "jne 0x401100");
    assert_eq!(
        encoder.encode_one(&decoded).unwrap(),
        vec![0x0f, 0x85, 0xfa, 0x00, 0x00, 0x00]
    );

    let parsed = parser.parse_one("jne 0x401100", 0x401000).unwrap();
    assert_eq!(
        encoder.encode_one(&parsed).unwrap(),
        vec![0x0f, 0x85, 0xfa, 0x00, 0x00, 0x00]
    );
}

#[test]
fn aarch64_adr_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x10000080u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "adr x0, 0x400110");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("adr x0, 0x400110", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_adrp_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xb0000000u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "adrp x0, 0x401000");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("adrp x0, 0x401000", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_add_immediate_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x91002000u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "add x0, x0, #0x8");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("add x0, x0, #0x8", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_cmp_immediate_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xf100201fu32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmp x0, #0x8");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cmp x0, #0x8", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_mov_r64_imm64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "mov rax, 0x1122334455667788"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("mov rax, 0x1122334455667788", 0x401000)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_loopne_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xe0, 0xfe];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "loopne 0x401000");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("loopne 0x401000", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_mov_wide_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xd2800020u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "mov x0, #0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("mov x0, #0x1", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_movk_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xf2800041u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "movk x1, #0x2");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("movk x1, #0x2", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_and_immediate_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x12001c08u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "and w8, w0, #0xff");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("and w8, w0, #0xff", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_lsr_immediate_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x53067d09u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "lsr w9, w8, #0x6");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("lsr w9, w8, #0x6", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_lsl_immediate_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xd37ffae8u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "lsl x8, x23, #0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("lsl x8, x23, #0x1", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_asr_immediate_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x9341fc21u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "asr x1, x1, #0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("asr x1, x1, #0x1", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_ret_imm16_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xc2, 0xc2, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "ret 0xc2");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret 0xc2", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_retf_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xcb];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "retf");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("retf", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_retf_imm16_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xca, 0x10, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "retf 0x10");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("retf 0x10", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_call_rax_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x48, 0xff, 0xd0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "call rax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("call rax", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_jmp_rax_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x48, 0xff, 0xe0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "jmp rax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("jmp rax", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_jrcxz_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xe3, 0xfe];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "jrcxz 0x401000");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("jrcxz 0x401000", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
