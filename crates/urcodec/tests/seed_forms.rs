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
fn aarch64_ldr_unsigned_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xf9400420u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "ldr x0, [x1, #0x8]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ldr x0, [x1, #0x8]", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_str_post_index_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xf8008422u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "str x2, [x1], #0x8");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("str x2, [x1], #0x8", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_runtime_roundtrips_imul_r64_m64() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x48, 0x0f, 0xaf, 0x08];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "imul rcx, [rax]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("imul rcx, [rax]", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_runtime_roundtrips_movaps_memory_forms() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let load_bytes = [0x0f, 0x28, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00];
    let load = decoder.decode_one(&load_bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&load),
        "movaps xmm0, [rsp+0x80]"
    );
    assert_eq!(encoder.encode_one(&load).unwrap(), load_bytes.to_vec());

    let parsed_load = parser
        .parse_one("movaps xmm0, [rsp+0x80]", 0x401000)
        .unwrap();
    assert_eq!(
        encoder.encode_one(&parsed_load).unwrap(),
        load_bytes.to_vec()
    );

    let store_bytes = [0x0f, 0x29, 0x44, 0x24, 0x20];
    let store = decoder.decode_one(&store_bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&store),
        "movaps [rsp+0x20], xmm0"
    );
    assert_eq!(encoder.encode_one(&store).unwrap(), store_bytes.to_vec());

    let parsed_store = parser
        .parse_one("movaps [rsp+0x20], xmm0", 0x401000)
        .unwrap();
    assert_eq!(
        encoder.encode_one(&parsed_store).unwrap(),
        store_bytes.to_vec()
    );
}

#[test]
fn x86_runtime_roundtrips_mmx_pavgb() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0xe0, 0xe0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "pavgb mm4, mm0");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("pavgb mm4, mm0", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_runtime_roundtrips_vmovdqu_and_related_non_vvvv_forms() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let load_bytes = [0xc5, 0xfe, 0x6f, 0x52, 0x20];
    let load = decoder.decode_one(&load_bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&load),
        "vmovdqu ymm2, [rdx+0x20]"
    );
    assert_eq!(encoder.encode_one(&load).unwrap(), load_bytes.to_vec());

    let parsed_load = parser
        .parse_one("vmovdqu ymm2, [rdx+0x20]", 0x401000)
        .unwrap();
    assert_eq!(
        encoder.encode_one(&parsed_load).unwrap(),
        load_bytes.to_vec()
    );

    let indexed_load_bytes = [0xc4, 0xa1, 0x7e, 0x6f, 0x8c, 0x0a, 0x00, 0xff, 0xff, 0xff];
    let indexed_load = decoder.decode_one(&indexed_load_bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&indexed_load),
        "vmovdqu ymm1, [rdx+r9+-0x100]"
    );
    assert_eq!(
        encoder.encode_one(&indexed_load).unwrap(),
        indexed_load_bytes.to_vec()
    );

    let parsed_indexed_load = parser
        .parse_one("vmovdqu ymm1, [rdx+r9+-0x100]", 0x401000)
        .unwrap();
    assert_eq!(
        encoder.encode_one(&parsed_indexed_load).unwrap(),
        indexed_load_bytes.to_vec()
    );

    let store_bytes = [0xc4, 0xa1, 0x7e, 0x7f, 0x8c, 0x09, 0x00, 0xff, 0xff, 0xff];
    let store = decoder.decode_one(&store_bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&store),
        "vmovdqu [rcx+r9+-0x100], ymm1"
    );
    assert_eq!(encoder.encode_one(&store).unwrap(), store_bytes.to_vec());

    let parsed_store = parser
        .parse_one("vmovdqu [rcx+r9+-0x100], ymm1", 0x401000)
        .unwrap();
    assert_eq!(
        encoder.encode_one(&parsed_store).unwrap(),
        store_bytes.to_vec()
    );

    let stream_store_bytes = [0xc4, 0xa1, 0x7d, 0xe7, 0x8c, 0x09, 0x00, 0xff, 0xff, 0xff];
    let stream_store = decoder.decode_one(&stream_store_bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&stream_store),
        "vmovntdq [rcx+r9+-0x100], ymm1"
    );
    assert_eq!(
        encoder.encode_one(&stream_store).unwrap(),
        stream_store_bytes.to_vec()
    );

    let parsed_stream_store = parser
        .parse_one("vmovntdq [rcx+r9+-0x100], ymm1", 0x401000)
        .unwrap();
    assert_eq!(
        encoder.encode_one(&parsed_stream_store).unwrap(),
        stream_store_bytes.to_vec()
    );

    let movmask_bytes = [0xc5, 0xf9, 0xd7, 0xc0];
    let movmask = decoder.decode_one(&movmask_bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&movmask), "vpmovmskb eax, xmm0");
    assert_eq!(
        encoder.encode_one(&movmask).unwrap(),
        movmask_bytes.to_vec()
    );

    let parsed_movmask = parser.parse_one("vpmovmskb eax, xmm0", 0x401000).unwrap();
    assert_eq!(
        encoder.encode_one(&parsed_movmask).unwrap(),
        movmask_bytes.to_vec()
    );
}

#[test]
fn aarch64_stur_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xb806b349u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "stur w9, [x26, #0x6b]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("stur w9, [x26, #0x6b]", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_stp_pair_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xa9122748u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "stp x8, x9, [x26, #0x120]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("stp x8, x9, [x26, #0x120]", 0x400100)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_ldp_q_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xad4387e0u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "ldp q0, q1, [sp, #0x70]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("ldp q0, q1, [sp, #0x70]", 0x400100)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_ldr_register_offset_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xf8695b29u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "ldr x9, [x25, w9, uxtw #0x3]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("ldr x9, [x25, w9, uxtw #0x3]", 0x400100)
        .unwrap();
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
fn x86_mov_r64_r64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x48, 0x89, 0xd8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "mov rax, rbx");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("mov rax, rbx", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmovb_r32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0x42, 0xf7];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmovb esi, edi");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cmovb esi, edi", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_bswap_eax_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0xc8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "bswap eax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("bswap eax", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_mov_r64_m64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0x8b, 0x43, 0x08];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "mov rax, [rbx+0x8]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_mov_m32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x89, 0x45, 0xfc];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "mov [rbp+-0x4], eax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("mov [rbp+-0x4], eax", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_mov_r32_m32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x8b, 0x45, 0xfc];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "mov eax, [rbp+-0x4]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("mov eax, [rbp+-0x4]", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_mov_m64_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0xc7, 0x43, 0x08, 0x34, 0x12, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "mov [rbx+0x8], 0x1234"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_lea_r64_m64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0x8d, 0x44, 0x8b, 0x10];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "lea rax, [rbx+rcx*4+0x10]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_mov_m8_r8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x88, 0x84, 0x24, 0x97, 0x00, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "mov [rsp+0x97], al");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_movsx_r32_m8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x0f, 0xbe, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "movsx eax, [rax]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_movzx_r32_m8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x0f, 0xb6, 0x40, 0x01];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "movzx eax, [rax+0x1]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmp_m8_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x80, 0x7b, 0x2f, 0x01];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmp [rbx+0x2f], 0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmp_al_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x3c, 0x02];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmp al, 0x2");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmpxchg_r16_r16_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x66, 0x0f, 0xb1, 0xc8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmpxchg ax, cx");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cmpxchg ax, cx", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmpxchg_r32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0xb1, 0xc8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmpxchg eax, ecx");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cmpxchg eax, ecx", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmpxchg_m64_r64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x48, 0x0f, 0xb1, 0x10];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmpxchg [rax], rdx");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cmpxchg [rax], rdx", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_xadd_lock_m32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xf0, 0x0f, 0xc1, 0x81, 0x5c, 0x01, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "xadd [rcx+0x15c], eax"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("xadd [rcx+0x15c], eax", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_imul_r32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0xaf, 0xd0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "imul edx, eax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("imul edx, eax", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_movq_mm_m64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0x6f, 0x74, 0x24, 0x20];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "movq mm6, [rsp+0x20]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("movq mm6, [rsp+0x20]", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_movups_m128_xmm_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0x11, 0x24, 0x24];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "movups [rsp], xmm4");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("movups [rsp], xmm4", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_movups_xmm_m128_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0x0f, 0x10, 0x44, 0x24, 0x40];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "movups xmm0, [rsp+0x40]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("movups xmm0, [rsp+0x40]", 0x401000)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_vmovdqa_xmm_m128_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xc5, 0xf9, 0x6f, 0x74, 0x24, 0x20];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "vmovdqa xmm6, [rsp+0x20]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("vmovdqa xmm6, [rsp+0x20]", 0x401000)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn x86_or_al_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x0c, 0x7c];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "or al, 0x7c");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_adc_al_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x14, 0x14];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "adc al, 0x14");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_sbb_al_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x1c, 0x05];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "sbb al, 0x5");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_and_al_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x24, 0xf0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "and al, 0xf0");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_sub_al_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x2c, 0x20];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "sub al, 0x20");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmp_m64_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0x81, 0x7b, 0x08, 0x34, 0x12, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "cmp [rbx+0x8], 0x1234"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmp_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x3d, 0x00, 0x01, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmp eax, 0x100");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_cmp_rax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0x3d, 0x00, 0x01, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmp rax, 0x100");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_test_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xa9, 0x00, 0x01, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "test eax, 0x100");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_test_rax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0xa9, 0x00, 0x01, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "test rax, 0x100");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_add_r8_r8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x02, 0xc1];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "add al, cl");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_or_r8_r8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x08, 0xc8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "or al, cl");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_adc_r32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x13, 0xd1];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "adc edx, ecx");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_sbb_r32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x1b, 0xc9];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "sbb ecx, ecx");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_and_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x25, 0xff, 0xff, 0xff, 0x1f];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "and eax, 0x1fffffff");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_add_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x05, 0x19, 0x01, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "add eax, 0x119");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_or_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x0d, 0x7c, 0x92, 0x14, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "or eax, 0x14927c");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_adc_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x15, 0x34, 0x12, 0x00, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "adc eax, 0x1234");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_sbb_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x1d, 0x05, 0x93, 0x14, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "sbb eax, 0x149305");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_sub_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x2d, 0x20, 0x05, 0x93, 0x19];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "sub eax, 0x19930520");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_xor_eax_imm32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x35, 0x1b, 0x94, 0x14, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "xor eax, 0x14941b");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_imul_m64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0xf7, 0x6b, 0x08];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "imul [rbx+0x8]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_idiv_r64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0xf7, 0xf8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "idiv rax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_inc_m8_groupfe_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xfe, 0x03];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "inc [rbx]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_dec_al_groupfe_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xfe, 0xc8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "dec al");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_shr_al_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xc0, 0xe8, 0x06];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "shr al, 0x6");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_rol_m32_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xc1, 0x01, 0x01];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "rol [rcx], 0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_sar_r64_imm8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0xc1, 0xf8, 0x03];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "sar rax, 0x3");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_shl_eax_one_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xd1, 0xe0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "shl eax, 0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_shr_rax_one_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0xd1, 0xe8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "shr rax, 0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_rcl_dl_cl_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xd2, 0xd2];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "rcl dl, cl");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_rcl_m8_cl_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xd2, 0x12];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "rcl [rdx], cl");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_ror_eax_cl_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xd3, 0xc8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "ror eax, cl");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_rcl_ebx_cl_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xd3, 0xd3];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "rcl ebx, cl");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_shr_rax_cl_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0xd3, 0xe8];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "shr rax, cl");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_xchg_m8_r8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x86, 0x03];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "xchg [rbx], al");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_xchg_m32_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x87, 0x84, 0xf6, 0xf0, 0xff, 0x4f, 0x00];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "xchg [rsi+rsi*8+0x4ffff0], eax"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_mov_m16_imm16_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x66, 0xc7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x34, 0x12];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "mov [rsp+0x90], 0x1234"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_movsxd_r32_m32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x63, 0x4e, 0x08];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "movsxd ecx, [rsi+0x8]"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_movsxd_r64_r32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x48, 0x63, 0xc1];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "movsxd rax, ecx");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_setne_m8_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x0f, 0x95, 0x44, 0x24, 0x08];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "setne [rsp+0x8]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_stmxcsr_m32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0x0f, 0xae, 0x1c, 0x24];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "stmxcsr [rsp]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_fimul_m32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xda, 0x0b];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "fimul [rbx]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
}

#[test]
fn x86_fisttp_m64_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let bytes = [0xdd, 0x0a];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "fisttp [rdx]");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());
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
fn aarch64_add_shifted_register_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x8b41fc21u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "add x1, x1, x1, lsr #0x3f"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("add x1, x1, x1, lsr #0x3f", 0x400100)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_lsr_register_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x9ac82528u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "lsr x8, x9, x8");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("lsr x8, x9, x8", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_mov_logical_immediate_negative_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xb24107ecu32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "mov x12, #-0x7fffffffffffffff"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("mov x12, #-0x7fffffffffffffff", 0x400100)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_csel_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x9a983101u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "csel x1, x8, x24, lo"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("csel x1, x8, x24, lo", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_cset_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x1a9f17e8u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cset w8, eq");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cset w8, eq", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_tbz_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x36000082u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "tbz w2, #0x0, 0x400110"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("tbz w2, #0x0, 0x400110", 0x400100)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_tbnz_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x370000a3u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(
        urcodec::format_instruction(&decoded),
        "tbnz w3, #0x0, 0x400114"
    );
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser
        .parse_one("tbnz w3, #0x0, 0x400114", 0x400100)
        .unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_movi_zero_2d_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x6f00e400u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "movi v0.2d, #0x0");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("movi v0.2d, #0x0", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn aarch64_brk_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xd4200020u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "brk #0x1");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("brk #0x1", 0x400100).unwrap();
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
