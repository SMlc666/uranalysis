use capstone::{arch, prelude::*};
use urcodec::{Architecture, DecodeOptions, DecodeStatus, Decoder};

#[derive(Debug)]
struct OracleCase {
    name: &'static str,
    word: u32,
    urcodec_text: &'static str,
    mnemonic: &'static str,
}

const CASES: &[OracleCase] = &[
    OracleCase {
        name: "ret",
        word: 0xd65f03c0,
        urcodec_text: "ret",
        mnemonic: "ret",
    },
    OracleCase {
        name: "br",
        word: 0xd61f0000,
        urcodec_text: "br x0",
        mnemonic: "br",
    },
    OracleCase {
        name: "b_imm",
        word: 0x14000004,
        urcodec_text: "b 0x400110",
        mnemonic: "b",
    },
    OracleCase {
        name: "bl_imm",
        word: 0x97fffffc,
        urcodec_text: "bl 0x4000f0",
        mnemonic: "bl",
    },
    OracleCase {
        name: "b_eq",
        word: 0x54000080,
        urcodec_text: "b.eq 0x400110",
        mnemonic: "b.eq",
    },
    OracleCase {
        name: "cbz",
        word: 0xb4000080,
        urcodec_text: "cbz x0, 0x400110",
        mnemonic: "cbz",
    },
    OracleCase {
        name: "tbz",
        word: 0x36000082,
        urcodec_text: "tbz w2, #0x0, 0x400110",
        mnemonic: "tbz",
    },
    OracleCase {
        name: "adr",
        word: 0x10000080,
        urcodec_text: "adr x0, 0x400110",
        mnemonic: "adr",
    },
    OracleCase {
        name: "adrp",
        word: 0xb0000000,
        urcodec_text: "adrp x0, 0x401000",
        mnemonic: "adrp",
    },
    OracleCase {
        name: "nop",
        word: 0xd503201f,
        urcodec_text: "nop",
        mnemonic: "nop",
    },
    OracleCase {
        name: "add_imm",
        word: 0x91002000,
        urcodec_text: "add x0, x0, #0x8",
        mnemonic: "add",
    },
    OracleCase {
        name: "cmp_imm",
        word: 0xf100201f,
        urcodec_text: "cmp x0, #0x8",
        mnemonic: "cmp",
    },
    OracleCase {
        name: "mov_wide",
        word: 0xd2800020,
        urcodec_text: "mov x0, #0x1",
        mnemonic: "mov",
    },
    OracleCase {
        name: "ldr_unsigned",
        word: 0xf9400420,
        urcodec_text: "ldr x0, [x1, #0x8]",
        mnemonic: "ldr",
    },
    OracleCase {
        name: "str_unsigned",
        word: 0xf9000822,
        urcodec_text: "str x2, [x1, #0x10]",
        mnemonic: "str",
    },
];

fn urcodec_decoder() -> Decoder {
    Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap()
}

fn capstone_aarch64() -> Capstone {
    Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .build()
        .unwrap()
}

#[test]
fn aarch64_complete_fixture_decode_matches_capstone_oracle() {
    let decoder = urcodec_decoder();
    let capstone = capstone_aarch64();

    for case in CASES {
        let bytes = case.word.to_le_bytes();
        let decoded = decoder
            .decode_one(&bytes, 0x400100)
            .unwrap_or_else(|err| panic!("{}: urcodec decode failed: {err}", case.name));
        assert_eq!(decoded.status, DecodeStatus::Complete, "{}", case.name);
        assert_eq!(decoded.size, 4, "{}", case.name);
        assert_eq!(decoded.text, case.urcodec_text, "{}", case.name);
        assert_eq!(decoded.mnemonic, case.mnemonic, "{}", case.name);

        let oracle = capstone
            .disasm_count(&bytes, 0x400100, 1)
            .unwrap_or_else(|err| panic!("{}: capstone decode failed: {err}", case.name));
        let oracle = oracle
            .iter()
            .next()
            .unwrap_or_else(|| panic!("{}: capstone produced no instruction", case.name));
        assert_eq!(oracle.bytes().len(), 4, "{}", case.name);
        assert_eq!(oracle.mnemonic(), Some(case.mnemonic), "{}", case.name);
    }
}
