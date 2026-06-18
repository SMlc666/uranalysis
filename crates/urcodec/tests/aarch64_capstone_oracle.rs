use capstone::{arch, arch::arm64::Arm64OperandType, prelude::*, Insn};
use urcodec::{Architecture, DecodeOptions, DecodeStatus, Decoder, Operand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperandShape {
    Reg,
    Mem,
    Imm,
}

#[derive(Debug)]
struct OracleCase {
    name: &'static str,
    word: u32,
    urcodec_text: &'static str,
    mnemonic: &'static str,
    operands: &'static [OperandShape],
}

const CASES: &[OracleCase] = &[
    OracleCase {
        name: "ret",
        word: 0xd65f03c0,
        urcodec_text: "ret",
        mnemonic: "ret",
        operands: &[],
    },
    OracleCase {
        name: "br",
        word: 0xd61f0000,
        urcodec_text: "br x0",
        mnemonic: "br",
        operands: &[OperandShape::Reg],
    },
    OracleCase {
        name: "b_imm",
        word: 0x14000004,
        urcodec_text: "b 0x400110",
        mnemonic: "b",
        operands: &[OperandShape::Imm],
    },
    OracleCase {
        name: "bl_imm",
        word: 0x97fffffc,
        urcodec_text: "bl 0x4000f0",
        mnemonic: "bl",
        operands: &[OperandShape::Imm],
    },
    OracleCase {
        name: "b_eq",
        word: 0x54000080,
        urcodec_text: "b.eq 0x400110",
        mnemonic: "b.eq",
        operands: &[OperandShape::Imm],
    },
    OracleCase {
        name: "cbz",
        word: 0xb4000080,
        urcodec_text: "cbz x0, 0x400110",
        mnemonic: "cbz",
        operands: &[OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "tbz",
        word: 0x36000082,
        urcodec_text: "tbz w2, #0x0, 0x400110",
        mnemonic: "tbz",
        operands: &[OperandShape::Reg, OperandShape::Imm, OperandShape::Imm],
    },
    OracleCase {
        name: "adr",
        word: 0x10000080,
        urcodec_text: "adr x0, 0x400110",
        mnemonic: "adr",
        operands: &[OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "adrp",
        word: 0xb0000000,
        urcodec_text: "adrp x0, 0x401000",
        mnemonic: "adrp",
        operands: &[OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "nop",
        word: 0xd503201f,
        urcodec_text: "nop",
        mnemonic: "nop",
        operands: &[],
    },
    OracleCase {
        name: "add_imm",
        word: 0x91002000,
        urcodec_text: "add x0, x0, #0x8",
        mnemonic: "add",
        operands: &[OperandShape::Reg, OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "cmp_imm",
        word: 0xf100201f,
        urcodec_text: "cmp x0, #0x8",
        mnemonic: "cmp",
        operands: &[OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "mov_wide",
        word: 0xd2800020,
        urcodec_text: "mov x0, #0x1",
        mnemonic: "mov",
        operands: &[OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "ldr_unsigned",
        word: 0xf9400420,
        urcodec_text: "ldr x0, [x1, #0x8]",
        mnemonic: "ldr",
        operands: &[OperandShape::Reg, OperandShape::Mem],
    },
    OracleCase {
        name: "str_unsigned",
        word: 0xf9000822,
        urcodec_text: "str x2, [x1, #0x10]",
        mnemonic: "str",
        operands: &[OperandShape::Reg, OperandShape::Mem],
    },
];

fn urcodec_decoder() -> Decoder {
    Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap()
}

fn capstone_aarch64() -> Capstone {
    Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .unwrap()
}

fn urcodec_operand_shapes(operands: &[Operand]) -> Vec<OperandShape> {
    operands
        .iter()
        .map(|operand| match operand {
            Operand::Register(_) => OperandShape::Reg,
            Operand::Memory(_) => OperandShape::Mem,
            Operand::Immediate(_) | Operand::AbsoluteAddress(_) | Operand::Condition(_) => {
                OperandShape::Imm
            }
        })
        .collect()
}

fn capstone_operand_shapes(capstone: &Capstone, insn: &Insn) -> Vec<OperandShape> {
    let detail = capstone
        .insn_detail(insn)
        .unwrap_or_else(|err| panic!("capstone detail failed: {err}"));
    let arch_detail = detail.arch_detail();
    let arm64_detail = arch_detail
        .arm64()
        .unwrap_or_else(|| panic!("expected arm64 capstone detail"));
    arm64_detail
        .operands()
        .map(|operand| match operand.op_type {
            Arm64OperandType::Reg(_) => OperandShape::Reg,
            Arm64OperandType::Mem(_) => OperandShape::Mem,
            Arm64OperandType::Imm(_) => OperandShape::Imm,
            Arm64OperandType::Fp(_)
            | Arm64OperandType::Cimm(_)
            | Arm64OperandType::RegMrs(_)
            | Arm64OperandType::RegMsr(_)
            | Arm64OperandType::Pstate(_)
            | Arm64OperandType::Sys(_)
            | Arm64OperandType::Prefetch(_)
            | Arm64OperandType::Barrier(_)
            | Arm64OperandType::Invalid => {
                panic!("capstone produced unsupported arm64 operand shape")
            }
        })
        .collect()
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
        assert_eq!(
            urcodec_operand_shapes(&decoded.operands),
            case.operands,
            "{}",
            case.name
        );

        let oracle = capstone
            .disasm_count(&bytes, 0x400100, 1)
            .unwrap_or_else(|err| panic!("{}: capstone decode failed: {err}", case.name));
        let oracle = oracle
            .iter()
            .next()
            .unwrap_or_else(|| panic!("{}: capstone produced no instruction", case.name));
        assert_eq!(oracle.bytes().len(), 4, "{}", case.name);
        assert_eq!(oracle.mnemonic(), Some(case.mnemonic), "{}", case.name);
        assert_eq!(
            capstone_operand_shapes(&capstone, oracle),
            case.operands,
            "{}",
            case.name
        );
    }
}
