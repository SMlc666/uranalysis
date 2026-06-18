use capstone::{arch, arch::x86::X86OperandType, prelude::*, Insn};
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
    bytes: &'static [u8],
    urcodec_text: &'static str,
    mnemonic: &'static str,
    size: u8,
    operands: &'static [OperandShape],
}

const CASES: &[OracleCase] = &[
    OracleCase {
        name: "ret",
        bytes: &[0xc3],
        urcodec_text: "ret",
        mnemonic: "ret",
        size: 1,
        operands: &[],
    },
    OracleCase {
        name: "cmpxchg_dword",
        bytes: &[0x0f, 0xb1, 0xc8],
        urcodec_text: "cmpxchg eax, ecx",
        mnemonic: "cmpxchg",
        size: 3,
        operands: &[OperandShape::Reg, OperandShape::Reg],
    },
    OracleCase {
        name: "bsf_reg",
        bytes: &[0x0f, 0xbc, 0xc8],
        urcodec_text: "bsf ecx, eax",
        mnemonic: "bsf",
        size: 3,
        operands: &[OperandShape::Reg, OperandShape::Reg],
    },
    OracleCase {
        name: "bsr_reg",
        bytes: &[0x0f, 0xbd, 0xc9],
        urcodec_text: "bsr ecx, ecx",
        mnemonic: "bsr",
        size: 3,
        operands: &[OperandShape::Reg, OperandShape::Reg],
    },
    OracleCase {
        name: "bts_reg",
        bytes: &[0x0f, 0xab, 0xc1],
        urcodec_text: "bts ecx, eax",
        mnemonic: "bts",
        size: 3,
        operands: &[OperandShape::Reg, OperandShape::Reg],
    },
    OracleCase {
        name: "bswap_eax",
        bytes: &[0x0f, 0xc8],
        urcodec_text: "bswap eax",
        mnemonic: "bswap",
        size: 2,
        operands: &[OperandShape::Reg],
    },
    OracleCase {
        name: "cpuid",
        bytes: &[0x0f, 0xa2],
        urcodec_text: "cpuid",
        mnemonic: "cpuid",
        size: 2,
        operands: &[],
    },
    OracleCase {
        name: "imul_mem",
        bytes: &[0x48, 0x0f, 0xaf, 0x08],
        urcodec_text: "imul rcx, [rax]",
        mnemonic: "imul",
        size: 4,
        operands: &[OperandShape::Reg, OperandShape::Mem],
    },
    OracleCase {
        name: "movzx_word",
        bytes: &[0x0f, 0xb7, 0x07],
        urcodec_text: "movzx eax, [rdi]",
        mnemonic: "movzx",
        size: 3,
        operands: &[OperandShape::Reg, OperandShape::Mem],
    },
    OracleCase {
        name: "btr_imm",
        bytes: &[0x0f, 0xba, 0x33, 0x07],
        urcodec_text: "btr [rbx], 0x7",
        mnemonic: "btr",
        size: 4,
        operands: &[OperandShape::Mem, OperandShape::Imm],
    },
    OracleCase {
        name: "psrlq_mmx_imm",
        bytes: &[0x0f, 0x73, 0xd0, 0x08],
        urcodec_text: "psrlq mm0, 0x8",
        mnemonic: "psrlq",
        size: 4,
        operands: &[OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "psrldq_xmm_imm",
        bytes: &[0x66, 0x0f, 0x73, 0xd9, 0x05],
        urcodec_text: "psrldq xmm1, 0x5",
        mnemonic: "psrldq",
        size: 5,
        operands: &[OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "addps",
        bytes: &[0x0f, 0x58, 0xc1],
        urcodec_text: "addps xmm0, xmm1",
        mnemonic: "addps",
        size: 3,
        operands: &[OperandShape::Reg, OperandShape::Reg],
    },
    OracleCase {
        name: "addsd",
        bytes: &[0xf2, 0x0f, 0x58, 0xc3],
        urcodec_text: "addsd xmm0, xmm3",
        mnemonic: "addsd",
        size: 4,
        operands: &[OperandShape::Reg, OperandShape::Reg],
    },
    OracleCase {
        name: "pshufd",
        bytes: &[0x66, 0x0f, 0x70, 0xc1, 0x1b],
        urcodec_text: "pshufd xmm0, xmm1, 0x1b",
        mnemonic: "pshufd",
        size: 5,
        operands: &[OperandShape::Reg, OperandShape::Reg, OperandShape::Imm],
    },
    OracleCase {
        name: "vzeroupper",
        bytes: &[0xc5, 0xf8, 0x77],
        urcodec_text: "vzeroupper",
        mnemonic: "vzeroupper",
        size: 3,
        operands: &[],
    },
];

fn urcodec_decoder() -> Decoder {
    Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap()
}

fn capstone_x86_64() -> Capstone {
    Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
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
    let x86_detail = arch_detail
        .x86()
        .unwrap_or_else(|| panic!("expected x86 capstone detail"));
    x86_detail
        .operands()
        .map(|operand| match operand.op_type {
            X86OperandType::Reg(_) => OperandShape::Reg,
            X86OperandType::Mem(_) => OperandShape::Mem,
            X86OperandType::Imm(_) => OperandShape::Imm,
            X86OperandType::Invalid => panic!("capstone produced invalid x86 operand"),
        })
        .collect()
}

#[test]
fn x86_64_complete_fixture_decode_matches_capstone_oracle() {
    let decoder = urcodec_decoder();
    let capstone = capstone_x86_64();

    for case in CASES {
        let decoded = decoder
            .decode_one(case.bytes, 0x401000)
            .unwrap_or_else(|err| panic!("{}: urcodec decode failed: {err}", case.name));
        assert_eq!(decoded.status, DecodeStatus::Complete, "{}", case.name);
        assert_eq!(decoded.size, case.size, "{}", case.name);
        assert_eq!(decoded.text, case.urcodec_text, "{}", case.name);
        assert_eq!(decoded.mnemonic, case.mnemonic, "{}", case.name);
        assert_eq!(
            urcodec_operand_shapes(&decoded.operands),
            case.operands,
            "{}",
            case.name
        );

        let oracle = capstone
            .disasm_count(case.bytes, 0x401000, 1)
            .unwrap_or_else(|err| panic!("{}: capstone decode failed: {err}", case.name));
        let oracle = oracle
            .iter()
            .next()
            .unwrap_or_else(|| panic!("{}: capstone produced no instruction", case.name));
        assert_eq!(
            oracle.bytes().len(),
            usize::from(case.size),
            "{}",
            case.name
        );
        assert_eq!(oracle.mnemonic(), Some(case.mnemonic), "{}", case.name);
        assert_eq!(
            capstone_operand_shapes(&capstone, oracle),
            case.operands,
            "{}",
            case.name
        );
    }
}
