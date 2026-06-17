use crate::model::{MemoryOperand, Operand, Register};

pub fn render_instruction(mnemonic: &str, operands: &[Operand]) -> String {
    let operand_text = render_operands(operands);
    if operand_text.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {operand_text}")
    }
}

pub fn render_operands(operands: &[Operand]) -> String {
    operands
        .iter()
        .map(render_operand)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render_operand(operand: &Operand) -> String {
    match operand {
        Operand::Register(reg) => reg.name.clone(),
        Operand::Immediate(value) => format!("#{}", format_signed_hex(*value)),
        Operand::AbsoluteAddress(addr) => format!("0x{addr:x}"),
        Operand::Memory(mem) => render_memory(mem),
        Operand::Condition(cond) => cond.clone(),
    }
}

fn render_memory(mem: &MemoryOperand) -> String {
    if mem.offset == 0 && !mem.writeback && !mem.post_index {
        format!("[{}]", mem.base.name)
    } else if mem.post_index {
        format!("[{}], #{}", mem.base.name, format_signed_hex(mem.offset))
    } else if mem.writeback {
        format!("[{}, #{}]!", mem.base.name, format_signed_hex(mem.offset))
    } else {
        format!("[{}, #{}]", mem.base.name, format_signed_hex(mem.offset))
    }
}

fn format_signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

pub fn reg(name: impl Into<String>) -> Operand {
    Operand::Register(Register { name: name.into() })
}
