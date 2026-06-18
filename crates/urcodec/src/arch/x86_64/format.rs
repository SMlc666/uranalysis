use crate::model::{MemoryOperand, Operand};

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
        Operand::Immediate(value) => format!("0x{:x}", *value as u64),
        Operand::AbsoluteAddress(addr) => format!("0x{addr:x}"),
        Operand::Memory(mem) => render_memory(mem),
        Operand::Condition(cond) => cond.clone(),
    }
}

fn render_memory(mem: &MemoryOperand) -> String {
    let mut parts = Vec::new();
    if let Some(base) = &mem.base {
        parts.push(base.name.clone());
    }
    if let Some(index) = &mem.index {
        if mem.scale > 1 {
            parts.push(format!("{}*{}", index.name, mem.scale));
        } else {
            parts.push(index.name.clone());
        }
    }
    if mem.offset > 0 {
        parts.push(format!("0x{:x}", mem.offset));
    } else if mem.offset < 0 {
        parts.push(format!("-0x{:x}", mem.offset.unsigned_abs()));
    }
    if parts.is_empty() {
        "[0x0]".to_string()
    } else {
        format!("[{}]", parts.join("+"))
    }
}
