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
        Operand::ShiftedRegister(reg) => {
            format!("{}, {} #0x{:x}", reg.register.name, reg.shift, reg.amount)
        }
        Operand::Immediate(value) => format!("#{}", format_signed_hex(*value)),
        Operand::AbsoluteAddress(addr) => format!("0x{addr:x}"),
        Operand::Memory(mem) => render_memory(mem),
        Operand::Condition(cond) => cond.clone(),
    }
}

fn render_memory(mem: &MemoryOperand) -> String {
    let base = mem
        .base
        .as_ref()
        .map(|reg| reg.name.as_str())
        .unwrap_or("unknown");
    if let Some(index) = &mem.index {
        let extend = if index.name.starts_with('w') {
            "uxtw"
        } else {
            "lsl"
        };
        let shift = mem.scale.trailing_zeros();
        if shift == 0 {
            return format!("[{base}, {}, {extend}]", index.name);
        }
        return format!("[{base}, {}, {extend} #0x{shift:x}]", index.name);
    }
    if mem.offset == 0 && !mem.writeback && !mem.post_index {
        format!("[{base}]")
    } else if mem.post_index {
        format!("[{base}], #{}", format_signed_hex(mem.offset))
    } else if mem.writeback {
        format!("[{base}, #{}]!", format_signed_hex(mem.offset))
    } else {
        format!("[{base}, #{}]", format_signed_hex(mem.offset))
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
