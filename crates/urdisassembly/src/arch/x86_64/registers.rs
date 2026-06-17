use crate::model::Register;

pub fn reg64(index: u8) -> Register {
    let name = match index & 0x0f {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        _ => "r15",
    };
    Register {
        name: name.to_string(),
    }
}
