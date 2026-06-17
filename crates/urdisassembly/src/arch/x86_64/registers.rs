use crate::model::Register;

pub fn reg32(index: u8) -> Register {
    let name = match index & 0x0f {
        0 => "eax",
        1 => "ecx",
        2 => "edx",
        3 => "ebx",
        4 => "esp",
        5 => "ebp",
        6 => "esi",
        7 => "edi",
        8 => "r8d",
        9 => "r9d",
        10 => "r10d",
        11 => "r11d",
        12 => "r12d",
        13 => "r13d",
        14 => "r14d",
        _ => "r15d",
    };
    Register {
        name: name.to_string(),
    }
}

pub fn reg64(index: u8) -> Register {
    let name = if index == 16 {
        "rip"
    } else {
        match index & 0x0f {
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
        }
    };
    Register {
        name: name.to_string(),
    }
}
