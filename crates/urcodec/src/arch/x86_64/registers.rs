use crate::model::Register;

pub fn reg8(index: u8, rex_present: bool) -> Register {
    let name = match index & 0x0f {
        0 => "al",
        1 => "cl",
        2 => "dl",
        3 => "bl",
        4 if rex_present => "spl",
        4 => "ah",
        5 if rex_present => "bpl",
        5 => "ch",
        6 if rex_present => "sil",
        6 => "dh",
        7 if rex_present => "dil",
        7 => "bh",
        8 => "r8b",
        9 => "r9b",
        10 => "r10b",
        11 => "r11b",
        12 => "r12b",
        13 => "r13b",
        14 => "r14b",
        _ => "r15b",
    };
    Register {
        name: name.to_string(),
    }
}

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

pub fn xmm(index: u8) -> Register {
    Register {
        name: format!("xmm{}", index & 0x0f),
    }
}
