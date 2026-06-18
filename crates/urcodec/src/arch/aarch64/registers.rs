use crate::model::Register;

pub fn x(reg: u32) -> Register {
    Register {
        name: match reg {
            30 => "lr".to_string(),
            _ => format!("x{reg}"),
        },
    }
}

pub fn w(reg: u32) -> Register {
    Register {
        name: format!("w{reg}"),
    }
}

pub fn q(reg: u32) -> Register {
    Register {
        name: format!("q{reg}"),
    }
}

pub fn v_lane(reg: u32, lane: &str) -> Register {
    Register {
        name: format!("v{reg}.{lane}"),
    }
}

pub fn x_or_sp(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "sp".to_string()
        } else {
            format!("x{reg}")
        },
    }
}

pub fn w_or_sp(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "wsp".to_string()
        } else {
            format!("w{reg}")
        },
    }
}

pub fn x_or_zr(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "xzr".to_string()
        } else {
            format!("x{reg}")
        },
    }
}

pub fn w_or_zr(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "wzr".to_string()
        } else {
            format!("w{reg}")
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_general_registers() {
        assert_eq!(x(0).name, "x0");
        assert_eq!(w(1).name, "w1");
        assert_eq!(q(2).name, "q2");
        assert_eq!(v_lane(3, "2d").name, "v3.2d");
        assert_eq!(x(30).name, "lr");
    }

    #[test]
    fn formats_zero_and_stack_registers_by_context() {
        assert_eq!(x_or_sp(31).name, "sp");
        assert_eq!(w_or_sp(31).name, "wsp");
        assert_eq!(x_or_zr(31).name, "xzr");
        assert_eq!(w_or_zr(31).name, "wzr");
    }
}
