use crate::model::{IlExpr, IlReg};

#[allow(dead_code)]
pub(crate) fn reg_expr(arch: urdisassembly::Architecture, name: &str, width_bits: u16) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch,
        name: name.to_string(),
        width_bits,
    })
}
