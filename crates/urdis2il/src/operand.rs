use crate::model::{IlExpr, IlLocation, IlReg};

pub(crate) fn reg_expr(arch: urcodec::Architecture, name: &str, width_bits: u16) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch,
        name: name.to_string(),
        width_bits,
    })
}

pub(crate) fn reg_location(arch: urcodec::Architecture, name: &str, width_bits: u16) -> IlLocation {
    IlLocation::Reg(IlReg {
        arch,
        name: name.to_string(),
        width_bits,
    })
}

pub(crate) fn const_expr(value: u64, width_bits: u16) -> IlExpr {
    IlExpr::Const { value, width_bits }
}

pub(crate) fn memory_address(arch: urcodec::Architecture, mem: &urcodec::MemoryOperand) -> IlExpr {
    let base = mem.base.as_ref().map(|reg| reg_expr(arch, &reg.name, 64));
    let index = mem.index.as_ref().map(|reg| {
        let expr = reg_expr(arch, &reg.name, 64);
        if mem.scale > 1 {
            IlExpr::Shl(
                Box::new(expr),
                Box::new(const_expr(u64::from(mem.scale.trailing_zeros()), 8)),
            )
        } else {
            expr
        }
    });
    let displacement = if mem.offset == 0 {
        None
    } else {
        Some(const_expr(mem.offset as u64, 64))
    };
    [base, index, displacement]
        .into_iter()
        .flatten()
        .reduce(|lhs, rhs| IlExpr::Add(Box::new(lhs), Box::new(rhs)))
        .unwrap_or_else(|| const_expr(0, 64))
}
