use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlInstruction {
    pub address: u64,
    pub size: u8,
    pub statements: Vec<IlStmt>,
    pub terminator: Option<IlTerminator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlBlock {
    pub start: u64,
    pub instructions: Vec<IlInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlFunction {
    pub address: u64,
    pub blocks: Vec<IlBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlStmt {
    Assign {
        dst: IlLocation,
        src: IlExpr,
    },
    Load {
        dst: IlLocation,
        address: IlExpr,
        size: u16,
    },
    Store {
        address: IlExpr,
        value: IlExpr,
        size: u16,
    },
    SetFlag {
        flag: IlFlag,
        value: IlExpr,
    },
    Intrinsic {
        name: String,
        inputs: Vec<IlExpr>,
        outputs: Vec<IlLocation>,
    },
    Unsupported {
        address: u64,
        mnemonic: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlExpr {
    Reg(IlReg),
    Flag(IlFlag),
    Temp(u32),
    Const { value: u64, width_bits: u16 },
    Add(Box<IlExpr>, Box<IlExpr>),
    Sub(Box<IlExpr>, Box<IlExpr>),
    And(Box<IlExpr>, Box<IlExpr>),
    Or(Box<IlExpr>, Box<IlExpr>),
    Xor(Box<IlExpr>, Box<IlExpr>),
    Shl(Box<IlExpr>, Box<IlExpr>),
    Shr(Box<IlExpr>, Box<IlExpr>),
    Eq(Box<IlExpr>, Box<IlExpr>),
    Ne(Box<IlExpr>, Box<IlExpr>),
    Lt(Box<IlExpr>, Box<IlExpr>),
    Le(Box<IlExpr>, Box<IlExpr>),
    Gt(Box<IlExpr>, Box<IlExpr>),
    Ge(Box<IlExpr>, Box<IlExpr>),
    Not(Box<IlExpr>),
    SignExtend { value: Box<IlExpr>, to_bits: u16 },
    ZeroExtend { value: Box<IlExpr>, to_bits: u16 },
    Truncate { value: Box<IlExpr>, to_bits: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlLocation {
    Reg(IlReg),
    Flag(IlFlag),
    Temp(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlReg {
    pub arch: urcodec::Architecture,
    pub name: String,
    pub width_bits: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlFlag {
    pub arch: urcodec::Architecture,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlTerminator {
    Jump {
        target: IlExpr,
    },
    Branch {
        condition: IlExpr,
        true_target: IlExpr,
        false_target: IlExpr,
    },
    Call {
        target: IlExpr,
        return_address: Option<u64>,
    },
    Return,
    Fallthrough {
        target: u64,
    },
    Unknown,
}
