#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace engine::mlil {

struct VarRef {
    std::string name;
    int version = -1;
    std::size_t size = 0;
    std::string type_name;
};

enum class MlilExprKind {
    kInvalid,
    kUnknown,
    kUndef,
    kVar,
    kImm,
    kOp,
    kLoad,
    kCall,
};

enum class MlilOp {
    kAdd,
    kSub,
    kMul,
    kDiv,
    kMod,
    kAnd,
    kOr,
    kXor,
    kShl,
    kShr,
    kSar,
    kRor,
    kNot,
    kNeg,
    kAbs,
    kMin,
    kMax,
    kBswap,
    kClz,
    kRbit,
    kSqrt,
    kCast,
    kSelect,
    kEq,
    kNe,
    kLt,
    kLe,
    kGt,
    kGe,
};

struct MlilExpr {
    MlilExprKind kind = MlilExprKind::kInvalid;
    std::size_t size = 0;
    MlilOp op = MlilOp::kAdd;
    VarRef var = {};
    std::uint64_t imm = 0;
    std::vector<MlilExpr> args;
};

enum class MlilStmtKind {
    kUnimpl,
    kNop,
    kAssign,
    kStore,
    kCall,
    kJump,
    kCJump,
    kRet,
    kPhi,
};

struct MlilStmt {
    MlilStmtKind kind = MlilStmtKind::kUnimpl;
    VarRef var = {};
    MlilExpr expr = {};
    MlilExpr target = {};
    MlilExpr condition = {};
    std::vector<MlilExpr> args;
    std::vector<VarRef> returns;
    std::string comment;
};

struct Instruction {
    std::uint64_t address = 0;
    std::vector<MlilStmt> stmts;
};

struct BasicBlock {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::vector<Instruction> instructions;
    std::vector<std::uint64_t> predecessors;
    std::vector<std::uint64_t> successors;
    std::vector<MlilStmt> phis;
};

struct Function {
    std::uint64_t entry = 0;
    std::vector<BasicBlock> blocks;
};

}  // namespace engine::mlil
