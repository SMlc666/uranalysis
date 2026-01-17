#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "engine/image.h"

namespace engine::llir {

struct RegRef {
    std::string name;
    int version = -1;
};

struct VarRef {
    std::string name;
    int version = -1;
    std::size_t size = 0;
    std::string type_name;
};

enum class LlilExprKind {
    kInvalid,
    kUnknown,
    kUndef,
    kReg,
    kVar,
    kImm,
    kOp,
    kLoad,
};

enum class LlilOp {
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

struct LlilExpr {
    LlilExprKind kind = LlilExprKind::kInvalid;
    std::size_t size = 0;
    LlilOp op = LlilOp::kAdd;
    RegRef reg = {};
    VarRef var = {};
    std::uint64_t imm = 0;
    std::vector<LlilExpr> args;
};

enum class LlilStmtKind {
    kUnimpl,
    kNop,
    kSetReg,
    kSetVar,
    kStore,
    kCall,
    kJump,
    kCJump,
    kRet,
    kPhi,
};

struct LlilStmt {
    LlilStmtKind kind = LlilStmtKind::kUnimpl;
    RegRef reg = {};
    VarRef var = {};
    LlilExpr expr = {};
    LlilExpr target = {};
    LlilExpr condition = {};
    std::vector<LlilExpr> args;
    std::vector<RegRef> returns;
    std::string comment;
};

enum class BranchKind {
    kNone,
    kJump,
    kCall,
    kRet
};

struct Instruction {
    std::uint64_t address = 0;
    std::uint32_t size = 0;
    std::string mnemonic;
    std::string operands;
    BranchKind branch = BranchKind::kNone;
    bool conditional = false;
    std::vector<std::uint64_t> targets;
    std::vector<LlilStmt> llil;
    std::vector<LlilStmt> llil_ssa;
    
    // Jump table info (populated by resolve_jump_tables pass)
    std::uint64_t jump_table_base = 0;
    std::size_t jump_table_size = 0;
    bool is_switch = false;
};

struct BasicBlock {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::vector<Instruction> instructions;
    std::vector<std::uint64_t> predecessors;
    std::vector<std::uint64_t> successors;
    std::vector<LlilStmt> phis;
};

struct Function {
    std::uint64_t entry = 0;
    std::vector<BasicBlock> blocks;
};

bool build_cfg_arm64(const LoadedImage& image,
                     std::uint64_t entry,
                     std::size_t max_instructions,
                     Function& function,
                     std::string& error);

bool build_cfg_x86_64(const LoadedImage& image,
                      std::uint64_t entry,
                      std::size_t max_instructions,
                      Function& function,
                      std::string& error);

}  // namespace engine::llir
