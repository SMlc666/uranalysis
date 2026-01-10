#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "engine/mlil.h"

namespace engine::hlil {

// HLIL is a structured layer on top of MLIL.
// For now it reuses MLIL expressions/vars but structures control flow.

using Expr = mlil::MlilExpr;
using VarRef = mlil::VarRef;

enum class HlilStmtKind {
    kNop,
    kAssign,
    kStore,
    kCall,
    kRet,
    kLabel,
    kGoto,
    kBreak,
    kContinue,
    kIf,
    kWhile,
    kDoWhile,
    kFor,
};

struct HlilStmt {
    HlilStmtKind kind = HlilStmtKind::kNop;

    // Common metadata.
    std::string comment;

    // kAssign
    VarRef var = {};
    Expr expr = {};

    // kStore
    Expr target = {};

    // kCall
    std::vector<Expr> args;
    std::vector<VarRef> returns;

    // kLabel/kGoto
    std::uint64_t address = 0;

    // kIf/kWhile
    Expr condition = {};
    std::vector<HlilStmt> then_body;
    std::vector<HlilStmt> else_body;
    std::vector<HlilStmt> body;
};

struct Function {
    std::uint64_t entry = 0;
    std::unordered_map<std::string, std::string> var_renames;
    std::vector<HlilStmt> stmts;
};

}  // namespace engine::hlil
