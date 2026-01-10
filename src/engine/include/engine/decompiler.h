#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "engine/hlil.h"
#include "engine/mlil.h"

namespace engine::decompiler {

struct VarDecl {
    std::string name;
    std::string type;
};

enum class StmtKind {
    kNop,
    kAssign,
    kStore,
    kCall,
    kReturn,
    kLabel,
    kGoto,
    kBreak,
    kContinue,
    kIf,
    kWhile,
    kDoWhile,
    kFor,
};

struct Stmt {
    StmtKind kind = StmtKind::kNop;
    std::string comment;

    // kAssign
    mlil::VarRef var = {};
    mlil::MlilExpr expr = {};

    // kStore
    mlil::MlilExpr target = {};

    // kCall
    std::vector<mlil::MlilExpr> args;
    std::vector<mlil::VarRef> returns;

    // kLabel/kGoto
    std::uint64_t address = 0;

    // kIf/kWhile
    mlil::MlilExpr condition = {};
    std::vector<Stmt> then_body;
    std::vector<Stmt> else_body;
    std::vector<Stmt> body;
};

struct Function {
    std::string name;
    std::string return_type;
    std::uint64_t entry = 0;
    std::unordered_map<std::string, std::string> var_map;
    std::vector<VarDecl> params;
    std::vector<VarDecl> locals;
    std::vector<Stmt> stmts;
};

struct FunctionHints {
    std::string name;
    std::string return_type;
    std::vector<VarDecl> params;
};

bool build_pseudoc_from_hlil(const hlil::Function& hlil_function,
                             Function& out,
                             std::string& error);
bool build_pseudoc_from_mlil_ssa(const mlil::Function& mlil_function,
                                 Function& out,
                                 std::string& error,
                                 const FunctionHints* hints = nullptr);
bool build_pseudoc_from_mlil_ssa_debug(const mlil::Function& mlil_function,
                                       Function& out,
                                       std::string& error,
                                       const FunctionHints* hints,
                                       mlil::Function* mlil_lowered_out);
void emit_pseudoc(const Function& function, std::vector<std::string>& out_lines);

}  // namespace engine::decompiler
