#include "engine/decompiler.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "engine/decompiler/passes/abi_params.h"
#include "engine/decompiler/passes/de_ssa.h"
#include "engine/decompiler/passes/naming.h"
#include "engine/decompiler/passes/rename_vars.h"
#include "engine/decompiler/passes/special_regs.h"
#include "engine/decompiler/passes/ssa_groups.h"
#include "engine/decompiler/types/type_constraints.h"
#include "engine/decompiler/types/signature_db.h"
#include "engine/decompiler/types/type_solver.h"
#include "engine/hlil_lift.h"
#include "engine/hlil_opt.h"

#include "printer.h"
#include "engine/decompiler/transforms.h"

namespace engine::decompiler {

namespace {

Stmt convert_stmt(const hlil::HlilStmt& in) {
    Stmt out;
    out.comment = in.comment;
    switch (in.kind) {
        case hlil::HlilStmtKind::kAssign:
            out.kind = StmtKind::kAssign;
            out.var = in.var;
            out.expr = in.expr;
            break;
        case hlil::HlilStmtKind::kStore:
            out.kind = StmtKind::kStore;
            out.target = in.target;
            out.expr = in.expr;
            break;
        case hlil::HlilStmtKind::kCall:
            out.kind = StmtKind::kCall;
            out.target = in.target;
            out.args = in.args;
            out.returns = in.returns;
            break;
        case hlil::HlilStmtKind::kRet:
            out.kind = StmtKind::kReturn;
            out.expr = in.expr;
            break;
        case hlil::HlilStmtKind::kLabel:
            out.kind = StmtKind::kLabel;
            out.address = in.address;
            break;
        case hlil::HlilStmtKind::kGoto:
            out.kind = StmtKind::kGoto;
            out.address = in.address;
            break;
        case hlil::HlilStmtKind::kBreak:
            out.kind = StmtKind::kBreak;
            break;
        case hlil::HlilStmtKind::kContinue:
            out.kind = StmtKind::kContinue;
            break;
        case hlil::HlilStmtKind::kIf:
            out.kind = StmtKind::kIf;
            out.condition = in.condition;
            out.then_body.reserve(in.then_body.size());
            for (const auto& stmt : in.then_body) {
                out.then_body.push_back(convert_stmt(stmt));
            }
            out.else_body.reserve(in.else_body.size());
            for (const auto& stmt : in.else_body) {
                out.else_body.push_back(convert_stmt(stmt));
            }
            break;
        case hlil::HlilStmtKind::kWhile:
            out.kind = StmtKind::kWhile;
            out.condition = in.condition;
            out.body.reserve(in.body.size());
            for (const auto& stmt : in.body) {
                out.body.push_back(convert_stmt(stmt));
            }
            break;
        case hlil::HlilStmtKind::kDoWhile:
            out.kind = StmtKind::kDoWhile;
            out.condition = in.condition;
            out.body.reserve(in.body.size());
            for (const auto& stmt : in.body) {
                out.body.push_back(convert_stmt(stmt));
            }
            break;
        case hlil::HlilStmtKind::kFor:
            out.kind = StmtKind::kFor;
            out.condition = in.condition;
            out.then_body.reserve(in.then_body.size());
            for (const auto& stmt : in.then_body) {
                out.then_body.push_back(convert_stmt(stmt));
            }
            out.else_body.reserve(in.else_body.size());
            for (const auto& stmt : in.else_body) {
                out.else_body.push_back(convert_stmt(stmt));
            }
            out.body.reserve(in.body.size());
            for (const auto& stmt : in.body) {
                out.body.push_back(convert_stmt(stmt));
            }
            break;
        default:
            out.kind = StmtKind::kNop;
            break;
    }
    return out;
}

} // namespace

bool build_pseudoc_from_hlil(const hlil::Function& hlil_function,
                             Function& out,
                             std::string& error) {
    error.clear();
    out.entry = hlil_function.entry;
    if (out.name.empty()) {
        out.name = "sub_" + format_hex(out.entry);
    }
    out.params.clear();
    out.locals.clear();
    out.var_map.clear();
    out.stmts.clear();

    out.stmts.reserve(hlil_function.stmts.size());
    for (const auto& stmt : hlil_function.stmts) {
        if (stmt.comment == "call clobber") {
            continue;
        }
        out.stmts.push_back(convert_stmt(stmt));
    }
    materialize_temporaries(out);
    propagate_pseudoc_exprs(out);
    inline_trivial_temps(out);
    fold_store_address_temps(out);
    merge_nested_ifs(out);
    flatten_guard_clauses(out);
    merge_tail_returns(out);
    normalize_post_increments(out);
    seed_uninit_loop_indices(out);
    normalize_string_copy_loops(out);
    repair_loop_bounds(out);
    merge_while_to_for(out);
    return true;
}

namespace {

bool build_pseudoc_from_mlil_ssa_internal(const mlil::Function& mlil_function,
                                          Function& out,
                                          std::string& error,
                                          const FunctionHints* hints,
                                          mlil::Function* mlil_lowered_out) {
    error.clear();

    hlil::Function hlil_ssa;
    if (!hlil::build_hlil_from_mlil(mlil_function, hlil_ssa, error)) {
        return false;
    }

    mlil::Function working = mlil_function;
    passes::rewrite_special_registers(working);
    passes::prune_call_args(working);

    types::TypeSolver solver;
    types::collect_constraints_mlil(working, solver);

    auto groups = passes::build_phi_groups(working);
    auto params = passes::collect_abi_params(working);
    std::vector<VarDecl> hinted_params;
    std::string hinted_return;
    const std::vector<VarDecl>* hinted_param_ptr = nullptr;
    if (hints) {
        hinted_params = hints->params;
        hinted_return = hints->return_type;
        if (!hints->name.empty() && hinted_params.empty()) {
            types::lookup_signature(hints->name, hinted_params, hinted_return);
        }
        if (!hinted_params.empty()) {
            hinted_param_ptr = &hinted_params;
        }
    }
    auto naming = passes::build_naming(working, hlil_ssa, solver, groups, params, hinted_param_ptr);

    mlil::Function renamed = working;
    passes::rename_vars(renamed, naming.names);
    passes::split_critical_edges(renamed);
    if (!passes::lower_mlil_ssa(renamed, error)) {
        return false;
    }
    if (mlil_lowered_out) {
        *mlil_lowered_out = renamed;
    }

    hlil::Function hlil_lowered;
    if (!hlil::build_hlil_from_mlil(renamed, hlil_lowered, error)) {
        return false;
    }

    hlil::HlilOptOptions opt_options;
    if (!hlil::optimize_hlil(hlil_lowered, opt_options, error)) {
        return false;
    }

    if (!build_pseudoc_from_hlil(hlil_lowered, out, error)) {
        return false;
    }
    out.params = std::move(naming.params);
    out.locals = std::move(naming.locals);
    if (hints && !hints->name.empty()) {
        out.name = normalize_function_name(hints->name);
    }
    if (out.return_type.empty()) {
        if (hints && !hinted_return.empty()) {
            out.return_type = hinted_return;
        } else {
            out.return_type = passes::infer_return_type(working);
        }
    }
    return true;
}

}  // namespace

bool build_pseudoc_from_mlil_ssa(const mlil::Function& mlil_function,
                                 Function& out,
                                 std::string& error,
                                 const FunctionHints* hints) {
    return build_pseudoc_from_mlil_ssa_internal(mlil_function, out, error, hints, nullptr);
}

bool build_pseudoc_from_mlil_ssa_debug(const mlil::Function& mlil_function,
                                       Function& out,
                                       std::string& error,
                                       const FunctionHints* hints,
                                       mlil::Function* mlil_lowered_out) {
    return build_pseudoc_from_mlil_ssa_internal(mlil_function, out, error, hints, mlil_lowered_out);
}

void emit_pseudoc(const Function& function, std::vector<std::string>& out_lines) {
    emit_function_pseudoc(function, out_lines);
}

}  // namespace engine::decompiler
