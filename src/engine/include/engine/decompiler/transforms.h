#pragma once

#include "engine/decompiler.h"
#include "engine/mlil.h"

#include <string>
#include <unordered_set>

namespace engine::decompiler {

// Expression helpers
bool get_imm_value(const mlil::MlilExpr& expr, std::uint64_t& out);
bool is_zero_imm(const mlil::MlilExpr& expr);
bool is_one_imm(const mlil::MlilExpr& expr);
bool is_var_or_imm(const mlil::MlilExpr& expr);
bool is_pure_expr(const mlil::MlilExpr& expr);
int expr_cost(const mlil::MlilExpr& expr);
std::string expr_key(const mlil::MlilExpr& expr);
bool expr_uses_var(const mlil::MlilExpr& expr, const std::string& name);
void collect_expr_vars(const mlil::MlilExpr& expr, std::unordered_set<std::string>& out);

mlil::MlilExpr make_imm_expr(std::size_t size, std::uint64_t value);
mlil::MlilExpr make_binary_expr(mlil::MlilOp op, std::size_t size, mlil::MlilExpr lhs, mlil::MlilExpr rhs);
mlil::MlilExpr make_var_expr(const std::string& name, std::size_t size);

// Stmt helpers
bool is_control_stmt(const Stmt& stmt);
bool stmt_uses_var(const Stmt& stmt, const std::string& name);
bool stmt_defines_var(const Stmt& stmt, const std::string& name);

// Simplification
void simplify_expr(mlil::MlilExpr& expr);

// Optimization Passes
void materialize_temporaries(Function& function);
void propagate_pseudoc_exprs(Function& function);
void inline_trivial_temps(Function& function);
void fold_store_address_temps(Function& function);
void merge_nested_ifs(Function& function);
void flatten_guard_clauses(Function& function);
void merge_tail_returns(Function& function);
void normalize_post_increments(Function& function);
void seed_uninit_loop_indices(Function& function);
void normalize_string_copy_loops(Function& function);
void repair_loop_bounds(Function& function);
void merge_while_to_for(Function& function);

} // namespace engine::decompiler