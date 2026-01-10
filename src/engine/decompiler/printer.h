#pragma once

#include <string>
#include <vector>
#include <unordered_set>

#include "engine/decompiler.h"
#include "engine/mlil.h"

namespace engine::decompiler {

// Expression Formatting
std::string op_name(mlil::MlilOp op);
bool is_unary_symbol(mlil::MlilOp op);
bool is_binary_symbol(mlil::MlilOp op);
std::string format_hex(std::uint64_t value);
std::string normalize_function_name(std::string name);
std::string display_name(const std::string& name);
std::string format_expr(const mlil::MlilExpr& expr);
std::string format_expr_raw(const mlil::MlilExpr& expr);
std::string format_bool_expr(const mlil::MlilExpr& expr);
std::string format_condition(const mlil::MlilExpr& expr);
std::string try_format_array_access(const mlil::MlilExpr& expr);

// Code Generation
void emit_stmt_to_lines(const Stmt& stmt,
                       int indent,
                       const std::unordered_set<std::string>& used,
                       const std::string& return_type,
                       std::vector<std::string>& out_lines);

// Main entry point for emission that handles name remapping etc.
void emit_function_pseudoc(const Function& function, std::vector<std::string>& out_lines);

} // namespace engine::decompiler