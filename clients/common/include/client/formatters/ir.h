#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "engine/hlil.h"
#include "engine/llir.h"
#include "engine/mlil.h"

namespace client::fmt {

// ============================================================================
// LLIR Formatting
// ============================================================================

/// Format LLIR register reference
std::string format_reg(const engine::llir::RegRef& reg);

/// Format LLIR variable reference
std::string format_var(const engine::llir::VarRef& var);

/// Get name for LLIR operation
const char* llir_op_name(engine::llir::LlilOp op);

/// Format LLIR expression
std::string format_llir_expr(const engine::llir::LlilExpr& expr);

/// Format LLIR statement
std::string format_llir_stmt(const engine::llir::LlilStmt& stmt);

/// Format entire LLIR function to lines
void format_llir_function(const engine::llir::Function& func, std::vector<std::string>& lines);

/// Calculate discovered function size from blocks
std::uint64_t discovered_size(const engine::llir::Function& function);

// ============================================================================
// MLIL Formatting
// ============================================================================

/// Format MLIL variable reference
std::string format_mlil_var(const engine::mlil::VarRef& var);

/// Get name for MLIL operation
const char* mlil_op_name(engine::mlil::MlilOp op);

/// Format MLIL expression
std::string format_mlil_expr(const engine::mlil::MlilExpr& expr);

/// Format MLIL statement
std::string format_mlil_stmt(const engine::mlil::MlilStmt& stmt);

/// Format entire MLIL function to lines
void format_mlil_function(const engine::mlil::Function& func, std::vector<std::string>& lines);

// ============================================================================
// HLIL Formatting
// ============================================================================

/// Variable rename map type
using HlilVarRenameMap = std::unordered_map<std::string, std::string>;

/// Apply variable renames to an MLIL expression (modifies in place)
void apply_hlil_var_renames(engine::mlil::MlilExpr& expr, const HlilVarRenameMap& renames);

/// Apply variable renames to a variable reference (returns new var)
engine::mlil::VarRef apply_hlil_var_renames(engine::mlil::VarRef var, const HlilVarRenameMap& renames);

/// Format HLIL expression with variable renames
std::string format_hlil_expr(const engine::hlil::Expr& expr, const HlilVarRenameMap& renames);

/// Format HLIL variable with renames
std::string format_hlil_var(const engine::hlil::VarRef& var, const HlilVarRenameMap& renames);

/// Format HLIL statement with renames and indentation
std::string format_hlil_stmt(const engine::hlil::HlilStmt& stmt,
                             const HlilVarRenameMap& renames,
                             int indent = 0);

/// Format HLIL statement block recursively
void format_hlil_stmt_block(const std::vector<engine::hlil::HlilStmt>& stmts,
                            int indent,
                            const HlilVarRenameMap& renames,
                            std::vector<std::string>& lines);

/// Format entire HLIL function to lines
void format_hlil_function(const engine::hlil::Function& func, std::vector<std::string>& lines);

}  // namespace client::fmt