#pragma once

/// @file llir_opt_internal.h
/// @brief Internal LLIR optimization functions exposed for PassManager integration.
///
/// These functions are the underlying implementations used by the legacy
/// optimize_llil_ssa() function and the new PassManager-compatible passes.

#include "engine/llir.h"
#include "engine/llir_ssa.h"

#include <string>

namespace engine::llir::detail {

/// Simplify a single expression by constant folding.
/// Returns true if any change was made.
bool simplify_op(LlilExpr& expr);

/// Fold constants in all expressions throughout the function.
/// Returns true if any change was made.
bool fold_constants(Function& function);

/// Propagate copies (assignments of immediates or registers) to their uses.
/// Requires up-to-date def-use information.
/// Returns true if any change was made.
bool propagate_copies(Function& function, const LlilSsaDefUse& defuse);

/// Inline flag register expressions into their uses.
/// Requires up-to-date def-use information.
/// Returns true if any change was made.
bool propagate_flag_exprs(Function& function, const LlilSsaDefUse& defuse);

/// Eliminate dead definitions (assignments with no uses).
/// Requires up-to-date def-use information.
/// Returns true if any change was made.
bool eliminate_dead_defs(Function& function, const LlilSsaDefUse& defuse);

/// Check if a function has any SSA statements.
bool has_ssa(const Function& function);

}  // namespace engine::llir::detail
