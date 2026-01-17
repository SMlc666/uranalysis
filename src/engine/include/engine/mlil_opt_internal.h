#pragma once

/// @file mlil_opt_internal.h
/// @brief Internal MLIL optimization functions exposed for PassManager integration.
///
/// These functions are the underlying implementations used by the legacy
/// optimize_mlil_ssa() function and the new PassManager-compatible passes.

#include "engine/mlil.h"
#include "engine/mlil_ssa.h"

#include <string>

namespace engine::mlil::detail {

/// Simplify a single expression by constant folding and algebraic simplification.
/// Returns true if any change was made.
bool simplify_op(MlilExpr& expr);

/// Fold constants in all expressions throughout the function.
/// Returns true if any change was made.
bool fold_constants(Function& function);

/// Propagate copies (assignments of immediates or variables) to their uses.
/// Requires up-to-date def-use information.
/// Returns true if any change was made.
bool propagate_copies(Function& function, const MlilSsaDefUse& defuse);

/// Eliminate dead definitions (assignments with no uses).
/// Requires up-to-date def-use information.
/// Returns true if any change was made.
bool eliminate_dead_defs(Function& function, const MlilSsaDefUse& defuse);

/// Check if a function has any SSA statements.
bool has_ssa(const Function& function);

}  // namespace engine::mlil::detail
