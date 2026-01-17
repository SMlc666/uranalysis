#pragma once

/// @file llir_constant_fold_pass.h
/// @brief Constant folding pass for LLIR SSA form.

#include "engine/llir.h"
#include "engine/llir_opt_internal.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::llir {

/// Pass that performs constant folding on LLIR expressions.
///
/// This pass simplifies expressions by evaluating operations on immediate values
/// at compile time (e.g., `add(5, 3)` becomes `8`).
///
/// This pass does NOT invalidate DefUse analysis since it only modifies
/// expression trees without changing register assignments or uses.
struct LlirConstantFoldPass : public pass::PassInfoMixin<LlirConstantFoldPass> {
    static const char* name() { return "LlirConstantFoldPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        if (!detail::has_ssa(function)) {
            return pass::PassResult::failure("LlirConstantFoldPass: function has no SSA form");
        }

        bool changed = detail::fold_constants(function);
        
        if (changed) {
            // Constant folding preserves DefUse since we only simplify expressions
            // but don't change register assignments
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::llir
