#pragma once

/// @file mlil_constant_fold_pass.h
/// @brief Constant folding pass for MLIL SSA form.

#include "engine/mlil.h"
#include "engine/mlil_opt_internal.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::mlil {

/// Pass that performs constant folding on MLIL expressions.
///
/// This pass simplifies expressions by evaluating operations on immediate values
/// at compile time. It also normalizes boolean comparisons and simplifies
/// zero-register operations.
struct MlilConstantFoldPass : public pass::PassInfoMixin<MlilConstantFoldPass> {
    static const char* name() { return "MlilConstantFoldPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        if (!detail::has_ssa(function)) {
            return pass::PassResult::failure("MlilConstantFoldPass: function has no SSA form");
        }

        bool changed = detail::fold_constants(function);
        
        if (changed) {
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::mlil
