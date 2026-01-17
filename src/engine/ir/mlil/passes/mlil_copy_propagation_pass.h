#pragma once

/// @file mlil_copy_propagation_pass.h
/// @brief Copy propagation pass for MLIL SSA form.

#include "mlil/analysis/mlil_defuse_analysis.h"
#include "engine/mlil.h"
#include "engine/mlil_opt_internal.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::mlil {

/// Pass that propagates copy assignments to their uses.
///
/// For assignments like `v1 = v0` or `v1 = 42`, this pass replaces
/// all uses of v1 with the RHS value.
struct MlilCopyPropagationPass : public pass::PassInfoMixin<MlilCopyPropagationPass> {
    static const char* name() { return "MlilCopyPropagationPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& am) {
        if (!detail::has_ssa(function)) {
            return pass::PassResult::failure("MlilCopyPropagationPass: function has no SSA form");
        }

        auto& defuse = am.getResult<MlilDefUseAnalysis>(function);
        
        bool changed = detail::propagate_copies(function, defuse);
        
        if (changed) {
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::mlil
