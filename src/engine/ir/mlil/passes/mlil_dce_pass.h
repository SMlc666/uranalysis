#pragma once

/// @file mlil_dce_pass.h
/// @brief Dead code elimination pass for MLIL SSA form.

#include "mlil/analysis/mlil_defuse_analysis.h"
#include "engine/mlil.h"
#include "engine/mlil_opt_internal.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::mlil {

/// Pass that eliminates dead code (definitions with no uses).
struct MlilDCEPass : public pass::PassInfoMixin<MlilDCEPass> {
    static const char* name() { return "MlilDCEPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& am) {
        if (!detail::has_ssa(function)) {
            return pass::PassResult::failure("MlilDCEPass: function has no SSA form");
        }

        auto& defuse = am.getResult<MlilDefUseAnalysis>(function);
        
        bool changed = detail::eliminate_dead_defs(function, defuse);
        
        if (changed) {
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::mlil
