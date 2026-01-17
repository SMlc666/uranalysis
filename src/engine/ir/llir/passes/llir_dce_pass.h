#pragma once

/// @file llir_dce_pass.h
/// @brief Dead code elimination pass for LLIR SSA form.

#include "llir/analysis/llir_defuse_analysis.h"
#include "engine/llir.h"
#include "engine/llir_opt_internal.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::llir {

/// Pass that eliminates dead code (definitions with no uses).
///
/// In SSA form, a definition is dead if no other statement uses it.
/// This includes both regular register assignments and phi nodes.
///
/// This pass invalidates DefUse analysis since it removes definitions.
struct LlirDCEPass : public pass::PassInfoMixin<LlirDCEPass> {
    static const char* name() { return "LlirDCEPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& am) {
        if (!detail::has_ssa(function)) {
            return pass::PassResult::failure("LlirDCEPass: function has no SSA form");
        }

        // Get or compute DefUse analysis
        auto& defuse = am.getResult<LlirDefUseAnalysis>(function);
        
        bool changed = detail::eliminate_dead_defs(function, defuse);
        
        if (changed) {
            // DCE removes statements, invalidating DefUse
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::llir
