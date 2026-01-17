#pragma once

/// @file llir_copy_propagation_pass.h
/// @brief Copy propagation pass for LLIR SSA form.

#include "llir/analysis/llir_defuse_analysis.h"
#include "engine/llir.h"
#include "engine/llir_opt_internal.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::llir {

/// Pass that propagates copy assignments to their uses.
///
/// For assignments like `x1 = x0` or `x1 = 42`, this pass replaces
/// all uses of x1 with the RHS value, enabling further optimization.
///
/// This pass invalidates DefUse analysis since it modifies use sites.
struct LlirCopyPropagationPass : public pass::PassInfoMixin<LlirCopyPropagationPass> {
    static const char* name() { return "LlirCopyPropagationPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& am) {
        if (!detail::has_ssa(function)) {
            return pass::PassResult::failure("LlirCopyPropagationPass: function has no SSA form");
        }

        // Get or compute DefUse analysis
        auto& defuse = am.getResult<LlirDefUseAnalysis>(function);
        
        bool changed = detail::propagate_copies(function, defuse);
        
        if (changed) {
            // Copy propagation modifies use sites, invalidating DefUse
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::llir
