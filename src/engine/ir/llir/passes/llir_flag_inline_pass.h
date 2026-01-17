#pragma once

/// @file llir_flag_inline_pass.h
/// @brief Flag expression inlining pass for LLIR SSA form.

#include "llir/analysis/llir_defuse_analysis.h"
#include "engine/llir.h"
#include "engine/llir_opt_internal.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::llir {

/// Pass that inlines flag register expressions into their uses.
///
/// Flag registers (flag_n, flag_z, flag_c, flag_v) often have simple
/// computed expressions. This pass inlines those expressions at use sites
/// to enable further simplification.
///
/// This pass invalidates DefUse analysis since it modifies use sites.
struct LlirFlagInlinePass : public pass::PassInfoMixin<LlirFlagInlinePass> {
    static const char* name() { return "LlirFlagInlinePass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& am) {
        if (!detail::has_ssa(function)) {
            return pass::PassResult::failure("LlirFlagInlinePass: function has no SSA form");
        }

        // Get or compute DefUse analysis
        auto& defuse = am.getResult<LlirDefUseAnalysis>(function);
        
        bool changed = detail::propagate_flag_exprs(function, defuse);
        
        if (changed) {
            // Flag inlining modifies use sites, invalidating DefUse
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::llir
