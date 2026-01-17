#pragma once

/// @file llir_defuse_analysis.h
/// @brief Def-use chain analysis for LLIR SSA form.
///
/// Wraps the existing build_ssa_def_use() function as a PassManager-compatible Analysis.

#include "engine/llir.h"
#include "engine/llir_ssa.h"
#include "engine/pass/analysis.h"
#include "engine/pass/analysis_manager.h"

namespace engine::llir {

/// Analysis that computes def-use chains for LLIR SSA form.
///
/// This analysis maps SSA register definitions to their use sites,
/// enabling optimization passes like copy propagation and dead code elimination.
///
/// Usage:
/// @code
/// AnalysisManager<Function> am;
/// am.registerAnalysis<LlirDefUseAnalysis>();
/// auto& defuse = am.getResult<LlirDefUseAnalysis>(function);
/// @endcode
struct LlirDefUseAnalysis : public pass::AnalysisInfoMixin<LlirDefUseAnalysis> {
    /// The result type - existing LlilSsaDefUse structure
    using Result = LlilSsaDefUse;

    /// Analysis name for debugging/logging
    static const char* name() { return "LlirDefUseAnalysis"; }

    /// Compute the def-use chains for a function's SSA form.
    ///
    /// @param function The LLIR function to analyze
    /// @param am Analysis manager (unused - this analysis has no dependencies)
    /// @return DefUse chains mapping registers to definition/use sites
    Result run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        LlilSsaDefUse defuse;
        std::string error;
        
        if (!build_ssa_def_use(function, defuse, error)) {
            // Analysis failed - return empty result
            // In a more robust implementation, we might want to propagate errors
            // For now, the empty result will cause dependent passes to be no-ops
            return {};
        }
        
        return defuse;
    }

    /// Custom invalidation logic.
    /// DefUse chains are invalidated when any IR transformation occurs
    /// (unless the pass explicitly preserves this analysis).
    bool invalidate(Function& /*ir*/,
                    const pass::PreservedAnalyses& pa,
                    pass::Invalidator<Function>& /*inv*/,
                    Result& /*result*/) {
        // Only preserved if explicitly kept
        return !pa.preserved(ID());
    }
};

}  // namespace engine::llir
