#pragma once

/// @file mlil_defuse_analysis.h
/// @brief Def-use chain analysis for MLIL SSA form.

#include "engine/mlil.h"
#include "engine/mlil_ssa.h"
#include "engine/pass/analysis.h"
#include "engine/pass/analysis_manager.h"

namespace engine::mlil {

/// Analysis that computes def-use chains for MLIL SSA form.
///
/// This analysis maps SSA variable definitions to their use sites,
/// enabling optimization passes like copy propagation and dead code elimination.
struct MlilDefUseAnalysis : public pass::AnalysisInfoMixin<MlilDefUseAnalysis> {
    /// The result type - existing MlilSsaDefUse structure
    using Result = MlilSsaDefUse;

    /// Analysis name for debugging/logging
    static const char* name() { return "MlilDefUseAnalysis"; }

    /// Compute the def-use chains for a function's SSA form.
    Result run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        MlilSsaDefUse defuse;
        std::string error;
        
        if (!build_ssa_def_use(function, defuse, error)) {
            return {};
        }
        
        return defuse;
    }

    /// Custom invalidation logic.
    bool invalidate(Function& /*ir*/,
                    const pass::PreservedAnalyses& pa,
                    pass::Invalidator<Function>& /*inv*/,
                    Result& /*result*/) {
        return !pa.preserved(ID());
    }
};

}  // namespace engine::mlil
