#pragma once

/// @file mlil_pass.h
/// @brief Aggregate header for all MLIL PassManager components.
///
/// This header provides all MLIL-specific analyses, passes, and type aliases
/// for use with the PassManager framework.
///
/// Usage example:
/// @code
/// #include "engine/ir/mlil/mlil_pass.h"
/// 
/// using namespace engine::mlil;
///
/// LlirAnalysisManager am;
/// am.registerAnalysis<MlilDefUseAnalysis>();
///
/// MlilPassManager pm;
/// pm.addPass(MlilCopyPropagationPass{});
/// pm.addPass(MlilConstantFoldPass{});
/// pm.addPass(MlilDCEPass{});
///
/// auto result = pm.run(function, am);
/// @endcode

// Core framework
#include "engine/pass.h"

// MLIL analyses
#include "mlil/analysis/mlil_defuse_analysis.h"

// MLIL optimization passes
#include "mlil/passes/mlil_constant_fold_pass.h"
#include "mlil/passes/mlil_copy_propagation_pass.h"
#include "mlil/passes/mlil_dce_pass.h"

namespace engine::mlil {

// ============================================================================
// Type aliases for convenience
// ============================================================================

/// Analysis manager for MLIL functions
using MlilAnalysisManager = pass::AnalysisManager<Function>;

/// Pass manager for MLIL functions
using MlilPassManager = pass::PassManager<Function>;

/// Pass builder for MLIL functions
using MlilPassBuilder = pass::PassBuilder<Function>;

// ============================================================================
// Pipeline construction helpers
// ============================================================================

/// Options for constructing the standard MLIL optimization pipeline.
struct MlilOptPipelineOptions {
    bool copy_propagation = true;
    bool constant_folding = true;
    bool dead_code_elim = true;
    int max_iterations = 3;
};

/// Construct the standard MLIL SSA optimization pipeline.
///
/// This creates a pipeline equivalent to the legacy optimize_mlil_ssa() function.
///
/// @param options Pipeline configuration options
/// @return Configured MlilPassManager ready to run
inline MlilPassManager buildMlilOptPipeline(const MlilOptPipelineOptions& options = {}) {
    MlilPassManager pm;
    
    if (options.copy_propagation) {
        pm.addPass(MlilCopyPropagationPass{});
    }
    if (options.constant_folding) {
        pm.addPass(MlilConstantFoldPass{});
    }
    if (options.dead_code_elim) {
        pm.addPass(MlilDCEPass{});
    }
    
    return pm;
}

}  // namespace engine::mlil
