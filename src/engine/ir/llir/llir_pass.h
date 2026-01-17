#pragma once

/// @file llir_pass.h
/// @brief Aggregate header for all LLIR PassManager components.
///
/// This header provides all LLIR-specific analyses, passes, and type aliases
/// for use with the PassManager framework.
///
/// Usage example:
/// @code
/// #include "engine/ir/llir/llir_pass.h"
/// 
/// using namespace engine::llir;
///
/// // Create analysis manager and register analyses
/// LlirAnalysisManager am;
/// am.registerAnalysis<LlirDefUseAnalysis>();
///
/// // Create pass manager and add passes
/// LlirPassManager pm;
/// pm.addPass(LlirCopyPropagationPass{});
/// pm.addPass(LlirConstantFoldPass{});
/// pm.addPass(LlirDCEPass{});
///
/// // Run on function
/// auto result = pm.run(function, am);
/// @endcode

// Core framework
#include "engine/pass.h"

// LLIR analyses
#include "llir/analysis/llir_defuse_analysis.h"

// LLIR optimization passes
#include "llir/passes/llir_constant_fold_pass.h"
#include "llir/passes/llir_copy_propagation_pass.h"
#include "llir/passes/llir_dce_pass.h"
#include "llir/passes/llir_flag_inline_pass.h"

// LLIR transformation passes
#include "llir/passes/llir_indirect_branch_pass.h"
#include "llir/passes/llir_jump_table_pass.h"
#include "llir/passes/llir_stack_vars_pass.h"

namespace engine::llir {

// ============================================================================
// Type aliases for convenience
// ============================================================================

/// Analysis manager for LLIR functions
using LlirAnalysisManager = pass::AnalysisManager<Function>;

/// Pass manager for LLIR functions
using LlirPassManager = pass::PassManager<Function>;

/// Pass builder for LLIR functions
using LlirPassBuilder = pass::PassBuilder<Function>;

// ============================================================================
// Pipeline construction helpers
// ============================================================================

/// Options for constructing the standard LLIR optimization pipeline.
struct LlirOptPipelineOptions {
    bool copy_propagation = true;
    bool constant_folding = true;
    bool flag_inlining = true;
    bool dead_code_elim = true;
    int max_iterations = 3;
};

/// Construct the standard LLIR SSA optimization pipeline.
///
/// This creates a pipeline equivalent to the legacy optimize_llil_ssa() function,
/// running optimization passes in a fixed-point loop.
///
/// @param options Pipeline configuration options
/// @return Configured LlirPassManager ready to run
inline LlirPassManager buildLlirOptPipeline(const LlirOptPipelineOptions& options = {}) {
    LlirPassManager pm;
    
    // Build a single iteration pass sequence
    // The caller can run multiple iterations if needed
    if (options.copy_propagation) {
        pm.addPass(LlirCopyPropagationPass{});
    }
    if (options.constant_folding) {
        pm.addPass(LlirConstantFoldPass{});
    }
    if (options.flag_inlining) {
        pm.addPass(LlirFlagInlinePass{});
    }
    if (options.dead_code_elim) {
        pm.addPass(LlirDCEPass{});
    }
    
    return pm;
}

/// Construct the LLIR CFG refinement pipeline.
///
/// This pipeline includes passes that improve CFG accuracy:
/// - Indirect branch resolution
/// - Jump table detection
///
/// @param image The loaded binary image (for memory reads)
/// @param segments Binary segments (for executable range checks)
/// @return Configured LlirPassManager
inline LlirPassManager buildLlirCfgPipeline(const LoadedImage& image,
                                             const std::vector<BinarySegment>& segments) {
    LlirPassManager pm;
    
    pm.addPass(LlirIndirectBranchPass{});
    pm.addPass(LlirJumpTablePass{image, segments});
    
    return pm;
}

}  // namespace engine::llir
