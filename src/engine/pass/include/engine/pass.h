#pragma once

/// @file pass.h
/// @brief Main include file for the PassManager framework.
///
/// This header provides the complete LLVM-style pass management infrastructure
/// for the uranayzle binary analysis engine.
///
/// Key components:
/// - PreservedAnalyses: Tracks which analyses remain valid after a pass
/// - AnalysisManager: Lazy computation and caching of analyses
/// - PassManager: Runs a pipeline of passes with automatic invalidation
/// - PassBuilder: Constructs pipelines with analysis registration
///
/// Usage example:
/// @code
/// // Define an analysis
/// struct MyAnalysis : public AnalysisInfoMixin<MyAnalysis> {
///     struct Result { int value; };
///     static const char* name() { return "MyAnalysis"; }
///     Result run(MyIR& ir, AnalysisManager<MyIR>& am) {
///         return Result{42};
///     }
/// };
///
/// // Define a pass
/// struct MyPass : public PassInfoMixin<MyPass> {
///     static const char* name() { return "MyPass"; }
///     PassResult run(MyIR& ir, AnalysisManager<MyIR>& am) {
///         auto& analysis = am.getResult<MyAnalysis>(ir);
///         // Use analysis...
///         return PassResult::successAll();
///     }
/// };
///
/// // Build and run pipeline
/// AnalysisManager<MyIR> am;
/// am.registerAnalysis<MyAnalysis>();
///
/// PassManager<MyIR> pm;
/// pm.addPass(MyPass{});
///
/// MyIR ir;
/// auto result = pm.run(ir, am);
/// @endcode

#include "engine/pass/preserved_analyses.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis.h"
#include "engine/pass/invalidator.h"
#include "engine/pass/analysis_manager.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_instrumentation.h"
#include "engine/pass/pass_manager.h"
#include "engine/pass/pass_builder.h"

namespace engine::pass {

// ============================================================================
// Convenience type aliases
// ============================================================================

// These will be populated as we integrate with specific IR types

}  // namespace engine::pass
