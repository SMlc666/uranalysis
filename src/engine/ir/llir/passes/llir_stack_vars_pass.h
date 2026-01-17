#pragma once

/// @file llir_stack_vars_pass.h
/// @brief Stack variable lifting pass for LLIR.

#include "engine/llir.h"
#include "engine/llir_passes.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::llir {

/// Pass that lifts stack accesses to named variables.
///
/// This pass identifies loads and stores to stack-relative addresses
/// (SP-based or FP-based) and rewrites them as variable accesses.
/// This is a crucial step for producing readable decompiled output.
///
/// This pass invalidates all analyses since it significantly transforms the IR.
struct LlirStackVarsPass : public pass::PassInfoMixin<LlirStackVarsPass> {
    static const char* name() { return "LlirStackVarsPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        std::string error;
        
        if (!lift_stack_vars(function, error)) {
            return pass::PassResult::failure("LlirStackVarsPass: " + error);
        }
        
        // Stack var lifting changes IR structure significantly
        return pass::PassResult::successNone();
    }
};

}  // namespace engine::llir
