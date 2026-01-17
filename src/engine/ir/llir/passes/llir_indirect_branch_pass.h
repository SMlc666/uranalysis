#pragma once

/// @file llir_indirect_branch_pass.h
/// @brief Indirect branch resolution pass for LLIR.

#include "engine/llir.h"
#include "engine/llir_passes.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::llir {

/// Pass that resolves constant indirect branches.
///
/// This pass evaluates indirect jump targets that can be computed
/// statically and updates the CFG with explicit targets.
///
/// This pass may modify the CFG (successor/predecessor lists),
/// which invalidates most analyses.
struct LlirIndirectBranchPass : public pass::PassInfoMixin<LlirIndirectBranchPass> {
    static const char* name() { return "LlirIndirectBranchPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        std::string error;
        
        if (!resolve_indirect_branches(function, error)) {
            return pass::PassResult::failure("LlirIndirectBranchPass: " + error);
        }
        
        // CFG may have changed
        return pass::PassResult::successNone();
    }
};

}  // namespace engine::llir
