#pragma once

/// @file llir_jump_table_pass.h
/// @brief Jump table resolution pass for LLIR.

#include "engine/binary_loader.h"
#include "engine/llir.h"
#include "engine/llir_passes.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

#include <vector>

namespace engine::llir {

/// Pass that detects and resolves jump tables (switch statements).
///
/// This pass identifies patterns like:
///   br [table_base + index * entry_size]
/// and reads the jump table from memory to determine all targets.
///
/// This pass requires external context (LoadedImage, segments) which
/// must be provided at construction time.
///
/// This pass may modify the CFG significantly.
struct LlirJumpTablePass : public pass::PassInfoMixin<LlirJumpTablePass> {
    LlirJumpTablePass(const LoadedImage& image, const std::vector<BinarySegment>& segments)
        : image_(image), segments_(segments) {}

    static const char* name() { return "LlirJumpTablePass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        std::string error;
        
        if (!resolve_jump_tables(function, image_, segments_, error)) {
            return pass::PassResult::failure("LlirJumpTablePass: " + error);
        }
        
        // CFG may have changed significantly
        return pass::PassResult::successNone();
    }

private:
    const LoadedImage& image_;
    const std::vector<BinarySegment>& segments_;
};

}  // namespace engine::llir
