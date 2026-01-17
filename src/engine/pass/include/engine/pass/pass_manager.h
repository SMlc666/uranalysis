#pragma once

#include "engine/pass/analysis_manager.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_instrumentation.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/preserved_analyses.h"

#include <memory>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>

namespace engine::pass {

/// Manages a pipeline of passes to run on a specific IR unit type.
///
/// The PassManager is responsible for:
/// - Storing and running a sequence of passes
/// - Tracking analysis invalidation between passes
/// - Providing instrumentation hooks for debugging
///
/// @tparam IRUnit The IR type this manager handles (e.g., llir::Function)
template <typename IRUnit>
class PassManager {
public:
    PassManager() = default;
    ~PassManager() = default;

    // Non-copyable due to unique_ptr, but movable
    PassManager(const PassManager&) = delete;
    PassManager& operator=(const PassManager&) = delete;
    PassManager(PassManager&&) = default;
    PassManager& operator=(PassManager&&) = default;

    /// Add a pass to the pipeline.
    /// @tparam PassT The pass type (must have run() and name())
    template <typename PassT>
    void addPass(PassT pass) {
        passes_.push_back(
            std::make_unique<PassModel<PassT, IRUnit>>(std::move(pass)));
    }

    /// Run all passes in the pipeline on the given IR unit.
    /// 
    /// @param ir The IR unit to transform
    /// @param am The analysis manager for this IR unit
    /// @return Combined PassResult from all passes
    PassResult run(IRUnit& ir, AnalysisManager<IRUnit>& am) {
        PreservedAnalyses all_preserved = PreservedAnalyses::all();

        for (auto& pass : passes_) {
            // Instrumentation: before pass
            instrumentation_.runBeforePass(pass->name(), &ir);

            // Run the pass
            PassResult result = pass->run(ir, am);

            // Check for failure
            if (result.failed()) {
                instrumentation_.runPassFailed(pass->name(), result.error);
                return result;
            }

            // Instrumentation: after pass
            instrumentation_.runAfterPass(pass->name(), &ir, result);

            // Invalidate analyses based on what the pass preserved
            am.invalidate(ir, result.preserved);

            // Track cumulative preservation
            all_preserved.intersect(result.preserved);
        }

        return PassResult::success(std::move(all_preserved));
    }

    /// Get the number of passes in the pipeline
    std::size_t size() const {
        return passes_.size();
    }

    /// Check if the pipeline is empty
    bool empty() const {
        return passes_.empty();
    }

    /// Clear all passes from the pipeline
    void clear() {
        passes_.clear();
    }

    /// Get the instrumentation object for configuration
    PassInstrumentation& instrumentation() {
        return instrumentation_;
    }

    /// Set instrumentation options
    void setInstrumentationOptions(const PassInstrumentationOptions& opts) {
        instrumentation_.setOptions(opts);
    }

    /// Get pass name by index (for debugging)
    const char* getPassName(std::size_t index) const {
        if (index >= passes_.size()) {
            return nullptr;
        }
        return passes_[index]->name();
    }

private:
    std::vector<std::unique_ptr<PassConcept<IRUnit>>> passes_;
    PassInstrumentation instrumentation_;
};

// ============================================================================
// Type aliases for convenience
// ============================================================================

// Forward declarations for IR types (to be used when these are available)
// These will be defined properly when integrating with the actual IR

}  // namespace engine::pass
