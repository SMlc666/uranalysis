#pragma once

#include "engine/pass/preserved_analyses.h"

#include <unordered_map>

namespace engine::pass {

// Forward declaration
template <typename IRUnit>
class AnalysisManager;

/// Handles transitive dependency invalidation with memoization.
/// 
/// When a pass runs and returns PreservedAnalyses, the Invalidator
/// is used to determine which cached analyses need to be discarded.
/// It supports transitive invalidation: if analysis A depends on B,
/// and B is invalidated, then A is also invalidated.
/// 
/// Memoization prevents redundant checks and handles cycles.
template <typename IRUnit>
class Invalidator {
public:
    Invalidator(AnalysisManager<IRUnit>& am, const PreservedAnalyses& pa)
        : am_(am), pa_(pa) {}

    /// Check if a specific analysis type is invalidated.
    /// Results are memoized to avoid redundant computation.
    /// 
    /// @tparam AnalysisT The analysis type to check
    /// @param ir The IR unit
    /// @return true if the analysis is invalidated, false if still valid
    template <typename AnalysisT>
    bool invalidate(IRUnit& ir);

    /// Check if a specific analysis key is invalidated.
    /// Used internally and for non-templated access.
    bool invalidate(AnalysisKey key, IRUnit& ir);

    /// Get the PreservedAnalyses this invalidator is checking against
    const PreservedAnalyses& preserved() const { return pa_; }

private:
    AnalysisManager<IRUnit>& am_;
    const PreservedAnalyses& pa_;
    std::unordered_map<AnalysisKey, bool> memoized_;
};

// Implementation is in analysis_manager.h due to circular dependency

}  // namespace engine::pass
