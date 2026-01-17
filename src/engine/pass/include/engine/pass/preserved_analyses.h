#pragma once

#include <unordered_set>

namespace engine::pass {

/// Opaque key type for identifying analyses
using AnalysisKey = void*;

/// Opaque key type for identifying analysis sets (e.g., CFGAnalyses, SSAAnalyses)
using AnalysisSetKey = void*;

/// Tracks which analyses remain valid after a pass execution.
///
/// Similar to LLVM's PreservedAnalyses, this class allows passes to
/// communicate which analyses they preserve, enabling the AnalysisManager
/// to avoid recomputation of still-valid analyses.
class PreservedAnalyses {
public:
    /// Create a PreservedAnalyses that preserves all analyses.
    /// Use when a pass makes no modifications to the IR.
    static PreservedAnalyses all() {
        PreservedAnalyses pa;
        pa.preserve_all_ = true;
        return pa;
    }

    /// Create a PreservedAnalyses that preserves no analyses.
    /// Use when a pass makes significant modifications.
    static PreservedAnalyses none() {
        return PreservedAnalyses{};
    }

    /// Mark a specific analysis as preserved.
    /// @tparam AnalysisT The analysis type (must have static ID() method)
    template <typename AnalysisT>
    void preserve() {
        if (!preserve_all_) {
            preserved_.insert(AnalysisT::ID());
        }
    }

    /// Mark a set of analyses as preserved.
    /// @tparam AnalysisSetT The analysis set type (must have static ID() method)
    template <typename AnalysisSetT>
    void preserveSet() {
        if (!preserve_all_) {
            preserved_sets_.insert(AnalysisSetT::ID());
        }
    }

    /// Check if a specific analysis is preserved.
    template <typename AnalysisT>
    bool preserved() const {
        if (preserve_all_) {
            return true;
        }
        return preserved_.count(AnalysisT::ID()) > 0;
    }

    /// Check if an analysis set is preserved.
    template <typename AnalysisSetT>
    bool preservedSet() const {
        if (preserve_all_) {
            return true;
        }
        return preserved_sets_.count(AnalysisSetT::ID()) > 0;
    }

    /// Check if a specific analysis key is preserved.
    bool preserved(AnalysisKey key) const {
        if (preserve_all_) {
            return true;
        }
        return preserved_.count(key) > 0;
    }

    /// Check if an analysis set key is preserved.
    bool preservedSet(AnalysisSetKey key) const {
        if (preserve_all_) {
            return true;
        }
        return preserved_sets_.count(key) > 0;
    }

    /// Check if all analyses are preserved.
    bool preservedAll() const {
        return preserve_all_;
    }

    /// Intersect with another PreservedAnalyses.
    /// After this call, only analyses preserved in both are preserved.
    void intersect(const PreservedAnalyses& other) {
        if (other.preserve_all_) {
            // Other preserves all, keep our state
            return;
        }
        if (preserve_all_) {
            // We preserve all, take other's state
            *this = other;
            return;
        }
        // Intersect the sets
        std::unordered_set<AnalysisKey> new_preserved;
        for (auto key : preserved_) {
            if (other.preserved_.count(key) > 0) {
                new_preserved.insert(key);
            }
        }
        preserved_ = std::move(new_preserved);

        std::unordered_set<AnalysisSetKey> new_sets;
        for (auto key : preserved_sets_) {
            if (other.preserved_sets_.count(key) > 0) {
                new_sets.insert(key);
            }
        }
        preserved_sets_ = std::move(new_sets);
    }

    /// Abandon preservation of a specific analysis.
    template <typename AnalysisT>
    void abandon() {
        preserve_all_ = false;
        preserved_.erase(AnalysisT::ID());
    }

    /// Abandon preservation of an analysis set.
    template <typename AnalysisSetT>
    void abandonSet() {
        preserve_all_ = false;
        preserved_sets_.erase(AnalysisSetT::ID());
    }

private:
    bool preserve_all_ = false;
    std::unordered_set<AnalysisKey> preserved_;
    std::unordered_set<AnalysisSetKey> preserved_sets_;
};

// ============================================================================
// Common Analysis Sets
// ============================================================================

/// Analysis set for CFG-related analyses (dominators, post-dominators, loops)
struct CFGAnalyses {
    static AnalysisSetKey ID() {
        static char id;
        return &id;
    }
};

/// Analysis set for SSA-related analyses (def-use chains, phi nodes)
struct SSAAnalyses {
    static AnalysisSetKey ID() {
        static char id;
        return &id;
    }
};

/// Analysis set for all analyses (used for checking if nothing is invalidated)
struct AllAnalyses {
    static AnalysisSetKey ID() {
        static char id;
        return &id;
    }
};

}  // namespace engine::pass
