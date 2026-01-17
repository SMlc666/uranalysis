#pragma once

#include "engine/pass/preserved_analyses.h"

#include <any>
#include <functional>
#include <memory>
#include <typeinfo>
#include <unordered_map>

namespace engine::pass {

// Forward declarations
template <typename IRUnit>
class AnalysisManager;

template <typename IRUnit>
class Invalidator;

/// Base class for analysis results that need custom invalidation logic.
/// Analysis results can optionally inherit from this to implement
/// transitive dependency tracking.
template <typename IRUnit>
struct AnalysisResultBase {
    virtual ~AnalysisResultBase() = default;

    /// Determine if this analysis result should be invalidated.
    /// 
    /// @param ir The IR unit this analysis was computed for
    /// @param pa What analyses are preserved by the pass that just ran
    /// @param inv Invalidator to check transitive dependencies
    /// @return true if this result should be invalidated, false to keep it
    virtual bool invalidate(IRUnit& ir, 
                           const PreservedAnalyses& pa,
                           Invalidator<IRUnit>& inv) {
        // Default: invalidate unless explicitly preserved
        return !pa.preservedAll();
    }
};

/// Concept interface for type-erased analysis storage.
/// This allows AnalysisManager to store analyses of different types.
template <typename IRUnit>
class AnalysisConcept {
public:
    virtual ~AnalysisConcept() = default;

    /// Get the analysis key for this analysis type
    virtual AnalysisKey key() const = 0;

    /// Get the name of this analysis (for debugging)
    virtual const char* name() const = 0;

    /// Run the analysis and return a type-erased result
    virtual std::any run(IRUnit& ir, AnalysisManager<IRUnit>& am) = 0;

    /// Check if a cached result should be invalidated
    virtual bool invalidate(IRUnit& ir,
                           const PreservedAnalyses& pa,
                           Invalidator<IRUnit>& inv,
                           std::any& result) = 0;
};

/// Concrete implementation of AnalysisConcept for a specific analysis type.
template <typename AnalysisT, typename IRUnit>
class AnalysisModel : public AnalysisConcept<IRUnit> {
public:
    using Result = typename AnalysisT::Result;

    AnalysisModel() : analysis_() {}
    explicit AnalysisModel(AnalysisT analysis) : analysis_(std::move(analysis)) {}

    AnalysisKey key() const override {
        return AnalysisT::ID();
    }

    const char* name() const override {
        return AnalysisT::name();
    }

    std::any run(IRUnit& ir, AnalysisManager<IRUnit>& am) override {
        return std::any(analysis_.run(ir, am));
    }

    bool invalidate(IRUnit& ir,
                   const PreservedAnalyses& pa,
                   Invalidator<IRUnit>& inv,
                   std::any& result) override {
        // Check if explicitly preserved
        if (pa.preserved<AnalysisT>()) {
            return false;
        }

        // Try to use the result's custom invalidation if it has one
        if constexpr (requires(Result& r) { r.invalidate(ir, pa, inv); }) {
            auto* typed_result = std::any_cast<Result>(&result);
            if (typed_result) {
                return typed_result->invalidate(ir, pa, inv);
            }
        }

        // Default: invalidate unless all analyses are preserved
        return !pa.preservedAll();
    }

private:
    AnalysisT analysis_;
};

/// CRTP mixin to provide static ID() method for analyses.
/// 
/// Usage:
/// @code
/// struct MyAnalysis : public AnalysisInfoMixin<MyAnalysis> {
///     using Result = MyResult;
///     static const char* name() { return "MyAnalysis"; }
///     Result run(IRUnit& ir, AnalysisManager<IRUnit>& am);
/// };
/// @endcode
template <typename DerivedT>
struct AnalysisInfoMixin {
    static AnalysisKey ID() {
        static char id;
        return &id;
    }
};

}  // namespace engine::pass
