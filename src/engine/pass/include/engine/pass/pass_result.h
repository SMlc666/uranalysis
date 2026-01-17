#pragma once

#include "engine/pass/preserved_analyses.h"

#include <string>
#include <utility>

namespace engine::pass {

/// Result type for pass execution.
/// Combines PreservedAnalyses information with error handling.
struct PassResult {
    PreservedAnalyses preserved;
    std::string error;

    /// Check if the pass succeeded (no error)
    bool success() const { return error.empty(); }

    /// Check if the pass failed
    bool failed() const { return !error.empty(); }

    /// Create a successful result that preserves all analyses
    static PassResult successAll() {
        return PassResult{PreservedAnalyses::all(), {}};
    }

    /// Create a successful result that preserves no analyses
    static PassResult successNone() {
        return PassResult{PreservedAnalyses::none(), {}};
    }

    /// Create a successful result with specific preserved analyses
    static PassResult success(PreservedAnalyses pa) {
        return PassResult{std::move(pa), {}};
    }

    /// Create a failed result with error message
    static PassResult failure(std::string err) {
        return PassResult{PreservedAnalyses::none(), std::move(err)};
    }
};

}  // namespace engine::pass
