#pragma once

#include "engine/pass/analysis.h"
#include "engine/pass/invalidator.h"
#include "engine/pass/preserved_analyses.h"

#include <any>
#include <cassert>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

namespace engine::pass {

/// Manages analysis computation, caching, and invalidation for a specific IR unit type.
///
/// The AnalysisManager is responsible for:
/// - Lazy computation of analyses (only when requested)
/// - Caching of analysis results
/// - Invalidation of analyses when the IR changes
/// - Transitive invalidation through dependencies
///
/// @tparam IRUnit The IR type this manager handles (e.g., llir::Function)
template <typename IRUnit>
class AnalysisManager {
public:
    AnalysisManager() = default;
    ~AnalysisManager() = default;

    // Non-copyable, movable
    AnalysisManager(const AnalysisManager&) = delete;
    AnalysisManager& operator=(const AnalysisManager&) = delete;
    AnalysisManager(AnalysisManager&&) = default;
    AnalysisManager& operator=(AnalysisManager&&) = default;

    /// Register an analysis type with this manager.
    /// Must be called before getResult() can be used for this analysis.
    template <typename AnalysisT>
    void registerAnalysis() {
        auto key = AnalysisT::ID();
        if (providers_.count(key) == 0) {
            providers_[key] = std::make_unique<AnalysisModel<AnalysisT, IRUnit>>();
            SPDLOG_DEBUG("Registered analysis: {}", AnalysisT::name());
        }
    }

    /// Register an analysis with a custom instance.
    template <typename AnalysisT>
    void registerAnalysis(AnalysisT analysis) {
        auto key = AnalysisT::ID();
        providers_[key] = std::make_unique<AnalysisModel<AnalysisT, IRUnit>>(std::move(analysis));
        SPDLOG_DEBUG("Registered analysis: {}", AnalysisT::name());
    }

    /// Get the result of an analysis, computing it if necessary.
    /// The result is cached and returned by reference.
    ///
    /// @tparam AnalysisT The analysis type to get results for
    /// @param ir The IR unit to analyze
    /// @return Reference to the analysis result
    template <typename AnalysisT>
    typename AnalysisT::Result& getResult(IRUnit& ir) {
        auto key = AnalysisT::ID();
        
        // Check cache first
        auto cache_it = cache_.find(key);
        if (cache_it != cache_.end()) {
            SPDLOG_TRACE("Analysis cache hit: {}", AnalysisT::name());
            return *std::any_cast<typename AnalysisT::Result>(&cache_it->second);
        }

        // Find provider
        auto provider_it = providers_.find(key);
        if (provider_it == providers_.end()) {
            // Auto-register if not registered
            registerAnalysis<AnalysisT>();
            provider_it = providers_.find(key);
        }

        // Compute and cache
        SPDLOG_DEBUG("Computing analysis: {}", AnalysisT::name());
        cache_[key] = provider_it->second->run(ir, *this);
        
        return *std::any_cast<typename AnalysisT::Result>(&cache_[key]);
    }

    /// Get a cached result without computing.
    /// Returns nullptr if the analysis has not been computed.
    template <typename AnalysisT>
    typename AnalysisT::Result* getCachedResult(IRUnit& /*ir*/) {
        auto key = AnalysisT::ID();
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return nullptr;
        }
        return std::any_cast<typename AnalysisT::Result>(&it->second);
    }

    /// Get a cached result (const version).
    template <typename AnalysisT>
    const typename AnalysisT::Result* getCachedResult(const IRUnit& /*ir*/) const {
        auto key = AnalysisT::ID();
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return nullptr;
        }
        return std::any_cast<typename AnalysisT::Result>(&it->second);
    }

    /// Invalidate analyses based on what a pass preserved.
    /// Analyses not in the preserved set will be removed from the cache.
    void invalidate(IRUnit& ir, const PreservedAnalyses& pa) {
        if (pa.preservedAll()) {
            // Nothing to invalidate
            return;
        }

        Invalidator<IRUnit> inv(*this, pa);
        std::vector<AnalysisKey> to_remove;

        for (auto& [key, result] : cache_) {
            auto provider_it = providers_.find(key);
            if (provider_it == providers_.end()) {
                continue;
            }

            if (provider_it->second->invalidate(ir, pa, inv, result)) {
                SPDLOG_DEBUG("Invalidating analysis: {}", provider_it->second->name());
                to_remove.push_back(key);
            }
        }

        for (auto key : to_remove) {
            cache_.erase(key);
        }
    }

    /// Clear all cached results.
    void clear() {
        SPDLOG_DEBUG("Clearing all cached analyses");
        cache_.clear();
    }

    /// Clear a specific analysis from the cache.
    template <typename AnalysisT>
    void clear() {
        auto key = AnalysisT::ID();
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            SPDLOG_DEBUG("Clearing analysis: {}", AnalysisT::name());
            cache_.erase(it);
        }
    }

    /// Check if an analysis is registered.
    template <typename AnalysisT>
    bool isRegistered() const {
        return providers_.count(AnalysisT::ID()) > 0;
    }

    /// Check if an analysis result is cached.
    template <typename AnalysisT>
    bool isCached() const {
        return cache_.count(AnalysisT::ID()) > 0;
    }

    /// Get provider for invalidation checks (internal use)
    AnalysisConcept<IRUnit>* getProvider(AnalysisKey key) {
        auto it = providers_.find(key);
        return it != providers_.end() ? it->second.get() : nullptr;
    }

    /// Get cached result by key (internal use)
    std::any* getCachedByKey(AnalysisKey key) {
        auto it = cache_.find(key);
        return it != cache_.end() ? &it->second : nullptr;
    }

private:
    /// Registered analysis providers
    std::unordered_map<AnalysisKey, std::unique_ptr<AnalysisConcept<IRUnit>>> providers_;
    
    /// Cached analysis results
    std::unordered_map<AnalysisKey, std::any> cache_;
};

// ============================================================================
// Invalidator implementation (here due to circular dependency with AnalysisManager)
// ============================================================================

template <typename IRUnit>
template <typename AnalysisT>
bool Invalidator<IRUnit>::invalidate(IRUnit& ir) {
    return invalidate(AnalysisT::ID(), ir);
}

template <typename IRUnit>
bool Invalidator<IRUnit>::invalidate(AnalysisKey key, IRUnit& ir) {
    // Check memoization cache
    auto it = memoized_.find(key);
    if (it != memoized_.end()) {
        return it->second;
    }

    // Check if explicitly preserved
    if (pa_.preserved(key)) {
        memoized_[key] = false;
        return false;
    }

    // Get the provider and cached result
    auto* provider = am_.getProvider(key);
    auto* result = am_.getCachedByKey(key);
    
    bool invalidated = true;
    if (provider && result) {
        // Let the analysis decide
        invalidated = provider->invalidate(ir, pa_, *this, *result);
    } else if (pa_.preservedAll()) {
        invalidated = false;
    }

    memoized_[key] = invalidated;
    return invalidated;
}

}  // namespace engine::pass
