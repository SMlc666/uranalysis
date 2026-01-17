#pragma once

#include "engine/pass/analysis_manager.h"
#include "engine/pass/pass_manager.h"
#include "engine/pass/pass_instrumentation.h"

#include <functional>
#include <vector>

namespace engine::pass {

/// Builder for constructing pass pipelines with analysis registration.
///
/// The PassBuilder provides:
/// - Centralized analysis registration
/// - Pipeline construction helpers
/// - Extension point callbacks for customization
///
/// @tparam IRUnit The IR type to build pipelines for
template <typename IRUnit>
class PassBuilder {
public:
    using PipelineCallback = std::function<void(PassManager<IRUnit>&)>;

    PassBuilder() = default;

    /// Register an analysis with the analysis manager.
    template <typename AnalysisT>
    void registerAnalysis(AnalysisManager<IRUnit>& am) {
        am.template registerAnalysis<AnalysisT>();
    }

    /// Register an analysis with a custom instance.
    template <typename AnalysisT>
    void registerAnalysis(AnalysisManager<IRUnit>& am, AnalysisT analysis) {
        am.template registerAnalysis<AnalysisT>(std::move(analysis));
    }

    /// Register a callback to run at the start of any pipeline.
    void registerPipelineStartCallback(PipelineCallback cb) {
        pipeline_start_callbacks_.push_back(std::move(cb));
    }

    /// Register a callback to run at the end of any pipeline.
    void registerPipelineEndCallback(PipelineCallback cb) {
        pipeline_end_callbacks_.push_back(std::move(cb));
    }

    /// Build a new, empty pass manager with extension callbacks applied.
    PassManager<IRUnit> buildPipeline() {
        PassManager<IRUnit> pm;
        
        // Apply start callbacks
        for (const auto& cb : pipeline_start_callbacks_) {
            cb(pm);
        }
        
        return pm;
    }

    /// Finalize a pipeline by applying end callbacks.
    void finalizePipeline(PassManager<IRUnit>& pm) {
        for (const auto& cb : pipeline_end_callbacks_) {
            cb(pm);
        }
    }

    /// Set default instrumentation options for new pipelines.
    void setDefaultInstrumentationOptions(const PassInstrumentationOptions& opts) {
        default_instrumentation_opts_ = opts;
    }

    /// Get default instrumentation options.
    const PassInstrumentationOptions& defaultInstrumentationOptions() const {
        return default_instrumentation_opts_;
    }

private:
    std::vector<PipelineCallback> pipeline_start_callbacks_;
    std::vector<PipelineCallback> pipeline_end_callbacks_;
    PassInstrumentationOptions default_instrumentation_opts_;
};

}  // namespace engine::pass
