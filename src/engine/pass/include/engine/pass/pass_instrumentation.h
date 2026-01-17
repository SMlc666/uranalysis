#pragma once

#include "engine/pass/analysis_manager.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/preserved_analyses.h"

#include <chrono>
#include <functional>
#include <string>

#include <spdlog/spdlog.h>

namespace engine::pass {

/// Options for pass instrumentation (debugging/profiling).
struct PassInstrumentationOptions {
    /// Log pass names before execution
    bool log_passes = false;

    /// Measure and log execution time for each pass
    bool time_passes = false;

    /// Log when a pass modifies the IR
    bool log_changes = false;

    /// Directory to dump IR snapshots (empty = disabled)
    std::string dump_ir_dir;
};

/// Callbacks for pass execution events.
/// Used by PassManager to provide hooks for debugging and profiling.
class PassInstrumentation {
public:
    using BeforePassCallback = std::function<void(const char* pass_name, void* ir)>;
    using AfterPassCallback = std::function<void(const char* pass_name, void* ir, 
                                                  const PassResult& result, 
                                                  double elapsed_ms)>;
    using PassFailedCallback = std::function<void(const char* pass_name, 
                                                   const std::string& error)>;

    PassInstrumentation() = default;
    explicit PassInstrumentation(const PassInstrumentationOptions& opts) 
        : options_(opts) {}

    /// Set instrumentation options
    void setOptions(const PassInstrumentationOptions& opts) {
        options_ = opts;
    }

    /// Get current options
    const PassInstrumentationOptions& options() const {
        return options_;
    }

    /// Register callback for before pass execution
    void registerBeforePassCallback(BeforePassCallback cb) {
        before_callbacks_.push_back(std::move(cb));
    }

    /// Register callback for after pass execution
    void registerAfterPassCallback(AfterPassCallback cb) {
        after_callbacks_.push_back(std::move(cb));
    }

    /// Register callback for pass failures
    void registerPassFailedCallback(PassFailedCallback cb) {
        failed_callbacks_.push_back(std::move(cb));
    }

    /// Called before a pass runs
    void runBeforePass(const char* pass_name, void* ir) {
        if (options_.log_passes) {
            SPDLOG_INFO("Running pass: {}", pass_name);
        }

        for (const auto& cb : before_callbacks_) {
            cb(pass_name, ir);
        }

        if (options_.time_passes) {
            start_time_ = std::chrono::steady_clock::now();
        }
    }

    /// Called after a pass runs
    void runAfterPass(const char* pass_name, void* ir, const PassResult& result) {
        double elapsed_ms = 0.0;
        
        if (options_.time_passes) {
            auto end_time = std::chrono::steady_clock::now();
            elapsed_ms = std::chrono::duration<double, std::milli>(
                end_time - start_time_).count();
            SPDLOG_INFO("  {} took {:.3f}ms", pass_name, elapsed_ms);
        }

        if (options_.log_changes && !result.preserved.preservedAll()) {
            SPDLOG_DEBUG("  {} modified IR", pass_name);
        }

        for (const auto& cb : after_callbacks_) {
            cb(pass_name, ir, result, elapsed_ms);
        }
    }

    /// Called when a pass fails
    void runPassFailed(const char* pass_name, const std::string& error) {
        SPDLOG_ERROR("Pass {} failed: {}", pass_name, error);

        for (const auto& cb : failed_callbacks_) {
            cb(pass_name, error);
        }
    }

private:
    PassInstrumentationOptions options_;
    std::chrono::steady_clock::time_point start_time_;
    
    std::vector<BeforePassCallback> before_callbacks_;
    std::vector<AfterPassCallback> after_callbacks_;
    std::vector<PassFailedCallback> failed_callbacks_;
};

}  // namespace engine::pass
