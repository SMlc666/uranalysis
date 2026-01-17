#pragma once

#include "engine/pass/analysis_manager.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/preserved_analyses.h"

#include <chrono>
#include <functional>
#include <string>
#include <ostream>

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

    // === NEW: Enhanced debugging options ===

    /// Dump IR before each pass runs (to log)
    bool dump_before = false;

    /// Dump IR after each pass runs (to log)
    bool dump_after = false;

    /// Only show diff between before/after (requires dump_before && dump_after)
    bool diff_only = false;

    /// Log statement count changes (deleted/added)
    bool log_stats = false;

    /// Filter: only instrument passes matching this name (empty = all)
    std::string filter_pass;

    /// Filter: only instrument when processing this function address (0 = all)
    std::uint64_t filter_func_addr = 0;

    /// Output stream for IR dumps (nullptr = use spdlog)
    std::ostream* dump_stream = nullptr;
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

    /// IR dump callback: takes pass name, IR pointer, returns string representation
    using IRDumpCallback = std::function<std::string(void* ir)>;

    /// IR stats callback: takes IR pointer, returns statement count
    using IRStatsCallback = std::function<std::size_t(void* ir)>;

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

    /// Get mutable options
    PassInstrumentationOptions& options() {
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

    /// Register IR dump callback for debugging
    void registerIRDumpCallback(IRDumpCallback cb) {
        ir_dump_callback_ = std::move(cb);
    }

    /// Register IR stats callback for counting
    void registerIRStatsCallback(IRStatsCallback cb) {
        ir_stats_callback_ = std::move(cb);
    }

    /// Check if a pass should be instrumented (based on filters)
    bool shouldInstrument(const char* pass_name) const {
        if (!options_.filter_pass.empty()) {
            if (options_.filter_pass != pass_name) {
                return false;
            }
        }
        return true;
    }

    /// Called before a pass runs
    void runBeforePass(const char* pass_name, void* ir) {
        if (!shouldInstrument(pass_name)) {
            return;
        }

        if (options_.log_passes) {
            SPDLOG_INFO("[Pass] {} starting", pass_name);
        }

        // Capture IR state before pass for diff/dump
        if ((options_.dump_before || options_.diff_only) && ir_dump_callback_) {
            ir_before_ = ir_dump_callback_(ir);
            if (options_.dump_before && !options_.diff_only) {
                outputDump("[Before {}]\n{}", pass_name, ir_before_);
            }
        }

        // Capture stats before
        if (options_.log_stats && ir_stats_callback_) {
            stats_before_ = ir_stats_callback_(ir);
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
        if (!shouldInstrument(pass_name)) {
            return;
        }

        double elapsed_ms = 0.0;
        
        if (options_.time_passes) {
            auto end_time = std::chrono::steady_clock::now();
            elapsed_ms = std::chrono::duration<double, std::milli>(
                end_time - start_time_).count();
        }

        bool changed = !result.preserved.preservedAll();

        // Log stats
        if (options_.log_stats && ir_stats_callback_) {
            std::size_t stats_after = ir_stats_callback_(ir);
            std::int64_t delta = static_cast<std::int64_t>(stats_after) - 
                                 static_cast<std::int64_t>(stats_before_);
            if (delta != 0 || changed) {
                SPDLOG_INFO("[Pass] {}: {} stmts -> {} stmts ({:+})", 
                           pass_name, stats_before_, stats_after, delta);
            }
        }

        // Dump IR after or show diff
        if ((options_.dump_after || options_.diff_only) && ir_dump_callback_) {
            std::string ir_after = ir_dump_callback_(ir);
            
            if (options_.diff_only && changed) {
                outputDiff(pass_name, ir_before_, ir_after);
            } else if (options_.dump_after && !options_.diff_only) {
                outputDump("[After {}]\n{}", pass_name, ir_after);
            }
        }

        // Log timing and changes
        if (options_.time_passes) {
            SPDLOG_INFO("[Pass] {} completed in {:.3f}ms{}", 
                       pass_name, elapsed_ms, 
                       changed ? " (modified)" : "");
        } else if (options_.log_changes && changed) {
            SPDLOG_DEBUG("[Pass] {} modified IR", pass_name);
        }

        for (const auto& cb : after_callbacks_) {
            cb(pass_name, ir, result, elapsed_ms);
        }

        // Clear captured state
        ir_before_.clear();
        stats_before_ = 0;
    }

    /// Called when a pass fails
    void runPassFailed(const char* pass_name, const std::string& error) {
        SPDLOG_ERROR("[Pass] {} FAILED: {}", pass_name, error);

        for (const auto& cb : failed_callbacks_) {
            cb(pass_name, error);
        }
    }

private:
    template<typename... Args>
    void outputDump(const char* fmt, Args&&... args) {
        std::string msg = fmt::format(fmt::runtime(fmt), std::forward<Args>(args)...);
        if (options_.dump_stream) {
            *options_.dump_stream << msg << "\n";
        } else {
            SPDLOG_DEBUG("{}", msg);
        }
    }

    void outputDiff(const char* pass_name, const std::string& before, const std::string& after) {
        if (before == after) {
            return;
        }

        std::string diff_output;
        diff_output += fmt::format("[Diff] {} changes:\n", pass_name);

        // Simple line-by-line diff
        std::vector<std::string> before_lines, after_lines;
        splitLines(before, before_lines);
        splitLines(after, after_lines);

        // Find removed lines (in before but not in after)
        for (const auto& line : before_lines) {
            bool found = false;
            for (const auto& aline : after_lines) {
                if (line == aline) {
                    found = true;
                    break;
                }
            }
            if (!found && !line.empty()) {
                diff_output += fmt::format("  - {}\n", line);
            }
        }

        // Find added lines (in after but not in before)
        for (const auto& line : after_lines) {
            bool found = false;
            for (const auto& bline : before_lines) {
                if (line == bline) {
                    found = true;
                    break;
                }
            }
            if (!found && !line.empty()) {
                diff_output += fmt::format("  + {}\n", line);
            }
        }

        if (options_.dump_stream) {
            *options_.dump_stream << diff_output;
        } else {
            SPDLOG_DEBUG("{}", diff_output);
        }
    }

    static void splitLines(const std::string& str, std::vector<std::string>& lines) {
        std::size_t start = 0;
        std::size_t end = str.find('\n');
        while (end != std::string::npos) {
            lines.push_back(str.substr(start, end - start));
            start = end + 1;
            end = str.find('\n', start);
        }
        if (start < str.size()) {
            lines.push_back(str.substr(start));
        }
    }

    PassInstrumentationOptions options_;
    std::chrono::steady_clock::time_point start_time_;
    
    std::vector<BeforePassCallback> before_callbacks_;
    std::vector<AfterPassCallback> after_callbacks_;
    std::vector<PassFailedCallback> failed_callbacks_;

    // IR dump/stats callbacks
    IRDumpCallback ir_dump_callback_;
    IRStatsCallback ir_stats_callback_;

    // Captured state for diff
    std::string ir_before_;
    std::size_t stats_before_ = 0;
};

}  // namespace engine::pass
