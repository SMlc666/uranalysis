#pragma once

#include <vector>
#include <mutex>
#include <string>

// Define SPDLOG_ACTIVE_LEVEL to ensure we can use macros if needed
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include <spdlog/sinks/base_sink.h>

namespace client {

struct LogEntry {
    spdlog::level::level_enum level;
    std::string message;
};

/**
 * A sink that stores logs in a vector for ImGui display.
 * Thread-safe using spdlog's mutex mechanism.
 */
template<typename Mutex>
class ImGuiLogSink : public spdlog::sinks::base_sink<Mutex> {
public:
    explicit ImGuiLogSink(size_t max_items = 1000) : max_items_(max_items) {
        items_.reserve(max_items);
    }

    // Returns a copy of items to avoid locking issues during rendering
    // Or we can expose a way to lock and iterate. 
    // For simplicity in UI, we'll provide a thread-safe copy or access with a callback.
    // Copying is safer for immediate mode GUI to avoid holding locks during render.
    std::vector<LogEntry> items_copy() {
        std::lock_guard<Mutex> lock(spdlog::sinks::base_sink<Mutex>::mutex_);
        return items_;
    }

    void clear() { 
        std::lock_guard<Mutex> lock(spdlog::sinks::base_sink<Mutex>::mutex_);
        items_.clear(); 
    }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        // Use the formatter to get the full string (timestamp, thread id, etc)
        spdlog::memory_buf_t formatted;
        spdlog::sinks::base_sink<Mutex>::formatter_->format(msg, formatted);
        
        std::string text = fmt::to_string(formatted);
        // Remove trailing newline
        if (!text.empty() && text.back() == '\n') {
            text.pop_back();
        }

        LogEntry entry;
        entry.level = msg.level;
        entry.message = std::move(text);

        if (items_.size() >= max_items_) {
            items_.erase(items_.begin());
        }
        items_.push_back(std::move(entry));
    }

    void flush_() override {}

private:
    std::vector<LogEntry> items_;
    size_t max_items_;
};

using ImGuiLogSinkMt = ImGuiLogSink<std::mutex>;

} // namespace client
