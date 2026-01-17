#pragma once

#include <memory>
#include <string>

// We use spdlog in header-only mode to avoid ABI issues
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

namespace engine {
namespace log {

// Initialize the logging system
void init();

// Add a sink to the engine logger
void add_sink(std::shared_ptr<spdlog::sinks::sink> sink);

// Set the global log level
void set_level(spdlog::level::level_enum level);

// Core logging wrappers using spdlog's registry
// We wrap these to ensure consistent usage across the engine
template<typename... Args>
inline void info(fmt::format_string<Args...> fmt, Args&&... args) {
    spdlog::info(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void warn(fmt::format_string<Args...> fmt, Args&&... args) {
    spdlog::warn(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void error(fmt::format_string<Args...> fmt, Args&&... args) {
    spdlog::error(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void debug(fmt::format_string<Args...> fmt, Args&&... args) {
    spdlog::debug(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void trace(fmt::format_string<Args...> fmt, Args&&... args) {
    spdlog::trace(fmt, std::forward<Args>(args)...);
}

} // namespace log
} // namespace engine
