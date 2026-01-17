#pragma once

/// @file log_channels.h
/// @brief Channel-based logging system for filtering debug output by module.
///
/// Allows enabling/disabling log output for specific subsystems:
/// - llir: LLIR lifting and optimization
/// - mlil: MLIR lifting and optimization  
/// - hlil: HLIR structuring and optimization
/// - pass: Pass execution and instrumentation
/// - decompiler: Decompilation pipeline
/// - loader: Binary loading
/// - analysis: Function discovery and analysis

#include <string>
#include <unordered_map>

#include <spdlog/spdlog.h>

namespace engine::log {

/// Available log channels
enum class Channel {
    kLlir,        ///< LLIR subsystem
    kMlil,        ///< MLIR subsystem
    kHlil,        ///< HLIR subsystem
    kPass,        ///< Pass execution
    kDecompiler,  ///< Decompiler pipeline
    kLoader,      ///< Binary loading
    kAnalysis,    ///< Function analysis
    kAll,         ///< All channels (for global setting)
};

/// Get channel name as string
const char* channel_name(Channel ch);

/// Parse channel from string (case-insensitive)
/// Returns false if channel name is unknown
bool parse_channel(const std::string& name, Channel& out);

/// Set log level for a specific channel
void set_channel_level(Channel ch, spdlog::level::level_enum level);

/// Set log level for a channel by name
/// Returns false if channel name is unknown
bool set_channel_level(const std::string& channel_name, spdlog::level::level_enum level);

/// Get current log level for a channel
spdlog::level::level_enum get_channel_level(Channel ch);

/// Check if a channel should log at the given level
bool should_log(Channel ch, spdlog::level::level_enum level);

/// Parse level from string (trace, debug, info, warn, error, off)
bool parse_level(const std::string& name, spdlog::level::level_enum& out);

/// Get level name as string
const char* level_name(spdlog::level::level_enum level);

// ============================================================================
// Channel-aware logging macros
// ============================================================================

/// Log to a specific channel at various levels
/// Usage: LOG_CH_DEBUG(Channel::kLlir, "Processing block 0x{:x}", addr);

#define LOG_CH_TRACE(ch, ...) \
    do { if (::engine::log::should_log(ch, spdlog::level::trace)) { \
        SPDLOG_TRACE("[{}] {}", ::engine::log::channel_name(ch), fmt::format(__VA_ARGS__)); \
    } } while(0)

#define LOG_CH_DEBUG(ch, ...) \
    do { if (::engine::log::should_log(ch, spdlog::level::debug)) { \
        SPDLOG_DEBUG("[{}] {}", ::engine::log::channel_name(ch), fmt::format(__VA_ARGS__)); \
    } } while(0)

#define LOG_CH_INFO(ch, ...) \
    do { if (::engine::log::should_log(ch, spdlog::level::info)) { \
        SPDLOG_INFO("[{}] {}", ::engine::log::channel_name(ch), fmt::format(__VA_ARGS__)); \
    } } while(0)

#define LOG_CH_WARN(ch, ...) \
    do { if (::engine::log::should_log(ch, spdlog::level::warn)) { \
        SPDLOG_WARN("[{}] {}", ::engine::log::channel_name(ch), fmt::format(__VA_ARGS__)); \
    } } while(0)

#define LOG_CH_ERROR(ch, ...) \
    do { if (::engine::log::should_log(ch, spdlog::level::err)) { \
        SPDLOG_ERROR("[{}] {}", ::engine::log::channel_name(ch), fmt::format(__VA_ARGS__)); \
    } } while(0)

// Convenience aliases for common channels
#define LOG_LLIR_DEBUG(...) LOG_CH_DEBUG(::engine::log::Channel::kLlir, __VA_ARGS__)
#define LOG_MLIL_DEBUG(...) LOG_CH_DEBUG(::engine::log::Channel::kMlil, __VA_ARGS__)
#define LOG_HLIL_DEBUG(...) LOG_CH_DEBUG(::engine::log::Channel::kHlil, __VA_ARGS__)
#define LOG_PASS_DEBUG(...) LOG_CH_DEBUG(::engine::log::Channel::kPass, __VA_ARGS__)
#define LOG_DECOMPILER_DEBUG(...) LOG_CH_DEBUG(::engine::log::Channel::kDecompiler, __VA_ARGS__)

#define LOG_LLIR_TRACE(...) LOG_CH_TRACE(::engine::log::Channel::kLlir, __VA_ARGS__)
#define LOG_MLIL_TRACE(...) LOG_CH_TRACE(::engine::log::Channel::kMlil, __VA_ARGS__)
#define LOG_HLIL_TRACE(...) LOG_CH_TRACE(::engine::log::Channel::kHlil, __VA_ARGS__)
#define LOG_PASS_TRACE(...) LOG_CH_TRACE(::engine::log::Channel::kPass, __VA_ARGS__)

}  // namespace engine::log
