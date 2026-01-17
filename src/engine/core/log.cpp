#include "engine/log.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

namespace engine {
namespace log {

namespace {
    bool g_ir_debug_enabled = false;
    bool g_pass_trace_enabled = false;
}

void init() {
    // By default, spdlog creates a singleton logger.
    // We ensure it's initialized with a default pattern.
    spdlog::set_pattern("%^[%H:%M:%S.%e] [%l] %v%$");
    spdlog::set_level(spdlog::level::info);
}

void add_sink(std::shared_ptr<spdlog::sinks::sink> sink) {
    auto logger = spdlog::default_logger();
    if (logger) {
        logger->sinks().push_back(sink);
    }
}

void set_level(spdlog::level::level_enum level) {
    spdlog::set_level(level);
}

void enable_ir_debug(bool enable) {
    g_ir_debug_enabled = enable;
    if (enable) {
        spdlog::set_level(spdlog::level::debug);
    }
}

bool ir_debug_enabled() {
    return g_ir_debug_enabled;
}

void enable_pass_trace(bool enable) {
    g_pass_trace_enabled = enable;
    if (enable) {
        spdlog::set_level(spdlog::level::trace);
    }
}

bool pass_trace_enabled() {
    return g_pass_trace_enabled;
}

} // namespace log
} // namespace engine
