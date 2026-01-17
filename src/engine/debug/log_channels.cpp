#include "engine/debug/log_channels.h"

#include <algorithm>
#include <cctype>
#include <mutex>

namespace engine::log {

namespace {

// Per-channel log levels
struct ChannelState {
    std::unordered_map<Channel, spdlog::level::level_enum> levels;
    std::mutex mutex;
    
    ChannelState() {
        // Default all channels to info level
        levels[Channel::kLlir] = spdlog::level::info;
        levels[Channel::kMlil] = spdlog::level::info;
        levels[Channel::kHlil] = spdlog::level::info;
        levels[Channel::kPass] = spdlog::level::info;
        levels[Channel::kDecompiler] = spdlog::level::info;
        levels[Channel::kLoader] = spdlog::level::info;
        levels[Channel::kAnalysis] = spdlog::level::info;
        levels[Channel::kAll] = spdlog::level::info;
    }
};

ChannelState& state() {
    static ChannelState s;
    return s;
}

std::string to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

}  // namespace

const char* channel_name(Channel ch) {
    switch (ch) {
        case Channel::kLlir: return "llir";
        case Channel::kMlil: return "mlil";
        case Channel::kHlil: return "hlil";
        case Channel::kPass: return "pass";
        case Channel::kDecompiler: return "decompiler";
        case Channel::kLoader: return "loader";
        case Channel::kAnalysis: return "analysis";
        case Channel::kAll: return "all";
    }
    return "unknown";
}

bool parse_channel(const std::string& name, Channel& out) {
    std::string lower = to_lower(name);
    
    if (lower == "llir") { out = Channel::kLlir; return true; }
    if (lower == "mlil") { out = Channel::kMlil; return true; }
    if (lower == "hlil") { out = Channel::kHlil; return true; }
    if (lower == "pass") { out = Channel::kPass; return true; }
    if (lower == "decompiler") { out = Channel::kDecompiler; return true; }
    if (lower == "loader") { out = Channel::kLoader; return true; }
    if (lower == "analysis") { out = Channel::kAnalysis; return true; }
    if (lower == "all") { out = Channel::kAll; return true; }
    
    return false;
}

void set_channel_level(Channel ch, spdlog::level::level_enum level) {
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    
    if (ch == Channel::kAll) {
        // Set all channels
        for (auto& [channel, lvl] : s.levels) {
            lvl = level;
        }
    } else {
        s.levels[ch] = level;
    }
    
    // Also update global spdlog level if setting to a more verbose level
    auto current_global = spdlog::get_level();
    if (level < current_global) {
        spdlog::set_level(level);
    }
}

bool set_channel_level(const std::string& channel_name, spdlog::level::level_enum level) {
    Channel ch;
    if (!parse_channel(channel_name, ch)) {
        return false;
    }
    set_channel_level(ch, level);
    return true;
}

spdlog::level::level_enum get_channel_level(Channel ch) {
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    
    auto it = s.levels.find(ch);
    if (it != s.levels.end()) {
        return it->second;
    }
    return spdlog::level::info;
}

bool should_log(Channel ch, spdlog::level::level_enum level) {
    // First check global spdlog level
    if (level < spdlog::get_level()) {
        return false;
    }
    
    // Then check channel-specific level
    return level >= get_channel_level(ch);
}

bool parse_level(const std::string& name, spdlog::level::level_enum& out) {
    std::string lower = to_lower(name);
    
    if (lower == "trace") { out = spdlog::level::trace; return true; }
    if (lower == "debug") { out = spdlog::level::debug; return true; }
    if (lower == "info") { out = spdlog::level::info; return true; }
    if (lower == "warn" || lower == "warning") { out = spdlog::level::warn; return true; }
    if (lower == "error" || lower == "err") { out = spdlog::level::err; return true; }
    if (lower == "off" || lower == "none") { out = spdlog::level::off; return true; }
    
    return false;
}

const char* level_name(spdlog::level::level_enum level) {
    switch (level) {
        case spdlog::level::trace: return "trace";
        case spdlog::level::debug: return "debug";
        case spdlog::level::info: return "info";
        case spdlog::level::warn: return "warn";
        case spdlog::level::err: return "error";
        case spdlog::level::critical: return "critical";
        case spdlog::level::off: return "off";
        default: return "unknown";
    }
}

}  // namespace engine::log
