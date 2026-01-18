#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// Platform-specific export macros
#if defined(_WIN32) || defined(_WIN64)
    #define URANAYZLE_PLUGIN_EXPORT __declspec(dllexport)
    #define URANAYZLE_PLUGIN_IMPORT __declspec(dllimport)
#else
    #define URANAYZLE_PLUGIN_EXPORT __attribute__((visibility("default")))
    #define URANAYZLE_PLUGIN_IMPORT
#endif

// Use this macro when defining plugin entry points
#define URANAYZLE_PLUGIN_API extern "C" URANAYZLE_PLUGIN_EXPORT

namespace engine::plugin {

/// Plugin API version for compatibility checking
struct PluginApiVersion {
    std::uint16_t major;
    std::uint16_t minor;
    std::uint16_t patch;

    bool is_compatible_with(const PluginApiVersion& host) const {
        // Major version must match, minor can be lower or equal
        return major == host.major && minor <= host.minor;
    }
};

/// Current plugin API version
inline constexpr PluginApiVersion kCurrentApiVersion = {1, 0, 0};

/// Result codes for plugin operations
enum class Result : std::int32_t {
    Ok = 0,
    Error = -1,
    InvalidArgument = -2,
    NotFound = -3,
    AlreadyExists = -4,
    NotSupported = -5,
    NotInitialized = -6,
    OutOfMemory = -7,
};

/// Plugin metadata structure (ABI-safe, C-compatible layout)
struct PluginMetadata {
    const char* name;
    const char* version;
    const char* author;
    const char* description;
    PluginApiVersion api_version;
};

/// Log levels for plugin logging
enum class LogLevel : std::int32_t {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
};

/// ABI-safe string view (non-owning)
struct StringView {
    const char* data;
    std::size_t size;

    StringView() : data(nullptr), size(0) {}
    StringView(const char* s) : data(s), size(s ? std::strlen(s) : 0) {}
    StringView(const char* s, std::size_t len) : data(s), size(len) {}
};

/// ABI-safe span for byte arrays (non-owning)
struct ByteSpan {
    const std::uint8_t* data;
    std::size_t size;

    ByteSpan() : data(nullptr), size(0) {}
    ByteSpan(const std::uint8_t* d, std::size_t s) : data(d), size(s) {}
};

/// ABI-safe mutable span for byte arrays
struct MutableByteSpan {
    std::uint8_t* data;
    std::size_t size;

    MutableByteSpan() : data(nullptr), size(0) {}
    MutableByteSpan(std::uint8_t* d, std::size_t s) : data(d), size(s) {}
};

}  // namespace engine::plugin
