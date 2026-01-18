#pragma once

#include "engine/plugin/plugin.h"

#include <functional>
#include <string>
#include <vector>

namespace engine::plugin {

/// Static plugin registration entry.
/// 
/// Static plugins are compiled directly into the executable instead of
/// being loaded as dynamic libraries. This is useful for:
/// - Embedded systems where dynamic loading isn't available
/// - Reducing deployment complexity
/// - Faster startup (no filesystem scanning)
struct StaticPluginEntry {
    const char* name;
    CreatePluginFunc create_func;
};

/// Registry for static plugins.
/// 
/// Static plugins register themselves at program startup using
/// the URANAYZLE_REGISTER_STATIC_PLUGIN macro.
/// 
/// Usage in plugin source file:
///     URANAYZLE_REGISTER_STATIC_PLUGIN(MyPlugin)
/// 
/// In host application:
///     auto& entries = StaticPluginRegistry::instance().entries();
///     for (const auto& entry : entries) {
///         IPlugin* plugin = entry.create_func();
///         // ... initialize and use plugin
///     }
class StaticPluginRegistry {
public:
    /// Get the singleton instance
    static StaticPluginRegistry& instance() {
        static StaticPluginRegistry registry;
        return registry;
    }

    /// Register a static plugin
    void register_plugin(const char* name, CreatePluginFunc create_func) {
        entries_.push_back({name, create_func});
    }

    /// Get all registered static plugins
    const std::vector<StaticPluginEntry>& entries() const {
        return entries_;
    }

    /// Clear all registered plugins (for testing)
    void clear() {
        entries_.clear();
    }

private:
    StaticPluginRegistry() = default;
    std::vector<StaticPluginEntry> entries_;
};

/// Helper class for auto-registration at startup
template <typename PluginClass>
class StaticPluginRegistrar {
public:
    explicit StaticPluginRegistrar(const char* name) {
        StaticPluginRegistry::instance().register_plugin(name, &create);
    }

private:
    static IPlugin* create() {
        return new PluginClass();
    }
};

}  // namespace engine::plugin

/// Register a static plugin that will be available without dynamic loading.
/// 
/// Usage at the end of your plugin source file:
///     URANAYZLE_REGISTER_STATIC_PLUGIN(MyPluginClass)
/// 
/// The plugin will be automatically registered when the program starts.
#define URANAYZLE_REGISTER_STATIC_PLUGIN(PluginClass) \
    static ::engine::plugin::StaticPluginRegistrar<PluginClass> \
        _static_plugin_registrar_##PluginClass(#PluginClass)

/// Convenience macro to both declare the dynamic entry point AND register
/// as a static plugin. Use this if you want the plugin to work both ways.
/// 
/// Usage:
///     URANAYZLE_DECLARE_HYBRID_PLUGIN(MyPluginClass)
#define URANAYZLE_DECLARE_HYBRID_PLUGIN(PluginClass) \
    URANAYZLE_DECLARE_PLUGIN(PluginClass) \
    URANAYZLE_REGISTER_STATIC_PLUGIN(PluginClass)
