#pragma once

#include "engine/plugin/host.h"
#include "engine/plugin/library.h"
#include "engine/plugin/plugin.h"
#include "engine/plugin/static_registry.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace engine {
class Session;
}

namespace client {
class CommandRegistry;
}

namespace engine::plugin {

/// Information about a loaded plugin
struct LoadedPlugin {
    std::string path;                   // Full path to the plugin file (empty for static)
    std::string directory;              // Directory containing the plugin
    Library library;                    // The loaded library (empty for static)
    Ref<IPlugin> plugin;                // The plugin instance
    bool initialized = false;           // Whether initialize() was called successfully
    bool is_static = false;             // Whether this is a statically linked plugin
};

/// Plugin discovery and loading options
struct PluginManagerOptions {
    std::string plugin_directory;       // Directory to scan for plugins
    bool auto_load = true;              // Load all plugins on startup
    bool fail_on_error = false;         // Abort if any plugin fails to load
};

/// Manages plugin discovery, loading, and lifecycle.
/// 
/// Usage:
///     PluginManager mgr;
///     mgr.set_options({.plugin_directory = "./plugins"});
///     mgr.set_command_registry(&registry);
///     mgr.set_session(&session);
///     mgr.discover_and_load();
///     
///     // Later, when shutting down:
///     mgr.shutdown_all();
class PluginManager {
public:
    PluginManager();
    ~PluginManager();

    // Non-copyable
    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    /// Configure the plugin manager
    void set_options(const PluginManagerOptions& options);
    
    /// Set the command registry for plugin command registration
    void set_command_registry(client::CommandRegistry* registry);
    
    /// Set the current session for plugin access
    void set_session(Session* session);

    /// Discover plugins in the configured directory
    /// @return Number of plugin files found
    std::size_t discover();

    /// Load all discovered plugins
    /// @return Number of plugins successfully loaded
    std::size_t load_all();

    /// Initialize all loaded plugins
    /// @return Number of plugins successfully initialized
    std::size_t initialize_all();

    /// Convenience method: discover, load, and initialize
    /// @return Number of plugins successfully initialized
    std::size_t discover_and_load();

    /// Load a single plugin from a path
    /// @return true if loaded and initialized successfully
    bool load_plugin(const std::string& path);

    /// Load all statically registered plugins
    /// @return Number of static plugins loaded
    std::size_t load_static_plugins();

    /// Register and initialize a plugin instance directly (for static plugins)
    /// @param plugin The plugin instance (takes ownership)
    /// @param name Name for logging
    /// @return true if initialized successfully
    bool register_static_plugin(IPlugin* plugin, const std::string& name = "");

    /// Shutdown all plugins (call before destruction)
    void shutdown_all();

    /// Unload all plugins
    void unload_all();

    /// Get list of loaded plugins
    const std::vector<LoadedPlugin>& plugins() const { return plugins_; }

    /// Get list of discovered plugin paths
    const std::vector<std::string>& discovered_paths() const { return discovered_paths_; }

    /// Get last error message
    const std::string& last_error() const { return last_error_; }

    /// Callback for plugin events
    using PluginEventCallback = std::function<void(const std::string& plugin_name, const std::string& event)>;
    void set_event_callback(PluginEventCallback callback);
    
    /// Callback for command registration (called when plugins register commands)
    /// Returns true if registration succeeded
    using CommandRegisterCallback = std::function<bool(ICommand* cmd)>;
    void set_command_register_callback(CommandRegisterCallback callback);

private:
    class HostContextImpl;
    
    PluginManagerOptions options_;
    std::vector<std::string> discovered_paths_;
    std::vector<LoadedPlugin> plugins_;
    std::string last_error_;
    
    client::CommandRegistry* command_registry_ = nullptr;
    Session* session_ = nullptr;
    
    std::unique_ptr<HostContextImpl> host_context_;
    PluginEventCallback event_callback_;
    CommandRegisterCallback command_register_callback_;
    
    void notify_event(const std::string& plugin_name, const std::string& event);
};

}  // namespace engine::plugin
