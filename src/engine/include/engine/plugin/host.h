#pragma once

#include "engine/plugin/object.h"
#include "engine/plugin/types.h"

namespace engine::plugin {

// Forward declarations
struct ICommand;
struct ISession;

/// Host context interface provided to plugins.
/// 
/// This is the plugin's gateway to the host engine. Plugins receive this
/// in their initialize() method and can use it to:
/// - Log messages
/// - Register extensions (commands, passes, etc.)
/// - Access engine state
/// 
/// The host context remains valid for the entire lifetime of the plugin.
struct IHostContext : public IObject {
    virtual ~IHostContext() = default;

    // =========================================================================
    // Version & Info
    // =========================================================================

    /// Get the host's plugin API version
    virtual PluginApiVersion api_version() const = 0;

    /// Get the engine name (e.g., "uranayzle")
    virtual const char* engine_name() const = 0;

    /// Get the engine version string
    virtual const char* engine_version() const = 0;

    // =========================================================================
    // Logging
    // =========================================================================

    /// Log a message at the specified level.
    /// 
    /// @param level Log level
    /// @param message The message to log (null-terminated)
    virtual void log(LogLevel level, const char* message) = 0;

    /// Convenience methods for different log levels
    void trace(const char* msg) { log(LogLevel::Trace, msg); }
    void debug(const char* msg) { log(LogLevel::Debug, msg); }
    void info(const char* msg) { log(LogLevel::Info, msg); }
    void warning(const char* msg) { log(LogLevel::Warning, msg); }
    void error(const char* msg) { log(LogLevel::Error, msg); }
    void critical(const char* msg) { log(LogLevel::Critical, msg); }

    // =========================================================================
    // Command Registration
    // =========================================================================

    /// Register a command with the host.
    /// 
    /// The command will be available in both CLI and GUI interfaces.
    /// The host takes ownership of the command (adds a reference).
    /// 
    /// @param cmd The command to register
    /// @return Result::Ok on success, Result::AlreadyExists if name conflicts
    virtual Result register_command(ICommand* cmd) = 0;

    /// Unregister a previously registered command.
    /// 
    /// @param name The command name to unregister
    /// @return Result::Ok on success, Result::NotFound if not registered
    virtual Result unregister_command(const char* name) = 0;

    // =========================================================================
    // Session Access
    // =========================================================================

    /// Get the current analysis session.
    /// 
    /// @return The current session, or nullptr if no file is loaded.
    ///         The returned pointer is valid until the session changes.
    ///         Do not store this pointer long-term; re-query when needed.
    virtual ISession* get_session() = 0;

    // =========================================================================
    // Plugin Directory
    // =========================================================================

    /// Get the directory where plugins are stored.
    /// Useful for loading plugin-specific resources.
    virtual const char* plugin_directory() const = 0;

    /// Get the plugin's own directory (where its DLL/SO is located).
    /// Returns nullptr if called before plugin is fully loaded.
    virtual const char* current_plugin_directory() const = 0;
};

}  // namespace engine::plugin
