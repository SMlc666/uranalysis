#pragma once

#include "engine/plugin/command.h"
#include "client/command.h"

#include <memory>
#include <string>
#include <vector>

namespace engine {
class Session;
}

namespace engine::plugin {
class SessionWrapper;
}

namespace client::plugin {

/// Adapter that wraps a plugin ICommand and presents it as a client Command.
/// 
/// This allows plugin commands to be registered in the CommandRegistry
/// and executed through the normal command infrastructure.
class PluginCommandAdapter {
public:
    /// Create an adapter for a plugin command.
    /// 
    /// @param cmd The plugin command (ownership is shared via retain)
    /// @param session Pointer to the engine session
    explicit PluginCommandAdapter(engine::plugin::ICommand* cmd, engine::Session* session);
    ~PluginCommandAdapter();

    // Non-copyable
    PluginCommandAdapter(const PluginCommandAdapter&) = delete;
    PluginCommandAdapter& operator=(const PluginCommandAdapter&) = delete;

    /// Build a CommandV2 from this adapter.
    CommandV2 build() const;

    /// Get the underlying plugin command
    engine::plugin::ICommand* plugin_command() const { return cmd_; }

private:
    engine::plugin::ICommand* cmd_;
    engine::Session* session_;
};

/// Manages the bridge between plugin commands and the client command registry.
class PluginCommandBridge {
public:
    explicit PluginCommandBridge(CommandRegistry& registry, engine::Session* session);
    ~PluginCommandBridge();

    /// Register a plugin command
    bool register_command(engine::plugin::ICommand* cmd);

    /// Unregister a command by name
    bool unregister_command(const std::string& name);

    /// Unregister all plugin commands
    void unregister_all();

private:
    CommandRegistry& registry_;
    engine::Session* session_;
    std::vector<std::unique_ptr<PluginCommandAdapter>> adapters_;
    std::vector<std::string> registered_names_;
};

}  // namespace client::plugin
