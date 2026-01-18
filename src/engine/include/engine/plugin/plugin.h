#pragma once

#include "engine/plugin/object.h"
#include "engine/plugin/types.h"

namespace engine::plugin {

// Forward declarations
struct IHostContext;

/// The main plugin interface.
/// 
/// Every plugin must implement this interface and export a factory function:
/// 
///     URANAYZLE_PLUGIN_API IPlugin* uranayzle_create_plugin();
/// 
/// The returned plugin starts with refcount = 1.
struct IPlugin : public IObject {
    virtual ~IPlugin() = default;

    /// Get plugin metadata (name, version, author, etc.)
    virtual const PluginMetadata& metadata() const = 0;

    /// Initialize the plugin with host context.
    /// 
    /// Called once after the plugin is loaded. Use this to:
    /// - Store the host context for later use
    /// - Register commands, passes, loaders, etc.
    /// - Allocate plugin-global resources
    /// 
    /// @param ctx The host context (valid for the plugin's lifetime)
    /// @return Result::Ok on success, error code on failure
    virtual Result initialize(IHostContext* ctx) = 0;

    /// Shutdown the plugin.
    /// 
    /// Called before the plugin is unloaded. Use this to:
    /// - Unregister any registered extensions
    /// - Free plugin-global resources
    /// - Flush any pending data
    /// 
    /// After this returns, the plugin's release() will be called.
    virtual void shutdown() = 0;
};

/// Factory function type for creating plugins.
/// Plugins must export: URANAYZLE_PLUGIN_API IPlugin* uranayzle_create_plugin();
using CreatePluginFunc = IPlugin* (*)();

/// The name of the factory function that plugins must export.
inline constexpr const char* kCreatePluginFuncName = "uranayzle_create_plugin";

/// Helper base class for implementing IPlugin.
/// 
/// Usage:
///     class MyPlugin : public PluginBase {
///     public:
///         MyPlugin() : PluginBase({
///             .name = "My Plugin",
///             .version = "1.0.0",
///             .author = "Me",
///             .description = "Does something cool",
///             .api_version = kCurrentApiVersion,
///         }) {}
///         
///         Result initialize(IHostContext* ctx) override {
///             ctx_ = ctx;
///             // Register extensions...
///             return Result::Ok;
///         }
///         
///         void shutdown() override {
///             // Cleanup...
///         }
///     };
class PluginBase : public ObjectBase, public IPlugin {
public:
    explicit PluginBase(PluginMetadata metadata) : metadata_(metadata) {}
    virtual ~PluginBase() = default;

    // Forward IObject methods to ObjectBase
    void retain() override { ObjectBase::retain(); }
    void release() override { ObjectBase::release(); }
    std::int32_t ref_count() const override { return ObjectBase::ref_count(); }

    const PluginMetadata& metadata() const override { return metadata_; }

protected:
    PluginMetadata metadata_;
    IHostContext* ctx_ = nullptr;
};

}  // namespace engine::plugin

/// Convenience macro for declaring the plugin entry point.
/// 
/// Usage at the end of your plugin source file:
///     URANAYZLE_DECLARE_PLUGIN(MyPluginClass)
#define URANAYZLE_DECLARE_PLUGIN(PluginClass) \
    URANAYZLE_PLUGIN_API engine::plugin::IPlugin* uranayzle_create_plugin() { \
        return new PluginClass(); \
    }
