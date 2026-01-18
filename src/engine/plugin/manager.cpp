#include "engine/plugin/manager.h"
#include "engine/plugin/command.h"
#include "engine/plugin/session.h"
#include "session_wrapper.h"
#include "engine/api.h"
#include "engine/session.h"
#include "engine/log.h"

#include <filesystem>

namespace fs = std::filesystem;

namespace engine::plugin {

// =============================================================================
// HostContextImpl - Implementation of IHostContext
// =============================================================================

class PluginManager::HostContextImpl : public ObjectBase, public IHostContext {
public:
    explicit HostContextImpl(PluginManager* manager) : manager_(manager) {}
    
    // IObject forwarding
    void retain() override { ObjectBase::retain(); }
    void release() override { ObjectBase::release(); }
    std::int32_t ref_count() const override { return ObjectBase::ref_count(); }
    
    // IHostContext implementation
    PluginApiVersion api_version() const override {
        return kCurrentApiVersion;
    }
    
    const char* engine_name() const override {
        return "uranayzle";
    }
    
    const char* engine_version() const override {
        static std::string version;
        if (version.empty()) {
            version = get_engine_info().version;
        }
        return version.c_str();
    }
    
    void log(LogLevel level, const char* message) override {
        switch (level) {
            case LogLevel::Trace:
                SPDLOG_TRACE("[plugin] {}", message);
                break;
            case LogLevel::Debug:
                SPDLOG_DEBUG("[plugin] {}", message);
                break;
            case LogLevel::Info:
                SPDLOG_INFO("[plugin] {}", message);
                break;
            case LogLevel::Warning:
                SPDLOG_WARN("[plugin] {}", message);
                break;
            case LogLevel::Error:
                SPDLOG_ERROR("[plugin] {}", message);
                break;
            case LogLevel::Critical:
                SPDLOG_CRITICAL("[plugin] {}", message);
                break;
        }
    }
    
    Result register_command(ICommand* cmd) override;
    Result unregister_command(const char* name) override;
    
    ISession* get_session() override;
    
    const char* plugin_directory() const override {
        return manager_->options_.plugin_directory.c_str();
    }
    
    const char* current_plugin_directory() const override {
        return current_plugin_dir_.c_str();
    }
    
    void set_current_plugin_directory(const std::string& dir) {
        current_plugin_dir_ = dir;
    }

private:
    PluginManager* manager_;
    std::string current_plugin_dir_;
    mutable std::unique_ptr<SessionWrapper> session_wrapper_;
};

// =============================================================================
// PluginManager Implementation
// =============================================================================

PluginManager::PluginManager() 
    : host_context_(std::make_unique<HostContextImpl>(this)) {
}

PluginManager::~PluginManager() {
    shutdown_all();
    unload_all();
}

void PluginManager::set_options(const PluginManagerOptions& options) {
    options_ = options;
}

void PluginManager::set_command_registry(client::CommandRegistry* registry) {
    command_registry_ = registry;
}

void PluginManager::set_session(Session* session) {
    session_ = session;
}

std::size_t PluginManager::discover() {
    discovered_paths_.clear();
    
    if (options_.plugin_directory.empty()) {
        SPDLOG_WARN("Plugin directory not set");
        return 0;
    }
    
    fs::path plugin_dir(options_.plugin_directory);
    if (!fs::exists(plugin_dir)) {
        SPDLOG_DEBUG("Plugin directory does not exist: {}", options_.plugin_directory);
        return 0;
    }
    
    const char* ext = Library::library_extension();
    const char* prefix = Library::library_prefix();
    
    for (const auto& entry : fs::directory_iterator(plugin_dir)) {
        if (!entry.is_regular_file()) continue;
        
        const auto& path = entry.path();
        std::string filename = path.filename().string();
        
        // Check extension
        if (path.extension().string() != ext) continue;
        
        // On Unix, check prefix
        if (prefix[0] != '\0' && filename.find(prefix) != 0) continue;
        
        discovered_paths_.push_back(path.string());
        SPDLOG_DEBUG("Discovered plugin: {}", path.string());
    }
    
    SPDLOG_INFO("Discovered {} plugin(s) in {}", discovered_paths_.size(), options_.plugin_directory);
    return discovered_paths_.size();
}

std::size_t PluginManager::load_all() {
    std::size_t loaded = 0;
    
    for (const auto& path : discovered_paths_) {
        LoadedPlugin lp;
        lp.path = path;
        lp.directory = fs::path(path).parent_path().string();
        
        // Load the library
        if (!lp.library.load(path)) {
            last_error_ = lp.library.error();
            SPDLOG_ERROR("Failed to load plugin library {}: {}", path, last_error_);
            if (options_.fail_on_error) return loaded;
            continue;
        }
        
        // Get the factory function
        auto create_func = lp.library.get_function<CreatePluginFunc>(kCreatePluginFuncName);
        if (!create_func) {
            last_error_ = "Plugin does not export " + std::string(kCreatePluginFuncName);
            SPDLOG_ERROR("Failed to load plugin {}: {}", path, last_error_);
            if (options_.fail_on_error) return loaded;
            continue;
        }
        
        // Create the plugin instance
        IPlugin* raw_plugin = create_func();
        if (!raw_plugin) {
            last_error_ = "Plugin factory returned nullptr";
            SPDLOG_ERROR("Failed to load plugin {}: {}", path, last_error_);
            if (options_.fail_on_error) return loaded;
            continue;
        }
        
        // Take ownership with Ref (plugin starts with refcount=1)
        lp.plugin = adopt_ref(raw_plugin);
        
        // Version check
        const auto& meta = lp.plugin->metadata();
        if (!meta.api_version.is_compatible_with(kCurrentApiVersion)) {
            last_error_ = "Plugin API version mismatch";
            SPDLOG_ERROR("Plugin {} has incompatible API version {}.{}.{} (host: {}.{}.{})",
                        meta.name, 
                        meta.api_version.major, meta.api_version.minor, meta.api_version.patch,
                        kCurrentApiVersion.major, kCurrentApiVersion.minor, kCurrentApiVersion.patch);
            if (options_.fail_on_error) return loaded;
            continue;
        }
        
        plugins_.push_back(std::move(lp));
        SPDLOG_INFO("Loaded plugin: {} v{} by {}", meta.name, meta.version, meta.author);
        notify_event(meta.name, "loaded");
        ++loaded;
    }
    
    return loaded;
}

std::size_t PluginManager::initialize_all() {
    std::size_t initialized = 0;
    
    for (auto& lp : plugins_) {
        if (lp.initialized) {
            ++initialized;
            continue;
        }
        
        // Set current plugin directory for the host context
        host_context_->set_current_plugin_directory(lp.directory);
        
        const auto& meta = lp.plugin->metadata();
        Result result = lp.plugin->initialize(host_context_.get());
        
        if (result != Result::Ok) {
            last_error_ = "Plugin initialization failed";
            SPDLOG_ERROR("Failed to initialize plugin {}: error code {}", 
                        meta.name, static_cast<int>(result));
            notify_event(meta.name, "init_failed");
            if (options_.fail_on_error) return initialized;
            continue;
        }
        
        lp.initialized = true;
        SPDLOG_INFO("Initialized plugin: {}", meta.name);
        notify_event(meta.name, "initialized");
        ++initialized;
    }
    
    return initialized;
}

std::size_t PluginManager::discover_and_load() {
    discover();
    load_all();
    return initialize_all();
}

bool PluginManager::load_plugin(const std::string& path) {
    discovered_paths_.clear();
    discovered_paths_.push_back(path);
    
    if (load_all() == 0) return false;
    if (initialize_all() == 0) return false;
    
    return true;
}

std::size_t PluginManager::load_static_plugins() {
    std::size_t loaded = 0;
    
    for (const auto& entry : StaticPluginRegistry::instance().entries()) {
        if (register_static_plugin(entry.create_func(), entry.name)) {
            ++loaded;
        }
    }
    
    SPDLOG_INFO("Loaded {} static plugin(s)", loaded);
    return loaded;
}

bool PluginManager::register_static_plugin(IPlugin* plugin, const std::string& name) {
    if (!plugin) {
        last_error_ = "Static plugin factory returned nullptr";
        SPDLOG_ERROR("Failed to load static plugin '{}': {}", name, last_error_);
        return false;
    }
    
    // Take ownership (plugin starts with refcount=1)
    LoadedPlugin lp;
    lp.plugin = adopt_ref(plugin);
    lp.is_static = true;
    
    const auto& meta = lp.plugin->metadata();
    
    // Version check
    if (!meta.api_version.is_compatible_with(kCurrentApiVersion)) {
        last_error_ = "Plugin API version mismatch";
        SPDLOG_ERROR("Static plugin {} has incompatible API version {}.{}.{} (host: {}.{}.{})",
                    meta.name, 
                    meta.api_version.major, meta.api_version.minor, meta.api_version.patch,
                    kCurrentApiVersion.major, kCurrentApiVersion.minor, kCurrentApiVersion.patch);
        return false;
    }
    
    // Initialize immediately
    Result result = lp.plugin->initialize(host_context_.get());
    if (result != Result::Ok) {
        last_error_ = "Plugin initialization failed";
        SPDLOG_ERROR("Failed to initialize static plugin {}: error code {}", 
                    meta.name, static_cast<int>(result));
        notify_event(meta.name, "init_failed");
        return false;
    }
    
    lp.initialized = true;
    plugins_.push_back(std::move(lp));
    
    SPDLOG_INFO("Loaded static plugin: {} v{} by {}", meta.name, meta.version, meta.author);
    notify_event(meta.name, "loaded");
    notify_event(meta.name, "initialized");
    
    return true;
}

void PluginManager::shutdown_all() {
    for (auto& lp : plugins_) {
        if (!lp.initialized) continue;
        
        const auto& meta = lp.plugin->metadata();
        SPDLOG_DEBUG("Shutting down plugin: {}", meta.name);
        
        lp.plugin->shutdown();
        lp.initialized = false;
        
        notify_event(meta.name, "shutdown");
    }
}

void PluginManager::unload_all() {
    // Release plugin references first (so destructor runs before library unload)
    for (auto& lp : plugins_) {
        if (lp.plugin) {
            const auto& meta = lp.plugin->metadata();
            notify_event(meta.name, "unloading");
        }
        lp.plugin.reset();
    }
    
    // Now unload libraries
    plugins_.clear();
}

void PluginManager::set_event_callback(PluginEventCallback callback) {
    event_callback_ = std::move(callback);
}

void PluginManager::set_command_register_callback(CommandRegisterCallback callback) {
    command_register_callback_ = std::move(callback);
}

void PluginManager::notify_event(const std::string& plugin_name, const std::string& event) {
    if (event_callback_) {
        event_callback_(plugin_name, event);
    }
}

// =============================================================================
// HostContextImpl deferred implementations (need full types)
// =============================================================================

Result PluginManager::HostContextImpl::register_command(ICommand* cmd) {
    if (!cmd) return Result::InvalidArgument;
    
    // Use the callback if available
    if (manager_->command_register_callback_) {
        try {
            bool success = manager_->command_register_callback_(cmd);
            if (success) {
                SPDLOG_DEBUG("Registered command via callback: {}", cmd->name());
                return Result::Ok;
            } else {
                SPDLOG_WARN("Failed to register command: {}", cmd->name());
                return Result::Error;
            }
        } catch (const std::exception& e) {
            SPDLOG_ERROR("Exception in command registration callback: {}", e.what());
            return Result::Error;
        } catch (...) {
            SPDLOG_ERROR("Unknown exception in command registration callback");
            return Result::Error;
        }
    }
    
    SPDLOG_WARN("Cannot register command '{}': no registration callback set", cmd->name());
    return Result::NotInitialized;
}

Result PluginManager::HostContextImpl::unregister_command(const char* name) {
    if (!name) return Result::InvalidArgument;
    if (!manager_->command_registry_) {
        return Result::NotInitialized;
    }
    
    // TODO: Implement command unregistration
    SPDLOG_DEBUG("Command unregistration requested: {}", name);
    return Result::Ok;
}

ISession* PluginManager::HostContextImpl::get_session() {
    if (!manager_->session_ || !manager_->session_->loaded()) {
        return nullptr;
    }
    
    // Create or return cached session wrapper
    if (!session_wrapper_) {
        session_wrapper_ = std::make_unique<SessionWrapper>(manager_->session_);
    }
    return session_wrapper_.get();
}

}  // namespace engine::plugin
