#include "client/plugin/command_bridge.h"
#include "engine/plugin/session.h"
#include "engine/session.h"

#include <sstream>

namespace client::plugin {

// =============================================================================
// Output Adapter - wraps client::Output as plugin::IOutput
// =============================================================================

class OutputAdapter : public engine::plugin::ObjectBase, public engine::plugin::IOutput {
public:
    explicit OutputAdapter(Output& output) : output_(output) {}

    void retain() override { engine::plugin::ObjectBase::retain(); }
    void release() override { engine::plugin::ObjectBase::release(); }
    std::int32_t ref_count() const override { return engine::plugin::ObjectBase::ref_count(); }

    void write_line(const char* text) override {
        output_.write_line(text ? text : "");
    }

    void write(const char* text) override {
        // Output doesn't have a write() without newline
        // Accumulate text and flush on next write_line or destruction
        if (text && text[0] != '\0') {
            output_.write_line(text);
        }
    }

    void write_error(const char* text) override {
        output_.write_line(std::string("Error: ") + (text ? text : ""));
    }

    void write_fmt(const char* format, const char* arg) override {
        if (!format) return;
        // Simple %s replacement
        std::string fmt(format);
        std::size_t pos = fmt.find("%s");
        if (pos != std::string::npos && arg) {
            fmt.replace(pos, 2, arg);
        }
        output_.write_line(fmt);
    }

private:
    Output& output_;
};

// =============================================================================
// Args Adapter - wraps vector<string> as plugin::IArgs
// =============================================================================

class ArgsAdapter : public engine::plugin::ObjectBase, public engine::plugin::IArgs {
public:
    explicit ArgsAdapter(const std::vector<std::string>& args) : args_(args) {}

    void retain() override { engine::plugin::ObjectBase::retain(); }
    void release() override { engine::plugin::ObjectBase::release(); }
    std::int32_t ref_count() const override { return engine::plugin::ObjectBase::ref_count(); }

    std::size_t positional_count() const override {
        return args_.size();
    }

    const char* positional(std::size_t index) const override {
        if (index >= args_.size()) return nullptr;
        return args_[index].c_str();
    }

    bool has_flag(const char* name) const override {
        if (!name) return false;
        std::string flag = std::string("-") + name;
        std::string long_flag = std::string("--") + name;
        for (const auto& arg : args_) {
            if (arg == flag || arg == long_flag) return true;
        }
        return false;
    }

    const char* option(const char* name) const override {
        if (!name) return nullptr;
        std::string opt = std::string("--") + name + "=";
        for (const auto& arg : args_) {
            if (arg.find(opt) == 0) {
                // Return everything after the '='
                last_option_ = arg.substr(opt.size());
                return last_option_.c_str();
            }
        }
        return nullptr;
    }

    const char* raw_arg(std::size_t index) const override {
        return positional(index);
    }

    std::size_t raw_count() const override {
        return args_.size();
    }

private:
    std::vector<std::string> args_;
    mutable std::string last_option_;
};

// =============================================================================
// Session Wrapper for plugin use
// =============================================================================

class SimpleSessionWrapper : public engine::plugin::ObjectBase, public engine::plugin::ISession {
public:
    explicit SimpleSessionWrapper(engine::Session* session) : session_(session) {}

    void retain() override { engine::plugin::ObjectBase::retain(); }
    void release() override { engine::plugin::ObjectBase::release(); }
    std::int32_t ref_count() const override { return engine::plugin::ObjectBase::ref_count(); }

    bool is_loaded() const override {
        return session_ && session_->loaded();
    }

    const char* file_path() const override {
        if (!session_) return "";
        return session_->path().c_str();
    }

    const engine::plugin::IBinaryInfo* binary_info() const override {
        // Simplified - return nullptr, full implementation in session_wrapper.cpp
        return nullptr;
    }

    const engine::plugin::IImage* image() const override {
        return nullptr;
    }

    const engine::plugin::ISymbolTable* symbol_table() const override {
        return nullptr;
    }

    std::uint64_t cursor() const override {
        if (!session_) return 0;
        return session_->cursor();
    }

    void set_cursor(std::uint64_t addr) override {
        if (session_) session_->set_cursor(addr);
    }

    std::size_t disassemble_text(std::uint64_t, std::size_t, char*, std::size_t) const override {
        return 0;
    }

private:
    engine::Session* session_;
};

// =============================================================================
// PluginCommandAdapter
// =============================================================================

PluginCommandAdapter::PluginCommandAdapter(engine::plugin::ICommand* cmd, engine::Session* session)
    : cmd_(cmd), session_(session) {
    if (cmd_) {
        cmd_->retain();
    }
}

PluginCommandAdapter::~PluginCommandAdapter() {
    if (cmd_) {
        cmd_->release();
    }
}

CommandV2 PluginCommandAdapter::build() const {
    std::vector<std::string> aliases;
    if (cmd_->aliases() && cmd_->aliases()[0] != '\0') {
        // Parse comma-separated aliases
        std::string alias_str = cmd_->aliases();
        std::istringstream iss(alias_str);
        std::string alias;
        while (std::getline(iss, alias, ',')) {
            // Trim whitespace
            while (!alias.empty() && alias.front() == ' ') alias.erase(0, 1);
            while (!alias.empty() && alias.back() == ' ') alias.pop_back();
            if (!alias.empty()) {
                aliases.push_back(alias);
            }
        }
    }

    CommandV2 v2(cmd_->name(), aliases);
    v2.description(cmd_->help() ? cmd_->help() : "");
    v2.requires_file(cmd_->requires_file());

    // IMPORTANT: We capture a raw pointer here because:
    // 1. The PluginCommandAdapter already holds a reference (via retain in constructor)
    // 2. The lambda may outlive the DLL (stored in CommandRegistry)
    // 3. If we stored Ref<> here, its destructor would try to call release() after DLL unload
    // The adapter ensures the command stays alive as long as we need it.
    auto* plugin_cmd = cmd_;
    auto* session = session_;

    v2.handler([plugin_cmd, session](Session& /*client_session*/, Output& output, 
                                      const args::ArgMatches& matches) -> bool {
        // Create adapters
        OutputAdapter out_adapter(output);
        
        // Get raw args from matches (simplified)
        std::vector<std::string> raw_args;
        // For now, just pass empty args - full implementation would extract from matches
        ArgsAdapter args_adapter(raw_args);
        
        // Create session wrapper
        SimpleSessionWrapper session_wrapper(session);

        // Execute the plugin command
        auto result = plugin_cmd->execute(&session_wrapper, &out_adapter, &args_adapter);
        
        return result == engine::plugin::Result::Ok;
    });

    return v2;
}

// =============================================================================
// PluginCommandBridge
// =============================================================================

PluginCommandBridge::PluginCommandBridge(CommandRegistry& registry, engine::Session* session)
    : registry_(registry), session_(session) {
}

PluginCommandBridge::~PluginCommandBridge() {
    unregister_all();
}

bool PluginCommandBridge::register_command(engine::plugin::ICommand* cmd) {
    if (!cmd) return false;

    auto adapter = std::make_unique<PluginCommandAdapter>(cmd, session_);
    CommandV2 v2 = adapter->build();
    
    std::string name = cmd->name();
    registry_.register_command(std::move(v2));
    
    registered_names_.push_back(name);
    adapters_.push_back(std::move(adapter));
    
    return true;
}

bool PluginCommandBridge::unregister_command(const std::string& name) {
    // Find and remove from our tracking
    auto it = std::find(registered_names_.begin(), registered_names_.end(), name);
    if (it == registered_names_.end()) {
        return false;
    }
    
    std::size_t index = std::distance(registered_names_.begin(), it);
    registered_names_.erase(it);
    
    if (index < adapters_.size()) {
        adapters_.erase(adapters_.begin() + index);
    }
    
    // Note: CommandRegistry doesn't support unregistration currently
    // The command will remain registered until the registry is destroyed
    return true;
}

void PluginCommandBridge::unregister_all() {
    registered_names_.clear();
    adapters_.clear();
}

}  // namespace client::plugin
