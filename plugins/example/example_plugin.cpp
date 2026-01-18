/// @file example_plugin.cpp
/// @brief Example plugin demonstrating the uranayzle plugin SDK.
///
/// This plugin adds a "hello" command that greets the user and shows
/// basic session information if a file is loaded.

#include <engine/plugin/sdk.h>

#include <cstring>
#include <sstream>

using namespace engine::plugin;

// =============================================================================
// HelloCommand - A simple command that says hello
// =============================================================================

class HelloCommand : public CommandBase {
public:
    const char* name() const override { return "hello"; }
    const char* help() const override { return "Say hello from the example plugin"; }
    const char* aliases() const override { return "hi"; }

    Result execute(ISession* session, IOutput* output, IArgs* args) override {
        output->write_line("Hello from the example plugin!");
        output->write_line("");

        if (session && session->is_loaded()) {
            output->write_line("Current session info:");
            output->write_fmt("  File: %s", session->file_path());
            
            const auto* info = session->binary_info();
            if (info) {
                output->write_fmt("  Format: %s", info->format());
                output->write_fmt("  Machine: %s", info->machine());
                
                std::ostringstream oss;
                oss << "  Entry: 0x" << std::hex << info->entry_point();
                output->write_line(oss.str().c_str());
            }

            const auto* syms = session->symbol_table();
            if (syms) {
                std::ostringstream oss;
                oss << "  Symbols: " << syms->count();
                output->write_line(oss.str().c_str());
            }
        } else {
            output->write_line("No file is currently loaded.");
            output->write_line("Use 'open <file>' to load a binary.");
        }

        return Result::Ok;
    }
};

// =============================================================================
// InfoCommand - Shows detailed plugin/engine info
// =============================================================================

class InfoCommand : public CommandBase {
public:
    const char* name() const override { return "pluginfo"; }
    const char* help() const override { return "Show plugin system information"; }

    Result execute(ISession* session, IOutput* output, IArgs* args) override {
        output->write_line("=== Plugin System Info ===");
        output->write_line("");
        output->write_fmt("Engine: %s", ctx_->engine_name());
        output->write_fmt("Engine Version: %s", ctx_->engine_version());
        
        auto ver = ctx_->api_version();
        std::ostringstream oss;
        oss << "Plugin API Version: " << ver.major << "." << ver.minor << "." << ver.patch;
        output->write_line(oss.str().c_str());
        
        output->write_fmt("Plugin Directory: %s", ctx_->plugin_directory());
        
        return Result::Ok;
    }

    void set_context(IHostContext* ctx) { ctx_ = ctx; }

private:
    IHostContext* ctx_ = nullptr;
};

// =============================================================================
// ExamplePlugin - Main plugin class
// =============================================================================

class ExamplePlugin : public PluginBase {
public:
    ExamplePlugin() : PluginBase({
        .name = "Example Plugin",
        .version = "1.0.0",
        .author = "uranayzle team",
        .description = "Demonstrates the uranayzle plugin SDK",
        .api_version = kCurrentApiVersion,
    }) {}

    Result initialize(IHostContext* ctx) override {
        ctx_ = ctx;
        ctx->info("Example plugin initializing...");

        // Register commands
        hello_cmd_ = new HelloCommand();
        info_cmd_ = new InfoCommand();
        info_cmd_->set_context(ctx);

        Result r = ctx->register_command(hello_cmd_);
        if (r != Result::Ok) {
            ctx->error("Failed to register 'hello' command");
            return r;
        }

        r = ctx->register_command(info_cmd_);
        if (r != Result::Ok) {
            ctx->error("Failed to register 'pluginfo' command");
            return r;
        }

        ctx->info("Example plugin initialized successfully!");
        return Result::Ok;
    }

    void shutdown() override {
        if (ctx_) {
            ctx_->info("Example plugin shutting down...");
            
            // Unregister commands
            ctx_->unregister_command("hello");
            ctx_->unregister_command("pluginfo");
        }

        // Release command objects
        if (hello_cmd_) {
            hello_cmd_->release();
            hello_cmd_ = nullptr;
        }
        if (info_cmd_) {
            info_cmd_->release();
            info_cmd_ = nullptr;
        }
    }

private:
    HelloCommand* hello_cmd_ = nullptr;
    InfoCommand* info_cmd_ = nullptr;
};

// Export the plugin entry point
URANAYZLE_DECLARE_PLUGIN(ExamplePlugin)
