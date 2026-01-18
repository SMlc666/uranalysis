#pragma once

/// @file plugin.h
/// @brief Main include file for uranayzle plugin SDK.
///
/// Include this single header in your plugin to get all plugin API types.

#include "engine/plugin/types.h"
#include "engine/plugin/object.h"
#include "engine/plugin/plugin.h"
#include "engine/plugin/host.h"
#include "engine/plugin/command.h"
#include "engine/plugin/session.h"
#include "engine/plugin/static_registry.h"

/// @mainpage uranayzle Plugin SDK
///
/// @section intro Introduction
/// 
/// The uranayzle plugin SDK allows you to extend the binary analysis
/// framework with custom commands, analysis passes, binary loaders,
/// and more.
///
/// @section quickstart Quick Start
///
/// 1. Include the SDK header:
///    @code
///    #include <engine/plugin/sdk.h>
///    @endcode
///
/// 2. Create your plugin class:
///    @code
///    class MyPlugin : public engine::plugin::PluginBase {
///    public:
///        MyPlugin() : PluginBase({
///            .name = "My Plugin",
///            .version = "1.0.0",
///            .author = "Your Name",
///            .description = "Does something cool",
///            .api_version = engine::plugin::kCurrentApiVersion,
///        }) {}
///        
///        engine::plugin::Result initialize(engine::plugin::IHostContext* ctx) override {
///            ctx_ = ctx;
///            ctx->info("My plugin initialized!");
///            return engine::plugin::Result::Ok;
///        }
///        
///        void shutdown() override {
///            ctx_->info("My plugin shutting down");
///        }
///    };
///    @endcode
///
/// 3. Export the plugin entry point:
///    @code
///    URANAYZLE_DECLARE_PLUGIN(MyPlugin)
///    @endcode
///
/// @section commands Adding Commands
///
/// @code
/// class HelloCommand : public engine::plugin::CommandBase {
/// public:
///     const char* name() const override { return "hello"; }
///     const char* help() const override { return "Say hello"; }
///     
///     engine::plugin::Result execute(
///         engine::plugin::ISession* session,
///         engine::plugin::IOutput* output,
///         engine::plugin::IArgs* args) override 
///     {
///         output->write_line("Hello from plugin!");
///         return engine::plugin::Result::Ok;
///     }
/// };
///
/// // In plugin initialize():
/// ctx->register_command(new HelloCommand());
/// @endcode
