/// @file plugin_test.cpp
/// @brief Unit tests for the plugin system

#include <catch2/catch_test_macros.hpp>

#include "engine/plugin/types.h"
#include "engine/plugin/object.h"
#include "engine/plugin/plugin.h"
#include "engine/plugin/host.h"
#include "engine/plugin/command.h"
#include "engine/plugin/manager.h"
#include "engine/plugin/static_registry.h"

using namespace engine::plugin;

// =============================================================================
// Test Helper Classes (defined at namespace scope for MSVC compatibility)
// =============================================================================

namespace {

/// A simple test plugin for unit tests
class TestPlugin : public PluginBase {
public:
    TestPlugin() : PluginBase({
        .name = "Test Plugin",
        .version = "1.0.0",
        .author = "Test Author",
        .description = "A plugin for testing",
        .api_version = kCurrentApiVersion,
    }) {}

    Result initialize(IHostContext* ctx) override {
        ctx_ = ctx;
        init_count_++;
        if (should_fail_init_) {
            return Result::Error;
        }
        return Result::Ok;
    }

    void shutdown() override {
        shutdown_count_++;
    }

    static int init_count_;
    static int shutdown_count_;
    static bool should_fail_init_;
    
    static void reset() {
        init_count_ = 0;
        shutdown_count_ = 0;
        should_fail_init_ = false;
    }
};

int TestPlugin::init_count_ = 0;
int TestPlugin::shutdown_count_ = 0;
bool TestPlugin::should_fail_init_ = false;

/// A test command for unit tests
class TestCommand : public CommandBase {
public:
    TestCommand() = default;
    
    const char* name() const override { return "testcmd"; }
    const char* help() const override { return "A test command"; }
    
    Result execute(ISession* session, IOutput* output, IArgs* args) override {
        execute_count_++;
        if (output) {
            output->write_line("TestCommand executed!");
        }
        return Result::Ok;
    }
    
    static int execute_count_;
    static void reset() { execute_count_ = 0; }
};

int TestCommand::execute_count_ = 0;

/// Test object for reference counting tests
class RefCountTestObject : public ObjectBase {
public:
    ~RefCountTestObject() override { destructor_count_++; }
    
    static int destructor_count_;
    static void reset() { destructor_count_ = 0; }
};

int RefCountTestObject::destructor_count_ = 0;

}  // namespace

// =============================================================================
// Type Tests
// =============================================================================

TEST_CASE("Plugin API version comparison", "[plugin][types]") {
    PluginApiVersion v1{1, 0, 0};
    PluginApiVersion v2{1, 1, 0};
    PluginApiVersion v3{2, 0, 0};
    PluginApiVersion host{1, 2, 0};

    SECTION("Same major, lower minor is compatible") {
        REQUIRE(v1.is_compatible_with(host));
        REQUIRE(v2.is_compatible_with(host));
    }

    SECTION("Different major is incompatible") {
        REQUIRE_FALSE(v3.is_compatible_with(host));
    }

    SECTION("Higher minor is incompatible") {
        PluginApiVersion higher{1, 5, 0};
        REQUIRE_FALSE(higher.is_compatible_with(host));
    }
}

TEST_CASE("StringView construction", "[plugin][types]") {
    SECTION("From nullptr") {
        StringView sv(nullptr);
        REQUIRE(sv.data == nullptr);
        REQUIRE(sv.size == 0);
    }

    SECTION("From C string") {
        StringView sv("hello");
        REQUIRE(sv.data != nullptr);
        REQUIRE(sv.size == 5);
    }

    SECTION("From C string with explicit size") {
        StringView sv("hello world", 5);
        REQUIRE(sv.size == 5);
    }
}

// =============================================================================
// Object Reference Counting Tests
// =============================================================================

TEST_CASE("ObjectBase reference counting", "[plugin][object]") {
    RefCountTestObject::reset();

    SECTION("Initial refcount is 1") {
        auto* obj = new RefCountTestObject();
        REQUIRE(obj->ref_count() == 1);
        obj->release();
        REQUIRE(RefCountTestObject::destructor_count_ == 1);
    }

    SECTION("Retain increases refcount") {
        RefCountTestObject::reset();
        auto* obj = new RefCountTestObject();
        obj->retain();
        REQUIRE(obj->ref_count() == 2);
        obj->release();
        REQUIRE(obj->ref_count() == 1);
        REQUIRE(RefCountTestObject::destructor_count_ == 0);
        obj->release();
        REQUIRE(RefCountTestObject::destructor_count_ == 1);
    }
}

TEST_CASE("Ref smart pointer", "[plugin][object]") {
    RefCountTestObject::reset();

    SECTION("Ref manages lifetime") {
        {
            Ref<RefCountTestObject> ref(new RefCountTestObject(), false); // adopt
            REQUIRE(ref->ref_count() == 1);
        }
        REQUIRE(RefCountTestObject::destructor_count_ == 1);
    }

    SECTION("Ref copy increases refcount") {
        RefCountTestObject::reset();
        auto* obj = new RefCountTestObject();
        {
            Ref<RefCountTestObject> ref1(obj, false);
            {
                Ref<RefCountTestObject> ref2 = ref1;
                REQUIRE(obj->ref_count() == 2);
            }
            REQUIRE(obj->ref_count() == 1);
            REQUIRE(RefCountTestObject::destructor_count_ == 0);
        }
        REQUIRE(RefCountTestObject::destructor_count_ == 1);
    }

    SECTION("Ref move doesn't change refcount") {
        RefCountTestObject::reset();
        auto* obj = new RefCountTestObject();
        {
            Ref<RefCountTestObject> ref1(obj, false);
            Ref<RefCountTestObject> ref2 = std::move(ref1);
            REQUIRE(obj->ref_count() == 1);
            REQUIRE(ref1.get() == nullptr);
        }
        REQUIRE(RefCountTestObject::destructor_count_ == 1);
    }

    SECTION("adopt_ref doesn't add reference") {
        RefCountTestObject::reset();
        auto* obj = new RefCountTestObject();
        REQUIRE(obj->ref_count() == 1);
        {
            auto ref = adopt_ref(obj);
            REQUIRE(obj->ref_count() == 1);
        }
        REQUIRE(RefCountTestObject::destructor_count_ == 1);
    }

    SECTION("make_ref adds reference") {
        RefCountTestObject::reset();
        auto* obj = new RefCountTestObject();
        REQUIRE(obj->ref_count() == 1);
        {
            auto ref = make_ref(obj);
            REQUIRE(obj->ref_count() == 2);
        }
        REQUIRE(obj->ref_count() == 1);
        obj->release();
        REQUIRE(RefCountTestObject::destructor_count_ == 1);
    }
}

// =============================================================================
// Plugin Tests
// =============================================================================

TEST_CASE("PluginBase metadata", "[plugin][plugin]") {
    TestPlugin plugin;
    
    const auto& meta = plugin.metadata();
    REQUIRE(std::string(meta.name) == "Test Plugin");
    REQUIRE(std::string(meta.version) == "1.0.0");
    REQUIRE(std::string(meta.author) == "Test Author");
    REQUIRE(meta.api_version.major == kCurrentApiVersion.major);
}

TEST_CASE("PluginBase reference counting", "[plugin][plugin]") {
    auto* plugin = new TestPlugin();
    REQUIRE(plugin->ref_count() == 1);
    
    plugin->retain();
    REQUIRE(plugin->ref_count() == 2);
    
    plugin->release();
    REQUIRE(plugin->ref_count() == 1);
    
    plugin->release();
    // Object deleted
}

// =============================================================================
// Static Plugin Registry Tests
// =============================================================================

TEST_CASE("Static plugin registry", "[plugin][static]") {
    // Clear any previous registrations
    StaticPluginRegistry::instance().clear();
    
    SECTION("Initially empty") {
        REQUIRE(StaticPluginRegistry::instance().entries().empty());
    }
    
    SECTION("Manual registration") {
        StaticPluginRegistry::instance().register_plugin("Test", []() -> IPlugin* {
            return new TestPlugin();
        });
        
        auto& entries = StaticPluginRegistry::instance().entries();
        REQUIRE(entries.size() == 1);
        REQUIRE(std::string(entries[0].name) == "Test");
        
        // Create and verify
        IPlugin* plugin = entries[0].create_func();
        REQUIRE(plugin != nullptr);
        REQUIRE(std::string(plugin->metadata().name) == "Test Plugin");
        plugin->release();
    }
    
    SECTION("Multiple registrations") {
        StaticPluginRegistry::instance().register_plugin("Plugin1", []() -> IPlugin* {
            return new TestPlugin();
        });
        StaticPluginRegistry::instance().register_plugin("Plugin2", []() -> IPlugin* {
            return new TestPlugin();
        });
        
        REQUIRE(StaticPluginRegistry::instance().entries().size() == 2);
    }
    
    // Clean up
    StaticPluginRegistry::instance().clear();
}

// =============================================================================
// Plugin Manager Tests
// =============================================================================

TEST_CASE("PluginManager basic operations", "[plugin][manager]") {
    TestPlugin::reset();
    
    PluginManager manager;
    manager.set_options({
        .plugin_directory = "",  // No dynamic plugins
        .auto_load = false,
        .fail_on_error = false,
    });
    
    SECTION("Register static plugin directly") {
        auto* plugin = new TestPlugin();
        bool result = manager.register_static_plugin(plugin, "TestPlugin");
        
        REQUIRE(result);
        REQUIRE(manager.plugins().size() == 1);
        REQUIRE(manager.plugins()[0].is_static);
        REQUIRE(manager.plugins()[0].initialized);
        REQUIRE(TestPlugin::init_count_ == 1);
        
        manager.shutdown_all();
        REQUIRE(TestPlugin::shutdown_count_ == 1);
    }
    
    SECTION("Static plugin init failure is handled") {
        TestPlugin::should_fail_init_ = true;
        
        auto* plugin = new TestPlugin();
        bool result = manager.register_static_plugin(plugin, "FailPlugin");
        
        REQUIRE_FALSE(result);
        REQUIRE(manager.plugins().empty());
    }
    
    SECTION("Nullptr plugin is rejected") {
        bool result = manager.register_static_plugin(nullptr, "NullPlugin");
        REQUIRE_FALSE(result);
    }
}

TEST_CASE("PluginManager loads static plugins from registry", "[plugin][manager]") {
    TestPlugin::reset();
    StaticPluginRegistry::instance().clear();
    
    // Register a static plugin
    StaticPluginRegistry::instance().register_plugin("TestStatic", []() -> IPlugin* {
        return new TestPlugin();
    });
    
    PluginManager manager;
    manager.set_options({.plugin_directory = ""});
    
    std::size_t loaded = manager.load_static_plugins();
    
    REQUIRE(loaded == 1);
    REQUIRE(manager.plugins().size() == 1);
    REQUIRE(manager.plugins()[0].is_static);
    REQUIRE(TestPlugin::init_count_ == 1);
    
    manager.shutdown_all();
    StaticPluginRegistry::instance().clear();
}

TEST_CASE("PluginManager discover with empty directory", "[plugin][manager]") {
    PluginManager manager;
    manager.set_options({.plugin_directory = ""});
    
    std::size_t found = manager.discover();
    REQUIRE(found == 0);
}

TEST_CASE("PluginManager discover with non-existent directory", "[plugin][manager]") {
    PluginManager manager;
    manager.set_options({.plugin_directory = "/path/that/does/not/exist/hopefully"});
    
    std::size_t found = manager.discover();
    REQUIRE(found == 0);
}

// =============================================================================
// Command Interface Tests
// =============================================================================

TEST_CASE("CommandBase implementation", "[plugin][command]") {
    TestCommand cmd;
    
    REQUIRE(std::string(cmd.name()) == "testcmd");
    REQUIRE(std::string(cmd.help()) == "A test command");
    REQUIRE(cmd.detailed_help() == nullptr);
    REQUIRE(cmd.aliases() == nullptr);
    REQUIRE_FALSE(cmd.requires_file());
}

TEST_CASE("Command reference counting", "[plugin][command]") {
    TestCommand::reset();
    
    auto* cmd = new TestCommand();
    REQUIRE(cmd->ref_count() == 1);
    
    cmd->retain();
    REQUIRE(cmd->ref_count() == 2);
    
    cmd->release();
    REQUIRE(cmd->ref_count() == 1);
    
    cmd->release();
    // Object should be deleted now
}
