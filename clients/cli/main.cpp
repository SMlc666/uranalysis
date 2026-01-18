#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

#include "client/command.h"
#include "client/output.h"
#include "client/plugin/command_bridge.h"
#include "client/session.h"
#include "engine/api.h"
#include "engine/log.h"
#include "engine/plugin/manager.h"
#include "replxx.hxx"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <filesystem>


namespace {

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [options]\n";
    std::cerr << "Options:\n";
    std::cerr << "  -e, --execute <cmd>   Execute a single command and exit\n";
    std::cerr << "  -s, --script <file>   Execute commands from a script file (use - for stdin)\n";
    std::cerr << "  -q, --quiet           Suppress banner in interactive mode\n";
    std::cerr << "  -h, --help            Show this help message\n";
    std::cerr << "\n";
    std::cerr << "If no options are given, starts in interactive mode.\n";
    std::cerr << "Pipe input is automatically detected and read from stdin.\n";
}

bool run_stdin(client::CommandRegistry& registry,
               client::Session& session,
               client::Output& output) {
    std::vector<std::string> commands;
    std::string line;
    while (std::getline(std::cin, line)) {
        commands.push_back(line);
    }

    for (const auto& cmd : commands) {
        if (cmd.empty()) {
            continue;
        }
        // Skip comment lines
        if (cmd[0] == '#') {
            continue;
        }
        if (!registry.execute_line(cmd, session, output)) {
            return true;  // quit command was issued
        }
    }
    return true;
}

bool run_interactive(client::CommandRegistry& registry,
                     client::Session& session,
                     client::Output& output,
                     bool quiet) {
    if (!quiet) {
        auto info = engine::get_engine_info();
        std::cout << info.name << " " << info.version << "\n";
        std::cout << "Type 'help' for commands.\n";
    }

    auto command_names = registry.command_names();

    replxx::Replxx rx;
    const std::string history_path = ".uranayzle_history";
    rx.set_max_history_size(200);
    rx.history_load(history_path);
    rx.set_completion_callback([&command_names](std::string const& input, int& context_len) {
        replxx::Replxx::completions_t completions;
        context_len = static_cast<int>(input.size());
        for (const auto& cmd : command_names) {
            if (cmd.rfind(input, 0) == 0) {
                completions.push_back(cmd);
            }
        }
        return completions;
    });

    while (true) {
        char const* input = rx.input("uranayzle> ");
        if (!input) {
            break;
        }
        std::string line = input;
        if (!line.empty()) {
            rx.history_add(line);
            rx.history_save(history_path);
        }

        if (!registry.execute_line(line, session, output)) {
            break;
        }
    }

    return true;
}

bool run_commands(client::CommandRegistry& registry,
                  client::Session& session,
                  client::Output& output,
                  const std::vector<std::string>& commands) {
    for (const auto& line : commands) {
        if (line.empty()) {
            continue;
        }
        // Skip comment lines
        if (!line.empty() && line[0] == '#') {
            continue;
        }
        if (!registry.execute_line(line, session, output)) {
            return true;  // quit command was issued
        }
    }
    return true;
}

bool run_script(client::CommandRegistry& registry,
                client::Session& session,
                client::Output& output,
                const std::string& script_path) {
    std::ifstream file(script_path);
    if (!file.is_open()) {
        std::cerr << "Error: cannot open script file: " << script_path << "\n";
        return false;
    }

    std::vector<std::string> commands;
    std::string line;
    while (std::getline(file, line)) {
        commands.push_back(line);
    }

    return run_commands(registry, session, output, commands);
}

}  // namespace

int main(int argc, char* argv[]) {
    std::vector<std::string> execute_commands;
    std::string script_path;
    bool quiet = false;

    // Initialize engine logging (use stderr to not interfere with command output)
    engine::log::init();
    auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    engine::log::add_sink(console_sink);

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        } else if (arg == "-e" || arg == "--execute") {
            if (i + 1 >= argc) {
                std::cerr << "Error: -e/--execute requires an argument\n";
                return 1;
            }
            execute_commands.push_back(argv[++i]);
        } else if (arg == "-s" || arg == "--script") {
            if (i + 1 >= argc) {
                std::cerr << "Error: -s/--script requires an argument\n";
                return 1;
            }
            script_path = argv[++i];
        } else {
            std::cerr << "Error: unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    client::Session session;
    client::StdoutOutput output;
    auto registry = client::make_default_registry();
    
    // Initialize plugin system (must be declared before command_bridge so it's destroyed after)
    engine::plugin::PluginManager plugin_manager;
    
    // Command bridge for plugin commands (destroyed before plugin_manager unloads DLLs)
    client::plugin::PluginCommandBridge command_bridge(registry, &session);
    
    // Determine plugin directory: check next to executable first, then current directory
    std::filesystem::path exe_dir = std::filesystem::path(argv[0]).parent_path();
    if (exe_dir.empty()) exe_dir = std::filesystem::current_path();
    
    std::filesystem::path plugin_dir = exe_dir / "plugins";
    if (!std::filesystem::exists(plugin_dir)) {
        // Fallback to current working directory
        plugin_dir = std::filesystem::current_path() / "plugins";
    }
    
    if (std::filesystem::exists(plugin_dir)) {
        plugin_manager.set_options({
            .plugin_directory = plugin_dir.string(),
            .auto_load = true,
            .fail_on_error = false,
        });
        plugin_manager.set_command_registry(&registry);
        plugin_manager.set_session(&session);
        
        // Set up command registration callback
        plugin_manager.set_command_register_callback([&command_bridge](engine::plugin::ICommand* cmd) {
            return command_bridge.register_command(cmd);
        });
        
        std::size_t loaded = plugin_manager.discover_and_load();
        if (loaded > 0 && !quiet) {
            std::cout << "Loaded " << loaded << " plugin(s)\n";
        }
    }

    // Execute commands from -e options
    if (!execute_commands.empty()) {
        return run_commands(registry, session, output, execute_commands) ? 0 : 1;
    }

    // Execute script from -s option
    if (!script_path.empty()) {
        // Special case: "-" means read from stdin
        if (script_path == "-") {
            return run_stdin(registry, session, output) ? 0 : 1;
        }
        return run_script(registry, session, output, script_path) ? 0 : 1;
    }

    // Check if stdin is a pipe (not a tty)
    if (!isatty(fileno(stdin))) {
        return run_stdin(registry, session, output) ? 0 : 1;
    }

    // Interactive mode
    run_interactive(registry, session, output, quiet);
    return 0;
}
