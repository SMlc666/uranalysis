#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "client/output.h"
#include "client/session.h"
#include "client/args/arg_parser.h"

namespace client {

// =============================================================================
// Legacy Command (v1) - for backwards compatibility
// =============================================================================

struct Command {
    std::string name;
    std::vector<std::string> aliases;
    std::string help;
    std::function<bool(Session&, Output&, const std::vector<std::string>&)> handler;
};

// =============================================================================
// Modern Command (v2) - with integrated ArgParser
// =============================================================================

/**
 * @brief Modern command with built-in argument parsing.
 * 
 * Usage:
 *   CommandV2 cmd("seek", {"s"});
 *   cmd.description("Seek to an address or symbol")
 *      .positional("target", "Address (0x...) or symbol name")
 *      .flag('v', "verbose", "Show detailed output")
 *      .handler([](Session& s, Output& o, const args::ArgMatches& m) {
 *          auto target = m.get<std::string>("target");
 *          // ...
 *          return true;
 *      });
 */
class CommandV2 {
public:
    using Handler = std::function<bool(Session&, Output&, const args::ArgMatches&)>;
    
    explicit CommandV2(std::string name, std::vector<std::string> aliases = {});

    // Builder methods for command metadata
    CommandV2& description(std::string desc);
    CommandV2& requires_file(bool val = true);  // Auto-check if file is loaded

    // Builder methods for arguments (delegate to ArgParser)
    CommandV2& positional(const std::string& name, const std::string& help,
                          bool required = true, args::ValueType type = args::ValueType::String);
    CommandV2& flag(char short_name, const std::string& long_name, const std::string& help);
    CommandV2& option(char short_name, const std::string& long_name, const std::string& help,
                      args::ValueType type = args::ValueType::String);

    // Set the handler
    CommandV2& handler(Handler h);

    // Accessors
    const std::string& name() const { return name_; }
    const std::vector<std::string>& aliases() const { return aliases_; }
    const args::ArgParser& parser() const { return parser_; }
    std::string help() const;          // Short help (one-liner)
    std::string detailed_help() const; // Full help with args
    bool needs_file() const { return requires_file_; }

    // Execute the command
    bool execute(Session& session, Output& output, const std::vector<std::string>& args) const;

private:
    std::string name_;
    std::vector<std::string> aliases_;
    std::string description_;
    args::ArgParser parser_;
    Handler handler_;
    bool requires_file_ = false;
};

// =============================================================================
// CommandRegistry - supports both v1 and v2 commands
// =============================================================================

class CommandRegistry {
public:
    void register_command(Command cmd);
    void register_command(CommandV2 cmd);
    
    bool execute_line(const std::string& line, Session& session, Output& output);
    std::vector<std::string> command_names() const;
    
    // Get help for a specific command (for "help <cmd>")
    std::string get_command_help(const std::string& name) const;
    
    // Get all commands for help listing
    struct CommandInfo {
        std::string name;
        std::vector<std::string> aliases;
        std::string help;
        bool is_v2;
    };
    std::vector<CommandInfo> all_commands() const;

private:
    std::vector<Command> commands_v1_;
    std::vector<CommandV2> commands_v2_;
};

CommandRegistry make_default_registry();

}  // namespace client
