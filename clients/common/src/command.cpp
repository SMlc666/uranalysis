#include "client/command.h"
#include "client/tokenizer.h"

#include <iostream>
#include <memory>
#include <sstream>

namespace client {

namespace {

// Legacy split_words for backwards compatibility (used for v1 commands)
std::vector<std::string> split_words(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> out;
    std::string word;
    while (iss >> word) {
        out.push_back(word);
    }
    return out;
}

bool matches_name(const std::string& cmd_name, const std::vector<std::string>& aliases, 
                  const std::string& input) {
    if (cmd_name == input) return true;
    for (const auto& alias : aliases) {
        if (alias == input) return true;
    }
    return false;
}

}  // namespace

// =============================================================================
// CommandV2 Implementation
// =============================================================================

CommandV2::CommandV2(std::string name, std::vector<std::string> aliases)
    : name_(std::move(name))
    , aliases_(std::move(aliases))
    , parser_(name_) {}

CommandV2& CommandV2::description(std::string desc) {
    description_ = std::move(desc);
    parser_.description(description_);
    return *this;
}

CommandV2& CommandV2::requires_file(bool val) {
    requires_file_ = val;
    return *this;
}

CommandV2& CommandV2::positional(const std::string& name, const std::string& help,
                                  bool required, args::ValueType type) {
    parser_.positional(name, help, required, type);
    return *this;
}

CommandV2& CommandV2::flag(char short_name, const std::string& long_name, const std::string& help) {
    parser_.flag(long_name, short_name, long_name, help);
    return *this;
}

CommandV2& CommandV2::option(char short_name, const std::string& long_name, const std::string& help,
                              args::ValueType type) {
    parser_.option(long_name, short_name, long_name, help, type);
    return *this;
}

CommandV2& CommandV2::handler(Handler h) {
    handler_ = std::move(h);
    return *this;
}

std::string CommandV2::help() const {
    // Short one-liner help
    std::ostringstream oss;
    oss << parser_.usage();
    if (!description_.empty()) {
        oss << "  - " << description_;
    }
    return oss.str();
}

std::string CommandV2::detailed_help() const {
    return parser_.help();
}

bool CommandV2::execute(Session& session, Output& output, const std::vector<std::string>& args) const {
    // Parse arguments first (to handle --help before file check)
    auto result = parser_.parse(args);
    
    // Handle help request (always works, even without file loaded)
    if (result.help_requested()) {
        output.write_line(parser_.help());
        return true;
    }
    
    // Handle parse errors
    if (!result.ok()) {
        output.write_line("Error: " + result.error());
        output.write_line("Usage: " + parser_.usage());
        return true;
    }
    
    // Check if file is required (after help/errors, before execution)
    if (requires_file_ && !session.loaded()) {
        output.write_line("no file loaded, use: open <path>");
        return true;
    }
    
    // Execute handler
    if (handler_) {
        return handler_(session, output, result.matches());
    }
    
    // No handler - command not implemented, return false to signal error
    output.write_line("error: command not implemented: " + name_);
    return false;
}

// =============================================================================
// CommandRegistry Implementation
// =============================================================================

void CommandRegistry::register_command(Command cmd) {
    commands_v1_.push_back(std::move(cmd));
}

void CommandRegistry::register_command(CommandV2 cmd) {
    commands_v2_.push_back(std::move(cmd));
}

bool CommandRegistry::execute_line(const std::string& line, Session& session, Output& output) {
    // Parse redirection and pipe
    RedirectInfo redirect = parse_redirect(line);
    
    // Create appropriate output
    std::unique_ptr<FileOutput> file_output;
    std::unique_ptr<StringOutput> string_output;
    Output* effective_output = &output;
    
    if (!redirect.pipe_command.empty()) {
        string_output = std::make_unique<StringOutput>();
        effective_output = string_output.get();
    } else if (!redirect.redirect_path.empty()) {
        file_output = std::make_unique<FileOutput>(redirect.redirect_path, redirect.append);
        if (!file_output->is_open()) {
            std::cerr << "Error: cannot open file for writing: " << redirect.redirect_path << "\n";
            return true;
        }
        effective_output = file_output.get();
    }
    
    // Try to tokenize with new tokenizer, fall back to split_words on error
    std::vector<std::string> args;
    try {
        args = Tokenizer::tokenize(redirect.command);
    } catch (const Tokenizer::ParseError& e) {
        // Fall back to simple split for backwards compatibility
        args = split_words(redirect.command);
    }
    
    if (args.empty()) {
        return true;
    }

    const std::string& cmd_name = args[0];
    bool found = false;
    bool result = true;
    
    // Try V2 commands first (newer, preferred)
    for (const auto& cmd : commands_v2_) {
        if (matches_name(cmd.name(), cmd.aliases(), cmd_name)) {
            result = cmd.execute(session, *effective_output, args);
            found = true;
            break;
        }
    }
    
    // Fall back to V1 commands
    if (!found) {
        for (const auto& cmd : commands_v1_) {
            if (matches_name(cmd.name, cmd.aliases, cmd_name)) {
                result = cmd.handler(session, *effective_output, args);
                found = true;
                break;
            }
        }
    }

    if (!found) {
        effective_output->write_line("unknown command: " + cmd_name);
    }
    
    // Handle pipe output
    if (string_output && !redirect.pipe_command.empty()) {
        std::string captured = string_output->get_output();
        if (!captured.empty()) {
            execute_external_command(redirect.pipe_command, captured);
        }
    }
    
    return result;
}

std::vector<std::string> CommandRegistry::command_names() const {
    std::vector<std::string> out;
    out.reserve(commands_v1_.size() + commands_v2_.size());
    
    for (const auto& cmd : commands_v2_) {
        out.push_back(cmd.name());
        for (const auto& alias : cmd.aliases()) {
            out.push_back(alias);
        }
    }
    
    for (const auto& cmd : commands_v1_) {
        out.push_back(cmd.name);
        for (const auto& alias : cmd.aliases) {
            out.push_back(alias);
        }
    }
    
    return out;
}

std::string CommandRegistry::get_command_help(const std::string& name) const {
    // Check V2 commands
    for (const auto& cmd : commands_v2_) {
        if (matches_name(cmd.name(), cmd.aliases(), name)) {
            return cmd.detailed_help();
        }
    }
    
    // Check V1 commands
    for (const auto& cmd : commands_v1_) {
        if (matches_name(cmd.name, cmd.aliases, name)) {
            return cmd.help;
        }
    }
    
    return "unknown command: " + name;
}

std::vector<CommandRegistry::CommandInfo> CommandRegistry::all_commands() const {
    std::vector<CommandInfo> result;
    
    for (const auto& cmd : commands_v2_) {
        result.push_back({cmd.name(), cmd.aliases(), cmd.help(), true});
    }
    
    for (const auto& cmd : commands_v1_) {
        result.push_back({cmd.name, cmd.aliases, cmd.help, false});
    }
    
    return result;
}

}  // namespace client
