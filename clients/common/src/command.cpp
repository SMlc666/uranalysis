#include "client/command.h"

#include <iostream>
#include <memory>
#include <sstream>

namespace client {

namespace {

std::vector<std::string> split_words(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> out;
    std::string word;
    while (iss >> word) {
        out.push_back(word);
    }
    return out;
}

bool matches_command(const Command& cmd, const std::string& name) {
    if (cmd.name == name) {
        return true;
    }
    for (const auto& alias : cmd.aliases) {
        if (alias == name) {
            return true;
        }
    }
    return false;
}

}  // namespace

void CommandRegistry::register_command(Command cmd) {
    commands_.push_back(std::move(cmd));
}

bool CommandRegistry::execute_line(const std::string& line, Session& session, Output& output) {
    // Parse redirection and pipe
    RedirectInfo redirect = parse_redirect(line);
    
    // Create appropriate output
    std::unique_ptr<FileOutput> file_output;
    std::unique_ptr<StringOutput> string_output;
    Output* effective_output = &output;
    
    if (!redirect.pipe_command.empty()) {
        // Pipe mode: capture output to string first
        string_output = std::make_unique<StringOutput>();
        effective_output = string_output.get();
    } else if (!redirect.redirect_path.empty()) {
        // File redirect mode
        file_output = std::make_unique<FileOutput>(redirect.redirect_path, redirect.append);
        if (!file_output->is_open()) {
            std::cerr << "Error: cannot open file for writing: " << redirect.redirect_path << "\n";
            return true;
        }
        effective_output = file_output.get();
    }
    
    auto args = split_words(redirect.command);
    if (args.empty()) {
        return true;
    }

    const std::string& cmd_name = args[0];
    bool found = false;
    bool result = true;
    
    for (const auto& cmd : commands_) {
        if (matches_command(cmd, cmd_name)) {
            result = cmd.handler(session, *effective_output, args);
            found = true;
            break;
        }
    }

    if (!found) {
        effective_output->write_line("unknown command: " + cmd_name);
    }
    
    // If we were in pipe mode, execute the external command with the captured output
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
    out.reserve(commands_.size());
    for (const auto& cmd : commands_) {
        out.push_back(cmd.name);
        for (const auto& alias : cmd.aliases) {
            out.push_back(alias);
        }
    }
    return out;
}

}  // namespace client
