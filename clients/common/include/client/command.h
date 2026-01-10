#pragma once

#include <functional>
#include <string>
#include <vector>

#include "client/output.h"
#include "client/session.h"

namespace client {

struct Command {
    std::string name;
    std::vector<std::string> aliases;
    std::string help;
    std::function<bool(Session&, Output&, const std::vector<std::string>&)> handler;
};

class CommandRegistry {
public:
    void register_command(Command cmd);
    bool execute_line(const std::string& line, Session& session, Output& output);
    std::vector<std::string> command_names() const;

private:
    std::vector<Command> commands_;
};

CommandRegistry make_default_registry();

}  // namespace client
