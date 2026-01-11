// This file is now a compatibility shim that delegates to modular commands.
// The actual command implementations are in clients/common/src/commands/*.cpp

#include "client/command.h"
#include "client/commands/commands.h"

namespace client {

CommandRegistry make_default_registry() {
    CommandRegistry registry;
    commands::register_all_commands(registry);
    return registry;
}

}  // namespace client
