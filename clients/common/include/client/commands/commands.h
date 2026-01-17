#pragma once

#include "client/command.h"
#include "client/args.h"

namespace client::commands {

/// Register file-related commands: open, close, info, ph, sh, relocs
void register_file_commands(CommandRegistry& registry);

/// Register navigation commands: seek, pd, px
void register_navigation_commands(CommandRegistry& registry);

/// Register symbol-related commands: symbols, funcs, names, strings
void register_symbol_commands(CommandRegistry& registry);

/// Register IR commands: llir, mlil, hlil, hlilraw, pseudoc
void register_ir_commands(CommandRegistry& registry);

/// Register analysis commands: fdisc, franges, xrefs
void register_analysis_commands(CommandRegistry& registry);

/// Register debug info commands: dwarf, ehframe
void register_debug_commands(CommandRegistry& registry);

/// Register help and misc commands: help, quit
void register_help_commands(CommandRegistry& registry);

/// Register all default commands
void register_all_commands(CommandRegistry& registry);

}  // namespace client::commands
