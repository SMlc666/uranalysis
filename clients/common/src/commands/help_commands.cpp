#include "client/commands/commands.h"

#include <sstream>

namespace client::commands {

void register_help_commands(CommandRegistry& registry) {
    // ==========================================================================
    // help - Show help
    // ==========================================================================
    registry.register_command(
        CommandV2("help", {"h", "?"})
            .description("Show commands or help for a specific command")
            .positional("command", "Command name for detailed help", false)
            .handler([&registry](Session&, Output& output, const args::ArgMatches& m) {
                if (m.has("command")) {
                    output.write_line(registry.get_command_help(m.get<std::string>("command")));
                    return true;
                }
                
                output.write_line("Commands:");
                output.write_line("");
                output.write_line("  File:       open, close, info, ph, sh, relocs");
                output.write_line("  Navigation: seek, pd, px, where");
                output.write_line("  Symbols:    symbols, funcs, names, strings");
                output.write_line("  IR:         llir, mlil, hlil, hlilraw, pseudoc");
                output.write_line("  Analysis:   xrefs, fdisc, franges");
                output.write_line("  Debug:      dwarf, ehframe");
                output.write_line("  Misc:       help, quit");
                output.write_line("");
                output.write_line("Type 'help <command>' for detailed usage.");
                output.write_line("Type '<command> --help' for argument help.");
                return true;
            }));

    // ==========================================================================
    // quit - Exit the program
    // ==========================================================================
    registry.register_command(
        CommandV2("quit", {"q", "exit", "bye"})
            .description("Exit the program")
            .handler([](Session&, Output&, const args::ArgMatches&) {
                return false;
            }));

    // ==========================================================================
    // clear - Clear output (placeholder for REPL)
    // ==========================================================================
    registry.register_command(
        CommandV2("clear", {"cls"})
            .description("Clear the screen")
            .handler([](Session&, Output& output, const args::ArgMatches&) {
                // ANSI escape for clear screen
                output.write_line("\033[2J\033[H");
                return true;
            }));
}

void register_all_commands(CommandRegistry& registry) {
    register_file_commands(registry);
    register_navigation_commands(registry);
    register_symbol_commands(registry);
    register_ir_commands(registry);
    register_analysis_commands(registry);
    register_debug_commands(registry);
    register_help_commands(registry);
}

}  // namespace client::commands
