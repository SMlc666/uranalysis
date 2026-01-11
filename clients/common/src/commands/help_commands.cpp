#include "client/commands/commands.h"

namespace client::commands {

void register_help_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "help",
        {"h", "?"},
        "help          show commands",
        [](Session&, Output& output, const std::vector<std::string>&) {
            output.write_line("Commands:");
            output.write_line("  open   close  info   ph      sh      relocs");
            output.write_line("  symbols funcs  names  strings xrefs");
            output.write_line("  seek   s      pd     px      llir    mlil");
            output.write_line("  hlil   hlilraw pseudoc");
            output.write_line("  fdisc  franges dwarf  ehframe");
            output.write_line("  help   quit   q      exit");
            return true;
        }});

    registry.register_command(Command{
        "quit",
        {"q", "exit"},
        "quit          exit",
        [](Session&, Output&, const std::vector<std::string>&) { return false; }});
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