#include "client/commands/commands.h"
#include "client/formatters/address.h"
#include "client/formatters/symbols.h"
#include "client/util/address_resolver.h"
#include "engine/dwarf.h"
#include "engine/eh_frame.h"
#include "engine/debug/log_channels.h"

#include <sstream>

namespace client::commands {

void register_debug_commands(CommandRegistry& registry) {
    // ==========================================================================
    // dwarf - Show DWARF debug information
    // ==========================================================================
    registry.register_command(
        CommandV2("dwarf", {"dw", "debug"})
            .description("Show DWARF debug information")
            .requires_file()
            .positional("subcmd", "Subcommand: funcs, vars, line", true)
            .positional("arg", "Filter pattern or address for line", false)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                const auto& catalog = session.dwarf_catalog();
                std::string sub = m.get<std::string>("subcmd");
                std::string arg = m.get_or<std::string>("arg", "");
                
                if (sub == "funcs" || sub == "fn" || sub == "functions") {
                    const auto& funcs = catalog.functions();
                    if (funcs.empty()) {
                        output.write_line("no dwarf functions");
                        return true;
                    }
                    bool any = false;
                    for (const auto& func : funcs) {
                        std::string name = fmt::dwarf_function_name(func);
                        if (!arg.empty() && !fmt::matches_filter(arg, name) &&
                            !fmt::matches_filter(arg, func.linkage_name)) {
                            continue;
                        }
                        std::ostringstream oss;
                        oss << fmt::hex(func.low_pc) << " - " << fmt::hex(func.high_pc) << " " << name;
                        if (!func.linkage_name.empty() && func.linkage_name != name) {
                            oss << " (" << func.linkage_name << ")";
                        }
                        if (func.decl_line != 0) {
                            oss << " line=" << func.decl_line;
                        }
                        if (!func.ranges.empty()) {
                            oss << " ranges=" << func.ranges.size();
                        }
                        output.write_line(oss.str());
                        any = true;
                    }
                    if (!any) {
                        output.write_line("no matching dwarf functions");
                    }
                    return true;
                }
                
                if (sub == "vars" || sub == "variables") {
                    const auto& vars = catalog.variables();
                    if (vars.empty()) {
                        output.write_line("no dwarf variables");
                        return true;
                    }
                    bool any = false;
                    for (const auto& var : vars) {
                        std::string name = fmt::dwarf_variable_name(var);
                        if (!arg.empty() && !fmt::matches_filter(arg, name) &&
                            !fmt::matches_filter(arg, var.linkage_name)) {
                            continue;
                        }
                        std::ostringstream oss;
                        oss << name;
                        if (!var.linkage_name.empty() && var.linkage_name != name) {
                            oss << " (" << var.linkage_name << ")";
                        }
                        if (!var.location_list.empty()) {
                            oss << " locs=" << var.location_list.size();
                        }
                        if (!var.location_expr.empty()) {
                            oss << " expr=" << var.location_expr.size();
                        }
                        output.write_line(oss.str());
                        any = true;
                    }
                    if (!any) {
                        output.write_line("no matching dwarf variables");
                    }
                    return true;
                }
                
                if (sub == "line" || sub == "ln") {
                    if (arg.empty()) {
                        output.write_line("usage: dwarf line <address>");
                        return true;
                    }
                    auto result = util::resolve_address(arg, session);
                    if (!result.success) {
                        output.write_line(result.error);
                        return true;
                    }
                    const auto* row = catalog.find_line_for_address(result.address);
                    if (!row) {
                        output.write_line("no line info for address");
                        return true;
                    }
                    std::ostringstream oss;
                    oss << fmt::hex(result.address) << " ";
                    if (!row->file.empty()) {
                        oss << row->file << ":";
                    }
                    oss << row->line;
                    output.write_line(oss.str());
                    return true;
                }
                
                output.write_line("unknown dwarf subcommand: " + sub);
                output.write_line("available: funcs, vars, line");
                return true;
            }));

    // ==========================================================================
    // log - Control logging levels by channel
    // ==========================================================================
    registry.register_command(
        CommandV2("log", {"loglevel", "ll"})
            .description("Control logging levels by channel")
            .positional("channel", "Channel: llir, mlil, hlil, pass, decompiler, loader, analysis, all", false)
            .positional("level", "Level: trace, debug, info, warn, error, off", false)
            .handler([](Session&, Output& output, const args::ArgMatches& m) {
                std::string channel_arg = m.get_or<std::string>("channel", "");
                std::string level_arg = m.get_or<std::string>("level", "");
                
                // No args: show current levels
                if (channel_arg.empty()) {
                    output.write_line("Current log levels:");
                    output.write_line("  llir       = " + std::string(engine::log::level_name(engine::log::get_channel_level(engine::log::Channel::kLlir))));
                    output.write_line("  mlil       = " + std::string(engine::log::level_name(engine::log::get_channel_level(engine::log::Channel::kMlil))));
                    output.write_line("  hlil       = " + std::string(engine::log::level_name(engine::log::get_channel_level(engine::log::Channel::kHlil))));
                    output.write_line("  pass       = " + std::string(engine::log::level_name(engine::log::get_channel_level(engine::log::Channel::kPass))));
                    output.write_line("  decompiler = " + std::string(engine::log::level_name(engine::log::get_channel_level(engine::log::Channel::kDecompiler))));
                    output.write_line("  loader     = " + std::string(engine::log::level_name(engine::log::get_channel_level(engine::log::Channel::kLoader))));
                    output.write_line("  analysis   = " + std::string(engine::log::level_name(engine::log::get_channel_level(engine::log::Channel::kAnalysis))));
                    output.write_line("");
                    output.write_line("Usage: log <channel> <level>");
                    output.write_line("  channel: llir, mlil, hlil, pass, decompiler, loader, analysis, all");
                    output.write_line("  level:   trace, debug, info, warn, error, off");
                    return true;
                }
                
                // Only channel given: show that channel's level
                if (level_arg.empty()) {
                    engine::log::Channel ch;
                    if (!engine::log::parse_channel(channel_arg, ch)) {
                        output.write_line("unknown channel: " + channel_arg);
                        return true;
                    }
                    output.write_line(channel_arg + " = " + engine::log::level_name(engine::log::get_channel_level(ch)));
                    return true;
                }
                
                // Both given: set the level
                engine::log::Channel ch;
                if (!engine::log::parse_channel(channel_arg, ch)) {
                    output.write_line("unknown channel: " + channel_arg);
                    return true;
                }
                
                spdlog::level::level_enum level;
                if (!engine::log::parse_level(level_arg, level)) {
                    output.write_line("unknown level: " + level_arg);
                    output.write_line("valid levels: trace, debug, info, warn, error, off");
                    return true;
                }
                
                engine::log::set_channel_level(ch, level);
                output.write_line("set " + channel_arg + " = " + engine::log::level_name(level));
                return true;
            }));

    // ==========================================================================
    // ehframe - List .eh_frame entries
    // ==========================================================================
    registry.register_command(
        CommandV2("ehframe", {"eh", "cfi"})
            .description("List .eh_frame entries (CFI)")
            .requires_file()
            .handler([](Session& session, Output& output, const args::ArgMatches&) {
                const auto& entries = session.eh_frame_catalog().entries();
                if (entries.empty()) {
                    output.write_line("no eh_frame entries");
                    return true;
                }
                for (const auto& entry : entries) {
                    std::ostringstream oss;
                    oss << fmt::hex(entry.start) << " size=" << fmt::hex(entry.size);
                    oss << " rows=" << entry.rows.size();
                    oss << " cie=" << fmt::hex(entry.cie);
                    output.write_line(oss.str());
                }
                return true;
            }));
}

}  // namespace client::commands
