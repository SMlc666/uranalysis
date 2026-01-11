#include "client/commands/commands.h"

#include <sstream>

#include "client/formatters/address.h"
#include "client/formatters/symbols.h"
#include "engine/dwarf.h"
#include "engine/eh_frame.h"

namespace client::commands {

namespace {

bool require_loaded(const Session& session, Output& output) {
    if (!session.loaded()) {
        output.write_line("no file loaded, use: open <path>");
        return false;
    }
    return true;
}

}  // namespace

void register_debug_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "dwarf",
        {},
        "dwarf <funcs|vars|line>  show DWARF data",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2) {
                output.write_line("usage: dwarf <funcs|vars|line>");
                output.write_line("  dwarf funcs [filter]");
                output.write_line("  dwarf vars [filter]");
                output.write_line("  dwarf line <addr>");
                return true;
            }
            const auto& catalog = session.dwarf_catalog();
            const std::string& sub = args[1];
            if (sub == "funcs") {
                if (args.size() > 3) {
                    output.write_line("usage: dwarf funcs [filter]");
                    return true;
                }
                std::string filter;
                if (args.size() == 3) {
                    filter = args[2];
                }
                const auto& funcs = catalog.functions();
                if (funcs.empty()) {
                    output.write_line("no dwarf functions");
                    return true;
                }
                bool any = false;
                for (const auto& func : funcs) {
                    std::string name = fmt::dwarf_function_name(func);
                    if (!fmt::matches_filter(filter, name) &&
                        !fmt::matches_filter(filter, func.linkage_name)) {
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
            if (sub == "vars") {
                if (args.size() > 3) {
                    output.write_line("usage: dwarf vars [filter]");
                    return true;
                }
                std::string filter;
                if (args.size() == 3) {
                    filter = args[2];
                }
                const auto& vars = catalog.variables();
                if (vars.empty()) {
                    output.write_line("no dwarf variables");
                    return true;
                }
                bool any = false;
                for (const auto& var : vars) {
                    std::string name = fmt::dwarf_variable_name(var);
                    if (!fmt::matches_filter(filter, name) &&
                        !fmt::matches_filter(filter, var.linkage_name)) {
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
            if (sub == "line") {
                if (args.size() != 3) {
                    output.write_line("usage: dwarf line <addr>");
                    return true;
                }
                std::uint64_t addr = 0;
                if (!fmt::parse_u64(args[2], addr)) {
                    output.write_line("invalid address: " + args[2]);
                    return true;
                }
                const auto* row = catalog.find_line_for_address(addr);
                if (!row) {
                    output.write_line("no line info for address");
                    return true;
                }
                std::ostringstream oss;
                oss << fmt::hex(addr) << " ";
                if (!row->file.empty()) {
                    oss << row->file << ":";
                }
                oss << row->line;
                output.write_line(oss.str());
                return true;
            }
            output.write_line("unknown dwarf command: " + sub);
            return true;
        }});

    registry.register_command(Command{
        "ehframe",
        {},
        "ehframe       list .eh_frame entries",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
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
        }});
}

}  // namespace client::commands