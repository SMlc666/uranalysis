#include "client/commands/commands.h"

#include <sstream>

#include "client/formatters/address.h"
#include "client/formatters/symbols.h"
#include "engine/rtti.h"
#include "engine/strings.h"
#include "engine/symbols.h"

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

void register_symbol_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "symbols",
        {"sym"},
        "symbols [filter]  list symbols",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: symbols [filter]");
                return true;
            }
            std::string filter;
            if (args.size() >= 2) {
                filter = args[1];
            }
            const auto& symbols = session.symbol_table().entries();
            if (symbols.empty()) {
                output.write_line("no symbols");
                return true;
            }
            for (const auto& entry : symbols) {
                if (!fmt::symbol_matches_filter(entry, filter)) {
                    continue;
                }
                std::string name = fmt::symbol_display_name(entry);
                std::ostringstream oss;
                oss << fmt::hex(entry.address) << " size=" << fmt::hex(entry.size) << " "
                    << (entry.is_function() ? "func" : "data") << " " << name;
                if (!entry.demangled_name.empty() && !entry.name.empty() &&
                    entry.demangled_name != entry.name) {
                    oss << " (" << entry.name << ")";
                }
                if (!entry.section_name.empty()) {
                    oss << " [" << entry.section_name << "]";
                }
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "funcs",
        {"af"},
        "funcs [min] [filter]  list function symbols",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            std::uint64_t min_size = 1;
            std::string filter;
            if (args.size() >= 2) {
                std::uint64_t parsed = 0;
                if (fmt::parse_u64(args[1], parsed)) {
                    min_size = parsed;
                    if (args.size() >= 3) {
                        filter = args[2];
                    }
                    if (args.size() > 3) {
                        output.write_line("usage: funcs [min] [filter]");
                        return true;
                    }
                } else {
                    filter = args[1];
                    if (args.size() > 2) {
                        output.write_line("usage: funcs [min] [filter]");
                        return true;
                    }
                }
            }
            const auto& symbols = session.symbol_table().entries();
            bool any = false;
            for (const auto& entry : symbols) {
                if (!entry.is_function()) {
                    continue;
                }
                if (entry.size < min_size) {
                    continue;
                }
                if (!fmt::symbol_matches_filter(entry, filter)) {
                    continue;
                }
                std::ostringstream oss;
                oss << fmt::hex(entry.address) << " size=" << fmt::hex(entry.size) << " "
                    << fmt::symbol_display_name(entry);
                if (!entry.demangled_name.empty() && !entry.name.empty() &&
                    entry.demangled_name != entry.name) {
                    oss << " (" << entry.name << ")";
                }
                output.write_line(oss.str());
                any = true;
            }
            if (!any) {
                output.write_line("no matching functions");
            }
            return true;
        }});

    registry.register_command(Command{
        "names",
        {},
        "names [filter]  list symbols and RTTI names",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: names [filter]");
                return true;
            }
            std::string filter;
            if (args.size() >= 2) {
                filter = args[1];
            }
            bool any = false;
            for (const auto& entry : session.symbol_table().entries()) {
                if (!fmt::symbol_matches_filter(entry, filter)) {
                    continue;
                }
                std::ostringstream oss;
                oss << "symbol " << fmt::hex(entry.address) << " size=" << fmt::hex(entry.size) << " "
                    << fmt::symbol_display_name(entry);
                if (!entry.section_name.empty()) {
                    oss << " [" << entry.section_name << "]";
                }
                output.write_line(oss.str());
                any = true;
            }
            for (const auto& type : session.rtti_catalog().types()) {
                std::string name = type.name.empty() ? "<unnamed type>" : type.name;
                if (!fmt::matches_filter(filter, name)) {
                    continue;
                }
                std::ostringstream oss;
                oss << "type " << fmt::hex(type.address) << " vtable=" << fmt::hex(type.vtable_address)
                    << " " << name;
                output.write_line(oss.str());
                any = true;
            }
            for (const auto& vtable : session.rtti_catalog().vtables()) {
                std::string name = vtable.type_name.empty() ? "<vtable>" : vtable.type_name;
                if (!fmt::matches_filter(filter, name)) {
                    continue;
                }
                std::ostringstream oss;
                oss << "vtable " << fmt::hex(vtable.address) << " entries=" << vtable.entries.size()
                    << " " << name;
                output.write_line(oss.str());
                any = true;
            }
            if (!any) {
                output.write_line("no matching names");
            }
            return true;
        }});

    registry.register_command(Command{
        "strings",
        {"str"},
        "strings [min] [filter]  list strings",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            std::size_t min_length = 4;
            std::string filter;
            if (args.size() >= 2) {
                std::uint64_t parsed = 0;
                if (fmt::parse_u64(args[1], parsed)) {
                    min_length = static_cast<std::size_t>(parsed);
                    if (args.size() >= 3) {
                        filter = args[2];
                    }
                    if (args.size() > 3) {
                        output.write_line("usage: strings [min] [filter]");
                        return true;
                    }
                } else {
                    filter = args[1];
                    if (args.size() > 2) {
                        output.write_line("usage: strings [min] [filter]");
                        return true;
                    }
                }
            }
            const auto& entries = session.string_catalog().entries();
            bool any = false;
            for (const auto& entry : entries) {
                if (entry.length < min_length) {
                    continue;
                }
                if (!fmt::matches_filter(filter, entry.text)) {
                    continue;
                }
                std::ostringstream oss;
                oss << fmt::hex(entry.address) << " len=" << entry.length;
                if (!entry.section_name.empty()) {
                    oss << " [" << entry.section_name << "]";
                }
                if (!entry.symbol_name.empty()) {
                    oss << " sym=" << entry.symbol_name;
                }
                if (!entry.text.empty()) {
                    oss << " " << entry.text;
                }
                output.write_line(oss.str());
                any = true;
            }
            if (!any) {
                output.write_line("no matching strings");
            }
            return true;
        }});
}

}  // namespace client::commands