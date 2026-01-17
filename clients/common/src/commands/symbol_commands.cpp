#include "client/commands/commands.h"
#include "client/formatters/address.h"
#include "client/formatters/symbols.h"
#include "engine/rtti.h"
#include "engine/strings.h"
#include "engine/symbols.h"

#include <sstream>

namespace client::commands {

void register_symbol_commands(CommandRegistry& registry) {
    // ==========================================================================
    // symbols - List all symbols
    // ==========================================================================
    registry.register_command(
        CommandV2("symbols", {"sym", "syms"})
            .description("List symbols from the binary")
            .requires_file()
            .positional("filter", "Filter by name (substring match)", false)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                std::string filter = m.get_or<std::string>("filter", "");
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
            }));

    // ==========================================================================
    // funcs - List function symbols
    // ==========================================================================
    registry.register_command(
        CommandV2("funcs", {"af", "fn", "functions"})
            .description("List function symbols")
            .requires_file()
            .positional("min_size", "Minimum function size (default: 1)", false, args::ValueType::Unsigned)
            .positional("filter", "Filter by name (substring match)", false)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                uint64_t min_size = m.get_or<uint64_t>("min_size", 1);
                std::string filter = m.get_or<std::string>("filter", "");
                const auto& symbols = session.symbol_table().entries();
                bool any = false;
                for (const auto& entry : symbols) {
                    if (!entry.is_function()) continue;
                    if (entry.size < min_size) continue;
                    if (!fmt::symbol_matches_filter(entry, filter)) continue;
                    
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
            }));

    // ==========================================================================
    // names - List symbols and RTTI names
    // ==========================================================================
    registry.register_command(
        CommandV2("names", {"n", "nm"})
            .description("List symbols, RTTI types, and vtables")
            .requires_file()
            .positional("filter", "Filter by name (substring match)", false)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                std::string filter = m.get_or<std::string>("filter", "");
                bool any = false;
                
                for (const auto& entry : session.symbol_table().entries()) {
                    if (!fmt::symbol_matches_filter(entry, filter)) continue;
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
                    if (!fmt::matches_filter(filter, name)) continue;
                    std::ostringstream oss;
                    oss << "type " << fmt::hex(type.address) << " vtable=" << fmt::hex(type.vtable_address)
                        << " " << name;
                    output.write_line(oss.str());
                    any = true;
                }
                
                for (const auto& vtable : session.rtti_catalog().vtables()) {
                    std::string name = vtable.type_name.empty() ? "<vtable>" : vtable.type_name;
                    if (!fmt::matches_filter(filter, name)) continue;
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
            }));

    // ==========================================================================
    // strings - List strings
    // ==========================================================================
    registry.register_command(
        CommandV2("strings", {"str", "strs"})
            .description("List strings found in the binary")
            .requires_file()
            .positional("min_length", "Minimum string length (default: 4)", false, args::ValueType::Unsigned)
            .positional("filter", "Filter by content (substring match)", false)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                size_t min_length = static_cast<size_t>(m.get_or<uint64_t>("min_length", 4));
                std::string filter = m.get_or<std::string>("filter", "");
                const auto& entries = session.string_catalog().entries();
                bool any = false;
                
                for (const auto& entry : entries) {
                    if (entry.length < min_length) continue;
                    if (!fmt::matches_filter(filter, entry.text)) continue;
                    
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
            }));
}

}  // namespace client::commands
