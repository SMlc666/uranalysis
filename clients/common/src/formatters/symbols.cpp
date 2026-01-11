#include "client/formatters/symbols.h"

#include "client/formatters/address.h"

namespace client::fmt {

std::string symbol_display_name(const engine::symbols::SymbolEntry& entry) {
    if (!entry.demangled_name.empty()) {
        return entry.demangled_name;
    }
    if (!entry.name.empty()) {
        return entry.name;
    }
    return "<anon>";
}

bool symbol_matches_filter(const engine::symbols::SymbolEntry& entry, const std::string& filter) {
    if (filter.empty()) {
        return true;
    }
    if (matches_filter(filter, entry.demangled_name)) {
        return true;
    }
    return matches_filter(filter, entry.name);
}

std::string dwarf_function_name(const engine::dwarf::DwarfFunction& func) {
    if (!func.name.empty()) {
        return func.name;
    }
    if (!func.linkage_name.empty()) {
        return func.linkage_name;
    }
    return "<anon>";
}

std::string dwarf_variable_name(const engine::dwarf::DwarfVariable& var) {
    if (!var.name.empty()) {
        return var.name;
    }
    if (!var.linkage_name.empty()) {
        return var.linkage_name;
    }
    return "<anon>";
}

}  // namespace client::fmt