#pragma once

#include <string>

#include "engine/dwarf.h"
#include "engine/symbols.h"

namespace client::fmt {

/// Get display name for a symbol (demangled > name > "<anon>")
std::string symbol_display_name(const engine::symbols::SymbolEntry& entry);

/// Check if symbol matches filter (matches demangled or raw name)
bool symbol_matches_filter(const engine::symbols::SymbolEntry& entry, const std::string& filter);

/// Get display name for DWARF function (name > linkage_name > "<anon>")
std::string dwarf_function_name(const engine::dwarf::DwarfFunction& func);

/// Get display name for DWARF variable (name > linkage_name > "<anon>")
std::string dwarf_variable_name(const engine::dwarf::DwarfVariable& var);

}  // namespace client::fmt