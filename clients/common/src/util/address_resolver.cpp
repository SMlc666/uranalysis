#include "client/util/address_resolver.h"
#include <cstdlib>
#include <algorithm>

namespace client::util {

bool parse_number(const std::string& input, uint64_t& out) {
    if (input.empty()) return false;
    
    const char* str = input.c_str();
    char* end = nullptr;
    
    // Handle hex prefix (0x or 0X)
    if (input.size() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        out = std::strtoull(str + 2, &end, 16);
        // Verify the entire hex portion was consumed
        return end == str + input.size();
    } else {
        // Try decimal only - no implicit hex fallback
        // This prevents surprising behavior like "12ab" being parsed as hex
        out = std::strtoull(str, &end, 10);
    }
    
    return end == str + input.size();
}

std::optional<uint64_t> lookup_symbol(const std::string& name, const Session& session) {
    if (!session.loaded()) return std::nullopt;
    
    // Search in symbol table
    const auto& symbols = session.symbol_table().entries();
    for (const auto& sym : symbols) {
        if (sym.name == name || sym.demangled_name == name) {
            return sym.address;
        }
    }
    
    // Search in DWARF functions
    const auto& dwarf_funcs = session.dwarf_catalog().functions();
    for (const auto& func : dwarf_funcs) {
        if (func.name == name || func.linkage_name == name) {
            return func.low_pc;
        }
    }
    
    return std::nullopt;
}

AddressResult resolve_address(const std::string& input, const Session& session) {
    AddressResult result;
    
    if (input.empty()) {
        result.error = "empty address";
        return result;
    }
    
    std::string trimmed = input;
    
    // Handle current cursor
    if (trimmed == "." || trimmed == "$" || trimmed == "here") {
        result.success = true;
        result.address = session.cursor();
        return result;
    }
    
    // Handle entry point
    if (trimmed == "entry" || trimmed == "_start") {
        if (session.loaded()) {
            result.success = true;
            result.address = session.binary_info().entry;
            result.resolved_name = "entry";
            return result;
        }
    }
    
    // Handle relative addresses: +0x10, -0x20, .+0x10
    bool relative = false;
    uint64_t base = 0;
    
    if (trimmed[0] == '.') {
        base = session.cursor();
        trimmed = trimmed.substr(1);
        relative = true;
    }
    
    if (!trimmed.empty() && (trimmed[0] == '+' || trimmed[0] == '-')) {
        if (!relative) {
            base = session.cursor();
            relative = true;
        }
        
        bool negative = (trimmed[0] == '-');
        std::string offset_str = trimmed.substr(1);
        
        uint64_t offset = 0;
        if (parse_number(offset_str, offset)) {
            result.success = true;
            result.address = negative ? (base - offset) : (base + offset);
            return result;
        }
    }
    
    // Try parsing as number first
    uint64_t addr = 0;
    if (parse_number(trimmed, addr)) {
        result.success = true;
        result.address = addr;
        return result;
    }
    
    // Try symbol lookup
    auto sym_addr = lookup_symbol(trimmed, session);
    if (sym_addr.has_value()) {
        result.success = true;
        result.address = *sym_addr;
        result.resolved_name = trimmed;
        return result;
    }
    
    result.error = "invalid address or unknown symbol: " + input;
    return result;
}

} // namespace client::util
