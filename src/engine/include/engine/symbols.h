#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "engine/binary_format.h"

namespace engine::symbols {

struct SymbolEntry {
    std::string name;
    std::string demangled_name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::uint8_t info = 0;
    std::uint8_t other = 0;
    std::uint16_t section_index = 0;
    std::string section_name;

    bool is_function() const {
        constexpr std::uint8_t kMask = 0x0f;
        constexpr std::uint8_t kFunction = 0x02;
        return (info & kMask) == kFunction;
    }
};

class SymbolTable {
public:
    void reset();
    void populate(const std::vector<BinarySymbol>& symbols, const std::vector<BinarySection>& sections);

    const std::vector<SymbolEntry>& entries() const;
    const SymbolEntry* lookup_by_name(const std::string& name) const;
    std::vector<const SymbolEntry*> within_range(std::uint64_t addr, std::size_t max_results) const;

private:
    std::vector<SymbolEntry> entries_;
    std::unordered_map<std::string, std::size_t> name_index_;
};

}  // namespace engine::symbols
