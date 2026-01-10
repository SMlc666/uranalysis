#include "engine/symbols.h"

#include "engine/demangle.h"

#include <algorithm>

namespace engine::symbols {

void SymbolTable::reset() {
    entries_.clear();
    name_index_.clear();
}

void SymbolTable::populate(const std::vector<BinarySymbol>& symbols, const std::vector<BinarySection>& sections) {
    reset();
    entries_.reserve(symbols.size());

    for (std::size_t i = 0; i < symbols.size(); ++i) {
        const auto& sym = symbols[i];
        SymbolEntry entry;
        entry.name = sym.name;
        entry.demangled_name = demangle::symbol(sym.name);
        entry.address = sym.value;
        entry.size = sym.size;
        entry.info = sym.info;
        entry.other = sym.other;
        entry.section_index = sym.shndx;
        if (sym.shndx < sections.size()) {
            entry.section_name = sections[sym.shndx].name;
        }
        name_index_.emplace(entry.name, entries_.size());
        entries_.push_back(std::move(entry));
    }
}

const std::vector<SymbolEntry>& SymbolTable::entries() const {
    return entries_;
}

const SymbolEntry* SymbolTable::lookup_by_name(const std::string& name) const {
    const auto it = name_index_.find(name);
    if (it == name_index_.end()) {
        return nullptr;
    }
    const std::size_t idx = it->second;
    if (idx >= entries_.size()) {
        return nullptr;
    }
    return &entries_[idx];
}

std::vector<const SymbolEntry*> SymbolTable::within_range(std::uint64_t addr, std::size_t max_results) const {
    std::vector<const SymbolEntry*> result;
    if (entries_.empty() || max_results == 0) {
        return result;
    }
    result.reserve(max_results);
    for (const auto& entry : entries_) {
        if (entry.address <= addr && addr < entry.address + entry.size) {
            result.push_back(&entry);
            if (result.size() >= max_results) {
                break;
            }
        }
    }
    return result;
}

}  // namespace engine::symbols
