#pragma once

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "engine/binary_format.h"
#include "engine/image.h"

namespace engine::ehframe {

struct CfaState {
    int cfa_reg = -1;
    int cfa_offset = 0;
    std::vector<std::uint8_t> cfa_expr;
    std::unordered_map<int, int> saved;
    std::unordered_map<int, std::vector<std::uint8_t>> expr;
    std::unordered_map<int, std::vector<std::uint8_t>> val_expr;
    std::unordered_set<int> same_value;
    std::unordered_set<int> undefined;
};

struct CieEntry {
    std::uint64_t address = 0;
    std::uint8_t fde_encoding = 0;
    std::uint64_t code_align = 0;
    std::int64_t data_align = 0;
    std::uint64_t return_reg = 0;
    std::vector<std::uint8_t> instructions;
    CfaState initial;
};

struct CfaRow {
    std::uint64_t pc = 0;
    CfaState state;
};

struct FdeEntry {
    std::uint64_t start = 0;
    std::uint64_t size = 0;
    std::uint64_t cie = 0;
    std::vector<std::uint8_t> instructions;
    CfaState cfa;
    std::vector<CfaRow> rows;
};

class EhFrameCatalog {
public:
    void reset();
    void discover(const std::vector<BinarySection>& sections, const LoadedImage& image, const BinaryInfo& binary_info);

    const std::vector<FdeEntry>& entries() const;
    const std::vector<CieEntry>& cies() const;
    const FdeEntry* find_fde_for_address(std::uint64_t addr) const;
    const CfaRow* find_cfa_row(std::uint64_t addr) const;

private:
    std::vector<CieEntry> cies_;
    std::vector<FdeEntry> entries_;
};

}  // namespace engine::ehframe
