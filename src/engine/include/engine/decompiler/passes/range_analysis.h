#pragma once

#include "engine/decompiler.h"
#include <unordered_map>
#include <string>
#include <cstdint>

namespace engine::decompiler::passes {

struct Range {
    uint64_t min_val;
    uint64_t max_val;
    uint64_t stride; // 0 for singleton, 1 for contiguous
    uint64_t offset; // value % stride == offset

    Range() : min_val(0), max_val(UINT64_MAX), stride(1), offset(0) {}
    Range(uint64_t min, uint64_t max, uint64_t s = 1, uint64_t o = 0) 
        : min_val(min), max_val(max), stride(s), offset(o) {}

    bool is_singleton() const { return min_val == max_val; }
    bool is_full() const { return min_val == 0 && max_val == UINT64_MAX; }
    bool contains(uint64_t val) const;
    
    static Range full() { return Range(); }
    static Range singleton(uint64_t val) { return Range(val, val, 0, 0); }
};

// Main entry point
void analyze_ranges(Function& function);

} // namespace engine::decompiler::passes
