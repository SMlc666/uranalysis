#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "engine/function_discovery.h"

namespace engine::analysis {

enum class FunctionRangeKind {
    kDwarf,
    kEhFrame,
    kSymbol,
    kCfg
};

struct FunctionRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    FunctionRangeKind kind = FunctionRangeKind::kCfg;
    SeedKind seed_kind = SeedKind::kEntry;
    bool hard = false;
};

bool discover_function_ranges_arm64(const LoadedImage& image,
                                    std::uint64_t entry,
                                    std::size_t max_instructions_per_function,
                                    const FunctionDiscoveryOptions& options,
                                    std::vector<FunctionRange>& ranges,
                                    std::string& error);

bool discover_function_ranges_x86_64(const LoadedImage& image,
                                     std::uint64_t entry,
                                     std::size_t max_instructions_per_function,
                                     const FunctionDiscoveryOptions& options,
                                     std::vector<FunctionRange>& ranges,
                                     std::string& error);

}  // namespace engine::analysis
