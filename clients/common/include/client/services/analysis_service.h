#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "engine/function_boundaries.h"
#include "engine/function_discovery.h"
#include "engine/llir.h"
#include "engine/session.h"
#include "engine/xrefs.h"

namespace client::services {

/// Result of function discovery
struct DiscoveryResult {
    bool success = false;
    std::string error;
    std::vector<engine::llir::Function> functions;
};

/// Result of function range discovery
struct RangesResult {
    bool success = false;
    std::string error;
    std::vector<engine::analysis::FunctionRange> ranges;
};

/// Result of xrefs search
struct XrefsResult {
    bool success = false;
    std::string error;
    std::vector<engine::xrefs::XrefEntry> entries;
};

/// Service for analysis operations
class AnalysisService {
public:
    explicit AnalysisService(engine::Session& session);

    /// Discover functions starting from an entry point
    DiscoveryResult discover_functions(std::uint64_t entry,
                                       std::size_t max_instructions,
                                       const engine::analysis::FunctionDiscoveryOptions& options);

    /// Discover function ranges
    RangesResult discover_ranges(std::uint64_t entry,
                                 std::size_t max_instructions,
                                 const engine::analysis::FunctionDiscoveryOptions& options);

    /// Find xrefs to a target address
    XrefsResult find_xrefs_to(std::uint64_t target, std::size_t max_results);

    /// Find xrefs from a source address
    XrefsResult find_xrefs_from(std::uint64_t source, std::size_t max_results);

private:
    engine::Session& session_;
};

}  // namespace client::services