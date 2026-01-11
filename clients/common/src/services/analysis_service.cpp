#include "client/services/analysis_service.h"

#include <algorithm>

namespace client::services {

AnalysisService::AnalysisService(engine::Session& session) : session_(session) {}

DiscoveryResult AnalysisService::discover_functions(
    std::uint64_t entry,
    std::size_t max_instructions,
    const engine::analysis::FunctionDiscoveryOptions& options) {
    DiscoveryResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;

    if (machine == engine::BinaryMachine::kAarch64) {
        result.success = session_.discover_llir_functions_arm64(
            entry, max_instructions, options, result.functions, result.error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        result.success = session_.discover_llir_functions_x86_64(
            entry, max_instructions, options, result.functions, result.error);
    } else {
        result.error = "unsupported architecture for discovery";
    }

    // Sort functions by entry address
    if (result.success) {
        std::sort(result.functions.begin(),
                  result.functions.end(),
                  [](const engine::llir::Function& a, const engine::llir::Function& b) {
                      return a.entry < b.entry;
                  });
    }

    return result;
}

RangesResult AnalysisService::discover_ranges(
    std::uint64_t entry,
    std::size_t max_instructions,
    const engine::analysis::FunctionDiscoveryOptions& options) {
    RangesResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;

    if (machine == engine::BinaryMachine::kAarch64) {
        result.success = session_.discover_function_ranges_arm64(
            entry, max_instructions, options, result.ranges, result.error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        result.success = session_.discover_function_ranges_x86_64(
            entry, max_instructions, options, result.ranges, result.error);
    } else {
        result.error = "unsupported architecture for discovery";
    }

    // Sort ranges by start address
    if (result.success) {
        std::sort(result.ranges.begin(),
                  result.ranges.end(),
                  [](const engine::analysis::FunctionRange& a,
                     const engine::analysis::FunctionRange& b) { return a.start < b.start; });
    }

    return result;
}

XrefsResult AnalysisService::find_xrefs_to(std::uint64_t target, std::size_t max_results) {
    XrefsResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    result.success = session_.find_xrefs_to_address(target, max_results, result.entries);
    if (!result.success) {
        result.error = "xrefs search failed";
    }

    return result;
}

XrefsResult AnalysisService::find_xrefs_from(std::uint64_t source, std::size_t max_results) {
    XrefsResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    // Note: This would need engine support for find_xrefs_from_address
    // For now, return not implemented
    result.error = "xrefs from source not yet implemented";

    return result;
}

}  // namespace client::services