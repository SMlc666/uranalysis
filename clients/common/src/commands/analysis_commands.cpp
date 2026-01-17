#include "client/commands/commands.h"
#include "client/formatters/address.h"
#include "client/formatters/ir.h"
#include "client/formatters/symbols.h"
#include "client/formatters/xrefs.h"
#include "client/util/address_resolver.h"
#include "engine/function_boundaries.h"
#include "engine/function_discovery.h"
#include "engine/xrefs.h"

#include <algorithm>
#include <sstream>

namespace client::commands {

void register_analysis_commands(CommandRegistry& registry) {
    // ==========================================================================
    // xrefs - Find cross-references to an address
    // ==========================================================================
    registry.register_command(
        CommandV2("xrefs", {"xr", "x", "refs"})
            .description("Find cross-references to an address")
            .requires_file()
            .positional("target", "Target address or symbol", true)
            .positional("max", "Maximum results (default: 256)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                auto result = util::resolve_address(m.get<std::string>("target"), session);
                if (!result.success) {
                    output.write_line(result.error);
                    return true;
                }
                uint64_t target = result.address;
                size_t max_results = static_cast<size_t>(m.get_or<uint64_t>("max", 256));
                
                std::vector<engine::xrefs::XrefEntry> entries;
                if (!session.find_xrefs_to_address(target, max_results, entries)) {
                    output.write_line("xrefs search failed");
                    return true;
                }
                if (entries.empty()) {
                    output.write_line("no xrefs found");
                    return true;
                }
                for (const auto& entry : entries) {
                    std::ostringstream oss;
                    oss << fmt::hex(entry.source) << " -> " << fmt::hex(entry.target) << " "
                        << fmt::xref_kind_label(entry.kind);
                    output.write_line(oss.str());
                }
                return true;
            }));

    // ==========================================================================
    // fdisc - Discover functions
    // ==========================================================================
    registry.register_command(
        CommandV2("fdisc", {"fd", "discover"})
            .description("Discover functions from entry point")
            .requires_file()
            .positional("max", "Max instructions to analyze (default: 2048)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                size_t max_instructions = static_cast<size_t>(m.get_or<uint64_t>("max", 2048));
                
                engine::analysis::FunctionDiscoveryOptions options;
                std::vector<engine::llir::Function> functions;
                std::string error;
                bool ok = false;
                const auto machine = session.binary_info().machine;
                
                if (machine == engine::BinaryMachine::kAarch64) {
                    ok = session.discover_llir_functions_arm64(
                        session.binary_info().entry, max_instructions, options, functions, error);
                } else if (machine == engine::BinaryMachine::kX86_64) {
                    ok = session.discover_llir_functions_x86_64(
                        session.binary_info().entry, max_instructions, options, functions, error);
                } else {
                    error = "unsupported architecture for discovery";
                }
                
                if (!ok) {
                    output.write_line("discovery error: " + (error.empty() ? "failed" : error));
                    return true;
                }
                if (functions.empty()) {
                    output.write_line("no functions discovered");
                    return true;
                }
                
                std::sort(functions.begin(), functions.end(),
                    [](const engine::llir::Function& a, const engine::llir::Function& b) {
                        return a.entry < b.entry;
                    });
                
                for (const auto& func : functions) {
                    std::string name;
                    auto matches = session.symbol_table().within_range(func.entry, 1);
                    if (!matches.empty() && matches.front()) {
                        name = fmt::symbol_display_name(*matches.front());
                    } else {
                        name = "sub_" + fmt::hex(func.entry);
                    }
                    std::ostringstream oss;
                    oss << fmt::hex(func.entry) << " size=" << fmt::hex(fmt::discovered_size(func))
                        << " blocks=" << func.blocks.size() << " " << name;
                    output.write_line(oss.str());
                }
                return true;
            }));

    // ==========================================================================
    // franges - Discover function ranges
    // ==========================================================================
    registry.register_command(
        CommandV2("franges", {"fr", "ranges"})
            .description("Discover function address ranges")
            .requires_file()
            .positional("max", "Max instructions to analyze (default: 2048)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                size_t max_instructions = static_cast<size_t>(m.get_or<uint64_t>("max", 2048));
                
                engine::analysis::FunctionDiscoveryOptions options;
                std::vector<engine::analysis::FunctionRange> ranges;
                std::string error;
                bool ok = false;
                const auto machine = session.binary_info().machine;
                
                if (machine == engine::BinaryMachine::kAarch64) {
                    ok = session.discover_function_ranges_arm64(
                        session.binary_info().entry, max_instructions, options, ranges, error);
                } else if (machine == engine::BinaryMachine::kX86_64) {
                    ok = session.discover_function_ranges_x86_64(
                        session.binary_info().entry, max_instructions, options, ranges, error);
                } else {
                    error = "unsupported architecture for discovery";
                }
                
                if (!ok) {
                    output.write_line("range error: " + (error.empty() ? "failed" : error));
                    return true;
                }
                if (ranges.empty()) {
                    output.write_line("no ranges discovered");
                    return true;
                }
                
                std::sort(ranges.begin(), ranges.end(),
                    [](const engine::analysis::FunctionRange& a, const engine::analysis::FunctionRange& b) {
                        return a.start < b.start;
                    });
                
                for (const auto& range : ranges) {
                    std::ostringstream oss;
                    oss << fmt::hex(range.start) << " - " << fmt::hex(range.end)
                        << " kind=" << fmt::range_kind_label(range.kind)
                        << " seed=" << fmt::seed_kind_label(range.seed_kind)
                        << " hard=" << (range.hard ? "yes" : "no");
                    output.write_line(oss.str());
                }
                return true;
            }));
}

}  // namespace client::commands
