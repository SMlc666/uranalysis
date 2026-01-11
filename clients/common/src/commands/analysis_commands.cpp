#include "client/commands/commands.h"

#include <algorithm>
#include <sstream>

#include "client/formatters/address.h"
#include "client/formatters/ir.h"
#include "client/formatters/symbols.h"
#include "client/formatters/xrefs.h"
#include "engine/function_boundaries.h"
#include "engine/function_discovery.h"
#include "engine/xrefs.h"

namespace client::commands {

namespace {

bool require_loaded(const Session& session, Output& output) {
    if (!session.loaded()) {
        output.write_line("no file loaded, use: open <path>");
        return false;
    }
    return true;
}

}  // namespace

void register_analysis_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "xrefs",
        {"xr"},
        "xrefs <addr> [max]  find xrefs to address",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2 || args.size() > 3) {
                output.write_line("usage: xrefs <addr> [max]");
                return true;
            }
            std::uint64_t target = 0;
            if (!fmt::parse_u64(args[1], target)) {
                output.write_line("invalid address: " + args[1]);
                return true;
            }
            std::size_t max_results = 256;
            if (args.size() == 3) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[2], parsed)) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_results = static_cast<std::size_t>(parsed);
            }
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
        }});

    registry.register_command(Command{
        "fdisc",
        {"fd"},
        "fdisc [max]   discover functions",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: fdisc [max]");
                return true;
            }
            std::size_t max_instructions = 2048;
            if (args.size() == 2) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[1], parsed)) {
                    output.write_line("invalid max: " + args[1]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
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
            std::sort(functions.begin(),
                      functions.end(),
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
        }});

    registry.register_command(Command{
        "franges",
        {"fr"},
        "franges [max]  discover function ranges",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: franges [max]");
                return true;
            }
            std::size_t max_instructions = 2048;
            if (args.size() == 2) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[1], parsed)) {
                    output.write_line("invalid max: " + args[1]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
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
            std::sort(ranges.begin(),
                      ranges.end(),
                      [](const engine::analysis::FunctionRange& a,
                         const engine::analysis::FunctionRange& b) { return a.start < b.start; });
            for (const auto& range : ranges) {
                std::ostringstream oss;
                oss << fmt::hex(range.start) << " - " << fmt::hex(range.end)
                    << " kind=" << fmt::range_kind_label(range.kind)
                    << " seed=" << fmt::seed_kind_label(range.seed_kind)
                    << " hard=" << (range.hard ? "yes" : "no");
                output.write_line(oss.str());
            }
            return true;
        }});
}

}  // namespace client::commands