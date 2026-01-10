#include "engine/function_discovery.h"

#include "engine/arch/arm64/function_prologue.h"
#include "engine/arch/x86_64/function_prologue.h"

#include <unordered_set>

#include "function_discovery_internal.h"

namespace engine::analysis {

namespace {

void append_unique(const std::vector<std::uint64_t>& addresses,
                   SeedKind kind,
                   std::vector<SeedEntry>& out,
                   std::unordered_set<std::uint64_t>& seen) {
    for (std::uint64_t addr : addresses) {
        if (addr == 0) {
            continue;
        }
        if (!seen.insert(addr).second) {
            continue;
        }
        SeedEntry entry;
        entry.address = addr;
        entry.kind = kind;
        out.push_back(entry);
    }
}

}  // namespace

void collect_seed_entries(const LoadedImage& image,
                          std::uint64_t entry,
                          const FunctionDiscoveryOptions& options,
                          std::vector<SeedEntry>& out) {
    out.clear();
    if (entry != 0) {
        SeedEntry seed;
        seed.address = entry;
        seed.kind = SeedKind::kEntry;
        out.push_back(seed);
    }

    std::unordered_set<std::uint64_t> seen_manual;
    std::unordered_set<std::uint64_t> seen_symbol;
    std::unordered_set<std::uint64_t> seen_plt;
    std::unordered_set<std::uint64_t> seen_init;
    std::unordered_set<std::uint64_t> seen_eh;
    std::unordered_set<std::uint64_t> seen_prologue;
    std::unordered_set<std::uint64_t> seen_dwarf;
    std::unordered_set<std::uint64_t> seen_sweep;

    append_unique(options.entry_points, SeedKind::kManual, out, seen_manual);

    if (options.include_symbol_entries && options.symbols) {
        std::vector<std::uint64_t> addresses;
        detail::collect_symbol_entry_points(*options.symbols, options.binary_info, addresses);
        append_unique(addresses, SeedKind::kSymbol, out, seen_symbol);
    }

    if (options.include_plt_entries && options.sections) {
        std::vector<std::uint64_t> addresses;
        detail::collect_plt_entry_points(*options.sections, options.segments, options.relocations, addresses);
        append_unique(addresses, SeedKind::kPlt, out, seen_plt);
    }

    if (options.include_init_array_entries && options.sections) {
        std::vector<std::uint64_t> addresses;
        detail::collect_init_array_entry_points(image, *options.sections, options.segments, options.binary_info,
                                                addresses);
        append_unique(addresses, SeedKind::kInitArray, out, seen_init);
    }

    if (options.include_eh_frame_entries && options.eh_frame) {
        std::vector<std::uint64_t> addresses;
        detail::collect_eh_frame_entry_points(*options.eh_frame, options.segments, addresses);
        append_unique(addresses, SeedKind::kEhFrame, out, seen_eh);
    }

    if (options.include_dwarf_entries && options.dwarf) {
        std::vector<std::uint64_t> addresses;
        detail::collect_dwarf_entry_points(*options.dwarf, addresses);
        append_unique(addresses, SeedKind::kDwarf, out, seen_dwarf);
    }

    if (options.include_prologue_entries && options.sections) {
        const bool is_arm64 =
            options.binary_info && options.binary_info->machine == BinaryMachine::kAarch64;
        const bool is_x86_64 =
            options.binary_info && options.binary_info->machine == BinaryMachine::kX86_64;
        if (is_arm64) {
            std::vector<std::uint64_t> addresses;
            arch::arm64::collect_prologue_entry_points(image, *options.sections, options.segments, addresses);
            append_unique(addresses, SeedKind::kPrologue, out, seen_prologue);
        } else if (is_x86_64) {
            std::vector<std::uint64_t> addresses;
            arch::x86_64::collect_prologue_entry_points(image, *options.sections, options.segments, addresses);
            append_unique(addresses, SeedKind::kPrologue, out, seen_prologue);
        }
    }

    if (options.include_linear_sweep_entries && options.sections) {
        std::vector<std::uint64_t> addresses;
        detail::collect_linear_sweep_entry_points(image,
                                                  *options.sections,
                                                  options.segments,
                                                  options.dwarf,
                                                  options.eh_frame,
                                                  addresses);
        append_unique(addresses, SeedKind::kLinearSweep, out, seen_sweep);
    }
}

}  // namespace engine::analysis
