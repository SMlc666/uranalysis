#include "engine/function_discovery.h"

#include "engine/arch/arm64/function_prologue.h"
#include "engine/xrefs.h"

#include <optional>
#include <unordered_set>

#include "function_discovery_internal.h"

namespace engine::analysis {

namespace {

struct AddressRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
};

constexpr std::uint64_t kU64Max = ~static_cast<std::uint64_t>(0);
constexpr std::uint32_t kRelocAarch64Abs64 = 257;
constexpr std::uint32_t kRelocAarch64GlobDat = 1025;
constexpr std::uint32_t kRelocAarch64JumpSlot = 1026;
constexpr std::uint32_t kRelocAarch64Relative = 1027;
constexpr std::uint32_t kRelocAarch64TlsDtpMod64 = 1029;
constexpr std::uint32_t kRelocAarch64TlsDtpRel64 = 1030;
constexpr std::uint32_t kRelocAarch64TlsTpRel64 = 1031;
constexpr std::uint32_t kRelocAarch64IRelative = 1032;
constexpr std::uint32_t kRelocPeHighLow = 3;
constexpr std::uint32_t kRelocPeDir64 = 10;

bool ranges_overlap(std::uint64_t start_a, std::uint64_t end_a, std::uint64_t start_b, std::uint64_t end_b) {
    return start_a < end_b && start_b < end_a;
}

std::uint64_t image_base(const std::vector<BinarySegment>* segments, const BinaryInfo* binary_info) {
    if (segments && !segments->empty()) {
        std::uint64_t base = segments->front().vaddr;
        for (const auto& seg : *segments) {
            if (seg.vaddr < base) {
                base = seg.vaddr;
            }
        }
        return base;
    }
    if (binary_info) {
        return binary_info->image_base;
    }
    return 0;
}

const BinarySection* find_section(const std::vector<BinarySection>* sections, const std::string& name) {
    if (!sections || name.empty()) {
        return nullptr;
    }
    for (const auto& section : *sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

bool is_executable_address(const std::vector<BinarySegment>* segments, std::uint64_t address) {
    constexpr std::uint32_t kPfExec = 0x1;
    if (!segments) {
        return true;
    }
    for (const auto& seg : *segments) {
        if ((seg.flags & kPfExec) == 0) {
            continue;
        }
        if (address >= seg.vaddr && address < (seg.vaddr + seg.memsz)) {
            return true;
        }
    }
    return false;
}

bool is_inside_range(const AddressRange& range, std::uint64_t address, bool allow_start) {
    if (address < range.start || address >= range.end) {
        return false;
    }
    if (allow_start && address == range.start) {
        return false;
    }
    return true;
}

bool is_inside_ranges(const std::vector<AddressRange>& ranges, std::uint64_t address, bool allow_start) {
    for (const auto& range : ranges) {
        if (is_inside_range(range, address, allow_start)) {
            return true;
        }
    }
    return false;
}

void append_range(std::vector<AddressRange>& ranges,
                  std::uint64_t start,
                  std::uint64_t end,
                  const std::vector<BinarySegment>* segments) {
    if (start == 0 || end <= start) {
        return;
    }
    if (!is_executable_address(segments, start)) {
        return;
    }
    ranges.push_back(AddressRange{start, end});
}

void append_dwarf_ranges(const dwarf::DwarfCatalog* catalog,
                         const std::vector<BinarySegment>* segments,
                         std::vector<AddressRange>& ranges) {
    if (!catalog) {
        return;
    }
    for (const auto& func : catalog->functions()) {
        if (func.low_pc != 0 && func.high_pc > func.low_pc) {
            append_range(ranges, func.low_pc, func.high_pc, segments);
        }
        for (const auto& range : func.ranges) {
            append_range(ranges, range.start, range.end, segments);
        }
    }
}

void append_eh_ranges(const ehframe::EhFrameCatalog* catalog,
                      const std::vector<BinarySegment>* segments,
                      std::vector<AddressRange>& ranges) {
    if (!catalog) {
        return;
    }
    for (const auto& entry : catalog->entries()) {
        if (entry.start == 0 || entry.size == 0) {
            continue;
        }
        append_range(ranges, entry.start, entry.start + entry.size, segments);
    }
}

void append_symbol_ranges(const std::vector<BinarySymbol>* symbols,
                          const BinaryInfo* binary_info,
                          const std::vector<BinarySegment>* segments,
                          std::vector<AddressRange>& ranges) {
    if (!symbols) {
        return;
    }
    const bool is_elf = binary_info && binary_info->format == BinaryFormat::kElf;
    constexpr std::uint8_t kElfSymTypeMask = 0x0f;
    constexpr std::uint8_t kElfSymTypeFunc = 0x02;
    for (const auto& sym : *symbols) {
        if (sym.value == 0 || sym.size == 0) {
            continue;
        }
        if (sym.value + sym.size < sym.value) {
            continue;
        }
        if (is_elf && (sym.info & kElfSymTypeMask) != kElfSymTypeFunc) {
            continue;
        }
        append_range(ranges, sym.value, sym.value + sym.size, segments);
    }
}

AddressRange range_from_function(const llir::Function& function) {
    AddressRange range;
    if (function.blocks.empty()) {
        return range;
    }
    range.start = function.blocks.front().start;
    range.end = function.blocks.front().end;
    for (const auto& block : function.blocks) {
        if (block.start < range.start) {
            range.start = block.start;
        }
        if (block.end > range.end) {
            range.end = block.end;
        }
    }
    if (range.end < range.start) {
        range.end = range.start;
    }
    return range;
}

std::optional<std::uint64_t> relocation_target(const BinaryRelocation& reloc,
                                               std::uint64_t base,
                                               const BinaryInfo* binary_info) {
    switch (reloc.type) {
        case kRelocAarch64Relative:
        case kRelocAarch64IRelative:
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(base) + reloc.addend);
        case kRelocAarch64Abs64:
        case kRelocAarch64GlobDat:
        case kRelocAarch64JumpSlot:
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(reloc.symbol_value) + reloc.addend);
        case kRelocAarch64TlsDtpMod64:
        case kRelocAarch64TlsDtpRel64:
        case kRelocAarch64TlsTpRel64:
            return std::nullopt;
        case kRelocPeHighLow:
        case kRelocPeDir64:
            if (!binary_info || binary_info->format != BinaryFormat::kPe) {
                return std::nullopt;
            }
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(base) + reloc.addend);
        default:
            break;
    }
    return std::nullopt;
}

void collect_relocation_entry_points(const std::vector<BinaryRelocation>* relocations,
                                     const std::vector<BinarySection>* sections,
                                     const std::vector<BinarySegment>* segments,
                                     const BinaryInfo* binary_info,
                                     std::vector<std::uint64_t>& out) {
    if (!relocations) {
        return;
    }
    constexpr std::uint64_t kExecFlag = 0x4;
    const std::uint64_t base = image_base(segments, binary_info);
    for (const auto& reloc : *relocations) {
        if (reloc.addend == 0 && reloc.symbol_value == 0 && reloc.offset == 0) {
            continue;
        }
        const BinarySection* section = find_section(sections, reloc.target_section);
        if (section && (section->flags & kExecFlag) != 0) {
            continue;
        }
        auto target = relocation_target(reloc, base, binary_info);
        if (!target || *target == 0 || *target == kU64Max) {
            continue;
        }
        if ((*target & 0x3) != 0) {
            continue;
        }
        if (!is_executable_address(segments, *target)) {
            continue;
        }
        out.push_back(*target);
    }
}

bool overlaps_any(const AddressRange& range, const std::vector<AddressRange>& others, std::uint64_t entry) {
    for (const auto& other : others) {
        if (other.start == entry) {
            continue;
        }
        if (ranges_overlap(range.start, range.end, other.start, other.end)) {
            return true;
        }
    }
    return false;
}

void push_unique(std::vector<std::uint64_t>& worklist,
                 std::unordered_set<std::uint64_t>& seen,
                 std::uint64_t addr) {
    if (addr == 0) {
        return;
    }
    if (seen.find(addr) != seen.end()) {
        return;
    }
    seen.insert(addr);
    worklist.push_back(addr);
}

void push_unique_arm64(std::vector<std::uint64_t>& worklist,
                       std::unordered_set<std::uint64_t>& seen,
                       std::uint64_t addr,
                       const std::vector<BinarySegment>* segments,
                       const std::vector<AddressRange>& hard_ranges,
                       const std::vector<AddressRange>& discovered_ranges) {
    if (addr == 0) {
        return;
    }
    if ((addr & 0x3) != 0) {
        return;
    }
    if (!is_executable_address(segments, addr)) {
        return;
    }
    if (is_inside_ranges(hard_ranges, addr, true)) {
        return;
    }
    if (is_inside_ranges(discovered_ranges, addr, true)) {
        return;
    }
    push_unique(worklist, seen, addr);
}

}  // namespace

bool discover_functions_arm64(const LoadedImage& image,
                              std::uint64_t entry,
                              std::size_t max_instructions_per_function,
                              const FunctionDiscoveryOptions& options,
                              std::vector<llir::Function>& functions,
                              std::string& error) {
    functions.clear();
    error.clear();
    if (max_instructions_per_function == 0) {
        error = "max_instructions_per_function must be > 0";
        return false;
    }

    std::unordered_set<std::uint64_t> visited;
    std::unordered_set<std::uint64_t> queued;
    std::vector<std::uint64_t> worklist;
    std::vector<AddressRange> hard_ranges;
    std::vector<AddressRange> discovered_ranges;
    std::vector<std::uint64_t> manual_entries;
    std::vector<std::uint64_t> symbol_entries;
    std::vector<std::uint64_t> plt_entries;
    std::vector<std::uint64_t> init_entries;
    std::vector<std::uint64_t> relocation_entries;
    std::vector<std::uint64_t> eh_entries;
    std::vector<std::uint64_t> dwarf_entries;
    std::vector<std::uint64_t> prologue_entries;
    std::vector<std::uint64_t> linear_entries;

    if (entry != 0) {
        manual_entries.push_back(entry);
    }
    manual_entries.insert(manual_entries.end(), options.entry_points.begin(), options.entry_points.end());
    if (options.include_symbol_entries) {
        if (options.symbols) {
            detail::collect_symbol_entry_points(*options.symbols, options.binary_info, symbol_entries);
        }
    }
    if (options.include_plt_entries && options.sections) {
        detail::collect_plt_entry_points(*options.sections, options.segments, options.relocations, plt_entries);
    }
    if (options.include_init_array_entries && options.sections) {
        detail::collect_init_array_entry_points(image, *options.sections, options.segments, options.binary_info,
                                                init_entries);
    }
    collect_relocation_entry_points(options.relocations,
                                    options.sections,
                                    options.segments,
                                    options.binary_info,
                                    relocation_entries);
    if (options.include_eh_frame_entries && options.eh_frame) {
        detail::collect_eh_frame_entry_points(*options.eh_frame, options.segments, eh_entries);
    }
    if (options.include_dwarf_entries && options.dwarf) {
        detail::collect_dwarf_entry_points(*options.dwarf, dwarf_entries);
    }
    if (options.include_prologue_entries && options.sections) {
        arch::arm64::collect_prologue_entry_points(image, *options.sections, options.segments, prologue_entries);
    }
    if (options.include_linear_sweep_entries && options.sections) {
        detail::collect_linear_sweep_entry_points(image,
                                                  *options.sections,
                                                  options.segments,
                                                  options.dwarf,
                                                  options.eh_frame,
                                                  linear_entries);
    }

    append_dwarf_ranges(options.dwarf, options.segments, hard_ranges);
    append_eh_ranges(options.eh_frame, options.segments, hard_ranges);
    append_symbol_ranges(options.symbols, options.binary_info, options.segments, hard_ranges);

    for (std::uint64_t addr : prologue_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : linear_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : plt_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : init_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : relocation_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : symbol_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : eh_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : dwarf_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }
    for (std::uint64_t addr : manual_entries) {
        push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
    }

    while (!worklist.empty()) {
        std::uint64_t func_entry = worklist.back();
        worklist.pop_back();

        if (is_inside_ranges(hard_ranges, func_entry, true) ||
            is_inside_ranges(discovered_ranges, func_entry, true)) {
            continue;
        }
        if (visited.find(func_entry) != visited.end()) {
            continue;
        }
        visited.insert(func_entry);

        llir::Function function;
        if (!llir::build_cfg_arm64(image, func_entry, max_instructions_per_function, function, error)) {
            return false;
        }

        AddressRange func_range = range_from_function(function);
        if (func_range.end <= func_range.start) {
            continue;
        }
        if (overlaps_any(func_range, hard_ranges, func_entry) ||
            overlaps_any(func_range, discovered_ranges, func_entry)) {
            continue;
        }
        discovered_ranges.push_back(func_range);
        if (options.follow_calls || options.follow_tail_jumps) {
            for (const auto& block : function.blocks) {
                for (const auto& inst : block.instructions) {
                    if (inst.branch == llir::BranchKind::kCall && !inst.targets.empty()) {
                        if (options.follow_calls) {
                            push_unique_arm64(worklist,
                                              queued,
                                              inst.targets.front(),
                                              options.segments,
                                              hard_ranges,
                                              discovered_ranges);
                        }
                    }
                }
            }
        }

        if (options.include_indirect_targets && options.segments) {
            std::vector<xrefs::XrefEntry> xrefs;
            xrefs::collect_code_xrefs(image, *options.segments, function, xrefs);
            for (const auto& xref : xrefs) {
                if (xref.target == 0) {
                    continue;
                }
                if (xref.kind == xrefs::XrefKind::kCodeCallIndirect ||
                    xref.kind == xrefs::XrefKind::kCodeJumpIndirect) {
                    push_unique_arm64(worklist,
                                      queued,
                                      xref.target,
                                      options.segments,
                                      hard_ranges,
                                      discovered_ranges);
                }
            }
        }

        if (options.follow_tail_jumps) {
            std::vector<std::uint64_t> tail_targets;
            detail::collect_tailcall_entry_points(function, tail_targets);
            for (std::uint64_t addr : tail_targets) {
                push_unique_arm64(worklist, queued, addr, options.segments, hard_ranges, discovered_ranges);
            }
        }

        functions.push_back(std::move(function));
    }

    return true;
}

bool discover_functions_x86_64(const LoadedImage& image,
                               std::uint64_t entry,
                               std::size_t max_instructions_per_function,
                               const FunctionDiscoveryOptions& options,
                               std::vector<llir::Function>& functions,
                               std::string& error) {
    functions.clear();
    error.clear();
    if (max_instructions_per_function == 0) {
        error = "max_instructions_per_function must be > 0";
        return false;
    }

    std::unordered_set<std::uint64_t> visited;
    std::unordered_set<std::uint64_t> queued;
    std::vector<std::uint64_t> worklist;
    std::vector<std::uint64_t> entry_points;
    entry_points.push_back(entry);
    entry_points.insert(entry_points.end(), options.entry_points.begin(), options.entry_points.end());
    if (options.include_symbol_entries) {
        if (options.symbols) {
            detail::collect_symbol_entry_points(*options.symbols, options.binary_info, entry_points);
        }
    }
    if (options.include_plt_entries && options.sections) {
        detail::collect_plt_entry_points(*options.sections, options.segments, options.relocations, entry_points);
    }
    if (options.include_init_array_entries && options.sections) {
        detail::collect_init_array_entry_points(image, *options.sections, options.segments, options.binary_info,
                                                entry_points);
    }
    if (options.include_eh_frame_entries && options.eh_frame) {
        detail::collect_eh_frame_entry_points(*options.eh_frame, options.segments, entry_points);
    }
    if (options.include_dwarf_entries && options.dwarf) {
        detail::collect_dwarf_entry_points(*options.dwarf, entry_points);
    }
    if (options.include_linear_sweep_entries && options.sections) {
        detail::collect_linear_sweep_entry_points(image,
                                                  *options.sections,
                                                  options.segments,
                                                  options.dwarf,
                                                  options.eh_frame,
                                                  entry_points);
    }

    for (std::uint64_t addr : entry_points) {
        push_unique(worklist, queued, addr);
    }

    while (!worklist.empty()) {
        std::uint64_t func_entry = worklist.back();
        worklist.pop_back();

        if (visited.find(func_entry) != visited.end()) {
            continue;
        }
        visited.insert(func_entry);

        llir::Function function;
        if (!llir::build_cfg_x86_64(image, func_entry, max_instructions_per_function, function, error)) {
            return false;
        }
        if (options.follow_calls || options.follow_tail_jumps) {
            for (const auto& block : function.blocks) {
                for (const auto& inst : block.instructions) {
                    if (inst.branch == llir::BranchKind::kCall && !inst.targets.empty()) {
                        if (options.follow_calls) {
                            push_unique(worklist, queued, inst.targets.front());
                        }
                    }
                }
            }
        }

        if (options.include_indirect_targets && options.segments) {
            std::vector<xrefs::XrefEntry> xrefs;
            xrefs::collect_code_xrefs(image, *options.segments, function, xrefs);
            for (const auto& xref : xrefs) {
                if (xref.target == 0) {
                    continue;
                }
                if (xref.kind == xrefs::XrefKind::kCodeCallIndirect ||
                    xref.kind == xrefs::XrefKind::kCodeJumpIndirect) {
                    push_unique(worklist, queued, xref.target);
                }
            }
        }

        functions.push_back(std::move(function));
    }

    return true;
}

}  // namespace engine::analysis
