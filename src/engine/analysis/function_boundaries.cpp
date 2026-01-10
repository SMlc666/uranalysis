#include "engine/function_boundaries.h"

#include <algorithm>
#include <unordered_set>

namespace engine::analysis {

namespace {

constexpr std::uint8_t kElfSymTypeMask = 0x0f;
constexpr std::uint8_t kElfSymTypeFunc = 0x02;
constexpr std::uint32_t kPfExec = 0x1;
constexpr std::uint64_t kShfExecInstr = 0x4;

constexpr std::uint32_t kArm64Nop = 0xd503201f;
constexpr std::uint32_t kArm64Brk = 0xd4200000;
constexpr std::uint32_t kArm64Hlt = 0xd4400000;

struct AddressRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
};

int kind_priority(FunctionRangeKind kind) {
    switch (kind) {
        case FunctionRangeKind::kDwarf:
            return 3;
        case FunctionRangeKind::kEhFrame:
            return 2;
        case FunctionRangeKind::kSymbol:
            return 1;
        case FunctionRangeKind::kCfg:
        default:
            return 0;
    }
}

bool is_valid_range(std::uint64_t start, std::uint64_t end) {
    return start != 0 && end > start;
}

bool ranges_overlap(std::uint64_t start_a, std::uint64_t end_a, std::uint64_t start_b, std::uint64_t end_b) {
    return start_a < end_b && start_b < end_a;
}

bool range_contains(std::uint64_t start, std::uint64_t end, std::uint64_t addr) {
    return addr >= start && addr < end;
}

bool is_executable_address(const std::vector<BinarySegment>* segments, std::uint64_t address) {
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

const BinarySection* find_executable_section(const std::vector<BinarySection>* sections, std::uint64_t address) {
    if (!sections) {
        return nullptr;
    }
    for (const auto& sec : *sections) {
        if ((sec.flags & kShfExecInstr) == 0) {
            continue;
        }
        if (address >= sec.addr && address < (sec.addr + sec.size)) {
            return &sec;
        }
    }
    return nullptr;
}

const BinarySegment* find_executable_segment(const std::vector<BinarySegment>* segments, std::uint64_t address) {
    if (!segments) {
        return nullptr;
    }
    for (const auto& seg : *segments) {
        if ((seg.flags & kPfExec) == 0) {
            continue;
        }
        if (address >= seg.vaddr && address < (seg.vaddr + seg.memsz)) {
            return &seg;
        }
    }
    return nullptr;
}

std::uint64_t exec_region_end(std::uint64_t address,
                              const std::vector<BinarySegment>* segments,
                              const std::vector<BinarySection>* sections) {
    const BinarySegment* seg = find_executable_segment(segments, address);
    if (!seg) {
        return address;
    }
    std::uint64_t end = seg->vaddr + seg->memsz;
    const BinarySection* sec = find_executable_section(sections, address);
    if (sec) {
        const std::uint64_t sec_end = sec->addr + sec->size;
        if (sec_end < end) {
            end = sec_end;
        }
    }
    return end;
}

bool clamp_to_exec_region(FunctionRange& range,
                          const std::vector<BinarySegment>* segments,
                          const std::vector<BinarySection>* sections) {
    const std::uint64_t end = exec_region_end(range.start, segments, sections);
    if (end <= range.start) {
        return false;
    }
    if (range.end > end) {
        range.end = end;
    }
    return range.end > range.start;
}

bool read_u32(const LoadedImage& image, std::uint64_t addr, bool little_endian, std::uint32_t& out) {
    std::vector<std::uint8_t> bytes;
    if (!image.read_bytes(addr, 4, bytes) || bytes.size() != 4) {
        return false;
    }
    if (little_endian) {
        out = static_cast<std::uint32_t>(bytes[0]) |
              (static_cast<std::uint32_t>(bytes[1]) << 8) |
              (static_cast<std::uint32_t>(bytes[2]) << 16) |
              (static_cast<std::uint32_t>(bytes[3]) << 24);
    } else {
        out = static_cast<std::uint32_t>(bytes[3]) |
              (static_cast<std::uint32_t>(bytes[2]) << 8) |
              (static_cast<std::uint32_t>(bytes[1]) << 16) |
              (static_cast<std::uint32_t>(bytes[0]) << 24);
    }
    return true;
}

bool is_padding_word(std::uint32_t word) {
    return word == kArm64Nop || word == kArm64Brk || word == kArm64Hlt;
}

std::uint64_t trim_trailing_padding_arm64(const LoadedImage& image,
                                          std::uint64_t start,
                                          std::uint64_t end,
                                          bool little_endian) {
    if (end <= start || (end - start) < 4) {
        return end;
    }
    std::uint64_t cursor = end;
    while (cursor >= start + 4) {
        std::uint32_t word = 0;
        if (!read_u32(image, cursor - 4, little_endian, word)) {
            break;
        }
        if (!is_padding_word(word)) {
            break;
        }
        cursor -= 4;
    }
    return cursor;
}

void append_range(std::vector<FunctionRange>& out,
                  std::uint64_t start,
                  std::uint64_t end,
                  FunctionRangeKind kind,
                  SeedKind seed_kind,
                  bool hard) {
    if (!is_valid_range(start, end)) {
        return;
    }
    FunctionRange range;
    range.start = start;
    range.end = end;
    range.kind = kind;
    range.seed_kind = seed_kind;
    range.hard = hard;
    out.push_back(range);
}

void append_dwarf_ranges(const dwarf::DwarfCatalog* catalog, std::vector<FunctionRange>& out) {
    if (!catalog) {
        return;
    }
    for (const auto& func : catalog->functions()) {
        if (func.low_pc != 0 && func.high_pc > func.low_pc) {
            append_range(out, func.low_pc, func.high_pc, FunctionRangeKind::kDwarf, SeedKind::kDwarf, true);
        }
        for (const auto& range : func.ranges) {
            append_range(out, range.start, range.end, FunctionRangeKind::kDwarf, SeedKind::kDwarf, true);
        }
    }
}

void append_eh_ranges(const ehframe::EhFrameCatalog* catalog, std::vector<FunctionRange>& out) {
    if (!catalog) {
        return;
    }
    for (const auto& entry : catalog->entries()) {
        if (entry.start == 0 || entry.size == 0) {
            continue;
        }
        append_range(out,
                     entry.start,
                     entry.start + entry.size,
                     FunctionRangeKind::kEhFrame,
                     SeedKind::kEhFrame,
                     true);
    }
}

void append_symbol_ranges(const std::vector<BinarySymbol>* symbols,
                          const BinaryInfo* binary_info,
                          std::vector<FunctionRange>& out) {
    if (!symbols) {
        return;
    }
    const bool is_elf = binary_info && binary_info->format == BinaryFormat::kElf;
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
        append_range(out,
                     sym.value,
                     sym.value + sym.size,
                     FunctionRangeKind::kSymbol,
                     SeedKind::kSymbol,
                     false);
    }
}

void sort_ranges(std::vector<FunctionRange>& ranges) {
    std::sort(ranges.begin(), ranges.end(), [](const FunctionRange& lhs, const FunctionRange& rhs) {
        if (lhs.start != rhs.start) {
            return lhs.start < rhs.start;
        }
        if (lhs.end != rhs.end) {
            return lhs.end < rhs.end;
        }
        return kind_priority(lhs.kind) > kind_priority(rhs.kind);
    });
}

std::vector<FunctionRange> subtract_range(const FunctionRange& range,
                                          const std::vector<FunctionRange>& blockers) {
    if (blockers.empty()) {
        return {range};
    }
    std::vector<AddressRange> relevant;
    relevant.reserve(blockers.size());
    for (const auto& block : blockers) {
        if (!ranges_overlap(range.start, range.end, block.start, block.end)) {
            continue;
        }
        relevant.push_back(AddressRange{block.start, block.end});
    }
    if (relevant.empty()) {
        return {range};
    }
    std::sort(relevant.begin(), relevant.end(), [](const AddressRange& lhs, const AddressRange& rhs) {
        if (lhs.start != rhs.start) {
            return lhs.start < rhs.start;
        }
        return lhs.end < rhs.end;
    });

    std::vector<FunctionRange> out;
    std::uint64_t cursor = range.start;
    for (const auto& block : relevant) {
        if (block.end <= cursor) {
            continue;
        }
        if (block.start > cursor) {
            FunctionRange piece = range;
            piece.start = cursor;
            piece.end = std::min(block.start, range.end);
            if (piece.end > piece.start) {
                out.push_back(piece);
            }
        }
        if (block.end >= range.end) {
            cursor = range.end;
            break;
        }
        cursor = std::max(cursor, block.end);
    }
    if (cursor < range.end) {
        FunctionRange piece = range;
        piece.start = cursor;
        piece.end = range.end;
        if (piece.end > piece.start) {
            out.push_back(piece);
        }
    }
    return out;
}

void append_non_overlapping(std::vector<FunctionRange>& out,
                            const std::vector<FunctionRange>& candidates,
                            const std::vector<FunctionRange>& blockers) {
    for (const auto& candidate : candidates) {
        const auto pieces = subtract_range(candidate, blockers);
        out.insert(out.end(), pieces.begin(), pieces.end());
    }
}

void prune_invalid_ranges(std::vector<FunctionRange>& ranges,
                          const std::vector<BinarySegment>* segments,
                          const std::vector<BinarySection>* sections) {
    ranges.erase(std::remove_if(ranges.begin(),
                                ranges.end(),
                                [&](FunctionRange& range) {
                                    if (!is_valid_range(range.start, range.end)) {
                                        return true;
                                    }
                                    if (!is_executable_address(segments, range.start)) {
                                        return true;
                                    }
                                    return !clamp_to_exec_region(range, segments, sections);
                                }),
                 ranges.end());
}

void merge_adjacent(std::vector<FunctionRange>& ranges) {
    if (ranges.empty()) {
        return;
    }
    sort_ranges(ranges);
    std::vector<FunctionRange> merged;
    merged.reserve(ranges.size());
    for (const auto& range : ranges) {
        if (merged.empty()) {
            merged.push_back(range);
            continue;
        }
        auto& last = merged.back();
        if (last.end == range.start && last.kind == range.kind && last.seed_kind == range.seed_kind &&
            last.hard == range.hard) {
            last.end = range.end;
        } else {
            merged.push_back(range);
        }
    }
    ranges.swap(merged);
}

std::uint64_t clamp_end_by_boundaries(std::uint64_t start,
                                      std::uint64_t end,
                                      const std::vector<FunctionRange>& boundaries) {
    for (const auto& boundary : boundaries) {
        if (boundary.start > start && boundary.start < end) {
            end = boundary.start;
        }
    }
    return end;
}

std::uint64_t trim_trailing_padding_x86_64(const LoadedImage& image,
                                           std::uint64_t start,
                                           std::uint64_t end) {
    if (end <= start) {
        return end;
    }
    const std::size_t max_scan = 256;
    const std::size_t span = static_cast<std::size_t>(end - start);
    const std::size_t read_size = std::min(max_scan, span);
    std::vector<std::uint8_t> bytes;
    if (!image.read_bytes(end - read_size, read_size, bytes) || bytes.size() != read_size) {
        return end;
    }
    std::size_t trim = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const std::size_t idx = bytes.size() - 1 - i;
        const std::uint8_t value = bytes[idx];
        if (value == 0x90 || value == 0xcc) {
            trim += 1;
            continue;
        }
        break;
    }
    if (trim == 0) {
        return end;
    }
    return end - trim;
}

std::uint64_t cfg_range_end_from_blocks(const llir::Function& function,
                                        std::uint64_t entry,
                                        const std::unordered_set<std::uint64_t>& stop_entries) {
    std::uint64_t range_start = entry;
    std::uint64_t range_end = entry;
    for (const auto& block : function.blocks) {
        if (block.end <= block.start) {
            continue;
        }
        if (block.start != entry && stop_entries.find(block.start) != stop_entries.end()) {
            continue;
        }
        range_start = std::min(range_start, block.start);
        range_end = std::max(range_end, block.end);
    }
    if (range_end < range_start) {
        range_end = range_start;
    }
    return range_end;
}

bool contains_range(const std::vector<FunctionRange>& ranges, std::uint64_t addr) {
    for (const auto& range : ranges) {
        if (range_contains(range.start, range.end, addr)) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool discover_function_ranges_arm64(const LoadedImage& image,
                                    std::uint64_t entry,
                                    std::size_t max_instructions_per_function,
                                    const FunctionDiscoveryOptions& options,
                                    std::vector<FunctionRange>& ranges,
                                    std::string& error) {
    ranges.clear();
    error.clear();

    if (max_instructions_per_function == 0) {
        error = "max_instructions_per_function must be > 0";
        return false;
    }

    const bool little_endian = !options.binary_info || options.binary_info->little_endian;

    std::vector<FunctionRange> dwarf_ranges;
    append_dwarf_ranges(options.dwarf, dwarf_ranges);
    prune_invalid_ranges(dwarf_ranges, options.segments, options.sections);
    merge_adjacent(dwarf_ranges);

    std::vector<FunctionRange> eh_ranges;
    append_eh_ranges(options.eh_frame, eh_ranges);
    prune_invalid_ranges(eh_ranges, options.segments, options.sections);
    merge_adjacent(eh_ranges);

    std::vector<FunctionRange> hard_ranges = dwarf_ranges;
    append_non_overlapping(hard_ranges, eh_ranges, hard_ranges);
    merge_adjacent(hard_ranges);

    std::vector<FunctionRange> symbol_ranges;
    append_symbol_ranges(options.symbols, options.binary_info, symbol_ranges);
    prune_invalid_ranges(symbol_ranges, options.segments, options.sections);
    merge_adjacent(symbol_ranges);

    std::vector<FunctionRange> normalized_symbols;
    append_non_overlapping(normalized_symbols, symbol_ranges, hard_ranges);
    merge_adjacent(normalized_symbols);

    std::unordered_set<std::uint64_t> stop_entries;
    for (const auto& range : hard_ranges) {
        stop_entries.insert(range.start);
    }
    for (const auto& range : normalized_symbols) {
        stop_entries.insert(range.start);
    }

    std::vector<SeedEntry> seeds;
    collect_seed_entries(image, entry, options, seeds);

    std::vector<FunctionRange> cfg_ranges;
    std::unordered_set<std::uint64_t> seen_entries;

    std::vector<FunctionRange> boundary_ranges = hard_ranges;
    boundary_ranges.insert(boundary_ranges.end(), normalized_symbols.begin(), normalized_symbols.end());
    sort_ranges(boundary_ranges);

    for (const auto& seed : seeds) {
        if (seed.address == 0) {
            continue;
        }
        if (!seen_entries.insert(seed.address).second) {
            continue;
        }
        if (!is_executable_address(options.segments, seed.address)) {
            continue;
        }
        if (contains_range(boundary_ranges, seed.address)) {
            continue;
        }

        llir::Function function;
        if (!llir::build_cfg_arm64(image, seed.address, max_instructions_per_function, function, error)) {
            return false;
        }
        if (function.blocks.empty()) {
            continue;
        }

        std::uint64_t range_start = seed.address;
        std::uint64_t range_end = cfg_range_end_from_blocks(function, seed.address, stop_entries);
        range_end = clamp_end_by_boundaries(range_start, range_end, boundary_ranges);

        if (!is_valid_range(range_start, range_end)) {
            continue;
        }

        FunctionRange cfg_range;
        cfg_range.start = range_start;
        cfg_range.end = range_end;
        cfg_range.kind = FunctionRangeKind::kCfg;
        cfg_range.seed_kind = seed.kind;
        cfg_range.hard = false;

        if (!clamp_to_exec_region(cfg_range, options.segments, options.sections)) {
            continue;
        }

        cfg_range.end = trim_trailing_padding_arm64(image, cfg_range.start, cfg_range.end, little_endian);
        if (!is_valid_range(cfg_range.start, cfg_range.end)) {
            continue;
        }

        cfg_ranges.push_back(cfg_range);
    }

    std::vector<FunctionRange> normalized_cfg;
    std::vector<FunctionRange> blockers = hard_ranges;
    blockers.insert(blockers.end(), normalized_symbols.begin(), normalized_symbols.end());
    append_non_overlapping(normalized_cfg, cfg_ranges, blockers);
    merge_adjacent(normalized_cfg);

    ranges = hard_ranges;
    ranges.insert(ranges.end(), normalized_symbols.begin(), normalized_symbols.end());
    ranges.insert(ranges.end(), normalized_cfg.begin(), normalized_cfg.end());
    sort_ranges(ranges);

    return true;
}

bool discover_function_ranges_x86_64(const LoadedImage& image,
                                     std::uint64_t entry,
                                     std::size_t max_instructions_per_function,
                                     const FunctionDiscoveryOptions& options,
                                     std::vector<FunctionRange>& ranges,
                                     std::string& error) {
    ranges.clear();
    error.clear();

    if (max_instructions_per_function == 0) {
        error = "max_instructions_per_function must be > 0";
        return false;
    }

    std::vector<FunctionRange> dwarf_ranges;
    append_dwarf_ranges(options.dwarf, dwarf_ranges);
    prune_invalid_ranges(dwarf_ranges, options.segments, options.sections);
    merge_adjacent(dwarf_ranges);

    std::vector<FunctionRange> eh_ranges;
    append_eh_ranges(options.eh_frame, eh_ranges);
    prune_invalid_ranges(eh_ranges, options.segments, options.sections);
    merge_adjacent(eh_ranges);

    std::vector<FunctionRange> hard_ranges = dwarf_ranges;
    append_non_overlapping(hard_ranges, eh_ranges, hard_ranges);
    merge_adjacent(hard_ranges);

    std::vector<FunctionRange> symbol_ranges;
    append_symbol_ranges(options.symbols, options.binary_info, symbol_ranges);
    prune_invalid_ranges(symbol_ranges, options.segments, options.sections);
    merge_adjacent(symbol_ranges);

    std::vector<FunctionRange> normalized_symbols;
    append_non_overlapping(normalized_symbols, symbol_ranges, hard_ranges);
    merge_adjacent(normalized_symbols);

    std::unordered_set<std::uint64_t> stop_entries;
    for (const auto& range : hard_ranges) {
        stop_entries.insert(range.start);
    }
    for (const auto& range : normalized_symbols) {
        stop_entries.insert(range.start);
    }

    std::vector<SeedEntry> seeds;
    collect_seed_entries(image, entry, options, seeds);

    std::vector<FunctionRange> cfg_ranges;
    std::unordered_set<std::uint64_t> seen_entries;

    std::vector<FunctionRange> boundary_ranges = hard_ranges;
    boundary_ranges.insert(boundary_ranges.end(), normalized_symbols.begin(), normalized_symbols.end());
    sort_ranges(boundary_ranges);

    for (const auto& seed : seeds) {
        if (seed.address == 0) {
            continue;
        }
        if (!seen_entries.insert(seed.address).second) {
            continue;
        }
        if (!is_executable_address(options.segments, seed.address)) {
            continue;
        }
        if (contains_range(boundary_ranges, seed.address)) {
            continue;
        }

        llir::Function function;
        if (!llir::build_cfg_x86_64(image, seed.address, max_instructions_per_function, function, error)) {
            return false;
        }
        if (function.blocks.empty()) {
            continue;
        }

        std::uint64_t range_start = seed.address;
        std::uint64_t range_end = cfg_range_end_from_blocks(function, seed.address, stop_entries);
        range_end = clamp_end_by_boundaries(range_start, range_end, boundary_ranges);

        if (!is_valid_range(range_start, range_end)) {
            continue;
        }

        FunctionRange cfg_range;
        cfg_range.start = range_start;
        cfg_range.end = range_end;
        cfg_range.kind = FunctionRangeKind::kCfg;
        cfg_range.seed_kind = seed.kind;
        cfg_range.hard = false;

        if (!clamp_to_exec_region(cfg_range, options.segments, options.sections)) {
            continue;
        }

        cfg_range.end = trim_trailing_padding_x86_64(image, cfg_range.start, cfg_range.end);
        if (!is_valid_range(cfg_range.start, cfg_range.end)) {
            continue;
        }

        cfg_ranges.push_back(cfg_range);
    }

    std::vector<FunctionRange> normalized_cfg;
    std::vector<FunctionRange> blockers = hard_ranges;
    blockers.insert(blockers.end(), normalized_symbols.begin(), normalized_symbols.end());
    append_non_overlapping(normalized_cfg, cfg_ranges, blockers);
    merge_adjacent(normalized_cfg);

    ranges = hard_ranges;
    ranges.insert(ranges.end(), normalized_symbols.begin(), normalized_symbols.end());
    ranges.insert(ranges.end(), normalized_cfg.begin(), normalized_cfg.end());
    sort_ranges(ranges);

    return true;
}

}  // namespace engine::analysis
