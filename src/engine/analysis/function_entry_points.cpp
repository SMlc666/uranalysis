#include "function_discovery_internal.h"

#include <algorithm>
#include <limits>
#include <string>
#include <unordered_set>

#include <capstone/arm64.h>
#include <capstone/capstone.h>

namespace engine::analysis::detail {

namespace {

constexpr std::uint8_t kElfSymTypeMask = 0x0f;
constexpr std::uint8_t kElfSymTypeFunc = 0x02;
constexpr std::uint32_t kElfPfExecute = 0x1;
constexpr std::uint64_t kElfShfExecInstr = 0x4;
constexpr std::uint32_t kAarch64RelocJumpSlot = 1026;
constexpr std::size_t kDefaultPltEntrySize = 16;
constexpr std::uint64_t kU64Max = std::numeric_limits<std::uint64_t>::max();

struct AddressRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
};

bool is_executable_address(const std::vector<BinarySegment>& segments, std::uint64_t address) {
    for (const auto& seg : segments) {
        if ((seg.flags & kElfPfExecute) == 0) {
            continue;
        }
        if (address >= seg.vaddr && address < (seg.vaddr + seg.memsz)) {
            return true;
        }
    }
    return false;
}

void append_range(std::vector<AddressRange>& ranges, std::uint64_t start, std::uint64_t end) {
    if (start == 0 || end <= start) {
        return;
    }
    ranges.push_back(AddressRange{start, end});
}

void append_dwarf_ranges(const dwarf::DwarfCatalog* catalog,
                         std::vector<AddressRange>& ranges,
                         std::unordered_set<std::uint64_t>& starts) {
    if (!catalog) {
        return;
    }
    for (const auto& func : catalog->functions()) {
        if (func.low_pc != 0 && func.high_pc > func.low_pc) {
            append_range(ranges, func.low_pc, func.high_pc);
            starts.insert(func.low_pc);
        }
        for (const auto& range : func.ranges) {
            append_range(ranges, range.start, range.end);
            if (range.start != 0) {
                starts.insert(range.start);
            }
        }
    }
}

void append_eh_ranges(const ehframe::EhFrameCatalog* catalog,
                      std::vector<AddressRange>& ranges,
                      std::unordered_set<std::uint64_t>& starts) {
    if (!catalog) {
        return;
    }
    for (const auto& entry : catalog->entries()) {
        if (entry.start == 0 || entry.size == 0) {
            continue;
        }
        append_range(ranges, entry.start, entry.start + entry.size);
        starts.insert(entry.start);
    }
}

void normalize_ranges(std::vector<AddressRange>& ranges) {
    if (ranges.empty()) {
        return;
    }
    std::sort(ranges.begin(), ranges.end(), [](const AddressRange& lhs, const AddressRange& rhs) {
        if (lhs.start != rhs.start) {
            return lhs.start < rhs.start;
        }
        return lhs.end < rhs.end;
    });
    std::vector<AddressRange> merged;
    merged.reserve(ranges.size());
    for (const auto& range : ranges) {
        if (merged.empty() || range.start > merged.back().end) {
            merged.push_back(range);
        } else if (range.end > merged.back().end) {
            merged.back().end = range.end;
        }
    }
    ranges.swap(merged);
}

bool is_in_known_range(const std::vector<AddressRange>& ranges, std::uint64_t address) {
    if (ranges.empty()) {
        return false;
    }
    auto it = std::upper_bound(ranges.begin(),
                               ranges.end(),
                               address,
                               [](std::uint64_t value, const AddressRange& range) { return value < range.start; });
    if (it == ranges.begin()) {
        return false;
    }
    --it;
    return address >= it->start && address < it->end;
}

bool is_executable_section(const BinarySection& section) {
    return (section.flags & kElfShfExecInstr) != 0;
}

std::size_t count_jump_slot_relocations(const std::vector<BinaryRelocation>& relocations) {
    std::size_t count = 0;
    for (const auto& reloc : relocations) {
        if (reloc.type == kAarch64RelocJumpSlot) {
            ++count;
        }
    }
    return count;
}

std::size_t resolve_plt_entry_size(std::uint64_t section_size,
                                   std::size_t jump_slot_count,
                                   bool is_plt_section) {
    if (section_size == 0) {
        return 0;
    }
    if (jump_slot_count > 0) {
        const std::size_t slots = is_plt_section ? (jump_slot_count + 1) : jump_slot_count;
        if (slots > 0 && section_size % slots == 0) {
            return static_cast<std::size_t>(section_size / slots);
        }
    }
    if (section_size % kDefaultPltEntrySize == 0) {
        return kDefaultPltEntrySize;
    }
    return 0;
}

bool read_u64(const std::vector<std::uint8_t>& data, std::size_t offset, bool little_endian, std::uint64_t& value) {
    if (offset + 8 > data.size()) {
        return false;
    }
    value = 0;
    if (little_endian) {
        for (std::size_t i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(data[offset + i]) << (i * 8);
        }
    } else {
        for (std::size_t i = 0; i < 8; ++i) {
            value = (value << 8) | static_cast<std::uint64_t>(data[offset + i]);
        }
    }
    return true;
}

bool match_prologue_stp_fp_lr(const cs_insn& insn) {
    if (insn.id != ARM64_INS_STP || !insn.detail) {
        return false;
    }
    const cs_arm64& arm = insn.detail->arm64;
    if (!arm.writeback || arm.op_count < 3) {
        return false;
    }
    if (arm.operands[0].type != ARM64_OP_REG || arm.operands[1].type != ARM64_OP_REG ||
        arm.operands[2].type != ARM64_OP_MEM) {
        return false;
    }
    if (arm.operands[0].reg != ARM64_REG_X29 || arm.operands[1].reg != ARM64_REG_X30) {
        return false;
    }
    const auto& mem = arm.operands[2].mem;
    if (mem.base != ARM64_REG_SP) {
        return false;
    }
    if (mem.disp >= 0) {
        return false;
    }
    return true;
}

bool match_frame_setup(const cs_insn& insn) {
    if (!insn.detail) {
        return false;
    }
    const cs_arm64& arm = insn.detail->arm64;
    if (insn.id == ARM64_INS_MOV && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG &&
        arm.operands[1].type == ARM64_OP_REG) {
        return arm.operands[0].reg == ARM64_REG_X29 && arm.operands[1].reg == ARM64_REG_SP;
    }
    if (insn.id == ARM64_INS_ADD && arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG &&
        arm.operands[1].type == ARM64_OP_REG && arm.operands[2].type == ARM64_OP_IMM) {
        return arm.operands[0].reg == ARM64_REG_X29 && arm.operands[1].reg == ARM64_REG_SP;
    }
    return false;
}

bool is_probable_prologue(csh handle,
                          const std::vector<std::uint8_t>& data,
                          std::uint64_t section_addr,
                          std::uint64_t target) {
    if (target < section_addr) {
        return false;
    }
    const std::uint64_t offset = target - section_addr;
    if (offset + 8 > data.size()) {
        return false;
    }
    cs_insn* first = nullptr;
    std::size_t count = cs_disasm(handle, data.data() + offset, data.size() - offset, target, 1, &first);
    if (count == 0) {
        return false;
    }
    bool match = false;
    if (match_prologue_stp_fp_lr(first[0])) {
        cs_insn* next = nullptr;
        const std::size_t next_count =
            cs_disasm(handle, data.data() + offset + 4, data.size() - (offset + 4), target + 4, 1, &next);
        if (next_count == 1) {
            match = match_frame_setup(next[0]);
        }
        if (next_count > 0) {
            cs_free(next, next_count);
        }
    }
    cs_free(first, count);
    return match;
}

}  // namespace

void collect_symbol_entry_points(const std::vector<BinarySymbol>& symbols,
                                 const BinaryInfo* binary_info,
                                 std::vector<std::uint64_t>& out) {
    const bool is_elf = binary_info && binary_info->format == BinaryFormat::kElf;
    const bool is_pe = binary_info && binary_info->format == BinaryFormat::kPe;
    for (const auto& sym : symbols) {
        if (sym.value == 0) {
            continue;
        }
        if (is_elf && (sym.info & kElfSymTypeMask) != kElfSymTypeFunc) {
            continue;
        }
        if (is_pe && sym.name.find('!') != std::string::npos) {
            continue;
        }
        out.push_back(sym.value);
    }
}

void collect_plt_entry_points(const std::vector<BinarySection>& sections,
                              const std::vector<BinarySegment>* segments,
                              const std::vector<BinaryRelocation>* relocations,
                              std::vector<std::uint64_t>& out) {
    std::size_t jump_slot_count = 0;
    if (relocations) {
        jump_slot_count = count_jump_slot_relocations(*relocations);
    }
    for (const auto& section : sections) {
        if (section.name != ".plt" && section.name != ".plt.sec") {
            continue;
        }
        const bool is_plt = (section.name == ".plt");
        const std::size_t entry_size = resolve_plt_entry_size(section.size, jump_slot_count, is_plt);
        if (entry_size == 0) {
            continue;
        }
        const std::size_t total_entries = static_cast<std::size_t>(section.size / entry_size);
        if (total_entries == 0) {
            continue;
        }
        const std::size_t start_index = is_plt ? 1 : 0;
        for (std::size_t i = start_index; i < total_entries; ++i) {
            const std::uint64_t addr = section.addr + (i * entry_size);
            if (segments && !is_executable_address(*segments, addr)) {
                continue;
            }
            out.push_back(addr);
        }
    }
}

void collect_init_array_entry_points(const LoadedImage& image,
                                     const std::vector<BinarySection>& sections,
                                     const std::vector<BinarySegment>* segments,
                                     const BinaryInfo* binary_info,
                                     std::vector<std::uint64_t>& out) {
    bool little_endian = true;
    if (binary_info) {
        little_endian = binary_info->little_endian;
    }
    for (const auto& section : sections) {
        if (section.name != ".init_array") {
            continue;
        }
        if (section.size < 8) {
            continue;
        }
        std::vector<std::uint8_t> data;
        if (!image.read_bytes(section.addr, static_cast<std::size_t>(section.size), data)) {
            continue;
        }
        const std::size_t count = static_cast<std::size_t>(section.size / 8);
        for (std::size_t i = 0; i < count; ++i) {
            std::uint64_t value = 0;
            if (!read_u64(data, i * 8, little_endian, value)) {
                break;
            }
            if (value == 0 || value == kU64Max) {
                continue;
            }
            if (segments && !is_executable_address(*segments, value)) {
                continue;
            }
            out.push_back(value);
        }
    }
}

void collect_eh_frame_entry_points(const ehframe::EhFrameCatalog& catalog,
                                   const std::vector<BinarySegment>* segments,
                                   std::vector<std::uint64_t>& out) {
    for (const auto& entry : catalog.entries()) {
        if (entry.start == 0 || entry.size == 0) {
            continue;
        }
        if (segments && !is_executable_address(*segments, entry.start)) {
            continue;
        }
        out.push_back(entry.start);
    }
}

void collect_dwarf_entry_points(const dwarf::DwarfCatalog& catalog, std::vector<std::uint64_t>& out) {
    for (const auto& func : catalog.functions()) {
        if (func.low_pc != 0) {
            out.push_back(func.low_pc);
        }
        for (const auto& range : func.ranges) {
            if (range.start != 0) {
                out.push_back(range.start);
            }
        }
    }
}

void collect_linear_sweep_entry_points(const LoadedImage& image,
                                       const std::vector<BinarySection>& sections,
                                       const std::vector<BinarySegment>* segments,
                                       const dwarf::DwarfCatalog* dwarf,
                                       const ehframe::EhFrameCatalog* eh_frame,
                                       std::vector<std::uint64_t>& out) {
    std::vector<AddressRange> known_ranges;
    std::unordered_set<std::uint64_t> known_starts;
    append_dwarf_ranges(dwarf, known_ranges, known_starts);
    append_eh_ranges(eh_frame, known_ranges, known_starts);
    normalize_ranges(known_ranges);

    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (const auto& section : sections) {
        if (!is_executable_section(section)) {
            continue;
        }
        if (section.size < 4 || section.addr == 0) {
            continue;
        }
        if (segments && !is_executable_address(*segments, section.addr)) {
            continue;
        }
        std::vector<std::uint8_t> data;
        if (!image.read_bytes(section.addr, static_cast<std::size_t>(section.size), data)) {
            continue;
        }
        for (std::size_t offset = 0; offset + 4 <= data.size(); offset += 4) {
            const std::uint64_t addr = section.addr + offset;
            cs_insn* insn = nullptr;
            const std::size_t count =
                cs_disasm(handle, data.data() + offset, data.size() - offset, addr, 1, &insn);
            if (count == 0) {
                continue;
            }
            if (insn[0].id == ARM64_INS_BL && insn[0].detail) {
                const cs_arm64& arm = insn[0].detail->arm64;
                if (arm.op_count >= 1 && arm.operands[0].type == ARM64_OP_IMM) {
                    const std::uint64_t target = static_cast<std::uint64_t>(arm.operands[0].imm);
                    if (!segments || is_executable_address(*segments, target)) {
                        if (!known_ranges.empty() && is_in_known_range(known_ranges, target) &&
                            known_starts.find(target) == known_starts.end()) {
                            cs_free(insn, count);
                            continue;
                        }
                        out.push_back(target);
                    }
                }
            } else if (insn[0].id == ARM64_INS_B && insn[0].detail) {
                const cs_arm64& arm = insn[0].detail->arm64;
                if (arm.cc == ARM64_CC_INVALID || arm.cc == ARM64_CC_AL) {
                    if (arm.op_count >= 1 && arm.operands[0].type == ARM64_OP_IMM) {
                        const std::uint64_t target = static_cast<std::uint64_t>(arm.operands[0].imm);
                        if (!segments || is_executable_address(*segments, target)) {
                            if (!known_ranges.empty() && is_in_known_range(known_ranges, target) &&
                                known_starts.find(target) == known_starts.end()) {
                                cs_free(insn, count);
                                continue;
                            }
                            const bool same_section =
                                (target >= section.addr && target < (section.addr + section.size));
                            if (!same_section || is_probable_prologue(handle, data, section.addr, target)) {
                                out.push_back(target);
                            }
                        }
                    }
                }
            }
            cs_free(insn, count);
        }
    }

    cs_close(&handle);
}

}  // namespace engine::analysis::detail
