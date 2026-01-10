#include "engine/arch/arm64/function_prologue.h"

#include <capstone/arm64.h>
#include <capstone/capstone.h>

namespace engine::arch::arm64 {

namespace {

constexpr std::uint32_t kElfPfExecute = 0x1;
constexpr std::uint64_t kElfShfExecInstr = 0x4;

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

bool is_executable_section(const BinarySection& section) {
    return (section.flags & kElfShfExecInstr) != 0;
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

}  // namespace

void collect_prologue_entry_points(const LoadedImage& image,
                                   const std::vector<BinarySection>& sections,
                                   const std::vector<BinarySegment>* segments,
                                   std::vector<std::uint64_t>& out) {
    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (const auto& section : sections) {
        if (!is_executable_section(section)) {
            continue;
        }
        if (section.size < 8 || section.addr == 0) {
            continue;
        }
        if (segments && !is_executable_address(*segments, section.addr)) {
            continue;
        }
        std::vector<std::uint8_t> data;
        if (!image.read_bytes(section.addr, static_cast<std::size_t>(section.size), data)) {
            continue;
        }
        for (std::size_t offset = 0; offset + 8 <= data.size(); offset += 4) {
            cs_insn* insn = nullptr;
            const std::uint64_t addr = section.addr + offset;
            const std::size_t count = cs_disasm(handle,
                                                data.data() + offset,
                                                data.size() - offset,
                                                addr,
                                                1,
                                                &insn);
            if (count == 0) {
                continue;
            }
            bool is_entry = false;
            if (match_prologue_stp_fp_lr(insn[0])) {
                cs_insn* next = nullptr;
                const std::size_t next_count = cs_disasm(handle,
                                                         data.data() + offset + 4,
                                                         data.size() - (offset + 4),
                                                         addr + 4,
                                                         1,
                                                         &next);
                if (next_count == 1) {
                    is_entry = match_frame_setup(next[0]);
                }
                if (next_count > 0) {
                    cs_free(next, next_count);
                }
            }
            cs_free(insn, count);
            if (is_entry) {
                out.push_back(addr);
            }
        }
    }

    cs_close(&handle);
}

}  // namespace engine::arch::arm64
