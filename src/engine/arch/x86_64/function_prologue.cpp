#include "engine/arch/x86_64/function_prologue.h"

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <unordered_set>

namespace engine::arch::x86_64 {

namespace {

constexpr std::uint32_t kPfExec = 0x1;
constexpr std::uint64_t kShfExecInstr = 0x4;

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

bool is_executable_section(const BinarySection& section) {
    return (section.flags & kShfExecInstr) != 0;
}

bool is_stack_sub(cs_insn* insn) {
    if (!insn || !insn->detail) {
        return false;
    }
    if (insn->id != X86_INS_SUB) {
        return false;
    }
    const auto& x86 = insn->detail->x86;
    if (x86.op_count < 2) {
        return false;
    }
    return x86.operands[0].type == X86_OP_REG && x86.operands[0].reg == X86_REG_RSP &&
           x86.operands[1].type == X86_OP_IMM;
}

bool is_stack_align(cs_insn* insn) {
    if (!insn || !insn->detail) {
        return false;
    }
    if (insn->id != X86_INS_AND) {
        return false;
    }
    const auto& x86 = insn->detail->x86;
    if (x86.op_count < 2) {
        return false;
    }
    return x86.operands[0].type == X86_OP_REG && x86.operands[0].reg == X86_REG_RSP &&
           x86.operands[1].type == X86_OP_IMM;
}

bool is_push_reg(cs_insn* insn, x86_reg reg) {
    if (!insn || !insn->detail) {
        return false;
    }
    if (insn->id != X86_INS_PUSH) {
        return false;
    }
    const auto& x86 = insn->detail->x86;
    if (x86.op_count < 1) {
        return false;
    }
    return x86.operands[0].type == X86_OP_REG && x86.operands[0].reg == reg;
}

bool is_mov_rbp_rsp(cs_insn* insn) {
    if (!insn || !insn->detail) {
        return false;
    }
    if (insn->id != X86_INS_MOV) {
        return false;
    }
    const auto& x86 = insn->detail->x86;
    if (x86.op_count < 2) {
        return false;
    }
    const auto& dst = x86.operands[0];
    const auto& src = x86.operands[1];
    return dst.type == X86_OP_REG && dst.reg == X86_REG_RBP &&
           src.type == X86_OP_REG && src.reg == X86_REG_RSP;
}

bool is_callee_saved_push(cs_insn* insn) {
    return is_push_reg(insn, X86_REG_RBX) || is_push_reg(insn, X86_REG_R12) ||
           is_push_reg(insn, X86_REG_R13) || is_push_reg(insn, X86_REG_R14) ||
           is_push_reg(insn, X86_REG_R15) || is_push_reg(insn, X86_REG_RDI) ||
           is_push_reg(insn, X86_REG_RSI);
}

bool match_prologue(cs_insn* insn, std::size_t count) {
    if (count < 2 || !insn) {
        if (count >= 1 && insn) {
            return is_stack_sub(&insn[0]) || is_stack_align(&insn[0]);
        }
        return false;
    }
    const cs_insn& first = insn[0];
    const cs_insn& second = insn[1];
    if (!first.detail || !second.detail) {
        return false;
    }
    if (is_push_reg(&insn[0], X86_REG_RBP) && is_mov_rbp_rsp(&insn[1])) {
        return true;
    }
    if (is_push_reg(&insn[0], X86_REG_RBP) && is_stack_sub(&insn[1])) {
        return true;
    }
    if (is_callee_saved_push(&insn[0]) && is_stack_sub(&insn[1])) {
        return true;
    }
    if (is_stack_sub(&insn[0])) {
        return true;
    }
    if (is_stack_align(&insn[0])) {
        return true;
    }
    return false;
}

}  // namespace

void collect_prologue_entry_points(const LoadedImage& image,
                                   const std::vector<BinarySection>& sections,
                                   const std::vector<BinarySegment>* segments,
                                   std::vector<std::uint64_t>& out) {
    out.clear();
    csh handle = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    std::unordered_set<std::uint64_t> seen;
    for (const auto& section : sections) {
        if (!is_executable_section(section) || section.size < 4) {
            continue;
        }
        std::vector<std::uint8_t> data;
        if (!image.read_bytes(section.addr, static_cast<std::size_t>(section.size), data)) {
            continue;
        }
        const std::size_t limit = data.size();
        for (std::size_t offset = 0; offset + 4 <= limit; ++offset) {
            const std::uint64_t address = section.addr + offset;
            if (!is_executable_address(segments, address)) {
                continue;
            }
            if (!seen.insert(address).second) {
                continue;
            }
            cs_insn* insn = nullptr;
            std::size_t count =
                cs_disasm(handle, data.data() + offset, limit - offset, address, 2, &insn);
            if (count == 0) {
                continue;
            }
            bool matched = match_prologue(insn, count);
            cs_free(insn, count);
            if (matched) {
                out.push_back(address);
            }
        }
    }

    cs_close(&handle);
}

}  // namespace engine::arch::x86_64
