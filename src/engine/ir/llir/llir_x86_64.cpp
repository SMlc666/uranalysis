#include "engine/llir.h"

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <unordered_map>

#include "../../arch/x86_64/llil_lifter.h"
namespace engine::llir {

namespace {

struct Decoder {
    csh handle = 0;

    Decoder() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        } else {
            handle = 0;
        }
    }

    ~Decoder() {
        if (handle != 0) {
            cs_close(&handle);
        }
    }

    bool ok() const { return handle != 0; }
};

bool read_bytes_window(const LoadedImage& image,
                       std::uint64_t addr,
                       std::size_t max_size,
                       std::vector<std::uint8_t>& out) {
    out.clear();
    for (const auto& seg : image.segments) {
        if (addr < seg.vaddr) {
            continue;
        }
        const std::uint64_t offset = addr - seg.vaddr;
        if (offset >= seg.data.size()) {
            continue;
        }
        const std::size_t available = seg.data.size() - static_cast<std::size_t>(offset);
        const std::size_t count = std::min(max_size, available);
        out.insert(out.end(),
                   seg.data.begin() + static_cast<std::ptrdiff_t>(offset),
                   seg.data.begin() + static_cast<std::ptrdiff_t>(offset + count));
        return true;
    }
    return false;
}

bool has_group(const Decoder& decoder, const cs_insn& insn, std::uint8_t group) {
    return decoder.ok() && cs_insn_group(decoder.handle, &insn, group);
}

bool is_conditional_jump(const cs_insn& insn) {
    if (insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP) {
        return false;
    }
    return true;
}

bool extract_branch_target(const cs_insn& insn, std::uint64_t& target_out) {
    if (!insn.detail) {
        return false;
    }
    const cs_x86& x86 = insn.detail->x86;
    for (std::uint8_t i = 0; i < x86.op_count; ++i) {
        const auto& op = x86.operands[i];
        if (op.type == X86_OP_IMM) {
            target_out = static_cast<std::uint64_t>(op.imm);
            return true;
        }
    }
    return false;
}

Instruction decode_one(const Decoder& decoder,
                       const LoadedImage& image,
                       std::uint64_t addr,
                       std::string& error) {
    Instruction inst;
    if (!decoder.ok()) {
        error = "capstone not initialized";
        return inst;
    }

    std::vector<std::uint8_t> bytes;
    if (!read_bytes_window(image, addr, 15, bytes) || bytes.empty()) {
        error = "failed to read instruction";
        return inst;
    }

    cs_insn* insn = nullptr;
    std::size_t count = cs_disasm(decoder.handle,
                                  bytes.data(),
                                  bytes.size(),
                                  addr,
                                  1,
                                  &insn);
    if (count == 0 || !insn) {
        error = "capstone failed to decode";
        return inst;
    }

    inst.address = insn[0].address;
    inst.size = static_cast<std::uint32_t>(insn[0].size);
    inst.mnemonic = insn[0].mnemonic ? insn[0].mnemonic : "";
    inst.operands = insn[0].op_str ? insn[0].op_str : "";

    const bool is_jump = has_group(decoder, insn[0], CS_GRP_JUMP);
    const bool is_call = has_group(decoder, insn[0], CS_GRP_CALL);
    const bool is_ret = has_group(decoder, insn[0], CS_GRP_RET);

    if (is_ret) {
        inst.branch = BranchKind::kRet;
    } else if (is_call) {
        inst.branch = BranchKind::kCall;
        std::uint64_t target = 0;
        if (extract_branch_target(insn[0], target)) {
            inst.targets.push_back(target);
        }
    } else if (is_jump) {
        inst.branch = BranchKind::kJump;
        inst.conditional = is_conditional_jump(insn[0]);
        std::uint64_t target = 0;
        if (extract_branch_target(insn[0], target)) {
            inst.targets.push_back(target);
        }
    }

    x86_64::lift_instruction(decoder.handle, insn[0], inst);
    cs_free(insn, count);
    return inst;
}

}  // namespace

bool build_cfg_x86_64(const LoadedImage& image,
                      std::uint64_t entry,
                      std::size_t max_instructions,
                      Function& function,
                      std::string& error) {
    function = {};
    error.clear();
    if (max_instructions == 0) {
        error = "max_instructions must be > 0";
        return false;
    }

    Decoder decoder;
    if (!decoder.ok()) {
        error = "capstone not initialized";
        return false;
    }

    function.entry = entry;
    std::unordered_map<std::uint64_t, std::size_t> block_index;
    std::vector<std::uint64_t> worklist;
    worklist.push_back(entry);

    std::size_t total_instructions = 0;

    while (!worklist.empty()) {
        std::uint64_t block_addr = worklist.back();
        worklist.pop_back();

        if (block_index.find(block_addr) != block_index.end()) {
            continue;
        }

        BasicBlock block;
        block.start = block_addr;

        std::uint64_t current = block_addr;
        bool terminate = false;

        while (!terminate) {
            if (total_instructions >= max_instructions) {
                error = "instruction limit reached";
                return false;
            }

            Instruction inst = decode_one(decoder, image, current, error);
            if (!error.empty()) {
                break;
            }

            block.instructions.push_back(inst);
            total_instructions += 1;

            const std::uint64_t next_addr = current + inst.size;

            if (inst.branch == BranchKind::kRet) {
                terminate = true;
            } else if (inst.branch == BranchKind::kJump) {
                if (!inst.targets.empty()) {
                    block.successors.push_back(inst.targets.front());
                    worklist.push_back(inst.targets.front());
                }
                if (inst.conditional) {
                    block.successors.push_back(next_addr);
                    worklist.push_back(next_addr);
                }
                terminate = true;
            } else {
                current = next_addr;
            }
        }

        if (!block.instructions.empty()) {
            const auto& last = block.instructions.back();
            block.end = last.address + last.size;
        } else {
            block.end = block.start;
        }

        block.successors.erase(std::remove(block.successors.begin(), block.successors.end(), 0),
                               block.successors.end());
        std::sort(block.successors.begin(), block.successors.end());
        block.successors.erase(std::unique(block.successors.begin(), block.successors.end()),
                               block.successors.end());

        block_index[block.start] = function.blocks.size();
        function.blocks.push_back(std::move(block));
    }

    for (auto& block : function.blocks) {
        block.predecessors.clear();
    }
    for (const auto& block : function.blocks) {
        for (std::uint64_t succ : block.successors) {
            auto it = block_index.find(succ);
            if (it == block_index.end()) {
                continue;
            }
            function.blocks[it->second].predecessors.push_back(block.start);
        }
    }
    for (auto& block : function.blocks) {
        std::sort(block.predecessors.begin(), block.predecessors.end());
        block.predecessors.erase(std::unique(block.predecessors.begin(), block.predecessors.end()),
                                 block.predecessors.end());
    }

    return true;
}

}  // namespace engine::llir
