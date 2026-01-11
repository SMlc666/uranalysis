#include "client/services/disasm_service.h"

namespace client::services {

DisasmService::DisasmService(engine::Session& session) : session_(session) {}

DisasmResult DisasmService::disassemble(std::uint64_t address, std::size_t count) {
    DisasmResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;
    const std::size_t max_bytes = count * ((machine == engine::BinaryMachine::kAarch64) ? 4U : 15U);

    if (machine == engine::BinaryMachine::kAarch64) {
        result.success = session_.disasm_arm64(address, max_bytes, count, result.lines, result.error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        result.success = session_.disasm_x86_64(address, max_bytes, count, result.lines, result.error);
    } else {
        result.error = "unsupported architecture for disasm";
    }

    if (result.success && !result.lines.empty()) {
        const auto& last = result.lines.back();
        const std::uint64_t advance = last.size != 0 ? last.size : 4;
        result.next_address = last.address + advance;
    }

    return result;
}

DisasmResult DisasmService::disassemble_bytes(std::uint64_t address,
                                               std::size_t max_bytes,
                                               std::size_t max_count) {
    DisasmResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;

    if (machine == engine::BinaryMachine::kAarch64) {
        result.success =
            session_.disasm_arm64(address, max_bytes, max_count, result.lines, result.error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        result.success =
            session_.disasm_x86_64(address, max_bytes, max_count, result.lines, result.error);
    } else {
        result.error = "unsupported architecture for disasm";
    }

    if (result.success && !result.lines.empty()) {
        const auto& last = result.lines.back();
        const std::uint64_t advance = last.size != 0 ? last.size : 4;
        result.next_address = last.address + advance;
    }

    return result;
}

bool DisasmService::read_bytes(std::uint64_t address,
                               std::size_t length,
                               std::vector<std::uint8_t>& bytes) {
    if (!session_.loaded()) {
        return false;
    }
    return session_.image().read_bytes(address, length, bytes);
}

}  // namespace client::services