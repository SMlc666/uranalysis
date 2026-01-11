#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "engine/disasm.h"
#include "engine/session.h"

namespace client::services {

/// Result of a disassembly operation
struct DisasmResult {
    bool success = false;
    std::string error;
    std::vector<engine::DisasmLine> lines;
    std::uint64_t next_address = 0;
};

/// Service for disassembly operations
class DisasmService {
public:
    explicit DisasmService(engine::Session& session);

    /// Disassemble a given number of instructions
    DisasmResult disassemble(std::uint64_t address, std::size_t count);

    /// Disassemble with byte and instruction limits
    DisasmResult disassemble_bytes(std::uint64_t address,
                                   std::size_t max_bytes,
                                   std::size_t max_count);

    /// Read bytes from memory
    bool read_bytes(std::uint64_t address,
                    std::size_t length,
                    std::vector<std::uint8_t>& bytes);

private:
    engine::Session& session_;
};

}  // namespace client::services