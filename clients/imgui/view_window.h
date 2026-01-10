#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "client/session.h"
#include "engine/disasm.h"

namespace client {

struct ViewState {
    char address[32] = {};
    int instruction_count = 32;
    int byte_count = 128;
    std::vector<engine::DisasmLine> disasm;
    std::vector<std::uint8_t> bytes;
    std::string last_error;
    int ir_instruction_count = 512;
    std::vector<std::string> llir_lines;
    std::vector<std::string> mlil_lines;
    std::vector<std::string> hlil_lines;
    std::vector<std::string> pseudoc_lines;
    std::vector<std::string> pseudoc_mlil_lines;
    std::string ir_error;
    std::string mlil_error;
    std::string hlil_error;
    std::string pseudoc_error;
    std::string pseudoc_mlil_error;
    bool hlil_use_optimizations = true;
    std::uint64_t ir_last_address = 0;
    std::uint64_t last_address = 0;
    std::uint64_t disasm_start_address = 0;
    std::uint64_t disasm_next_address = 0;
    int disasm_cache_limit = 4096;
    bool disasm_reset_scroll = false;
    bool disasm_reached_end = false;
    bool disasm_loading = false;
    bool needs_refresh = true;
    bool ir_needs_refresh = true;

    void go_to(std::uint64_t addr) {
        std::snprintf(address, sizeof(address), "0x%llx", static_cast<unsigned long long>(addr));
        needs_refresh = true;
        ir_needs_refresh = true;
    }
};

void render_view_window(ViewState& state, Session& session);

}  // namespace client
