#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "client/session.h"
#include "view_window.h"

namespace client {

struct DiscoveredFunction {
    std::uint64_t entry = 0;
    std::uint64_t size = 0;
    std::size_t blocks = 0;
};

struct FunctionsViewState {
    char filter[128] = {};
    int min_size = 1;
    bool show_demangled = true;
    std::size_t selected_entry = static_cast<std::size_t>(-1);
    bool use_discovery = false;
    bool auto_discover = false;
    int max_instructions = 2048;
    bool follow_calls = true;
    bool follow_tail_jumps = true;
    bool include_indirect_targets = true;
    bool include_symbol_entries = true;
    bool include_plt_entries = true;
    bool include_init_array_entries = true;
    bool include_eh_frame_entries = true;
    bool include_prologue_entries = true;
    bool include_dwarf_entries = true;
    bool include_linear_sweep_entries = false;
    std::vector<DiscoveredFunction> discovered;
    std::string discovery_error;
    std::string last_session_path;
    bool discovery_dirty = true;
};

void render_functions_view(FunctionsViewState& state, Session& session, ViewState& view_state);

}  // namespace client
