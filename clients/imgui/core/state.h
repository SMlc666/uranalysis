#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <limits>

#include "client/session.h"
#include "engine/disasm.h"

namespace client {

struct DiscoveredFunction {
    std::uint64_t entry = 0;
    std::uint64_t size = 0;
    std::size_t blocks = 0;
};

struct ViewStateBase {
    bool visible = true;
    bool needs_refresh = false;
};

struct NavigationState {
    std::uint64_t current_address = 0;
    std::vector<std::uint64_t> history;
    int history_index = -1;

    void navigate_to(std::uint64_t address);
    bool can_go_back() const;
    bool can_go_forward() const;
    void go_back();
    void go_forward();
};

struct CodeViewState : ViewStateBase {
    std::uint64_t address = 0;
    int instruction_count = 32;
    int byte_count = 128;
    int ir_instruction_count = 512;
    std::vector<engine::DisasmLine> disasm_cache;
    std::vector<std::uint8_t> bytes_cache;
    
    // Disassembly state
    std::uint64_t disasm_start_address = 0;
    std::uint64_t disasm_next_address = 0;
    bool disasm_reached_end = false;
    bool disasm_loading = false;
    bool disasm_reset_scroll = false;
    std::string last_error;

    // IR state
    bool ir_needs_refresh = true;
    std::uint64_t ir_last_address = 0;
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
};

struct FunctionsViewState : ViewStateBase {
    char filter[128] = {};
    int min_size = 1;
    bool show_demangled = true;
    std::size_t selected_entry = static_cast<std::size_t>(-1);
    
    // Discovery options
    bool use_discovery = false;
    bool auto_discover = false;
    bool discovery_dirty = true;
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
};

struct NamesViewState : ViewStateBase {
    char filter[128] = {};
    bool show_symbols = true;
    bool show_types = true;
    bool show_vtables = true;
    std::size_t selected_entry = static_cast<std::size_t>(-1);
};

struct StringsViewState : ViewStateBase {
    char filter[128] = {};
    int min_length = 4;
    std::size_t selected_entry = static_cast<std::size_t>(-1);
};

struct FileBrowserState {
    char dir[512] = {};
    char filter[128] = ".elf;.so;.exe;.dll";
    char search[128] = {};
    std::string current_dir;
    std::vector<std::string> history;
    int history_index = -1;
    bool dirty = true;
    std::string status;
    bool open = false;
};

class AppState {
public:
    engine::Session& session() { return session_; }
    const engine::Session& session() const { return session_; }
    bool is_session_loaded() const { return session_.loaded(); }

    NavigationState& navigation() { return navigation_; }
    const NavigationState& navigation() const { return navigation_; }

    CodeViewState& code_view() { return code_view_; }
    FunctionsViewState& functions_view() { return functions_view_; }
    NamesViewState& names_view() { return names_view_; }
    StringsViewState& strings_view() { return strings_view_; }
    FileBrowserState& file_browser() { return file_browser_; }
    
    // General UI state
    bool show_about = false;
    bool reset_layout = false;
    std::string status_message;

private:
    engine::Session session_;
    NavigationState navigation_;
    CodeViewState code_view_;
    FunctionsViewState functions_view_;
    NamesViewState names_view_;
    StringsViewState strings_view_;
    FileBrowserState file_browser_;
};

}  // namespace client