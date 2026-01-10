#include "functions_view.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "engine/function_discovery.h"
#include "imgui.h"

namespace client {

namespace {

std::string to_lower(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    for (unsigned char c : input) {
        result.push_back(static_cast<char>(::tolower(c)));
    }
    return result;
}

bool matches_filter(const char* filter, const std::string& text) {
    if (!filter || filter[0] == '\0') {
        return true;
    }
    const std::string filter_lower = to_lower(filter);
    const std::string target = to_lower(text);
    return target.find(filter_lower) != std::string::npos;
}

std::string display_name(const engine::symbols::SymbolEntry& entry, bool prefer_demangled) {
    if (prefer_demangled && !entry.demangled_name.empty()) {
        return entry.demangled_name;
    }
    if (!entry.name.empty()) {
        return entry.name;
    }
    return "<anon>";
}

std::string format_address(std::uint64_t address) {
    std::ostringstream oss;
    oss << "0x" << std::hex << address;
    return oss.str();
}

std::string discovered_name(Session& session, std::uint64_t address, bool prefer_demangled) {
    auto matches = session.symbol_table().within_range(address, 1);
    if (!matches.empty()) {
        return display_name(*matches.front(), prefer_demangled);
    }
    return "sub_" + format_address(address);
}

std::string build_functions_clipboard(Session& session,
                                      const FunctionsViewState& state,
                                      const std::vector<const engine::symbols::SymbolEntry*>& functions,
                                      const std::vector<std::size_t>& discovered_indices) {
    std::ostringstream oss;
    if (state.use_discovery) {
        oss << "name\taddress\tsize\tblocks\n";
        for (std::size_t idx : discovered_indices) {
            const auto& entry = state.discovered[idx];
            oss << discovered_name(session, entry.entry, state.show_demangled) << "\t";
            oss << format_address(entry.entry) << "\t";
            oss << format_address(entry.size) << "\t";
            oss << entry.blocks << "\n";
        }
    } else {
        oss << "name\taddress\tsize\n";
        for (const auto* entry : functions) {
            oss << display_name(*entry, state.show_demangled) << "\t";
            oss << format_address(entry->address) << "\t";
            oss << format_address(entry->size) << "\n";
        }
    }
    return oss.str();
}

void render_readonly_text(const char* label, const std::string& text, const ImVec2& size) {
    std::vector<char> buffer(text.begin(), text.end());
    buffer.push_back('\0');
    ImGui::InputTextMultiline(label, buffer.data(), buffer.size(), size, ImGuiInputTextFlags_ReadOnly);
}

std::uint64_t discovered_size(const engine::llir::Function& function) {
    if (function.blocks.empty()) {
        return 0;
    }
    std::uint64_t start = function.blocks.front().start;
    std::uint64_t end = function.blocks.front().end;
    for (const auto& block : function.blocks) {
        if (block.start < start) {
            start = block.start;
        }
        if (block.end > end) {
            end = block.end;
        }
    }
    return end >= start ? (end - start) : 0;
}

bool discover_functions(FunctionsViewState& state, Session& session) {
    state.discovered.clear();
    state.discovery_error.clear();

    engine::analysis::FunctionDiscoveryOptions options;
    options.follow_calls = state.follow_calls;
    options.follow_tail_jumps = state.follow_tail_jumps;
    options.include_indirect_targets = state.include_indirect_targets;
    options.include_symbol_entries = state.include_symbol_entries;
    options.include_plt_entries = state.include_plt_entries;
    options.include_init_array_entries = state.include_init_array_entries;
    options.include_eh_frame_entries = state.include_eh_frame_entries;
    options.include_prologue_entries = state.include_prologue_entries;
    options.include_dwarf_entries = state.include_dwarf_entries;
    options.include_linear_sweep_entries = state.include_linear_sweep_entries;

    std::vector<engine::llir::Function> functions;
    std::string error;
    bool ok = false;
    const auto machine = session.binary_info().machine;
    if (machine == engine::BinaryMachine::kAarch64) {
        ok = session.discover_llir_functions_arm64(session.binary_info().entry,
                                                   static_cast<std::size_t>(state.max_instructions),
                                                   options,
                                                   functions,
                                                   error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        ok = session.discover_llir_functions_x86_64(session.binary_info().entry,
                                                    static_cast<std::size_t>(state.max_instructions),
                                                    options,
                                                    functions,
                                                    error);
    } else {
        error = "unsupported architecture for discovery";
    }
    if (!ok) {
        state.discovery_error = error.empty() ? "discovery failed" : error;
        state.discovery_dirty = false;
        return false;
    }

    state.discovered.reserve(functions.size());
    for (const auto& func : functions) {
        DiscoveredFunction entry;
        entry.entry = func.entry;
        entry.size = discovered_size(func);
        entry.blocks = func.blocks.size();
        state.discovered.push_back(entry);
    }
    std::sort(state.discovered.begin(),
              state.discovered.end(),
              [](const DiscoveredFunction& a, const DiscoveredFunction& b) { return a.entry < b.entry; });

    state.discovery_dirty = false;
    return true;
}

}  // namespace

void render_functions_view(FunctionsViewState& state, Session& session, ViewState& view_state) {
    static bool show_text_view = false;
    ImGui::Begin("Functions");

    ImGui::InputText("Filter", state.filter, sizeof(state.filter));
    ImGui::SameLine();
    ImGui::Checkbox("Demangled", &state.show_demangled);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::InputInt("Min size", &state.min_size);
    if (state.min_size < 0) {
        state.min_size = 0;
    }
    ImGui::SameLine();
    bool copy_requested = ImGui::Button("Copy");
    ImGui::SameLine();
    ImGui::Checkbox("Text View", &show_text_view);

    if (!session.loaded()) {
        state.last_session_path.clear();
        state.discovered.clear();
        state.discovery_error.clear();
        state.discovery_dirty = true;
    } else if (state.last_session_path != session.path()) {
        state.last_session_path = session.path();
        state.discovered.clear();
        state.discovery_error.clear();
        state.discovery_dirty = true;
        state.selected_entry = static_cast<std::size_t>(-1);
    }

    ImGui::Checkbox("Use discovery", &state.use_discovery);
    ImGui::SameLine();
    ImGui::BeginDisabled(!state.use_discovery);
    bool auto_changed = ImGui::Checkbox("Auto", &state.auto_discover);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    bool max_changed = ImGui::InputInt("Max instr", &state.max_instructions);
    if (state.max_instructions < 1) {
        state.max_instructions = 1;
    }
    ImGui::SameLine();
    bool request_discover = ImGui::Button("Discover");
    ImGui::EndDisabled();

    bool options_changed = auto_changed || max_changed;
    if (state.use_discovery && ImGui::TreeNode("Discovery Options")) {
        options_changed |= ImGui::Checkbox("Follow calls", &state.follow_calls);
        options_changed |= ImGui::Checkbox("Follow tail jumps", &state.follow_tail_jumps);
        options_changed |= ImGui::Checkbox("Include indirect targets", &state.include_indirect_targets);
        options_changed |= ImGui::Checkbox("Include symbols", &state.include_symbol_entries);
        options_changed |= ImGui::Checkbox("Include PLT", &state.include_plt_entries);
        options_changed |= ImGui::Checkbox("Include .init_array", &state.include_init_array_entries);
        options_changed |= ImGui::Checkbox("Include EH frame", &state.include_eh_frame_entries);
        options_changed |= ImGui::Checkbox("Include prologue", &state.include_prologue_entries);
        options_changed |= ImGui::Checkbox("Include DWARF", &state.include_dwarf_entries);
        options_changed |= ImGui::Checkbox("Include linear sweep", &state.include_linear_sweep_entries);
        ImGui::TreePop();
    }

    if (options_changed) {
        state.discovery_dirty = true;
    }
    if (state.use_discovery && (request_discover || (state.auto_discover && state.discovery_dirty)) &&
        session.loaded()) {
        discover_functions(state, session);
    }

    if (state.use_discovery && !state.discovery_error.empty()) {
        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", state.discovery_error.c_str());
    }

    const auto& symbols = session.symbol_table().entries();
    std::vector<const engine::symbols::SymbolEntry*> functions;
    std::vector<std::size_t> discovered_indices;
    if (!state.use_discovery) {
        functions.reserve(symbols.size());
        for (const auto& entry : symbols) {
            if (!entry.is_function()) {
                continue;
            }
            if (entry.size < static_cast<std::uint64_t>(state.min_size)) {
                continue;
            }
            std::string name = display_name(entry, state.show_demangled);
            if (!matches_filter(state.filter, name)) {
                continue;
            }
            functions.push_back(&entry);
        }
    } else {
        discovered_indices.reserve(state.discovered.size());
        for (std::size_t i = 0; i < state.discovered.size(); ++i) {
            const auto& entry = state.discovered[i];
            if (entry.size < static_cast<std::uint64_t>(state.min_size)) {
                continue;
            }
            std::string name = discovered_name(session, entry.entry, state.show_demangled);
            if (!matches_filter(state.filter, name)) {
                continue;
            }
            discovered_indices.push_back(i);
        }
    }

    std::size_t list_size = state.use_discovery ? discovered_indices.size() : functions.size();

    if (copy_requested && session.loaded()) {
        const std::string text = build_functions_clipboard(session, state, functions, discovered_indices);
        ImGui::SetClipboardText(text.c_str());
    }
    if (list_size == 0) {
        state.selected_entry = static_cast<std::size_t>(-1);
    } else if (state.selected_entry >= list_size) {
        state.selected_entry = 0;
    }

    const float text_height = show_text_view ? 140.0f : 0.0f;
    ImGui::BeginChild("FunctionsList", ImVec2(0, -text_height), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (list_size > 0) {
        ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable;
        int columns = state.use_discovery ? 4 : 3;
        if (ImGui::BeginTable("FunctionsTable", columns, flags)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            if (state.use_discovery) {
                ImGui::TableSetupColumn("Blocks", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            }
            ImGui::TableHeadersRow();
            for (std::size_t row_idx = 0; row_idx < list_size; ++row_idx) {
                std::uint64_t address = 0;
                std::uint64_t size = 0;
                std::size_t blocks = 0;
                std::string name;
                if (state.use_discovery) {
                    const auto& entry = state.discovered[discovered_indices[row_idx]];
                    address = entry.entry;
                    size = entry.size;
                    blocks = entry.blocks;
                    name = discovered_name(session, entry.entry, state.show_demangled);
                } else {
                    const auto* entry = functions[row_idx];
                    address = entry->address;
                    size = entry->size;
                    name = display_name(*entry, state.show_demangled);
                }
                bool selected = (row_idx == state.selected_entry);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(row_idx));
                ImGuiSelectableFlags select_flags =
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick;
                if (ImGui::Selectable(name.c_str(), selected, select_flags)) {
                    state.selected_entry = row_idx;
                }
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                    view_state.go_to(address);
                }
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%llx", static_cast<unsigned long long>(address));
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("0x%llx", static_cast<unsigned long long>(size));
                if (state.use_discovery) {
                    ImGui::TableSetColumnIndex(3);
                    ImGui::Text("%zu", blocks);
                }
            }
            ImGui::EndTable();
        }
    } else {
        if (session.loaded()) {
            if (state.use_discovery && state.discovered.empty()) {
                ImGui::TextDisabled("No discovered functions yet. Click Discover to analyze.");
            } else {
                ImGui::TextDisabled("No matching functions");
            }
        } else {
            ImGui::TextDisabled("Load a binary file to list functions.");
        }
    }
    ImGui::EndChild();

    if (show_text_view && session.loaded()) {
        const std::string text = build_functions_clipboard(session, state, functions, discovered_indices);
        render_readonly_text("##FunctionsText", text, ImVec2(0, text_height));
    }

    ImGui::End();
}

}  // namespace client
