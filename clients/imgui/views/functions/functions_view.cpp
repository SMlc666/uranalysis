#include "functions_view.h"

#include <algorithm>
#include <vector>
#include <string>
#include <sstream>

#include "imgui.h"
#include "client/formatters/address.h"
#include "client/formatters/symbols.h"
#include "../../utils/imgui_helpers.h"
#include "engine/function_discovery.h"
#include "client/session.h"

namespace client {

namespace {

std::string discovered_name(Session& session, std::uint64_t address, bool prefer_demangled) {
    auto matches = session.symbol_table().within_range(address, 1);
    if (!matches.empty()) {
        return client::fmt::symbol_display_name(*matches.front());
    }
    return "sub_" + client::fmt::hex(address);
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
            oss << client::fmt::hex(entry.entry) << "\t";
            oss << client::fmt::hex(entry.size) << "\t";
            oss << entry.blocks << "\n";
        }
    } else {
        oss << "name\taddress\tsize\n";
        for (const auto* entry : functions) {
            oss << client::fmt::symbol_display_name(*entry) << "\t";
            oss << client::fmt::hex(entry->address) << "\t";
            oss << client::fmt::hex(entry->size) << "\n";
        }
    }
    return oss.str();
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

} // namespace

FunctionsView::FunctionsView(AppContext& context)
    : ViewBase(context, "Functions"),
      filter_widget_("FunctionsFilter", "Filter") {}

void FunctionsView::on_render() {
    auto& fv_state = state().functions_view();
    static bool show_text_view = false;

    ImGui::Begin(name(), visible_ptr());

    render_toolbar();

    // Reset state on new session
    if (!session().loaded()) {
        fv_state.last_session_path.clear();
        fv_state.discovered.clear();
        fv_state.discovery_error.clear();
        fv_state.discovery_dirty = true;
    } else if (fv_state.last_session_path != session().path()) {
        fv_state.last_session_path = session().path();
        fv_state.discovered.clear();
        fv_state.discovery_error.clear();
        fv_state.discovery_dirty = true;
        fv_state.selected_entry = static_cast<std::size_t>(-1);
    }

    // Discovery options
    ImGui::Checkbox("Use discovery", &fv_state.use_discovery);
    ImGui::SameLine();
    ImGui::BeginDisabled(!fv_state.use_discovery);
    bool auto_changed = ImGui::Checkbox("Auto", &fv_state.auto_discover);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    bool max_changed = ImGui::InputInt("Max instr", &fv_state.max_instructions);
    if (fv_state.max_instructions < 1) fv_state.max_instructions = 1;
    ImGui::SameLine();
    bool request_discover = ImGui::Button("Discover");
    ImGui::EndDisabled();

    bool options_changed = auto_changed || max_changed;
    if (fv_state.use_discovery && ImGui::TreeNode("Discovery Options")) {
        render_discovery_options();
        ImGui::TreePop();
    } else if (options_changed) {
        fv_state.discovery_dirty = true;
    }

    if (fv_state.use_discovery && (request_discover || (fv_state.auto_discover && fv_state.discovery_dirty)) && session().loaded()) {
        discover_functions();
    }

    if (fv_state.use_discovery && !fv_state.discovery_error.empty()) {
        client::imgui::render_error_text(fv_state.discovery_error);
    }

    render_functions_table();

    ImGui::End();
}

void FunctionsView::render_toolbar() {
    auto& fv_state = state().functions_view();
    
    filter_widget_.render(fv_state.filter);
    ImGui::SameLine();
    ImGui::Checkbox("Demangled", &fv_state.show_demangled);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    if (ImGui::InputInt("Min size", &fv_state.min_size)) {
        if (fv_state.min_size < 0) fv_state.min_size = 0;
    }
}

void FunctionsView::render_discovery_options() {
    auto& fv_state = state().functions_view();
    bool changed = false;
    changed |= ImGui::Checkbox("Follow calls", &fv_state.follow_calls);
    changed |= ImGui::Checkbox("Follow tail jumps", &fv_state.follow_tail_jumps);
    changed |= ImGui::Checkbox("Include indirect targets", &fv_state.include_indirect_targets);
    changed |= ImGui::Checkbox("Include symbols", &fv_state.include_symbol_entries);
    changed |= ImGui::Checkbox("Include PLT", &fv_state.include_plt_entries);
    changed |= ImGui::Checkbox("Include .init_array", &fv_state.include_init_array_entries);
    changed |= ImGui::Checkbox("Include EH frame", &fv_state.include_eh_frame_entries);
    changed |= ImGui::Checkbox("Include prologue", &fv_state.include_prologue_entries);
    changed |= ImGui::Checkbox("Include DWARF", &fv_state.include_dwarf_entries);
    changed |= ImGui::Checkbox("Include linear sweep", &fv_state.include_linear_sweep_entries);
    
    if (changed) fv_state.discovery_dirty = true;
}

void FunctionsView::render_functions_table() {
    auto& fv_state = state().functions_view();
    
    const auto& symbols = session().symbol_table().entries();
    std::vector<const engine::symbols::SymbolEntry*> functions;
    std::vector<std::size_t> discovered_indices;

    // Filter logic
    if (!fv_state.use_discovery) {
        functions.reserve(symbols.size());
        for (const auto& entry : symbols) {
            if (!entry.is_function()) continue;
            if (entry.size < static_cast<std::uint64_t>(fv_state.min_size)) continue;
            std::string name = client::fmt::symbol_display_name(entry);
            if (!client::fmt::matches_filter(fv_state.filter, name)) continue;
            functions.push_back(&entry);
        }
    } else {
        discovered_indices.reserve(fv_state.discovered.size());
        for (std::size_t i = 0; i < fv_state.discovered.size(); ++i) {
            const auto& entry = fv_state.discovered[i];
            if (entry.size < static_cast<std::uint64_t>(fv_state.min_size)) continue;
            std::string name = discovered_name(session(), entry.entry, fv_state.show_demangled);
            if (!client::fmt::matches_filter(fv_state.filter, name)) continue;
            discovered_indices.push_back(i);
        }
    }

    std::size_t list_size = fv_state.use_discovery ? discovered_indices.size() : functions.size();

    // Table rendering
    ImGui::BeginChild("FunctionsList", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (list_size > 0) {
        ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable;
        int columns = fv_state.use_discovery ? 4 : 3;
        
        if (ImGui::BeginTable("FunctionsTable", columns, flags)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            if (fv_state.use_discovery) {
                ImGui::TableSetupColumn("Blocks", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            }
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(list_size));
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    std::size_t row_idx = static_cast<std::size_t>(i);
                    std::uint64_t address = 0;
                    std::uint64_t size = 0;
                    std::size_t blocks = 0;
                    std::string name;

                    if (fv_state.use_discovery) {
                        const auto& entry = fv_state.discovered[discovered_indices[row_idx]];
                        address = entry.entry;
                        size = entry.size;
                        blocks = entry.blocks;
                        name = discovered_name(session(), entry.entry, fv_state.show_demangled);
                    } else {
                        const auto* entry = functions[row_idx];
                        address = entry->address;
                        size = entry->size;
                        name = client::fmt::symbol_display_name(*entry);
                    }

                    bool selected = (row_idx == fv_state.selected_entry);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(i);
                    
                    if (ImGui::Selectable(name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        fv_state.selected_entry = row_idx;
                    }
                    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                        navigate_to(address);
                    }
                    
                    ImGui::PopID();
                    
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%s", client::fmt::hex(address).c_str());
                    
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%s", client::fmt::hex(size).c_str());
                    
                    if (fv_state.use_discovery) {
                        ImGui::TableSetColumnIndex(3);
                        ImGui::Text("%zu", blocks);
                    }
                }
            }
            ImGui::EndTable();
        }
    } else {
        if (session().loaded()) {
            ImGui::TextDisabled(fv_state.use_discovery && fv_state.discovered.empty() 
                ? "No discovered functions yet. Click Discover to analyze." 
                : "No matching functions");
        } else {
            ImGui::TextDisabled("Load a binary file to list functions.");
        }
    }
    ImGui::EndChild();
}

void FunctionsView::discover_functions() {
    auto& fv_state = state().functions_view();
    fv_state.discovered.clear();
    fv_state.discovery_error.clear();

    engine::analysis::FunctionDiscoveryOptions options;
    options.follow_calls = fv_state.follow_calls;
    options.follow_tail_jumps = fv_state.follow_tail_jumps;
    options.include_indirect_targets = fv_state.include_indirect_targets;
    options.include_symbol_entries = fv_state.include_symbol_entries;
    options.include_plt_entries = fv_state.include_plt_entries;
    options.include_init_array_entries = fv_state.include_init_array_entries;
    options.include_eh_frame_entries = fv_state.include_eh_frame_entries;
    options.include_prologue_entries = fv_state.include_prologue_entries;
    options.include_dwarf_entries = fv_state.include_dwarf_entries;
    options.include_linear_sweep_entries = fv_state.include_linear_sweep_entries;

    std::vector<engine::llir::Function> functions;
    std::string error;
    bool ok = false;
    const auto machine = session().binary_info().machine;
    
    if (machine == engine::BinaryMachine::kAarch64) {
        ok = session().discover_llir_functions_arm64(session().binary_info().entry,
                                                   static_cast<std::size_t>(fv_state.max_instructions),
                                                   options, functions, error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        ok = session().discover_llir_functions_x86_64(session().binary_info().entry,
                                                    static_cast<std::size_t>(fv_state.max_instructions),
                                                    options, functions, error);
    } else {
        error = "unsupported architecture for discovery";
    }

    if (!ok) {
        fv_state.discovery_error = error.empty() ? "discovery failed" : error;
    } else {
        fv_state.discovered.reserve(functions.size());
        for (const auto& func : functions) {
            DiscoveredFunction entry;
            entry.entry = func.entry;
            entry.size = discovered_size(func);
            entry.blocks = func.blocks.size();
            fv_state.discovered.push_back(entry);
        }
        std::sort(fv_state.discovered.begin(), fv_state.discovered.end(),
                  [](const DiscoveredFunction& a, const DiscoveredFunction& b) { return a.entry < b.entry; });
    }
    
    fv_state.discovery_dirty = false;
}

}  // namespace client