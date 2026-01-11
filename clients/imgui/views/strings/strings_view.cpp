#include "strings_view.h"

#include <vector>
#include <sstream>

#include "imgui.h"
#include "client/formatters/address.h"
#include "../../utils/imgui_helpers.h"
#include "engine/strings.h"

namespace client {

StringsView::StringsView(AppContext& context)
    : ViewBase(context, "Strings"),
      filter_widget_("StringsFilter", "Filter") {}

void StringsView::on_render() {
    auto& sv_state = state().strings_view();
    static bool show_text_view = false;

    // Filter logic
    const auto& entries = session().string_catalog().entries();
    std::vector<std::size_t> visible;
    visible.reserve(entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].length < static_cast<std::size_t>(sv_state.min_length)) {
            continue;
        }
        if (client::fmt::matches_filter(sv_state.filter, entries[i].text)) {
            visible.push_back(i);
        }
    }

    // Selection fixup
    if (visible.empty()) {
        sv_state.selected_entry = static_cast<std::size_t>(-1);
    } else {
        bool still_visible = false;
        for (std::size_t idx : visible) {
            if (idx == sv_state.selected_entry) {
                still_visible = true;
                break;
            }
        }
        if (!still_visible) {
            sv_state.selected_entry = visible.front();
        }
    }

    ImGui::Begin(name(), visible_ptr());
    filter_widget_.render(sv_state.filter);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    if (ImGui::InputInt("Min len", &sv_state.min_length)) {
        if (sv_state.min_length < 1) sv_state.min_length = 1;
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy")) {
        std::ostringstream oss;
        oss << "string\taddress\tlength\n";
        for (std::size_t idx : visible) {
            if (idx >= entries.size()) continue;
            const auto& entry = entries[idx];
            oss << entry.text << "\t";
            oss << client::fmt::hex(entry.address) << "\t";
            oss << entry.length << "\n";
        }
        client::imgui::copy_to_clipboard(oss.str());
    }
    ImGui::SameLine();
    ImGui::Checkbox("Text View", &show_text_view);

    float text_height = show_text_view ? 140.0f : 0.0f;
    
    ImGui::BeginChild("StringsList", ImVec2(0, -text_height), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (!visible.empty()) {
        ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable;
        if (ImGui::BeginTable("StringsTable", 2, flags)) {
            ImGui::TableSetupColumn("String", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableHeadersRow();
            
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(visible.size()));
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    std::size_t visible_idx = static_cast<std::size_t>(i);
                    const std::size_t entry_idx = visible[visible_idx];
                    const auto& entry = entries[entry_idx];
                    
                    bool selected = (entry_idx == sv_state.selected_entry);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(static_cast<int>(entry_idx));
                    
                    if (ImGui::Selectable(entry.text.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        sv_state.selected_entry = entry_idx;
                    }
                    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                        navigate_to(entry.address);
                    }
                    
                    ImGui::PopID();
                    
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%s", client::fmt::hex(entry.address).c_str());
                }
            }
            ImGui::EndTable();
        }
    } else {
        ImGui::TextDisabled("No matching strings");
    }
    ImGui::EndChild();

    if (show_text_view) {
        std::ostringstream oss;
        oss << "string\taddress\tlength\n";
        for (std::size_t idx : visible) {
            if (idx >= entries.size()) continue;
            const auto& entry = entries[idx];
            oss << entry.text << "\t";
            oss << client::fmt::hex(entry.address) << "\t";
            oss << entry.length << "\n";
        }
        client::imgui::render_readonly_text("##StringsText", oss.str(), ImVec2(0, text_height));
    }

    ImGui::End();
}

}  // namespace client