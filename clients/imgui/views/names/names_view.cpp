#include "names_view.h"

#include <vector>
#include <sstream>
#include <algorithm>

#include "imgui.h"
#include "client/formatters/address.h"
#include "../../utils/imgui_helpers.h"

namespace client {

namespace {

const char* kind_label(int kind) {
    switch (kind) {
        case 0: return "symbol";
        case 1: return "type";
        case 2: return "vtable";
    }
    return "unknown";
}

} // namespace

NamesView::NamesView(AppContext& context)
    : ViewBase(context, "Names"),
      filter_widget_("NamesFilter", "Filter") {}

void NamesView::on_render() {
    auto& nv_state = state().names_view();
    static bool show_text_view = false;
    
    // Rebuild cache
    std::vector<NameEntry> entries;
    entries.reserve(256);

    if (nv_state.show_symbols) {
        for (const auto& sym : session().symbol_table().entries()) {
            NameEntry entry;
            entry.kind = NameEntry::Kind::Symbol;
            entry.name = sym.name.empty() ? "<anon>" : sym.name;
            entry.address = sym.address;
            entry.size = sym.size;
            std::ostringstream oss;
            oss << "Section: " << sym.section_name << " Size: 0x" << std::hex << sym.size;
            entry.detail = oss.str();
            entries.push_back(std::move(entry));
        }
    }

    if (nv_state.show_types) {
        for (const auto& type : session().rtti_catalog().types()) {
            NameEntry entry;
            entry.kind = NameEntry::Kind::TypeInfo;
            entry.name = type.name.empty() ? "<unnamed type>" : type.name;
            entry.address = type.address;
            entry.size = 0;
            std::ostringstream oss;
            oss << "TypeInfo @ 0x" << std::hex << type.address << " vtable=0x" << type.vtable_address;
            entry.detail = oss.str();
            entries.push_back(std::move(entry));
        }
    }

    if (nv_state.show_vtables) {
        for (const auto& vtable : session().rtti_catalog().vtables()) {
            NameEntry entry;
            entry.kind = NameEntry::Kind::Vtable;
            entry.name = vtable.type_name.empty() ? "<vtable>" : vtable.type_name;
            entry.address = vtable.address;
            entry.size = vtable.entries.size() * sizeof(std::uint64_t);
            std::ostringstream oss;
            oss << "Entries: " << vtable.entries.size();
            entry.detail = oss.str();
            entries.push_back(std::move(entry));
        }
    }

    std::vector<std::size_t> visible;
    visible.reserve(entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (client::fmt::matches_filter(nv_state.filter, entries[i].name)) {
            visible.push_back(i);
        }
    }

    if (visible.empty()) {
        nv_state.selected_entry = static_cast<std::size_t>(-1);
    } else {
        bool still_visible = false;
        for (std::size_t idx : visible) {
            if (idx == nv_state.selected_entry) {
                still_visible = true;
                break;
            }
        }
        if (!still_visible) {
            nv_state.selected_entry = visible.front();
        }
    }

    ImGui::Begin(name(), visible_ptr());
    filter_widget_.render(nv_state.filter);
    ImGui::SameLine();
    ImGui::Checkbox("Symbols", &nv_state.show_symbols);
    ImGui::SameLine();
    ImGui::Checkbox("Types", &nv_state.show_types);
    ImGui::SameLine();
    ImGui::Checkbox("VTables", &nv_state.show_vtables);
    ImGui::SameLine();
    if (ImGui::Button("Copy")) {
        std::ostringstream oss;
        oss << "kind\tname\taddress\tsize\tdetail\n";
        for (std::size_t idx : visible) {
            if (idx >= entries.size()) continue;
            const auto& entry = entries[idx];
            oss << kind_label(static_cast<int>(entry.kind)) << "\t";
            oss << entry.name << "\t";
            oss << client::fmt::hex(entry.address) << "\t";
            oss << client::fmt::hex(entry.size) << "\t";
            oss << entry.detail << "\n";
        }
        client::imgui::copy_to_clipboard(oss.str());
    }
    ImGui::SameLine();
    ImGui::Checkbox("Text View", &show_text_view);

    float text_height = show_text_view ? 140.0f : 0.0f;
    float detail_height = 130.0f;
    
    ImGui::BeginChild("NamesList", ImVec2(0, -(detail_height + text_height)), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (!visible.empty()) {
        ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable;
        if (ImGui::BeginTable("NamesTable", 2, flags)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthFixed, 220.0f);
            ImGui::TableHeadersRow();
            
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(visible.size()));
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    std::size_t visible_idx = static_cast<std::size_t>(i);
                    const std::size_t entry_idx = visible[visible_idx];
                    const auto& entry = entries[entry_idx];
                    
                    bool selected = (entry_idx == nv_state.selected_entry);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(static_cast<int>(entry_idx));
                    
                    if (ImGui::Selectable(entry.name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        nv_state.selected_entry = entry_idx;
                    }
                    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                        navigate_to(entry.address);
                    }
                    
                    ImGui::PopID();
                    
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(entry.detail.c_str());
                }
            }
            ImGui::EndTable();
        }
    } else {
        ImGui::TextDisabled("No matching entries");
    }
    ImGui::EndChild();

    const NameEntry* detail = nullptr;
    if (nv_state.selected_entry < entries.size()) {
        detail = &entries[nv_state.selected_entry];
    }

    if (detail) {
        ImGui::Separator();
        ImGui::TextUnformatted("Detail");
        ImGui::Text("Name: %s", detail->name.c_str());
        ImGui::Text("Address: %s", client::fmt::hex(detail->address).c_str());
        ImGui::Text("Size: %s", client::fmt::hex(detail->size).c_str());
        ImGui::Text("%s", detail->detail.c_str());
        ImGui::Separator();
        ImGui::TextWrapped("Double-click an entry to jump the View window to that address.");
    } else {
        ImGui::Separator();
        ImGui::TextWrapped("Select a name to inspect its details and vtable/RTTI info.");
    }

    if (show_text_view) {
        std::ostringstream oss;
        oss << "kind\tname\taddress\tsize\tdetail\n";
        for (std::size_t idx : visible) {
            if (idx >= entries.size()) continue;
            const auto& entry = entries[idx];
            oss << kind_label(static_cast<int>(entry.kind)) << "\t";
            oss << entry.name << "\t";
            oss << client::fmt::hex(entry.address) << "\t";
            oss << client::fmt::hex(entry.size) << "\t";
            oss << entry.detail << "\n";
        }
        client::imgui::render_readonly_text("##NamesText", oss.str(), ImVec2(0, text_height));
    }

    ImGui::End();
}

}  // namespace client