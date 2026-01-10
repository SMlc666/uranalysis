#include "names_view.h"

#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "imgui.h"

namespace client {

namespace {

enum class NameKind {
    Symbol,
    TypeInfo,
    Vtable,
};

struct NameEntry {
    NameKind kind;
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::string detail;
};

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

void draw_entry_row(std::size_t row_index, const NameEntry& entry, NamesViewState& state) {
    const bool is_selected = (state.selected_entry == row_index);
    if (is_selected) {
        ImGui::PushStyleColor(ImGuiCol_Header, ImGui::GetStyleColorVec4(ImGuiCol_HeaderHovered));
    }

    if (ImGui::Selectable(entry.name.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
        state.selected_entry = row_index;
    }

    if (is_selected) {
        ImGui::PopStyleColor();
    }
}

const NameEntry* current_entry(const std::vector<NameEntry>& entries, std::size_t index) {
    if (index >= entries.size()) {
        return nullptr;
    }
    return &entries[index];
}

std::string format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

const char* kind_label(NameKind kind) {
    switch (kind) {
        case NameKind::Symbol: return "symbol";
        case NameKind::TypeInfo: return "type";
        case NameKind::Vtable: return "vtable";
    }
    return "unknown";
}

std::string build_names_clipboard(const std::vector<NameEntry>& entries, const std::vector<std::size_t>& visible) {
    std::ostringstream oss;
    oss << "kind\tname\taddress\tsize\tdetail\n";
    for (std::size_t idx : visible) {
        if (idx >= entries.size()) {
            continue;
        }
        const auto& entry = entries[idx];
        oss << kind_label(entry.kind) << "\t";
        oss << entry.name << "\t";
        oss << format_hex(entry.address) << "\t";
        oss << format_hex(entry.size) << "\t";
        oss << entry.detail << "\n";
    }
    return oss.str();
}

void render_readonly_text(const char* label, const std::string& text, const ImVec2& size) {
    std::vector<char> buffer(text.begin(), text.end());
    buffer.push_back('\0');
    ImGui::InputTextMultiline(label, buffer.data(), buffer.size(), size, ImGuiInputTextFlags_ReadOnly);
}

}  // namespace

void render_names_view(NamesViewState& state, Session& session, ViewState& view_state) {
    static bool show_text_view = false;
    std::vector<NameEntry> entries;
    entries.reserve(256);

    if (state.show_symbols) {
        for (const auto& sym : session.symbol_table().entries()) {
            NameEntry entry;
            entry.kind = NameKind::Symbol;
            entry.name = sym.name.empty() ? "<anon>" : sym.name;
            entry.address = sym.address;
            entry.size = sym.size;
            std::ostringstream oss;
            oss << "Section: " << sym.section_name << " Size: 0x" << std::hex << sym.size;
            entry.detail = oss.str();
            entries.push_back(std::move(entry));
        }
    }

    if (state.show_types) {
        for (const auto& type : session.rtti_catalog().types()) {
            NameEntry entry;
            entry.kind = NameKind::TypeInfo;
            entry.name = type.name.empty() ? "<unnamed type>" : type.name;
            entry.address = type.address;
            entry.size = 0;
            std::ostringstream oss;
            oss << "TypeInfo @ 0x" << std::hex << type.address << " vtable=0x" << type.vtable_address;
            entry.detail = oss.str();
            entries.push_back(std::move(entry));
        }
    }

    if (state.show_vtables) {
        for (const auto& vtable : session.rtti_catalog().vtables()) {
            NameEntry entry;
            entry.kind = NameKind::Vtable;
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
        if (matches_filter(state.filter, entries[i].name)) {
            visible.push_back(i);
        }
    }

    if (visible.empty()) {
        state.selected_entry = static_cast<std::size_t>(-1);
    } else {
        bool still_visible = false;
        for (std::size_t idx : visible) {
            if (idx == state.selected_entry) {
                still_visible = true;
                break;
            }
        }
        if (!still_visible) {
            state.selected_entry = visible.front();
        }
    }

    ImGui::Begin("Names");
    ImGui::InputText("Filter", state.filter, sizeof(state.filter));
    ImGui::SameLine();
    ImGui::Checkbox("Symbols", &state.show_symbols);
    ImGui::SameLine();
    ImGui::Checkbox("Types", &state.show_types);
    ImGui::SameLine();
    ImGui::Checkbox("VTables", &state.show_vtables);
    ImGui::SameLine();
    if (ImGui::Button("Copy")) {
        const std::string text = build_names_clipboard(entries, visible);
        ImGui::SetClipboardText(text.c_str());
    }
    ImGui::SameLine();
    ImGui::Checkbox("Text View", &show_text_view);

    const float text_height = show_text_view ? 140.0f : 0.0f;
    const float detail_height = 130.0f;
    ImGui::BeginChild("NamesList", ImVec2(0, -(detail_height + text_height)), true,
                      ImGuiWindowFlags_HorizontalScrollbar);
    if (!visible.empty()) {
        ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable;
        if (ImGui::BeginTable("NamesTable", 2, flags)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthFixed, 220.0f);
            ImGui::TableHeadersRow();
            for (std::size_t visible_idx = 0; visible_idx < visible.size(); ++visible_idx) {
                const std::size_t entry_idx = visible[visible_idx];
                const auto& entry = entries[entry_idx];
                bool selected = (entry_idx == state.selected_entry);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(entry_idx));
                ImGuiSelectableFlags select_flags =
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick;
                if (ImGui::Selectable(entry.name.c_str(), selected, select_flags)) {
                    state.selected_entry = entry_idx;
                }
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                    view_state.go_to(entry.address);
                }
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(entry.detail.c_str());
            }
            ImGui::EndTable();
        }
    } else {
        ImGui::TextDisabled("No matching entries");
    }
    ImGui::EndChild();

    const NameEntry* detail = current_entry(entries, state.selected_entry);
    if (detail) {
        ImGui::Separator();
        ImGui::TextUnformatted("Detail");
        ImGui::Text("Name: %s", detail->name.c_str());
        ImGui::Text("Address: 0x%llx", static_cast<unsigned long long>(detail->address));
        ImGui::Text("Size: 0x%llx", static_cast<unsigned long long>(detail->size));
        ImGui::Text("%s", detail->detail.c_str());
        ImGui::Separator();
        ImGui::TextWrapped("Double-click an entry to jump the View window to that address.");
    } else {
        ImGui::Separator();
        ImGui::TextWrapped("Select a name to inspect its details and vtable/RTTI info.");
    }

    if (show_text_view) {
        const std::string text = build_names_clipboard(entries, visible);
        render_readonly_text("##NamesText", text, ImVec2(0, text_height));
    }
    ImGui::End();
}

}  // namespace client
