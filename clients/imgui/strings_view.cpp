#include "strings_view.h"

#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "engine/strings.h"
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

std::string format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

std::string build_strings_clipboard(const std::vector<engine::strings::StringEntry>& entries,
                                    const std::vector<std::size_t>& visible) {
    std::ostringstream oss;
    oss << "string\taddress\tlength\n";
    for (std::size_t idx : visible) {
        if (idx >= entries.size()) {
            continue;
        }
        const auto& entry = entries[idx];
        oss << entry.text << "\t";
        oss << format_hex(entry.address) << "\t";
        oss << entry.length << "\n";
    }
    return oss.str();
}

void render_readonly_text(const char* label, const std::string& text, const ImVec2& size) {
    std::vector<char> buffer(text.begin(), text.end());
    buffer.push_back('\0');
    ImGui::InputTextMultiline(label, buffer.data(), buffer.size(), size, ImGuiInputTextFlags_ReadOnly);
}

}  // namespace

void render_strings_view(StringsViewState& state, Session& session, ViewState& view_state) {
    static bool show_text_view = false;
    ImGui::Begin("Strings");
    ImGui::InputText("Filter", state.filter, sizeof(state.filter));
    ImGui::InputInt("Min length", &state.min_length);
    if (state.min_length < 1) {
        state.min_length = 1;
    }
    ImGui::SameLine();
    bool copy_requested = ImGui::Button("Copy");
    ImGui::SameLine();
    ImGui::Checkbox("Text View", &show_text_view);

    const auto& entries = session.string_catalog().entries();
    std::vector<std::size_t> visible;
    visible.reserve(entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].length < static_cast<std::size_t>(state.min_length)) {
            continue;
        }
        if (!matches_filter(state.filter, entries[i].text)) {
            continue;
        }
        visible.push_back(i);
    }

    if (copy_requested) {
        const std::string text = build_strings_clipboard(entries, visible);
        ImGui::SetClipboardText(text.c_str());
    }

    const float text_height = show_text_view ? 140.0f : 0.0f;
    ImGui::BeginChild("StringsList", ImVec2(0, -text_height), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (!visible.empty()) {
        ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable;
        if (ImGui::BeginTable("StringsTable", 2, flags)) {
            ImGui::TableSetupColumn("String", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
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
                if (ImGui::Selectable(entry.text.c_str(), selected, select_flags)) {
                    state.selected_entry = entry_idx;
                }
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                    view_state.go_to(entry.address);
                }
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%llx", static_cast<unsigned long long>(entry.address));
            }
            ImGui::EndTable();
        }
    } else {
        ImGui::TextDisabled("No matching strings");
    }
    ImGui::EndChild();

    if (show_text_view) {
        const std::string text = build_strings_clipboard(entries, visible);
        render_readonly_text("##StringsText", text, ImVec2(0, text_height));
    }

    ImGui::End();
}

}  // namespace client
