#include "imgui_helpers.h"

#include <sstream>

#include "client/formatters/address.h"

namespace client::imgui {

void render_readonly_text(const char* label, std::string_view text, const ImVec2& size) {
    std::vector<char> buffer(text.begin(), text.end());
    buffer.push_back('\0');
    ImGui::InputTextMultiline(label, buffer.data(), buffer.size(), size, ImGuiInputTextFlags_ReadOnly);
}

void render_error_text(std::string_view message) {
    if (!message.empty()) {
        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", message.data());
    }
}

void render_info_text(std::string_view message) {
    if (!message.empty()) {
        ImGui::TextUnformatted(message.data());
    }
}

bool address_input(const char* label, char* buffer, std::size_t size, std::uint64_t* parsed) {
    if (ImGui::InputText(label, buffer, size)) {
        if (parsed) {
            std::uint64_t value = 0;
            if (client::fmt::parse_u64(buffer, value)) {
                *parsed = value;
                return true;
            }
        }
        return true; // Return true on modification, even if parsing fails for now
    }
    return false;
}

void copy_to_clipboard(std::string_view text) {
    std::string s(text);
    ImGui::SetClipboardText(s.c_str());
}

void table_setup_columns(std::initializer_list<std::pair<const char*, float>> columns) {
    for (const auto& [name, width] : columns) {
        ImGuiTableColumnFlags flags = ImGuiTableColumnFlags_None;
        if (width > 0.0f) {
            flags |= ImGuiTableColumnFlags_WidthFixed;
            ImGui::TableSetupColumn(name, flags, width);
        } else {
            ImGui::TableSetupColumn(name);
        }
    }
    ImGui::TableHeadersRow();
}

std::string join_lines(const std::vector<std::string>& lines) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i > 0) {
            oss << "\n";
        }
        oss << lines[i];
    }
    return oss.str();
}

std::string format_address_list(const std::vector<std::uint64_t>& addrs) {
    if (addrs.empty()) {
        return "-";
    }
    std::ostringstream oss;
    for (std::size_t i = 0; i < addrs.size(); ++i) {
        if (i > 0) {
            oss << ", ";
        }
        oss << client::fmt::hex(addrs[i]);
    }
    return oss.str();
}

}  // namespace client::imgui