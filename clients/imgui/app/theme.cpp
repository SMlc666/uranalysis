#include "theme.h"

#include <string>
#include "imgui.h"
#include <windows.h> // For font path

namespace client {

void apply_theme(const std::string& theme_name) {
    ImGui::StyleColorsClassic();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.FrameRounding = 0.0f;
    style.ScrollbarRounding = 0.0f;
    style.TabRounding = 0.0f;
    style.WindowPadding = ImVec2(8.0f, 6.0f);
    style.FramePadding = ImVec2(6.0f, 3.0f);
    style.ItemSpacing = ImVec2(6.0f, 4.0f);
    style.CellPadding = ImVec2(6.0f, 4.0f);
}

void setup_default_font() {
    ImGuiIO& io = ImGui::GetIO();
    if (!io.FontDefault) {
        io.FontDefault = io.Fonts->AddFontDefault();
    }
    char win_dir[MAX_PATH] = {};
    if (GetWindowsDirectoryA(win_dir, MAX_PATH) == 0) {
        return;
    }
    std::string base = win_dir;
    std::string font_path = base + "\\Fonts\\segoeui.ttf";
    if (!io.Fonts->AddFontFromFileTTF(font_path.c_str(), 18.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull())) {
        font_path = base + "\\Fonts\\msyh.ttc";
        io.Fonts->AddFontFromFileTTF(font_path.c_str(), 18.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull());
    }
    io.Fonts->Build();
}

}  // namespace client