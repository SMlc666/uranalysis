#include "theme.h"

#include <string>
#include "imgui.h"
#include <windows.h> // For font path
#include <filesystem>

namespace client {

void apply_theme(const std::string& theme_name) {
    ImGuiStyle& style = ImGui::GetStyle();
    
    // Modern Dark Theme Colors (VS Code-like)
    ImVec4* colors = style.Colors;
    
    const ImVec4 bg_dark       = ImVec4(0.11f, 0.11f, 0.11f, 1.00f); // Editor background
    const ImVec4 bg_mid        = ImVec4(0.14f, 0.14f, 0.14f, 1.00f); // Panel background
    const ImVec4 bg_light      = ImVec4(0.18f, 0.18f, 0.18f, 1.00f); // Hover/Active
    const ImVec4 bg_popup      = ImVec4(0.14f, 0.14f, 0.14f, 1.00f); 
    
    const ImVec4 accent        = ImVec4(0.00f, 0.48f, 0.80f, 1.00f); // Blue accent
    const ImVec4 accent_hover  = ImVec4(0.00f, 0.55f, 0.90f, 1.00f);
    const ImVec4 accent_active = ImVec4(0.00f, 0.40f, 0.70f, 1.00f);
    
    const ImVec4 text_main     = ImVec4(0.85f, 0.85f, 0.85f, 1.00f);
    const ImVec4 text_dim      = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    const ImVec4 border        = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);

    colors[ImGuiCol_Text]                   = text_main;
    colors[ImGuiCol_TextDisabled]           = text_dim;
    colors[ImGuiCol_WindowBg]               = bg_mid;
    colors[ImGuiCol_ChildBg]                = bg_dark;
    colors[ImGuiCol_PopupBg]                = bg_popup;
    colors[ImGuiCol_Border]                 = border;
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = bg_light;
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.22f, 0.22f, 0.22f, 1.00f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_TitleBg]                = bg_mid;
    colors[ImGuiCol_TitleBgActive]          = bg_mid;
    colors[ImGuiCol_TitleBgCollapsed]       = bg_mid;
    colors[ImGuiCol_MenuBarBg]              = bg_mid;
    colors[ImGuiCol_ScrollbarBg]            = bg_mid;
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.28f, 0.28f, 0.28f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.32f, 0.32f, 0.32f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.35f, 0.35f, 0.35f, 1.00f);
    colors[ImGuiCol_CheckMark]              = accent;
    colors[ImGuiCol_SliderGrab]             = accent;
    colors[ImGuiCol_SliderGrabActive]       = accent_active;
    colors[ImGuiCol_Button]                 = bg_light;
    colors[ImGuiCol_ButtonHovered]          = accent_hover;
    colors[ImGuiCol_ButtonActive]           = accent_active;
    colors[ImGuiCol_Header]                 = bg_light;
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.22f, 0.22f, 0.22f, 1.00f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_Separator]              = border;
    colors[ImGuiCol_SeparatorHovered]       = accent_hover;
    colors[ImGuiCol_SeparatorActive]        = accent_active;
    colors[ImGuiCol_ResizeGrip]             = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
    colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_Tab]                    = bg_mid;
    colors[ImGuiCol_TabHovered]             = accent_hover;
    colors[ImGuiCol_TabActive]              = accent; // Active tab matches accent
    colors[ImGuiCol_TabUnfocused]           = bg_mid;
    colors[ImGuiCol_TabUnfocusedActive]     = bg_light;
    colors[ImGuiCol_DockingPreview]         = ImVec4(0.26f, 0.59f, 0.98f, 0.70f);
    colors[ImGuiCol_DockingEmptyBg]         = bg_dark;
    colors[ImGuiCol_PlotLines]              = accent;
    colors[ImGuiCol_PlotLinesHovered]       = accent_hover;
    colors[ImGuiCol_PlotHistogram]          = accent;
    colors[ImGuiCol_PlotHistogramHovered]   = accent_hover;
    colors[ImGuiCol_TableHeaderBg]          = bg_light;
    colors[ImGuiCol_TableBorderStrong]      = border;
    colors[ImGuiCol_TableBorderLight]       = ImVec4(0.35f, 0.35f, 0.35f, 0.50f);
    colors[ImGuiCol_TableRowBg]             = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]          = ImVec4(1.00f, 1.00f, 1.00f, 0.02f);
    colors[ImGuiCol_TextSelectedBg]         = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    colors[ImGuiCol_DragDropTarget]         = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
    colors[ImGuiCol_NavHighlight]           = accent;
    colors[ImGuiCol_NavWindowingHighlight]  = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg]      = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg]       = ImVec4(0.00f, 0.00f, 0.00f, 0.60f);

    // Geometry
    style.WindowRounding    = 0.0f; // Modern flat look
    style.ChildRounding     = 0.0f;
    style.FrameRounding     = 2.0f; // Subtle rounding for inputs
    style.GrabRounding      = 2.0f;
    style.PopupRounding     = 2.0f;
    style.ScrollbarRounding = 0.0f;
    style.TabRounding       = 0.0f;
    
    style.WindowPadding     = ImVec2(8.0f, 8.0f);
    style.FramePadding      = ImVec2(5.0f, 3.0f);
    style.ItemSpacing       = ImVec2(6.0f, 4.0f);
    style.ItemInnerSpacing  = ImVec2(4.0f, 4.0f);
    style.IndentSpacing     = 20.0f;
    style.ScrollbarSize     = 12.0f;
    style.GrabMinSize       = 10.0f;
    
    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.FrameBorderSize   = 0.0f;
    style.TabBorderSize     = 0.0f;
}

void setup_default_font() {
    ImGuiIO& io = ImGui::GetIO();
    
    // Try to find a good coding font
    // Order of preference: Cascadia Code -> Consolas -> Segoe UI -> Default
    
    char win_dir[MAX_PATH] = {};
    if (GetWindowsDirectoryA(win_dir, MAX_PATH) == 0) {
        if (!io.FontDefault) io.FontDefault = io.Fonts->AddFontDefault();
        return;
    }
    
    std::string base = win_dir;
    std::string font_path;
    bool font_loaded = false;

    // 1. Try Cascadia Code (modern Windows terminal font)
    font_path = base + "\\Fonts\\CascadiaCode.ttf";
    if (std::filesystem::exists(font_path)) {
        io.Fonts->AddFontFromFileTTF(font_path.c_str(), 16.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull());
        font_loaded = true;
    }
    
    // 2. Try Consolas
    if (!font_loaded) {
        font_path = base + "\\Fonts\\consola.ttf";
        if (std::filesystem::exists(font_path)) {
            io.Fonts->AddFontFromFileTTF(font_path.c_str(), 16.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull());
            font_loaded = true;
        }
    }

    // 3. Fallback to Segoe UI
    if (!font_loaded) {
        font_path = base + "\\Fonts\\segoeui.ttf";
        if (std::filesystem::exists(font_path)) {
            io.Fonts->AddFontFromFileTTF(font_path.c_str(), 18.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull());
            font_loaded = true;
        }
    }
    
    // 4. Fallback to Microsoft YaHei (for better Chinese support if others fail)
    if (!font_loaded) {
        font_path = base + "\\Fonts\\msyh.ttc";
        if (std::filesystem::exists(font_path)) {
            io.Fonts->AddFontFromFileTTF(font_path.c_str(), 18.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull());
            font_loaded = true;
        }
    }

    if (!font_loaded && !io.FontDefault) {
        io.FontDefault = io.Fonts->AddFontDefault();
    }
    
    io.Fonts->Build();
}

}  // namespace client
