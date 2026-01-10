#include "imgui_app.h"

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_ui.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

namespace client {

namespace {

ImGuiBackend* g_backend = nullptr;

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

LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam)) {
        return true;
    }

    switch (msg) {
        case WM_SIZE:
            if (g_backend && g_backend->resize && wparam != SIZE_MINIMIZED) {
                g_backend->resize(LOWORD(lparam), HIWORD(lparam));
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wparam & 0xfff0) == SC_KEYMENU) {
                return 0;
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProc(hwnd, msg, wparam, lparam);
}

}  // namespace

bool run_win32_app(HINSTANCE instance, const engine::EngineInfo& info, ImGuiBackend& backend) {
    g_backend = &backend;

    WNDCLASSEXW wc = {
        sizeof(WNDCLASSEXW),
        CS_CLASSDC,
        wnd_proc,
        0L,
        0L,
        instance,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        backend.window_class,
        nullptr,
    };
    if (!RegisterClassExW(&wc)) {
        g_backend = nullptr;
        return false;
    }
    HWND hwnd = CreateWindowW(
        wc.lpszClassName,
        backend.window_title,
        WS_OVERLAPPEDWINDOW,
        100,
        100,
        1280,
        720,
        nullptr,
        nullptr,
        wc.hInstance,
        nullptr);

    if (!hwnd) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        g_backend = nullptr;
        return false;
    }

    IMGUI_CHECKVERSION();
    ImGuiContext* ctx = ImGui::CreateContext();
    if (!ctx) {
        DestroyWindow(hwnd);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        g_backend = nullptr;
        return false;
    }
    ImGui::SetCurrentContext(ctx);
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

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

    setup_default_font();
    if (!ImGui_ImplWin32_Init(hwnd)) {
        ImGui::DestroyContext();
        DestroyWindow(hwnd);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        g_backend = nullptr;
        return false;
    }

    if (!backend.init || !backend.init(hwnd)) {
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        DestroyWindow(hwnd);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return false;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    UiState ui_state;
    MSG msg = {};
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        if (!ImGui::GetCurrentContext()) {
            break;
        }
        if (backend.new_frame) {
            backend.new_frame();
        }
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        render_ui(ui_state, info);

        ImGui::Render();
        if (backend.render) {
            backend.render();
        }
    }

    if (backend.shutdown) {
        backend.shutdown();
    }
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    g_backend = nullptr;
    return true;
}

}  // namespace client
