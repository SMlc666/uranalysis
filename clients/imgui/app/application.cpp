#include "application.h"

#include <string>
#include <iostream>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "theme.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

namespace client {

namespace {

Application* g_app = nullptr;

LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam)) {
        return true;
    }

    switch (msg) {
        case WM_SIZE:
            if (g_app && wparam != SIZE_MINIMIZED) {
                g_app->on_resize(LOWORD(lparam), HIWORD(lparam));
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

} // namespace

Application::Application() {
    g_app = this;
}

Application::~Application() {
    shutdown();
    if (g_app == this) {
        g_app = nullptr;
    }
}

void Application::on_resize(int width, int height) {
    if (backend_) {
        backend_->resize(static_cast<UINT>(width), static_cast<UINT>(height));
    }
}

bool Application::init(HINSTANCE instance) {
    instance_ = instance;
    context_ = std::make_unique<AppContext>();
    
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
        L"uranayzle_imgui",
        nullptr,
    };
    RegisterClassExW(&wc);
    
    hwnd_ = CreateWindowW(
        wc.lpszClassName,
        L"uranayzle imgui",
        WS_OVERLAPPEDWINDOW,
        100, 100, 1280, 720,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!hwnd_) return false;

    backend_ = create_best_available_backend();
    if (!backend_) return false;
    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    client::apply_theme();
    
    if (!ImGui_ImplWin32_Init(hwnd_)) return false;
    
    if (!backend_->init(hwnd_)) return false;
    
    client::setup_default_font();

    main_window_ = std::make_unique<MainWindow>(*context_);

    ShowWindow(hwnd_, SW_SHOWDEFAULT);
    UpdateWindow(hwnd_);

    return true;
}

int Application::run() {
    running_ = true;
    MSG msg = {};
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        if (!running_) break;
        
        render_frame();
    }
    return static_cast<int>(msg.wParam);
}

void Application::shutdown() {
    running_ = false;
    if (backend_) backend_->shutdown();
    ImGui_ImplWin32_Shutdown();
    if (ImGui::GetCurrentContext()) ImGui::DestroyContext();
    
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
    if (instance_) {
        UnregisterClassW(L"uranayzle_imgui", instance_);
        instance_ = nullptr;
    }
}

void Application::render_frame() {
    backend_->new_frame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    main_window_->render();

    ImGui::Render();
    backend_->render();
}

}  // namespace client