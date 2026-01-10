#pragma once

#include <windows.h>

#include "engine/api.h"

namespace client {

struct ImGuiBackend {
    const wchar_t* window_class = nullptr;
    const wchar_t* window_title = nullptr;
    bool (*init)(HWND) = nullptr;
    void (*shutdown)() = nullptr;
    void (*new_frame)() = nullptr;
    void (*render)() = nullptr;
    void (*resize)(UINT width, UINT height) = nullptr;
};

bool run_win32_app(HINSTANCE instance, const engine::EngineInfo& info, ImGuiBackend& backend);
bool run_imgui_dx11(HINSTANCE instance, const engine::EngineInfo& info);
bool run_imgui_dx12(HINSTANCE instance, const engine::EngineInfo& info);

}  // namespace client
