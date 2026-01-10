#include <d3d12.h>
#include <windows.h>

#include <string>

#include "engine/api.h"
#include "imgui_app.h"

namespace {

bool has_arg(const std::string& cmdline, const char* flag) {
    return cmdline.find(flag) != std::string::npos;
}

bool dx12_available() {
    ID3D12Device* device = nullptr;
    HRESULT hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device));
    if (SUCCEEDED(hr) && device) {
        device->Release();
        return true;
    }
    return false;
}

}  // namespace

int APIENTRY WinMain(HINSTANCE instance, HINSTANCE, LPSTR cmd_line, int) {
    auto info = engine::get_engine_info();
    const std::string cmd = cmd_line ? cmd_line : "";
    const bool force_dx11 = has_arg(cmd, "--dx11");
    const bool force_dx12 = has_arg(cmd, "--dx12");

    if (force_dx11 && force_dx12) {
        MessageBoxA(nullptr, "Choose only one backend: --dx11 or --dx12", "uranayzle imgui", MB_OK);
        return 1;
    }

    if (force_dx12) {
        if (!dx12_available()) {
            MessageBoxA(nullptr, "DX12 not available on this system.", "uranayzle imgui", MB_OK);
            return 1;
        }
        return client::run_imgui_dx12(instance, info) ? 0 : 1;
    }

    if (!force_dx11 && dx12_available()) {
        if (client::run_imgui_dx12(instance, info)) {
            return 0;
        }
    }

    return client::run_imgui_dx11(instance, info) ? 0 : 1;
}
