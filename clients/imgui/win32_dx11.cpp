#include <d3d11.h>
#include <windows.h>

#include "imgui_app.h"
#include "imgui.h"
#include "imgui_impl_dx11.h"

static ID3D11Device* g_device = nullptr;
static ID3D11DeviceContext* g_device_context = nullptr;
static IDXGISwapChain* g_swap_chain = nullptr;
static ID3D11RenderTargetView* g_render_target_view = nullptr;

static void create_render_target() {
    ID3D11Texture2D* back_buffer = nullptr;
    g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
    g_device->CreateRenderTargetView(back_buffer, nullptr, &g_render_target_view);
    back_buffer->Release();
}

static void cleanup_render_target() {
    if (g_render_target_view) {
        g_render_target_view->Release();
        g_render_target_view = nullptr;
    }
}

static bool create_device_d3d(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT create_device_flags = 0;
    D3D_FEATURE_LEVEL feature_level;
    const D3D_FEATURE_LEVEL feature_level_array[2] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0,
    };

    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        create_device_flags,
        feature_level_array,
        2,
        D3D11_SDK_VERSION,
        &sd,
        &g_swap_chain,
        &g_device,
        &feature_level,
        &g_device_context);

    if (res != S_OK) {
        return false;
    }

    create_render_target();
    return true;
}

static void cleanup_device_d3d() {
    cleanup_render_target();
    if (g_swap_chain) {
        g_swap_chain->Release();
        g_swap_chain = nullptr;
    }
    if (g_device_context) {
        g_device_context->Release();
        g_device_context = nullptr;
    }
    if (g_device) {
        g_device->Release();
        g_device = nullptr;
    }
}

namespace client {

namespace {

void resize(UINT width, UINT height) {
    if (g_device != nullptr) {
        cleanup_render_target();
        g_swap_chain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
        create_render_target();
    }
}

bool init(HWND hwnd) {
    if (!create_device_d3d(hwnd)) {
        cleanup_device_d3d();
        return false;
    }
    return ImGui_ImplDX11_Init(g_device, g_device_context);
}

void shutdown() {
    ImGui_ImplDX11_Shutdown();
    cleanup_device_d3d();
}

void new_frame() {
    ImGui_ImplDX11_NewFrame();
}

void render() {
    const float clear_color[4] = {0.10f, 0.12f, 0.14f, 1.00f};
    g_device_context->OMSetRenderTargets(1, &g_render_target_view, nullptr);
    g_device_context->ClearRenderTargetView(g_render_target_view, clear_color);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_swap_chain->Present(1, 0);
}

}  // namespace

bool run_imgui_dx11(HINSTANCE instance, const engine::EngineInfo& info) {
    ImGuiBackend backend = {};
    backend.window_class = L"uranayzle_imgui_dx11";
    backend.window_title = L"uranayzle imgui (dx11)";
    backend.init = init;
    backend.shutdown = shutdown;
    backend.new_frame = new_frame;
    backend.render = render;
    backend.resize = resize;
    return run_win32_app(instance, info, backend);
}

}  // namespace client
