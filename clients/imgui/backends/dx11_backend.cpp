#include "dx11_backend.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"

namespace client {

DX11Backend::DX11Backend() {
    config_.window_class = L"uranayzle_imgui_dx11";
    config_.window_title = L"uranayzle imgui (dx11)";
}

DX11Backend::~DX11Backend() {
    shutdown();
}

bool DX11Backend::init(HWND hwnd) {
    if (!create_device_d3d(hwnd)) {
        cleanup_device_d3d();
        return false;
    }
    return ImGui_ImplDX11_Init(device_, device_context_);
}

void DX11Backend::shutdown() {
    ImGui_ImplDX11_Shutdown();
    cleanup_device_d3d();
}

void DX11Backend::new_frame() {
    ImGui_ImplDX11_NewFrame();
}

void DX11Backend::render() {
    const float clear_color[4] = {0.10f, 0.12f, 0.14f, 1.00f};
    device_context_->OMSetRenderTargets(1, &render_target_view_, nullptr);
    device_context_->ClearRenderTargetView(render_target_view_, clear_color);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    swap_chain_->Present(1, 0);
}

void DX11Backend::resize(UINT width, UINT height) {
    if (device_ != nullptr) {
        cleanup_render_target();
        swap_chain_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
        create_render_target();
    }
}

const BackendConfig& DX11Backend::config() const {
    return config_;
}

void DX11Backend::create_render_target() {
    ID3D11Texture2D* back_buffer = nullptr;
    swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
    device_->CreateRenderTargetView(back_buffer, nullptr, &render_target_view_);
    back_buffer->Release();
}

void DX11Backend::cleanup_render_target() {
    if (render_target_view_) {
        render_target_view_->Release();
        render_target_view_ = nullptr;
    }
}

bool DX11Backend::create_device_d3d(HWND hwnd) {
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
        &swap_chain_,
        &device_,
        &feature_level,
        &device_context_);

    if (res != S_OK) {
        return false;
    }

    create_render_target();
    return true;
}

void DX11Backend::cleanup_device_d3d() {
    cleanup_render_target();
    if (swap_chain_) {
        swap_chain_->Release();
        swap_chain_ = nullptr;
    }
    if (device_context_) {
        device_context_->Release();
        device_context_ = nullptr;
    }
    if (device_) {
        device_->Release();
        device_ = nullptr;
    }
}

std::unique_ptr<IBackend> create_dx11_backend() {
    return std::make_unique<DX11Backend>();
}

}  // namespace client