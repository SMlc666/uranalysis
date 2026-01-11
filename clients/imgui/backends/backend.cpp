#include "backend.h"

#include <d3d12.h>

namespace client {

// Helper to check DX12 availability
static bool dx12_available() {
    ID3D12Device* device = nullptr;
    HRESULT hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device));
    if (SUCCEEDED(hr) && device) {
        device->Release();
        return true;
    }
    return false;
}

std::unique_ptr<IBackend> create_best_available_backend() {
    if (dx12_available()) {
        return create_dx12_backend();
    }
    return create_dx11_backend();
}

}  // namespace client