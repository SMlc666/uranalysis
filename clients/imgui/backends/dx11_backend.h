#pragma once

#include "backend.h"
#include <d3d11.h>

namespace client {

class DX11Backend : public IBackend {
public:
    DX11Backend();
    ~DX11Backend() override;

    bool init(HWND hwnd) override;
    void shutdown() override;
    void new_frame() override;
    void render() override;
    void resize(UINT width, UINT height) override;
    const BackendConfig& config() const override;

private:
    bool create_device_d3d(HWND hwnd);
    void cleanup_device_d3d();
    void create_render_target();
    void cleanup_render_target();

    BackendConfig config_;
    ID3D11Device* device_ = nullptr;
    ID3D11DeviceContext* device_context_ = nullptr;
    IDXGISwapChain* swap_chain_ = nullptr;
    ID3D11RenderTargetView* render_target_view_ = nullptr;
};

}  // namespace client