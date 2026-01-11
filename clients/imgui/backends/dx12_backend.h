#pragma once

#include "backend.h"
#include <d3d12.h>
#include <dxgi1_4.h>

namespace client {

class DX12Backend : public IBackend {
public:
    DX12Backend();
    ~DX12Backend() override;

    bool init(HWND hwnd) override;
    void shutdown() override;
    void new_frame() override;
    void render() override;
    void resize(UINT width, UINT height) override;
    const BackendConfig& config() const override;

private:
    struct FrameContext {
        ID3D12CommandAllocator* command_allocator = nullptr;
        UINT64 fence_value = 0;
    };

    bool create_device_d3d(HWND hwnd);
    void cleanup_device_d3d();
    void create_render_target();
    void cleanup_render_target();
    void wait_for_last_submitted_frame();
    FrameContext* wait_for_next_frame_resources();

    BackendConfig config_;
    static const int kNumFramesInFlight = 3;
    static const int kNumBackBuffers = 3;

    FrameContext frame_context_[kNumFramesInFlight] = {};
    UINT frame_index_ = 0;

    ID3D12Device* device_ = nullptr;
    ID3D12DescriptorHeap* rtv_heap_ = nullptr;
    ID3D12DescriptorHeap* srv_heap_ = nullptr;
    ID3D12CommandQueue* command_queue_ = nullptr;
    ID3D12GraphicsCommandList* command_list_ = nullptr;
    ID3D12Fence* fence_ = nullptr;
    HANDLE fence_event_ = nullptr;
    UINT64 fence_last_signaled_value_ = 0;
    IDXGISwapChain3* swap_chain_ = nullptr;
    HANDLE swap_chain_waitable_object_ = nullptr;
    ID3D12Resource* main_render_target_resource_[kNumBackBuffers] = {};
    D3D12_CPU_DESCRIPTOR_HANDLE main_render_target_descriptor_[kNumBackBuffers] = {};
};

}  // namespace client