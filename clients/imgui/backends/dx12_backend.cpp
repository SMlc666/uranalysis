#include "dx12_backend.h"

#include "imgui.h"
#include "imgui_impl_dx12.h"

namespace client {

DX12Backend::DX12Backend() {
    config_.window_class = L"uranayzle_imgui_dx12";
    config_.window_title = L"uranayzle imgui (dx12)";
}

DX12Backend::~DX12Backend() {
    shutdown();
}

bool DX12Backend::init(HWND hwnd) {
    if (!create_device_d3d(hwnd)) {
        cleanup_device_d3d();
        return false;
    }
    return ImGui_ImplDX12_Init(device_, kNumFramesInFlight, DXGI_FORMAT_R8G8B8A8_UNORM, srv_heap_,
                               srv_heap_->GetCPUDescriptorHandleForHeapStart(),
                               srv_heap_->GetGPUDescriptorHandleForHeapStart());
}

void DX12Backend::shutdown() {
    wait_for_last_submitted_frame();
    ImGui_ImplDX12_Shutdown();
    cleanup_device_d3d();
}

void DX12Backend::new_frame() {
    ImGui_ImplDX12_NewFrame();
}

void DX12Backend::render() {
    FrameContext* frame_context = wait_for_next_frame_resources();
    UINT back_buffer_idx = swap_chain_->GetCurrentBackBufferIndex();
    frame_context->command_allocator->Reset();

    D3D12_RESOURCE_BARRIER barrier = {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = main_render_target_resource_[back_buffer_idx];
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;

    command_list_->Reset(frame_context->command_allocator, nullptr);
    command_list_->ResourceBarrier(1, &barrier);
    command_list_->OMSetRenderTargets(1, &main_render_target_descriptor_[back_buffer_idx], FALSE, nullptr);
    command_list_->SetDescriptorHeaps(1, &srv_heap_);
    const float clear_color[4] = {0.10f, 0.12f, 0.14f, 1.00f};
    command_list_->ClearRenderTargetView(main_render_target_descriptor_[back_buffer_idx], clear_color, 0, nullptr);

    ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), command_list_);

    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
    command_list_->ResourceBarrier(1, &barrier);
    command_list_->Close();
    command_queue_->ExecuteCommandLists(1, reinterpret_cast<ID3D12CommandList* const*>(&command_list_));
    swap_chain_->Present(1, 0);

    UINT64 fence_value = fence_last_signaled_value_ + 1;
    command_queue_->Signal(fence_, fence_value);
    fence_last_signaled_value_ = fence_value;
    frame_context->fence_value = fence_value;
}

void DX12Backend::resize(UINT width, UINT height) {
    if (device_ != nullptr) {
        wait_for_last_submitted_frame();
        cleanup_render_target();
        swap_chain_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT);
        create_render_target();
    }
}

const BackendConfig& DX12Backend::config() const {
    return config_;
}

void DX12Backend::wait_for_last_submitted_frame() {
    FrameContext* frame_context = &frame_context_[frame_index_ % kNumFramesInFlight];
    UINT64 fence_value = frame_context->fence_value;
    if (fence_value == 0) {
        return;
    }

    frame_context->fence_value = 0;
    if (fence_->GetCompletedValue() >= fence_value) {
        return;
    }

    fence_->SetEventOnCompletion(fence_value, fence_event_);
    WaitForSingleObject(fence_event_, INFINITE);
}

DX12Backend::FrameContext* DX12Backend::wait_for_next_frame_resources() {
    UINT next_frame_index = frame_index_ + 1;
    frame_index_ = next_frame_index % kNumFramesInFlight;

    HANDLE waitable_objects[] = {swap_chain_waitable_object_, nullptr};
    DWORD num_waitable_objects = 1;

    FrameContext* frame_context = &frame_context_[frame_index_];
    UINT64 fence_value = frame_context->fence_value;
    if (fence_value != 0) {
        frame_context->fence_value = 0;
        if (fence_->GetCompletedValue() < fence_value) {
            fence_->SetEventOnCompletion(fence_value, fence_event_);
            waitable_objects[1] = fence_event_;
            num_waitable_objects = 2;
        }
    }

    WaitForMultipleObjects(num_waitable_objects, waitable_objects, TRUE, INFINITE);
    return frame_context;
}

void DX12Backend::create_render_target() {
    D3D12_CPU_DESCRIPTOR_HANDLE rtv_handle = rtv_heap_->GetCPUDescriptorHandleForHeapStart();
    const UINT rtv_descriptor_size = device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
    for (UINT i = 0; i < kNumBackBuffers; i++) {
        swap_chain_->GetBuffer(i, IID_PPV_ARGS(&main_render_target_resource_[i]));
        device_->CreateRenderTargetView(main_render_target_resource_[i], nullptr, rtv_handle);
        main_render_target_descriptor_[i] = rtv_handle;
        rtv_handle.ptr += rtv_descriptor_size;
    }
}

void DX12Backend::cleanup_render_target() {
    for (UINT i = 0; i < kNumBackBuffers; i++) {
        if (main_render_target_resource_[i]) {
            main_render_target_resource_[i]->Release();
            main_render_target_resource_[i] = nullptr;
        }
    }
}

bool DX12Backend::create_device_d3d(HWND hwnd) {
    UINT dxgi_factory_flags = 0;
    IDXGIFactory4* factory = nullptr;
    if (CreateDXGIFactory2(dxgi_factory_flags, IID_PPV_ARGS(&factory)) != S_OK) {
        return false;
    }

    IDXGIAdapter1* adapter = nullptr;
    for (UINT adapter_index = 0; factory->EnumAdapters1(adapter_index, &adapter) != DXGI_ERROR_NOT_FOUND; adapter_index++) {
        DXGI_ADAPTER_DESC1 desc;
        adapter->GetDesc1(&desc);
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
            continue;
        }
        if (D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device_)) == S_OK) {
            break;
        }
    }
    if (!device_) {
        factory->Release();
        return false;
    }

    D3D12_COMMAND_QUEUE_DESC queue_desc = {};
    queue_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    queue_desc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    if (device_->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&command_queue_)) != S_OK) {
        factory->Release();
        return false;
    }

    DXGI_SWAP_CHAIN_DESC1 sd = {};
    sd.BufferCount = kNumBackBuffers;
    sd.Width = 0;
    sd.Height = 0;
    sd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    sd.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
    sd.Scaling = DXGI_SCALING_STRETCH;
    sd.Stereo = FALSE;

    IDXGISwapChain1* swap_chain1 = nullptr;
    if (factory->CreateSwapChainForHwnd(command_queue_, hwnd, &sd, nullptr, nullptr, &swap_chain1) != S_OK) {
        factory->Release();
        return false;
    }

    swap_chain1->QueryInterface(IID_PPV_ARGS(&swap_chain_));
    swap_chain1->Release();
    swap_chain_->SetMaximumFrameLatency(kNumBackBuffers);
    swap_chain_waitable_object_ = swap_chain_->GetFrameLatencyWaitableObject();

    D3D12_DESCRIPTOR_HEAP_DESC rtv_heap_desc = {};
    rtv_heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    rtv_heap_desc.NumDescriptors = kNumBackBuffers;
    rtv_heap_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
    if (device_->CreateDescriptorHeap(&rtv_heap_desc, IID_PPV_ARGS(&rtv_heap_)) != S_OK) {
        factory->Release();
        return false;
    }

    D3D12_DESCRIPTOR_HEAP_DESC srv_heap_desc = {};
    srv_heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    srv_heap_desc.NumDescriptors = 1;
    srv_heap_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    if (device_->CreateDescriptorHeap(&srv_heap_desc, IID_PPV_ARGS(&srv_heap_)) != S_OK) {
        factory->Release();
        return false;
    }

    if (device_->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence_)) != S_OK) {
        factory->Release();
        return false;
    }

    fence_event_ = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (fence_event_ == nullptr) {
        factory->Release();
        return false;
    }

    for (UINT i = 0; i < kNumFramesInFlight; i++) {
        if (device_->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
                                            IID_PPV_ARGS(&frame_context_[i].command_allocator)) != S_OK) {
            factory->Release();
            return false;
        }
    }

    if (device_->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, frame_context_[0].command_allocator, nullptr,
                                   IID_PPV_ARGS(&command_list_)) != S_OK) {
        factory->Release();
        return false;
    }
    command_list_->Close();

    create_render_target();
    factory->Release();
    return true;
}

void DX12Backend::cleanup_device_d3d() {
    cleanup_render_target();
    if (swap_chain_) {
        swap_chain_->Release();
        swap_chain_ = nullptr;
    }
    if (swap_chain_waitable_object_ != nullptr) {
        CloseHandle(swap_chain_waitable_object_);
    }
    for (UINT i = 0; i < kNumFramesInFlight; i++) {
        if (frame_context_[i].command_allocator) {
            frame_context_[i].command_allocator->Release();
            frame_context_[i].command_allocator = nullptr;
        }
    }
    if (command_list_) {
        command_list_->Release();
        command_list_ = nullptr;
    }
    if (command_queue_) {
        command_queue_->Release();
        command_queue_ = nullptr;
    }
    if (rtv_heap_) {
        rtv_heap_->Release();
        rtv_heap_ = nullptr;
    }
    if (srv_heap_) {
        srv_heap_->Release();
        srv_heap_ = nullptr;
    }
    if (fence_) {
        fence_->Release();
        fence_ = nullptr;
    }
    if (fence_event_) {
        CloseHandle(fence_event_);
        fence_event_ = nullptr;
    }
    if (device_) {
        device_->Release();
        device_ = nullptr;
    }
}

std::unique_ptr<IBackend> create_dx12_backend() {
    return std::make_unique<DX12Backend>();
}

}  // namespace client