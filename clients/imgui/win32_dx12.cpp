#include <d3d12.h>
#include <dxgi1_4.h>
#include <windows.h>

#include "imgui_app.h"
#include "imgui.h"
#include "imgui_impl_dx12.h"

static int const kNumFramesInFlight = 3;
static int const kNumBackBuffers = 3;

struct FrameContext {
    ID3D12CommandAllocator* command_allocator = nullptr;
    UINT64 fence_value = 0;
};

static FrameContext g_frame_context[kNumFramesInFlight] = {};
static UINT g_frame_index = 0;

static ID3D12Device* g_device = nullptr;
static ID3D12DescriptorHeap* g_rtv_heap = nullptr;
static ID3D12DescriptorHeap* g_srv_heap = nullptr;
static ID3D12CommandQueue* g_command_queue = nullptr;
static ID3D12GraphicsCommandList* g_command_list = nullptr;
static ID3D12Fence* g_fence = nullptr;
static HANDLE g_fence_event = nullptr;
static UINT64 g_fence_last_signaled_value = 0;
static IDXGISwapChain3* g_swap_chain = nullptr;
static HANDLE g_swap_chain_waitable_object = nullptr;
static ID3D12Resource* g_main_render_target_resource[kNumBackBuffers] = {};
static D3D12_CPU_DESCRIPTOR_HANDLE g_main_render_target_descriptor[kNumBackBuffers] = {};

static FrameContext* wait_for_next_frame_resources() {
    UINT next_frame_index = g_frame_index + 1;
    g_frame_index = next_frame_index % kNumFramesInFlight;

    HANDLE waitable_objects[] = {g_swap_chain_waitable_object, nullptr};
    DWORD num_waitable_objects = 1;

    FrameContext* frame_context = &g_frame_context[g_frame_index];
    UINT64 fence_value = frame_context->fence_value;
    if (fence_value != 0) {
        frame_context->fence_value = 0;
        if (g_fence->GetCompletedValue() < fence_value) {
            g_fence->SetEventOnCompletion(fence_value, g_fence_event);
            waitable_objects[1] = g_fence_event;
            num_waitable_objects = 2;
        }
    }

    WaitForMultipleObjects(num_waitable_objects, waitable_objects, TRUE, INFINITE);
    return frame_context;
}

static void wait_for_last_submitted_frame() {
    FrameContext* frame_context = &g_frame_context[g_frame_index % kNumFramesInFlight];
    UINT64 fence_value = frame_context->fence_value;
    if (fence_value == 0) {
        return;
    }

    frame_context->fence_value = 0;
    if (g_fence->GetCompletedValue() >= fence_value) {
        return;
    }

    g_fence->SetEventOnCompletion(fence_value, g_fence_event);
    WaitForSingleObject(g_fence_event, INFINITE);
}

static void create_render_target() {
    D3D12_CPU_DESCRIPTOR_HANDLE rtv_handle = g_rtv_heap->GetCPUDescriptorHandleForHeapStart();
    const UINT rtv_descriptor_size = g_device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
    for (UINT i = 0; i < kNumBackBuffers; i++) {
        g_swap_chain->GetBuffer(i, IID_PPV_ARGS(&g_main_render_target_resource[i]));
        g_device->CreateRenderTargetView(g_main_render_target_resource[i], nullptr, rtv_handle);
        g_main_render_target_descriptor[i] = rtv_handle;
        rtv_handle.ptr += rtv_descriptor_size;
    }
}

static void cleanup_render_target() {
    for (UINT i = 0; i < kNumBackBuffers; i++) {
        if (g_main_render_target_resource[i]) {
            g_main_render_target_resource[i]->Release();
            g_main_render_target_resource[i] = nullptr;
        }
    }
}

static bool create_device_d3d(HWND hwnd) {
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
        if (D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&g_device)) == S_OK) {
            break;
        }
    }
    if (!g_device) {
        factory->Release();
        return false;
    }

    D3D12_COMMAND_QUEUE_DESC queue_desc = {};
    queue_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    queue_desc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    if (g_device->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&g_command_queue)) != S_OK) {
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
    if (factory->CreateSwapChainForHwnd(g_command_queue, hwnd, &sd, nullptr, nullptr, &swap_chain1) != S_OK) {
        factory->Release();
        return false;
    }

    swap_chain1->QueryInterface(IID_PPV_ARGS(&g_swap_chain));
    swap_chain1->Release();
    g_swap_chain->SetMaximumFrameLatency(kNumBackBuffers);
    g_swap_chain_waitable_object = g_swap_chain->GetFrameLatencyWaitableObject();

    D3D12_DESCRIPTOR_HEAP_DESC rtv_heap_desc = {};
    rtv_heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    rtv_heap_desc.NumDescriptors = kNumBackBuffers;
    rtv_heap_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
    if (g_device->CreateDescriptorHeap(&rtv_heap_desc, IID_PPV_ARGS(&g_rtv_heap)) != S_OK) {
        factory->Release();
        return false;
    }

    D3D12_DESCRIPTOR_HEAP_DESC srv_heap_desc = {};
    srv_heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    srv_heap_desc.NumDescriptors = 1;
    srv_heap_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    if (g_device->CreateDescriptorHeap(&srv_heap_desc, IID_PPV_ARGS(&g_srv_heap)) != S_OK) {
        factory->Release();
        return false;
    }

    if (g_device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&g_fence)) != S_OK) {
        factory->Release();
        return false;
    }

    g_fence_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (g_fence_event == nullptr) {
        factory->Release();
        return false;
    }

    for (UINT i = 0; i < kNumFramesInFlight; i++) {
        if (g_device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
                                             IID_PPV_ARGS(&g_frame_context[i].command_allocator)) != S_OK) {
            factory->Release();
            return false;
        }
    }

    if (g_device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, g_frame_context[0].command_allocator, nullptr,
                                    IID_PPV_ARGS(&g_command_list)) != S_OK) {
        factory->Release();
        return false;
    }
    g_command_list->Close();

    create_render_target();
    factory->Release();
    return true;
}

static void cleanup_device_d3d() {
    cleanup_render_target();
    if (g_swap_chain) {
        g_swap_chain->Release();
        g_swap_chain = nullptr;
    }
    if (g_swap_chain_waitable_object != nullptr) {
        CloseHandle(g_swap_chain_waitable_object);
    }
    for (UINT i = 0; i < kNumFramesInFlight; i++) {
        if (g_frame_context[i].command_allocator) {
            g_frame_context[i].command_allocator->Release();
            g_frame_context[i].command_allocator = nullptr;
        }
    }
    if (g_command_list) {
        g_command_list->Release();
        g_command_list = nullptr;
    }
    if (g_command_queue) {
        g_command_queue->Release();
        g_command_queue = nullptr;
    }
    if (g_rtv_heap) {
        g_rtv_heap->Release();
        g_rtv_heap = nullptr;
    }
    if (g_srv_heap) {
        g_srv_heap->Release();
        g_srv_heap = nullptr;
    }
    if (g_fence) {
        g_fence->Release();
        g_fence = nullptr;
    }
    if (g_fence_event) {
        CloseHandle(g_fence_event);
        g_fence_event = nullptr;
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
        wait_for_last_submitted_frame();
        cleanup_render_target();
        g_swap_chain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT);
        create_render_target();
    }
}

bool init(HWND hwnd) {
    if (!create_device_d3d(hwnd)) {
        cleanup_device_d3d();
        return false;
    }
    return ImGui_ImplDX12_Init(g_device, kNumFramesInFlight, DXGI_FORMAT_R8G8B8A8_UNORM, g_srv_heap,
                               g_srv_heap->GetCPUDescriptorHandleForHeapStart(),
                               g_srv_heap->GetGPUDescriptorHandleForHeapStart());
}

void shutdown() {
    wait_for_last_submitted_frame();
    ImGui_ImplDX12_Shutdown();
    cleanup_device_d3d();
}

void new_frame() {
    ImGui_ImplDX12_NewFrame();
}

void render() {
    FrameContext* frame_context = wait_for_next_frame_resources();
    UINT back_buffer_idx = g_swap_chain->GetCurrentBackBufferIndex();
    frame_context->command_allocator->Reset();

    D3D12_RESOURCE_BARRIER barrier = {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = g_main_render_target_resource[back_buffer_idx];
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;

    g_command_list->Reset(frame_context->command_allocator, nullptr);
    g_command_list->ResourceBarrier(1, &barrier);
    g_command_list->OMSetRenderTargets(1, &g_main_render_target_descriptor[back_buffer_idx], FALSE, nullptr);
    g_command_list->SetDescriptorHeaps(1, &g_srv_heap);
    const float clear_color[4] = {0.10f, 0.12f, 0.14f, 1.00f};
    g_command_list->ClearRenderTargetView(g_main_render_target_descriptor[back_buffer_idx], clear_color, 0, nullptr);

    ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), g_command_list);

    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
    g_command_list->ResourceBarrier(1, &barrier);
    g_command_list->Close();
    g_command_queue->ExecuteCommandLists(1, reinterpret_cast<ID3D12CommandList* const*>(&g_command_list));
    g_swap_chain->Present(1, 0);

    UINT64 fence_value = g_fence_last_signaled_value + 1;
    g_command_queue->Signal(g_fence, fence_value);
    g_fence_last_signaled_value = fence_value;
    frame_context->fence_value = fence_value;
}

}  // namespace

bool run_imgui_dx12(HINSTANCE instance, const engine::EngineInfo& info) {
    ImGuiBackend backend = {};
    backend.window_class = L"uranayzle_imgui_dx12";
    backend.window_title = L"uranayzle imgui (dx12)";
    backend.init = init;
    backend.shutdown = shutdown;
    backend.new_frame = new_frame;
    backend.render = render;
    backend.resize = resize;
    return run_win32_app(instance, info, backend);
}

}  // namespace client
