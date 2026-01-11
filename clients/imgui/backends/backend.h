#pragma once

#include <memory>
#include <windows.h>

namespace client {

struct BackendConfig {
    const wchar_t* window_class = nullptr;
    const wchar_t* window_title = nullptr;
    int initial_width = 1280;
    int initial_height = 720;
};

class IBackend {
public:
    virtual ~IBackend() = default;
    
    virtual bool init(HWND hwnd) = 0;
    virtual void shutdown() = 0;
    virtual void new_frame() = 0;
    virtual void render() = 0;
    virtual void resize(UINT width, UINT height) = 0;
    
    virtual const BackendConfig& config() const = 0;
};

std::unique_ptr<IBackend> create_dx11_backend();
std::unique_ptr<IBackend> create_dx12_backend();
std::unique_ptr<IBackend> create_best_available_backend();

}  // namespace client