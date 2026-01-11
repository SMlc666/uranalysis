#pragma once

#include <memory>
#include <windows.h>

#include "core/context.h"
#include "backends/backend.h"
#include "app/main_window.h"

namespace client {

class Application {
public:
    Application();
    ~Application();
    
    bool init(HINSTANCE instance);
    int run();
    void shutdown();
    
    // Called by wnd_proc
    void on_resize(int width, int height);

private:
    bool init_backend();
    bool init_imgui();
    bool init_views();
    
    void main_loop();
    void render_frame();
    
    std::unique_ptr<IBackend> backend_;
    std::unique_ptr<AppContext> context_;
    std::unique_ptr<MainWindow> main_window_;
    
    HINSTANCE instance_ = nullptr;
    HWND hwnd_ = nullptr;
    bool running_ = false;
};

}  // namespace client