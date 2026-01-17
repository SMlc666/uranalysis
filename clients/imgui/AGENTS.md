# ImGui Client Knowledge Base

## Overview

Windows-only GUI using ImGui with DX11/DX12 backends. Dockable multi-view layout.

## Structure

```
imgui/
├── main.cpp           # WinMain entry point
├── app/               # Application lifecycle
│   ├── application.cpp    # Init backend, ImGui, main loop
│   ├── main_window.cpp    # View orchestration, menu, toolbar
│   └── theme.cpp          # Color/style configuration
├── backends/          # DirectX rendering backends
│   ├── backend.cpp        # Backend selection (DX12 → DX11 fallback)
│   ├── dx11_backend.cpp
│   └── dx12_backend.cpp
├── core/              # Shared state
│   ├── state.h            # AppState with per-view state structs
│   ├── context.h          # AppContext for dependency injection
│   └── event_bus.h        # Type-safe event system
├── views/             # UI panels
│   ├── view_base.cpp      # Base class for all views
│   ├── code_view/         # Disassembly + IR tabs
│   ├── functions/         # Functions list
│   ├── names/             # Symbol names
│   ├── strings/           # Strings view
│   ├── binary_info/       # Binary metadata
│   ├── output/            # Output/log panels
│   └── file_browser/      # File open dialog
├── widgets/           # Reusable UI components
│   ├── widget_base.h      # Templated widget base
│   ├── toolbar_widget.h
│   └── command_palette.cpp
└── utils/
    ├── imgui_helpers.cpp
    └── log_sink.h         # spdlog sink for Log View
```

## Where to Look

| Task | Location |
|------|----------|
| Add new view | `views/` (inherit `ViewBase`, register in `main_window.cpp`) |
| Add widget | `widgets/` (inherit `WidgetBase<StateType>`) |
| Change menu/toolbar | `app/main_window.cpp` |
| Fix backend rendering | `backends/dx{11,12}_backend.cpp` |
| Add app state | `core/state.h` |
| Add event type | `core/event_bus.h` |

## Architecture

**Backend Selection**: `backend.cpp` tries DX12 first, falls back to DX11.

**View Lifecycle**: `ViewBase::on_render()` called each frame.

**State Management**: Centralized in `AppState`. Navigation supports history.

**Event Bus**: Decoupled pub/sub for cross-view communication:
```cpp
// Publish
event_bus.publish(FunctionSelectedEvent{func_addr});
// Subscribe
event_bus.subscribe<FunctionSelectedEvent>([](auto& e) { ... });
```

**View-Widget Pattern**: Views compose widgets. Widgets templated on state type.

## Adding a View

```cpp
class MyView : public ViewBase {
    void on_render() override {
        if (ImGui::Begin("My View", &visible_)) {
            // ImGui calls
        }
        ImGui::End();
    }
};
// Register in MainWindow::init_views()
```

## Notes

- Windows-only: links d3d11, d3d12, dxgi
- Build: `xmake f --plat=windows --with-imgui_client=y && xmake`
- ImGui docking enabled for flexible layouts
- Log View captures engine logs via custom spdlog sink
