# ImGui Client Knowledge Base

## Overview

Windows-only GUI using ImGui with DX11/DX12 backends. Dockable multi-view layout.

## Structure

```
imgui/
├── main.cpp           # WinMain entry point
├── app/               # Application lifecycle
│   ├── application.cpp    # Init backend, ImGui, main loop
│   └── main_window.cpp    # View orchestration, menu, toolbar, dockspace
├── backends/          # DirectX rendering backends
│   ├── backend.cpp        # Backend selection (DX12 preferred, DX11 fallback)
│   ├── dx11_backend.cpp   # DX11 implementation
│   └── dx12_backend.cpp   # DX12 implementation
├── core/              # Shared state
│   └── state.h            # AppState with per-view state structs
├── views/             # UI panels
│   ├── view_base.cpp      # Base class for all views
│   ├── code_view/         # Disassembly + IR tabs
│   ├── functions/         # Functions list
│   ├── names/             # Symbol names
│   ├── strings/           # Strings view
│   ├── binary_info/       # Binary metadata
│   ├── output/            # Output/log panels
│   └── file_browser/      # File open dialog
└── widgets/           # Reusable UI components
    ├── widget_base.h      # Templated widget base
    └── toolbar_widget.h   # Toolbar implementation
```

## Where to Look

| Task | Location |
|------|----------|
| Add new view | `views/` (inherit `ViewBase`, register in `main_window.cpp`) |
| Add widget | `widgets/` (inherit `WidgetBase<StateType>`) |
| Change menu/toolbar | `app/main_window.cpp` |
| Fix backend rendering | `backends/dx{11,12}_backend.cpp` |
| Add app state | `core/state.h` |

## Architecture

**Backend Selection**: `backend.cpp` tries DX12 first (creates D3D12 device), falls back to DX11.

**View Lifecycle**: `ViewBase::on_render()` called each frame. Views access `AppState` through `AppContext`.

**State Management**: Centralized in `AppState` with dedicated structs per view. Navigation state supports history.

**View-Widget Pattern**: Views compose widgets. Widgets are templated on state type, provide encapsulated rendering.

## Key Patterns

```cpp
// Adding a new view
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
- Enable with `xmake f --plat=windows --with-imgui_client=y`
- ImGui docking enabled for flexible layouts
