#pragma once

#include "widget_base.h"
#include "imgui.h"
#include <functional>

namespace client {

class ToolbarWidget : public WidgetBase<void> {
public:
    explicit ToolbarWidget(const char* id) : WidgetBase(id) {}

    void render(std::function<void()> content) {
        float height = ImGui::GetFrameHeight() + ImGui::GetStyle().FramePadding.y * 2.0f + 2.0f;
        ImGui::BeginChild(make_id("Toolbar").c_str(), ImVec2(0.0f, height), false,
                          ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        
        content();
        
        ImGui::EndChild();
    }
};

}  // namespace client