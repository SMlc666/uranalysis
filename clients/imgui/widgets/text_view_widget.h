#pragma once

#include "widget_base.h"
#include "imgui.h"
#include "../utils/imgui_helpers.h"
#include <string>

namespace client {

class TextViewWidget : public WidgetBase<void> {
public:
    explicit TextViewWidget(const char* id) : WidgetBase(id) {}

    void render(const std::string& text) {
        float height = ImGui::GetContentRegionAvail().y;
        client::imgui::render_readonly_text(make_id("Text").c_str(), text, ImVec2(0, height));
    }
};

}  // namespace client