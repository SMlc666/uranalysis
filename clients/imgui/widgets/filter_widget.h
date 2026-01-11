#pragma once

#include "widget_base.h"
#include "imgui.h"
#include <cstring>

namespace client {

class FilterWidget : public WidgetBase<void> {
public:
    explicit FilterWidget(const char* id, const char* hint = "Filter") 
        : WidgetBase<void>(id), hint_(hint) {}

    void render(char* buffer, size_t size = 128) {
        ImGui::InputText(make_id(hint_).c_str(), buffer, size);
    }
    
    template<size_t N>
    void render(char (&buffer)[N]) {
        render(buffer, N);
    }

private:
    const char* hint_;
};

}  // namespace client