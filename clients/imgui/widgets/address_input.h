#pragma once

#include "widget_base.h"
#include "imgui.h"
#include "../utils/imgui_helpers.h"
#include <cstdint>

namespace client {

class AddressInputWidget : public WidgetBase<void> {
public:
    explicit AddressInputWidget(const char* id, const char* label = "Address")
        : WidgetBase(id), label_(label) {}

    // Renders and returns true if parsed value changed
    bool render(char* buffer, std::size_t size, std::uint64_t* parsed_value) {
        return client::imgui::address_input(make_id(label_).c_str(), buffer, size, parsed_value);
    }
    
    // Convenience overload for fixed size array
    template<size_t N>
    bool render(char (&buffer)[N], std::uint64_t* parsed_value) {
        return render(buffer, N, parsed_value);
    }

private:
    const char* label_;
};

}  // namespace client