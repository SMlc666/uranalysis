#include "view_base.h"

#include "core/events.h"
#include "imgui.h"

namespace client {

ViewBase::ViewBase(AppContext& context, const char* name)
    : context_(context), name_(name) {}

void ViewBase::render() {
    if (visible_) {
        on_render();
    }
}

void ViewBase::navigate_to(std::uint64_t address) {
    events().publish(events::NavigateToAddress{address});
}

void ViewBase::show_error(const std::string& message) {
    // For now, just log to status. Could be a popup event.
    state().status_message = "Error: " + message;
}

}  // namespace client