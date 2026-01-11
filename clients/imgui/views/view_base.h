#pragma once

#include <string>

#include "core/context.h"
#include "core/event_bus.h"
#include "core/state.h"

namespace client {

class ViewBase {
public:
    explicit ViewBase(AppContext& context, const char* name);
    virtual ~ViewBase() = default;
    
    // Lifecycle
    virtual void on_attach() {}   // Called when view is added
    virtual void on_detach() {}   // Called when view is removed
    
    // Rendering
    void render();                 // Framework call, handles visibility
    virtual void on_render() = 0; // Subclass implementation
    
    // Properties
    const char* name() const { return name_; }
    bool is_visible() const { return visible_; }
    void set_visible(bool visible) { visible_ = visible; }
    bool* visible_ptr() { return &visible_; }
    
protected:
    AppContext& ctx() { return context_; }
    EventBus& events() { return context_.event_bus(); }
    AppState& state() { return context_.state(); }
    engine::Session& session() { return state().session(); }
    
    // Helpers
    void navigate_to(std::uint64_t address);
    void show_error(const std::string& message);
    
private:
    AppContext& context_;
    const char* name_;
    bool visible_ = true;
};

}  // namespace client