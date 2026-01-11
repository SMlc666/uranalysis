#pragma once

#include "client/command.h"
#include "engine/api.h"
#include "event_bus.h"
#include "state.h"

namespace client {

class AppContext {
public:
    AppContext() : commands_(make_default_registry()) {
        engine_info_ = engine::get_engine_info();
    }
    
    ~AppContext() = default;
    
    // Core services
    EventBus& event_bus() { return event_bus_; }
    AppState& state() { return state_; }
    CommandRegistry& commands() { return commands_; }
    
    // Engine info
    const engine::EngineInfo& engine_info() const { return engine_info_; }
    
private:
    engine::EngineInfo engine_info_;
    EventBus event_bus_;
    AppState state_;
    CommandRegistry commands_;
};

}  // namespace client