#include "state.h"

namespace client {

void NavigationState::navigate_to(std::uint64_t address) {
    if (current_address == address) {
        return;
    }

    // Remove forward history if we diverge
    if (history_index + 1 < static_cast<int>(history.size())) {
        history.resize(history_index + 1);
    }

    history.push_back(address);
    history_index = static_cast<int>(history.size()) - 1;
    current_address = address;
}

bool NavigationState::can_go_back() const {
    return history_index > 0;
}

bool NavigationState::can_go_forward() const {
    return history_index + 1 < static_cast<int>(history.size());
}

void NavigationState::go_back() {
    if (can_go_back()) {
        history_index--;
        current_address = history[history_index];
    }
}

void NavigationState::go_forward() {
    if (can_go_forward()) {
        history_index++;
        current_address = history[history_index];
    }
}

}  // namespace client