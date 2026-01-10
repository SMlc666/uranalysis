#pragma once

#include <cstddef>

#include "client/session.h"
#include "view_window.h"

namespace client {

struct NamesViewState {
    char filter[128] = {};
    bool show_symbols = true;
    bool show_types = true;
    bool show_vtables = true;
    std::size_t selected_entry = static_cast<std::size_t>(-1);
};

void render_names_view(NamesViewState& state, Session& session, ViewState& view_state);

}  // namespace client
