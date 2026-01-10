#pragma once

#include <cstddef>

#include "client/session.h"
#include "view_window.h"

namespace client {

struct StringsViewState {
    char filter[128] = {};
    int min_length = 4;
    std::size_t selected_entry = static_cast<std::size_t>(-1);
};

void render_strings_view(StringsViewState& state, Session& session, ViewState& view_state);

}  // namespace client
