#pragma once

#include <string>
#include <vector>

#include "client/session.h"
#include "engine/api.h"
#include "engine/xrefs.h"
#include "file_browser.h"
#include "functions_view.h"
#include "names_view.h"
#include "strings_view.h"
#include "view_window.h"

namespace client {

struct UiState {
    Session session;
    char path[512] = {};
    std::string status;
    FileBrowserState browser;
    FunctionsViewState functions;
    NamesViewState names;
    ViewState view;
    StringsViewState strings;
    struct XrefsState {
        char target[32] = {};
        int max_results = 256;
        bool auto_follow = true;
        bool needs_refresh = true;
        std::uint64_t last_target = 0;
        std::string error;
        std::vector<engine::xrefs::XrefEntry> entries;
    } xrefs;
    bool request_open = false;
    bool file_browser_open = false;
    bool show_about = false;
    bool dock_initialized = false;
    bool reset_layout = false;
};

void render_ui(UiState& state, const engine::EngineInfo& info);

}  // namespace client
