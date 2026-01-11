#pragma once

#include <memory>
#include <vector>

#include "core/context.h"
#include "views/view_base.h"
#include "views/binary_info/binary_info_view.h"
#include "views/code_view/code_view.h"
#include "views/functions/functions_view.h"
#include "views/names/names_view.h"
#include "views/output/output_view.h"
#include "views/strings/strings_view.h"
#include "views/file_browser/file_browser.h"
#include "imgui.h"

namespace client {

class MainWindow {
public:
    explicit MainWindow(AppContext& context);
    
    void render();
    void reset_layout();
    
private:
    void render_menu_bar();
    void render_toolbar();
    void render_dockspace();
    void render_views();
    void render_popups();
    void build_default_layout(ImGuiID dockspace_id, const ImVec2& size);
    
    void open_session(const std::string& path);
    void close_session();

    AppContext& context_;
    std::vector<std::unique_ptr<ViewBase>> views_;
    std::unique_ptr<FileBrowser> file_browser_;
    
    ImGuiID dockspace_id_ = 0;
    bool dock_initialized_ = false;
    
    // Event subscriptions
    EventBus::SubscriptionId open_file_sub_ = 0;
    EventBus::SubscriptionId session_opened_sub_ = 0;
    EventBus::SubscriptionId reset_layout_sub_ = 0;
};

}  // namespace client