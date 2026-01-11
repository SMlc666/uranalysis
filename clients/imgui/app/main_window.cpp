#include "main_window.h"

#include <windows.h>
#include "imgui.h"
#include "imgui_internal.h"
#include "core/events.h"
#include "theme.h"

namespace client {

MainWindow::MainWindow(AppContext& context)
    : context_(context) {
    
    // Initialize views
    views_.push_back(std::make_unique<CodeView>(context));
    views_.push_back(std::make_unique<FunctionsView>(context));
    views_.push_back(std::make_unique<NamesView>(context));
    views_.push_back(std::make_unique<StringsView>(context));
    views_.push_back(std::make_unique<BinaryInfoView>(context));
    views_.push_back(std::make_unique<OutputView>(context));
    
    file_browser_ = std::make_unique<FileBrowser>(context);

    // Subscribe to events
    open_file_sub_ = context_.event_bus().subscribe<events::RequestOpenFile>([this](const events::RequestOpenFile&) {
        context_.state().file_browser().open = true;
    });

    session_opened_sub_ = context_.event_bus().subscribe<events::SessionOpened>([this](const events::SessionOpened& event) {
        open_session(event.path);
    });

    reset_layout_sub_ = context_.event_bus().subscribe<events::LayoutReset>([this](const events::LayoutReset&) {
        reset_layout();
    });

    // Notify attachment
    for (auto& view : views_) {
        view->on_attach();
    }
}

void MainWindow::render() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImVec2 host_pos = viewport ? viewport->Pos : ImVec2(0.0f, 0.0f);
    ImVec2 host_size = viewport ? viewport->Size : ImGui::GetIO().DisplaySize;

    ImGui::SetNextWindowPos(host_pos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(host_size, ImGuiCond_Always);
    if (viewport) {
        ImGui::SetNextWindowViewport(viewport->ID);
    }
    
    ImGuiWindowFlags host_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
                                  ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                                  ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
                                  ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_MenuBar;
                                  
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::Begin("MainHost", nullptr, host_flags);
    ImGui::PopStyleVar(2);

    render_menu_bar();
    render_toolbar();
    render_dockspace();
    render_views();
    render_popups();

    ImGui::End();
}

void MainWindow::reset_layout() {
    dock_initialized_ = false;
}

void MainWindow::render_menu_bar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                context_.event_bus().publish(events::RequestOpenFile{});
            }
            if (ImGui::MenuItem("Reload", "F5", false, context_.state().is_session_loaded())) {
                context_.event_bus().publish(events::SessionReloaded{});
                // Reload logic needs to be triggered. For now just re-open same path.
                open_session(context_.state().session().path());
            }
            if (ImGui::MenuItem("Close", nullptr, false, context_.state().is_session_loaded())) {
                close_session();
            }
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                // Post quit message or handle app exit
                PostQuitMessage(0);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Reset layout")) {
                reset_layout();
            }
            ImGui::Separator();
            for (auto& view : views_) {
                if (ImGui::MenuItem(view->name(), nullptr, view->is_visible())) {
                    view->set_visible(!view->is_visible());
                }
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About")) {
                context_.state().show_about = true;
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}

void MainWindow::render_toolbar() {
    float toolbar_height = ImGui::GetFrameHeight() + ImGui::GetStyle().FramePadding.y * 2.0f + 2.0f;
    ImGui::BeginChild("MainToolbar", ImVec2(0.0f, toolbar_height), false,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    
    if (ImGui::Button("Open...")) {
        context_.event_bus().publish(events::RequestOpenFile{});
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload") && context_.state().is_session_loaded()) {
        open_session(context_.state().session().path());
    }
    
    // Engine info
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    const auto& info = context_.engine_info();
    ImGui::TextDisabled("%s %s", info.name.c_str(), info.version.c_str());

    ImGui::EndChild();
}

void MainWindow::render_dockspace() {
    dockspace_id_ = ImGui::GetID("MainDockspace");
    ImVec2 dockspace_size = ImGui::GetContentRegionAvail();
    if (!dock_initialized_) {
        build_default_layout(dockspace_id_, dockspace_size);
        dock_initialized_ = true;
    }
    ImGui::DockSpace(dockspace_id_, ImVec2(0.0f, 0.0f));
}

void MainWindow::render_views() {
    for (auto& view : views_) {
        view->render();
    }
}

void MainWindow::render_popups() {
    // About popup
    if (context_.state().show_about) {
        ImGui::OpenPopup("About");
        context_.state().show_about = false;
    }
    if (ImGui::BeginPopupModal("About", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        const auto& info = context_.engine_info();
        ImGui::Text("%s %s", info.name.c_str(), info.version.c_str());
        ImGui::Separator();
        ImGui::TextUnformatted("ImGui client (Refactored)");
        ImGui::Spacing();
        if (ImGui::Button("Close")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    // File Browser
    std::string selected_path;
    if (file_browser_->render(&context_.state().file_browser().open, selected_path)) {
        context_.event_bus().publish(events::SessionOpened{selected_path});
    }
}

void MainWindow::build_default_layout(ImGuiID dockspace_id, const ImVec2& size) {
    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, size);

    ImGuiID dock_main = dockspace_id;
    ImGuiID dock_left = ImGui::DockBuilderSplitNode(dock_main, ImGuiDir_Left, 0.24f, nullptr, &dock_main);
    ImGuiID dock_right = ImGui::DockBuilderSplitNode(dock_main, ImGuiDir_Right, 0.28f, nullptr, &dock_main);
    ImGuiID dock_bottom = ImGui::DockBuilderSplitNode(dock_main, ImGuiDir_Down, 0.25f, nullptr, &dock_main);

    ImGuiID dock_left_bottom = ImGui::DockBuilderSplitNode(dock_left, ImGuiDir_Down, 0.30f, nullptr, &dock_left);
    ImGuiID dock_left_mid = ImGui::DockBuilderSplitNode(dock_left, ImGuiDir_Down, 0.45f, nullptr, &dock_left);

    ImGui::DockBuilderDockWindow("Names", dock_left);
    ImGui::DockBuilderDockWindow("Functions", dock_left_mid);
    ImGui::DockBuilderDockWindow("Strings", dock_left_bottom);
    ImGui::DockBuilderDockWindow("IDA View-A", dock_main);
    ImGui::DockBuilderDockWindow("Binary Info", dock_right);
    ImGui::DockBuilderDockWindow("Output", dock_bottom);
    ImGui::DockBuilderFinish(dockspace_id);
}

void MainWindow::open_session(const std::string& path) {
    std::string error;
    if (!context_.state().session().open(path, error)) {
        context_.state().status_message = "Failed to load: " + error;
    } else {
        context_.state().status_message = "Loaded: " + path;
        // Reset navigation state
        context_.state().navigation().current_address = context_.state().session().binary_info().entry;
        context_.state().navigation().history.clear();
        context_.state().navigation().history_index = -1;
        context_.state().navigation().navigate_to(context_.state().navigation().current_address);
        
        // Notify views
        context_.event_bus().publish(events::NavigateToAddress{context_.state().navigation().current_address});
    }
}

void MainWindow::close_session() {
    context_.state().session().close();
    context_.state().status_message = "Session closed";
    // Clear view states... (To be implemented fully if needed)
}

}  // namespace client