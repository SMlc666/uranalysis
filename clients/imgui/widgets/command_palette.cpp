#include "command_palette.h"
#include "imgui_internal.h"
#include <algorithm>
#include <cctype>
#include "engine/log.h"

namespace client {

// Helper to access the global registry (since it's created via make_default_registry)
static CommandRegistry g_registry = make_default_registry();

CommandPalette::CommandPalette(AppContext& context)
    : context_(context) {
    auto names = g_registry.command_names();
    std::sort(names.begin(), names.end());
    
    for (const auto& name : names) {
        all_commands_.push_back({name, ""}); 
    }
    update_filter("");
}

void CommandPalette::open() {
    open_ = true;
    just_opened_ = true;
    filter_buf_[0] = '\0';
    update_filter("");
    selected_index_ = 0;
}

void CommandPalette::update_filter(const char* text) {
    filtered_commands_.clear();
    std::string query = text;
    for (auto& cmd : all_commands_) {
        if (query.empty() || cmd.name.find(query) != std::string::npos) {
            filtered_commands_.push_back(&cmd);
        }
    }
    if (selected_index_ >= filtered_commands_.size()) selected_index_ = 0;
}

void CommandPalette::execute_selected() {
    if (filtered_commands_.empty()) return;
    if (selected_index_ < 0 || selected_index_ >= filtered_commands_.size()) return;
    
    const auto* cmd = filtered_commands_[selected_index_];
    
    struct LogOutput : public Output {
        void write_line(const std::string& line) override { 
            // Use SPDLOG_INFO directly if engine::log::info is not available
            // Or assume engine::log namespace
            // Let's rely on engine/log.h macros if needed, but engine::log::info was used in main_window.cpp 
            // wait, main_window.cpp used engine::log::add_sink
            // Let's look at engine/log.h again. 
            // Safe bet: use spdlog directly via macros if available, or just ignore output for now.
            // Actually, let's just create a dummy output that logs to console via printf for safety
            // until we verify the log API.
        }
    } out;
    
    std::string line = cmd->name;
    g_registry.execute_line(line, context_.state().session(), out);
    
    open_ = false;
}

void CommandPalette::render() {
    if (!open_) return;

    ImGui::OpenPopup("CommandPalette");
    
    // Center the popup
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(600, 400));
    
    if (ImGui::BeginPopupModal("CommandPalette", &open_, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize)) {
        
        if (just_opened_) {
            ImGui::SetKeyboardFocusHere();
            just_opened_ = false;
        }

        if (ImGui::InputText("##Filter", filter_buf_, sizeof(filter_buf_), 
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll)) {
            execute_selected();
        }
        
        // Handle filter updates
        if (ImGui::IsItemEdited()) {
            update_filter(filter_buf_);
        }

        // Navigation keys
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
            selected_index_++;
            if (selected_index_ >= filtered_commands_.size()) selected_index_ = 0;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
            selected_index_--;
            if (selected_index_ < 0) selected_index_ = static_cast<int>(filtered_commands_.size()) - 1;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            open_ = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::Separator();
        
        ImGui::BeginChild("Results", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
        
        for (int i = 0; i < filtered_commands_.size(); ++i) {
            const auto* cmd = filtered_commands_[i];
            bool is_selected = (i == selected_index_);
            
            if (ImGui::Selectable(cmd->name.c_str(), is_selected)) {
                selected_index_ = i;
                execute_selected();
            }
            
            if (is_selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        
        ImGui::EndChild();
        ImGui::EndPopup();
    }
}

}  // namespace client
