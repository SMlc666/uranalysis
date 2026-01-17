#include "log_view.h"
#include "imgui.h"

namespace client {

LogView::LogView(AppContext& context)
    : ViewBase(context, "Logs") {
}

void LogView::set_sink(std::shared_ptr<ImGuiLogSinkMt> sink) {
    sink_ = sink;
}

void LogView::on_render() {
    if (!ImGui::Begin(name(), visible_ptr())) {
        ImGui::End();
        return;
    }

    // Top bar: Controls
    if (ImGui::Button("Clear")) {
        if (sink_) sink_->clear();
    }
    ImGui::SameLine();
    bool copy = ImGui::Button("Copy");
    ImGui::SameLine();
    filter_.Draw("Filter", -100.0f);
    
    ImGui::Separator();
    
    // Checkboxes for levels
    ImGui::Checkbox("Info", &show_info_); ImGui::SameLine();
    ImGui::Checkbox("Warn", &show_warn_); ImGui::SameLine();
    ImGui::Checkbox("Error", &show_error_); ImGui::SameLine();
    ImGui::Checkbox("Debug", &show_debug_); ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &auto_scroll_);

    ImGui::Separator();

    // Log Content
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    if (sink_) {
        // Get a copy to avoid holding the lock while rendering
        // In a very high frequency log scenario, this might be slow, but for now it's safe.
        auto items = sink_->items_copy();
        
        for (const auto& item : items) {
            if (!filter_.PassFilter(item.message.c_str())) continue;

            // Level filtering
            if (item.level == spdlog::level::info && !show_info_) continue;
            if (item.level == spdlog::level::warn && !show_warn_) continue;
            if (item.level == spdlog::level::err && !show_error_) continue;
            if (item.level == spdlog::level::debug && !show_debug_) continue;
            if (item.level == spdlog::level::trace && !show_trace_) continue;

            // Colorize based on level
            ImVec4 color;
            bool has_color = true;
            switch (item.level) {
                case spdlog::level::err:     color = ImVec4(1.0f, 0.4f, 0.4f, 1.0f); break;
                case spdlog::level::warn:    color = ImVec4(1.0f, 0.8f, 0.0f, 1.0f); break;
                case spdlog::level::info:    color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f); break;
                case spdlog::level::debug:   color = ImVec4(0.7f, 0.7f, 0.7f, 1.0f); break;
                case spdlog::level::trace:   color = ImVec4(0.5f, 0.5f, 0.5f, 1.0f); break;
                default: has_color = false;
            }

            if (has_color) ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::TextUnformatted(item.message.c_str());
            if (has_color) ImGui::PopStyleColor();

            if (copy) {
                ImGui::LogToClipboard();
                ImGui::LogText("%s\n", item.message.c_str());
                ImGui::LogFinish();
            }
        }
    }

    if (auto_scroll_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }

    ImGui::EndChild();
    ImGui::End();
}

} // namespace client
