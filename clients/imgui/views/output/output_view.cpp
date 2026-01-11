#include "output_view.h"

#include <sstream>

#include "imgui.h"
#include "../../utils/imgui_helpers.h"

namespace client {

OutputView::OutputView(AppContext& context)
    : ViewBase(context, "Output") {}

void OutputView::on_render() {
    ImGui::Begin(name(), visible_ptr());
    if (ImGui::Button("Copy")) {
        client::imgui::copy_to_clipboard(build_output_clipboard());
    }
    
    const std::string output_text = build_output_clipboard();
    client::imgui::render_readonly_text("##OutputText", output_text, ImVec2(0, ImGui::GetContentRegionAvail().y));
    
    ImGui::End();
}

std::string OutputView::build_output_clipboard() {
    std::ostringstream oss;
    if (session().loaded()) {
        oss << "Loaded:\t" << session().path() << "\n";
    } else {
        oss << "Loaded:\t<none>\n";
    }
    if (!state().status_message.empty()) {
        oss << "Status:\t" << state().status_message << "\n";
    }
    return oss.str();
}

}  // namespace client