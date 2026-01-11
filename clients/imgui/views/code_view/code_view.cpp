#include "code_view.h"

#include "imgui.h"
#include "../../widgets/address_input.h"
#include "../../utils/imgui_helpers.h"
#include "client/formatters/address.h"

namespace client {

CodeView::CodeView(AppContext& context)
    : ViewBase(context, "IDA View-A"),
      disasm_tab_(context),
      ir_tabs_(context) {}

void CodeView::on_attach() {
    nav_sub_id_ = events().subscribe<events::NavigateToAddress>([this](const events::NavigateToAddress& event) {
        // Only update if we are the active view or logic dictates (simplified for now)
        auto& cv_state = state().code_view();
        cv_state.address = event.address;
        cv_state.needs_refresh = true;
        cv_state.ir_needs_refresh = true;
        
        // Also update navigation state if it's a new navigation
        state().navigation().navigate_to(event.address);
    });
}

void CodeView::on_detach() {
    events().unsubscribe<events::NavigateToAddress>(nav_sub_id_);
}

void CodeView::on_render() {
    auto& cv_state = state().code_view();

    ImGui::Begin(name(), visible_ptr());

    render_toolbar();

    if (!session().loaded()) {
        ImGui::TextDisabled("Load a binary file to populate the view.");
        ImGui::End();
        return;
    }

    render_tabs();

    ImGui::End();
}

void CodeView::render_toolbar() {
    auto& cv_state = state().code_view();

    AddressInputWidget address_input("##Address", "Address");
    std::uint64_t new_addr = 0;
    
    ImGui::TextUnformatted("Address");
    ImGui::SameLine();
    char addr_buffer[32] = {};
    std::snprintf(addr_buffer, sizeof(addr_buffer), "0x%llx", static_cast<unsigned long long>(cv_state.address));
    
    ImGui::SetNextItemWidth(140.0f);
    if (address_input.render(addr_buffer, &new_addr)) {
        cv_state.address = new_addr;
        cv_state.needs_refresh = true;
        cv_state.ir_needs_refresh = true;
        state().navigation().navigate_to(new_addr);
    }

    ImGui::SameLine();
    ImGui::TextUnformatted("Instr");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    if (ImGui::InputInt("##Instr", &cv_state.instruction_count)) {
        if (cv_state.instruction_count < 1) cv_state.instruction_count = 1;
        cv_state.needs_refresh = true;
    }

    ImGui::SameLine();
    ImGui::TextUnformatted("Bytes");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    if (ImGui::InputInt("##Bytes", &cv_state.byte_count)) {
        if (cv_state.byte_count < 1) cv_state.byte_count = 16;
        cv_state.needs_refresh = true;
    }

    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        cv_state.needs_refresh = true;
        cv_state.ir_needs_refresh = true;
    }
}

void CodeView::render_tabs() {
    if (ImGui::BeginTabBar("ViewTabs")) {
        if (ImGui::BeginTabItem("Disasm")) {
            disasm_tab_.render(state().code_view());
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("IR")) {
            ir_tabs_.render(state().code_view());
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

}  // namespace client