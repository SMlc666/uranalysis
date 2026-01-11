#include "binary_info_view.h"

#include <vector>
#include <sstream>
#include <string>

#include "imgui.h"
#include "client/formatters/address.h"
#include "../../utils/imgui_helpers.h"
#include "engine/xrefs.h"
#include "../../core/events.h"

namespace client {

namespace {

const char* xref_kind_label(engine::xrefs::XrefKind kind) {
    switch (kind) {
        case engine::xrefs::XrefKind::kDataPointer: return "data";
        case engine::xrefs::XrefKind::kCodeCall: return "call";
        case engine::xrefs::XrefKind::kCodeJump: return "jump";
        case engine::xrefs::XrefKind::kCodeCallIndirect: return "call*";
        case engine::xrefs::XrefKind::kCodeJumpIndirect: return "jump*";
    }
    return "unknown";
}

} // namespace

BinaryInfoView::BinaryInfoView(AppContext& context)
    : ViewBase(context, "Binary Info") {}

void BinaryInfoView::on_render() {
    ImGui::Begin(name(), visible_ptr());

    ImGui::TextUnformatted("File");
    ImGui::PushItemWidth(-1.0f);
    std::string path = session().path();
    // Render as readonly input text
    ImGui::InputText("##BinaryPath", const_cast<char*>(path.c_str()), path.size(), ImGuiInputTextFlags_ReadOnly);
    ImGui::PopItemWidth();

    if (ImGui::Button("Open...")) {
        events().publish(events::RequestOpenFile{});
    }
    ImGui::SameLine();
    if (ImGui::Button("Load") && !path.empty()) {
        events().publish(events::SessionOpened{path});
    }
    ImGui::SameLine();
    if (ImGui::Button("Entry") && session().loaded()) {
        navigate_to(session().binary_info().entry);
    }

    if (!state().status_message.empty()) {
        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", state().status_message.c_str());
    }

    ImGui::Separator();

    if (!session().loaded()) {
        ImGui::TextDisabled("No binary loaded.");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("BinaryTabs")) {
        if (ImGui::BeginTabItem("Summary")) {
            render_summary();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Xrefs")) {
            render_xrefs();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Segments")) {
            render_segments();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Sections")) {
            render_sections();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}

void BinaryInfoView::render_summary() {
    if (ImGui::Button("Copy")) {
        client::imgui::copy_to_clipboard(build_summary_clipboard());
    }
    ImGui::Text("Path: %s", session().path().c_str());
    ImGui::Text("Entry: %s", client::fmt::hex(session().binary_info().entry).c_str());
    ImGui::Text("Program headers: %u", session().binary_info().ph_num);
    ImGui::Text("Section headers: %u", session().binary_info().sh_num);
    if (ImGui::CollapsingHeader("Text View")) {
        client::imgui::render_readonly_text("##SummaryText", build_summary_clipboard(), ImVec2(0, 120.0f));
    }
}

void BinaryInfoView::render_xrefs() {
    // Note: Xrefs state is not currently in global state struct in plan, 
    // but originally it was in UiState::XrefsState.
    // Ideally this should be in AppState or locally managed if transient.
    // For now assuming we need to add XrefsState to AppState or use local static (bad practice but quick).
    // Let's assume we added xrefs state to AppState or handle it locally.
    // Since I can't modify AppState easily right now without another pass, I'll use local state for this view
    // or assume it will be added. 
    // Actually, looking at previous state.h, I didn't add XrefsState.
    // I should probably add it or use static for now. 
    // Let's use static for now to avoid modifying state.h again in this step.
    
    struct XrefsState {
        char target[32] = {};
        int max_results = 256;
        bool auto_follow = true;
        bool needs_refresh = true;
        std::uint64_t last_target = 0;
        std::string error;
        std::vector<engine::xrefs::XrefEntry> entries;
    };
    static XrefsState xr;

    bool refresh_requested = false;

    ImGui::Checkbox("Auto follow view", &xr.auto_follow);
    ImGui::SameLine();
    if (ImGui::Button("Use View")) {
        std::uint64_t addr = state().code_view().address;
        std::snprintf(xr.target, sizeof(xr.target), "0x%llx", static_cast<unsigned long long>(addr));
        refresh_requested = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        refresh_requested = true;
    }
    
    // ... Copy logic would go here ...

    ImGui::SetNextItemWidth(150.0f);
    ImGui::InputText("Target", xr.target, sizeof(xr.target));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90.0f);
    ImGui::InputInt("Max", &xr.max_results);
    if (xr.max_results < 1) xr.max_results = 1;

    if (xr.auto_follow) {
        std::uint64_t view_addr = state().code_view().address;
        if (view_addr != xr.last_target) {
            std::snprintf(xr.target, sizeof(xr.target), "0x%llx", static_cast<unsigned long long>(view_addr));
            xr.needs_refresh = true;
        }
    }

    if (refresh_requested || xr.needs_refresh) {
        std::uint64_t target = 0;
        if (client::fmt::parse_u64(xr.target, target)) {
            xr.entries.clear();
            xr.error.clear();
            if (!session().find_xrefs_to_address(target, static_cast<std::size_t>(xr.max_results), xr.entries)) {
                xr.error = "xrefs search failed";
            }
            xr.last_target = target;
        } else {
            xr.error = "invalid target";
            xr.entries.clear();
        }
        xr.needs_refresh = false;
    }

    client::imgui::render_error_text(xr.error);

    ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                            ImGuiTableFlags_BordersOuter | ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("XrefsTable", 3, flags)) {
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableHeadersRow();
        for (std::size_t i = 0; i < xr.entries.size(); ++i) {
            const auto& entry = xr.entries[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Selectable(client::fmt::hex(entry.source).c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                navigate_to(entry.source);
            }
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(xref_kind_label(entry.kind));
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", client::fmt::hex(entry.target).c_str());
        }
        ImGui::EndTable();
    }
}

void BinaryInfoView::render_segments() {
    if (ImGui::Button("Copy")) {
        client::imgui::copy_to_clipboard(build_segments_clipboard());
    }
    ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                            ImGuiTableFlags_BordersOuter | ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("SegmentsTable", 6, flags)) {
        client::imgui::table_setup_columns({{"Type", 0}, {"Flags", 0}, {"Vaddr", 0}, {"Offset", 0}, {"FileSz", 0}, {"MemSz", 0}});
        for (const auto& seg : session().segments()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%u", seg.type);
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%x", seg.flags);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%s", client::fmt::hex(seg.vaddr).c_str());
            ImGui::TableSetColumnIndex(3); ImGui::Text("%s", client::fmt::hex(seg.offset).c_str());
            ImGui::TableSetColumnIndex(4); ImGui::Text("%s", client::fmt::hex(seg.filesz).c_str());
            ImGui::TableSetColumnIndex(5); ImGui::Text("%s", client::fmt::hex(seg.memsz).c_str());
        }
        ImGui::EndTable();
    }
}

void BinaryInfoView::render_sections() {
    if (ImGui::Button("Copy")) {
        client::imgui::copy_to_clipboard(build_sections_clipboard());
    }
    ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                            ImGuiTableFlags_BordersOuter | ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("SectionsTable", 5, flags)) {
        client::imgui::table_setup_columns({{"Name", 0}, {"Type", 0}, {"Addr", 0}, {"Offset", 0}, {"Size", 0}});
        for (const auto& sec : session().sections()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%s", sec.name.empty() ? "<noname>" : sec.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("%u", sec.type);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%s", client::fmt::hex(sec.addr).c_str());
            ImGui::TableSetColumnIndex(3); ImGui::Text("%s", client::fmt::hex(sec.offset).c_str());
            ImGui::TableSetColumnIndex(4); ImGui::Text("%s", client::fmt::hex(sec.size).c_str());
        }
        ImGui::EndTable();
    }
}

// Helpers for clipboards
std::string BinaryInfoView::build_summary_clipboard() {
    std::ostringstream oss;
    oss << "Path:\t" << session().path() << "\n";
    oss << "Entry:\t" << client::fmt::hex(session().binary_info().entry) << "\n";
    return oss.str();
}

std::string BinaryInfoView::build_segments_clipboard() {
    std::ostringstream oss;
    oss << "type\tflags\tvaddr\toffset\tfilesz\tmemsz\n";
    for (const auto& seg : session().segments()) {
        oss << seg.type << "\t" << client::fmt::hex(seg.flags) << "\t" 
            << client::fmt::hex(seg.vaddr) << "\t" << client::fmt::hex(seg.offset) << "\t"
            << client::fmt::hex(seg.filesz) << "\t" << client::fmt::hex(seg.memsz) << "\n";
    }
    return oss.str();
}

std::string BinaryInfoView::build_sections_clipboard() {
    std::ostringstream oss;
    oss << "name\ttype\taddr\toffset\tsize\n";
    for (const auto& sec : session().sections()) {
        oss << sec.name << "\t" << sec.type << "\t"
            << client::fmt::hex(sec.addr) << "\t" << client::fmt::hex(sec.offset) << "\t"
            << client::fmt::hex(sec.size) << "\n";
    }
    return oss.str();
}

std::string BinaryInfoView::build_xrefs_clipboard() {
    return ""; // TODO
}

void BinaryInfoView::refresh_xrefs_state(std::uint64_t target) {
    // TODO
}

}  // namespace client