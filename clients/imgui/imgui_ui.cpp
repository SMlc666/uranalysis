#include "imgui_ui.h"

#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include "file_browser.h"
#include "functions_view.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "names_view.h"
#include "strings_view.h"
#include "view_window.h"

namespace client {

namespace {

bool parse_u64_text(const char* text, std::uint64_t& value) {
    value = 0;
    if (!text || text[0] == '\0') {
        return false;
    }
    std::string s = text;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
        if (s.empty()) {
            return false;
        }
        std::istringstream iss(s);
        iss >> std::hex >> value;
        return !iss.fail();
    }
    std::istringstream iss(s);
    iss >> value;
    return !iss.fail();
}

const char* xref_kind_label(engine::xrefs::XrefKind kind) {
    switch (kind) {
        case engine::xrefs::XrefKind::kDataPointer:
            return "data";
        case engine::xrefs::XrefKind::kCodeCall:
            return "call";
        case engine::xrefs::XrefKind::kCodeJump:
            return "jump";
        case engine::xrefs::XrefKind::kCodeCallIndirect:
            return "call*";
        case engine::xrefs::XrefKind::kCodeJumpIndirect:
            return "jump*";
    }
    return "unknown";
}

std::string format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

std::string build_summary_clipboard(const UiState& state) {
    std::ostringstream oss;
    oss << "Path:\t" << state.session.path() << "\n";
    oss << "Entry:\t" << format_hex(state.session.binary_info().entry) << "\n";
    oss << "Program headers:\t" << state.session.binary_info().ph_num << "\n";
    oss << "Section headers:\t" << state.session.binary_info().sh_num << "\n";
    return oss.str();
}

std::string build_segments_clipboard(const Session& session) {
    std::ostringstream oss;
    oss << "type\tflags\tvaddr\toffset\tfilesz\tmemsz\n";
    for (const auto& seg : session.segments()) {
        oss << seg.type << "\t";
        oss << format_hex(seg.flags) << "\t";
        oss << format_hex(seg.vaddr) << "\t";
        oss << format_hex(seg.offset) << "\t";
        oss << format_hex(seg.filesz) << "\t";
        oss << format_hex(seg.memsz) << "\n";
    }
    return oss.str();
}

std::string build_sections_clipboard(const Session& session) {
    std::ostringstream oss;
    oss << "name\ttype\taddr\toffset\tsize\n";
    for (const auto& sec : session.sections()) {
        oss << (sec.name.empty() ? "<noname>" : sec.name) << "\t";
        oss << sec.type << "\t";
        oss << format_hex(sec.addr) << "\t";
        oss << format_hex(sec.offset) << "\t";
        oss << format_hex(sec.size) << "\n";
    }
    return oss.str();
}

std::string build_xrefs_clipboard(const std::vector<engine::xrefs::XrefEntry>& entries) {
    std::ostringstream oss;
    oss << "source\tkind\ttarget\n";
    for (const auto& entry : entries) {
        oss << format_hex(entry.source) << "\t";
        oss << xref_kind_label(entry.kind) << "\t";
        oss << format_hex(entry.target) << "\n";
    }
    return oss.str();
}

std::string build_output_clipboard(const UiState& state) {
    std::ostringstream oss;
    if (state.session.loaded()) {
        oss << "Loaded:\t" << state.session.path() << "\n";
    } else {
        oss << "Loaded:\t<none>\n";
    }
    if (!state.status.empty()) {
        oss << "Status:\t" << state.status << "\n";
    }
    return oss.str();
}

void render_readonly_text(const char* label, const std::string& text, const ImVec2& size) {
    std::vector<char> buffer(text.begin(), text.end());
    buffer.push_back('\0');
    ImGui::InputTextMultiline(label, buffer.data(), buffer.size(), size, ImGuiInputTextFlags_ReadOnly);
}

void refresh_xrefs(UiState& state, std::uint64_t target) {
    auto& xr = state.xrefs;
    xr.entries.clear();
    xr.error.clear();
    if (xr.max_results < 1) {
        xr.max_results = 1;
    }
    if (!state.session.find_xrefs_to_address(target,
                                             static_cast<std::size_t>(xr.max_results),
                                             xr.entries)) {
        xr.error = "xrefs search failed";
    }
    xr.last_target = target;
    xr.needs_refresh = false;
}

void apply_loaded_state(UiState& state) {
    state.view.go_to(state.session.cursor());
    state.view.last_error.clear();
    state.view.disasm.clear();
    state.view.bytes.clear();
    state.view.disasm_start_address = 0;
    state.view.disasm_next_address = 0;
    state.view.disasm_reached_end = false;
    state.view.disasm_loading = false;
    state.view.disasm_reset_scroll = true;
    state.view.llir_lines.clear();
    state.view.mlil_lines.clear();
    state.view.hlil_lines.clear();
    state.view.pseudoc_lines.clear();
    state.view.ir_error.clear();
    state.view.mlil_error.clear();
    state.view.hlil_error.clear();
    state.view.pseudoc_error.clear();
    state.functions.selected_entry = static_cast<std::size_t>(-1);
    state.functions.discovered.clear();
    state.functions.discovery_error.clear();
    state.functions.discovery_dirty = true;
    state.names.selected_entry = static_cast<std::size_t>(-1);
    state.strings.selected_entry = static_cast<std::size_t>(-1);
    state.xrefs.entries.clear();
    state.xrefs.error.clear();
    state.xrefs.last_target = 0;
    state.xrefs.needs_refresh = true;
    std::snprintf(state.xrefs.target,
                  sizeof(state.xrefs.target),
                  "0x%llx",
                  static_cast<unsigned long long>(state.session.cursor()));
}

bool open_session(UiState& state, const char* path) {
    if (!path || path[0] == '\0') {
        state.status = "path is empty";
        return false;
    }
    std::string error;
    if (!state.session.open(path, error)) {
        state.status = "load error: " + error;
        return false;
    }
    std::snprintf(state.path, sizeof(state.path), "%s", state.session.path().c_str());
    state.status = "loaded: " + state.session.path();
    apply_loaded_state(state);
    return true;
}

void close_session(UiState& state) {
    state.session.close();
    state.status = "session closed";
    state.view = ViewState{};
    state.functions = FunctionsViewState{};
    state.names = NamesViewState{};
    state.strings = StringsViewState{};
    state.xrefs = UiState::XrefsState{};
}

void render_about_popup(const engine::EngineInfo& info, bool& open_flag) {
    if (open_flag) {
        ImGui::OpenPopup("About");
        open_flag = false;
    }
    if (ImGui::BeginPopupModal("About", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("%s %s", info.name.c_str(), info.version.c_str());
        ImGui::Separator();
        ImGui::TextUnformatted("ImGui client");
        ImGui::Spacing();
        if (ImGui::Button("Close")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void render_toolbar_contents(UiState& state, const engine::EngineInfo& info) {
    if (ImGui::Button("Open...")) {
        state.request_open = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload") && state.session.loaded()) {
        open_session(state, state.session.path().c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Entry") && state.session.loaded()) {
        state.view.go_to(state.session.binary_info().entry);
    }

    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::TextDisabled("%s %s", info.name.c_str(), info.version.c_str());
}

void render_inspector(UiState& state) {
    ImGui::Begin("Binary Info");

    ImGui::TextUnformatted("File");
    ImGui::PushItemWidth(-1.0f);
    ImGui::InputText("##BinaryPath", state.path, sizeof(state.path));
    ImGui::PopItemWidth();

    if (ImGui::Button("Open...")) {
        state.request_open = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Load")) {
        open_session(state, state.path);
    }
    ImGui::SameLine();
    if (ImGui::Button("Entry") && state.session.loaded()) {
        state.view.go_to(state.session.binary_info().entry);
    }

    if (!state.status.empty()) {
        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", state.status.c_str());
    }

    ImGui::Separator();

    if (!state.session.loaded()) {
        ImGui::TextDisabled("No binary loaded.");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("BinaryTabs")) {
        if (ImGui::BeginTabItem("Summary")) {
            if (ImGui::Button("Copy")) {
                const std::string text = build_summary_clipboard(state);
                ImGui::SetClipboardText(text.c_str());
            }
            ImGui::Text("Path: %s", state.session.path().c_str());
            ImGui::Text("Entry: 0x%llx", static_cast<unsigned long long>(state.session.binary_info().entry));
            ImGui::Text("Program headers: %u", state.session.binary_info().ph_num);
            ImGui::Text("Section headers: %u", state.session.binary_info().sh_num);
            if (ImGui::CollapsingHeader("Text View")) {
                const std::string text = build_summary_clipboard(state);
                render_readonly_text("##SummaryText", text, ImVec2(0, 120.0f));
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Xrefs")) {
            auto& xr = state.xrefs;
            bool refresh_requested = false;

            ImGui::Checkbox("Auto follow view", &xr.auto_follow);
            ImGui::SameLine();
            if (ImGui::Button("Use View")) {
                std::uint64_t addr = state.view.last_address != 0 ? state.view.last_address : state.session.cursor();
                std::snprintf(xr.target, sizeof(xr.target), "0x%llx", static_cast<unsigned long long>(addr));
                refresh_requested = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh")) {
                refresh_requested = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Copy")) {
                const std::string text = build_xrefs_clipboard(xr.entries);
                ImGui::SetClipboardText(text.c_str());
            }

            ImGui::SetNextItemWidth(150.0f);
            ImGui::InputText("Target", xr.target, sizeof(xr.target));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(90.0f);
            ImGui::InputInt("Max", &xr.max_results);
            if (xr.max_results < 1) {
                xr.max_results = 1;
            }

            if (xr.auto_follow) {
                std::uint64_t view_addr = 0;
                if (parse_u64_text(state.view.address, view_addr)) {
                    if (view_addr != xr.last_target) {
                        std::snprintf(xr.target,
                                      sizeof(xr.target),
                                      "0x%llx",
                                      static_cast<unsigned long long>(view_addr));
                        xr.needs_refresh = true;
                    }
                }
            }

            if (refresh_requested || xr.needs_refresh) {
                std::uint64_t target = 0;
                if (parse_u64_text(xr.target, target)) {
                    refresh_xrefs(state, target);
                } else {
                    xr.error = "invalid target";
                    xr.entries.clear();
                    xr.needs_refresh = false;
                }
            }

            if (!xr.error.empty()) {
                ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", xr.error.c_str());
            }

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
                    ImGuiSelectableFlags select_flags =
                        ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick;
                    std::ostringstream oss;
                    oss << "0x" << std::hex << entry.source;
                    std::string label = oss.str();
                    if (ImGui::Selectable(label.c_str(), false, select_flags)) {
                        state.view.go_to(entry.source);
                    }
                    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                        state.view.go_to(entry.source);
                    }
                    ImGui::PopID();
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(xref_kind_label(entry.kind));
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(entry.target));
                }
                ImGui::EndTable();
            }
            if (xr.entries.empty()) {
                ImGui::TextDisabled("No xrefs found for this target.");
            }
            if (ImGui::CollapsingHeader("Text View")) {
                const std::string text = build_xrefs_clipboard(xr.entries);
                render_readonly_text("##XrefsText", text, ImVec2(0, 140.0f));
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Segments")) {
            if (ImGui::Button("Copy")) {
                const std::string text = build_segments_clipboard(state.session);
                ImGui::SetClipboardText(text.c_str());
            }
            ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                    ImGuiTableFlags_BordersOuter | ImGuiTableFlags_ScrollY |
                                    ImGuiTableFlags_Resizable;
            if (ImGui::BeginTable("SegmentsTable", 6, flags)) {
                ImGui::TableSetupColumn("Type");
                ImGui::TableSetupColumn("Flags");
                ImGui::TableSetupColumn("Vaddr");
                ImGui::TableSetupColumn("Offset");
                ImGui::TableSetupColumn("FileSz");
                ImGui::TableSetupColumn("MemSz");
                ImGui::TableHeadersRow();
                for (const auto& seg : state.session.segments()) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%u", seg.type);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("0x%x", seg.flags);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(seg.vaddr));
                    ImGui::TableSetColumnIndex(3);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(seg.offset));
                    ImGui::TableSetColumnIndex(4);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(seg.filesz));
                    ImGui::TableSetColumnIndex(5);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(seg.memsz));
                }
                ImGui::EndTable();
            }
            if (ImGui::CollapsingHeader("Text View")) {
                const std::string text = build_segments_clipboard(state.session);
                render_readonly_text("##SegmentsText", text, ImVec2(0, 160.0f));
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Sections")) {
            if (ImGui::Button("Copy")) {
                const std::string text = build_sections_clipboard(state.session);
                ImGui::SetClipboardText(text.c_str());
            }
            ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                    ImGuiTableFlags_BordersOuter | ImGuiTableFlags_ScrollY |
                                    ImGuiTableFlags_Resizable;
            if (ImGui::BeginTable("SectionsTable", 5, flags)) {
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupColumn("Type");
                ImGui::TableSetupColumn("Addr");
                ImGui::TableSetupColumn("Offset");
                ImGui::TableSetupColumn("Size");
                ImGui::TableHeadersRow();
                for (const auto& sec : state.session.sections()) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%s", sec.name.empty() ? "<noname>" : sec.name.c_str());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%u", sec.type);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(sec.addr));
                    ImGui::TableSetColumnIndex(3);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(sec.offset));
                    ImGui::TableSetColumnIndex(4);
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(sec.size));
                }
                ImGui::EndTable();
            }
            if (ImGui::CollapsingHeader("Text View")) {
                const std::string text = build_sections_clipboard(state.session);
                render_readonly_text("##SectionsText", text, ImVec2(0, 160.0f));
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}

void render_output(UiState& state) {
    ImGui::Begin("Output");
    if (ImGui::Button("Copy")) {
        const std::string text = build_output_clipboard(state);
        ImGui::SetClipboardText(text.c_str());
    }
    const std::string output_text = build_output_clipboard(state);
    render_readonly_text("##OutputText", output_text, ImVec2(0, ImGui::GetContentRegionAvail().y));
    ImGui::End();
}

void build_default_layout(ImGuiID dockspace_id, const ImVec2& size) {
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

}  // namespace

void render_ui(UiState& state, const engine::EngineInfo& info) {
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

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                state.request_open = true;
            }
            if (ImGui::MenuItem("Reload", "F5", false, state.session.loaded())) {
                open_session(state, state.session.path().c_str());
            }
            if (ImGui::MenuItem("Close", nullptr, false, state.session.loaded())) {
                close_session(state);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Reset layout")) {
                state.reset_layout = true;
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About")) {
                state.show_about = true;
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    float toolbar_height = ImGui::GetFrameHeight() + ImGui::GetStyle().FramePadding.y * 2.0f + 2.0f;
    ImGui::BeginChild("Toolbar", ImVec2(0.0f, toolbar_height), false,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    render_toolbar_contents(state, info);
    ImGui::EndChild();

    ImGuiID dockspace_id = ImGui::GetID("MainDockspace");
    ImVec2 dockspace_size = ImGui::GetContentRegionAvail();
    if (!state.dock_initialized || state.reset_layout) {
        build_default_layout(dockspace_id, dockspace_size);
        state.dock_initialized = true;
        state.reset_layout = false;
    }
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f));
    ImGui::End();

    render_names_view(state.names, state.session, state.view);

    render_functions_view(state.functions, state.session, state.view);

    render_strings_view(state.strings, state.session, state.view);

    render_view_window(state.view, state.session);

    render_inspector(state);

    render_output(state);

    render_about_popup(info, state.show_about);

    if (state.request_open) {
        ImGui::OpenPopup("Open Binary");
        state.file_browser_open = true;
        state.request_open = false;
    }

    std::string selected_path;
    if (render_file_browser(state.browser, selected_path, &state.file_browser_open)) {
        open_session(state, selected_path.c_str());
    }
}

}  // namespace client
