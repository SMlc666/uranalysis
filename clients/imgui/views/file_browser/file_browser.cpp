#include "file_browser.h"

#include <algorithm>
#include <filesystem>
#include <cstdio>
#include <cstdlib>

#include "imgui.h"
#include "../../utils/imgui_helpers.h"
#include "client/formatters/address.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace client {

namespace {

std::string get_env_value(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

std::string get_home_directory() {
    std::string home;
#ifdef _WIN32
    home = get_env_value("USERPROFILE");
    if (home.empty()) {
        auto drive = get_env_value("HOMEDRIVE");
        auto path = get_env_value("HOMEPATH");
        if (!drive.empty() && !path.empty()) {
            home = drive + path;
        }
    }
#else
    home = get_env_value("HOME");
#endif
    if (home.empty()) {
        std::error_code ec;
        home = std::filesystem::current_path(ec).string();
    }
    return home;
}

std::vector<std::string> enumerate_drive_roots() {
    std::vector<std::string> roots;
#ifdef _WIN32
    DWORD mask = GetLogicalDrives();
    if (mask == 0) {
        return roots;
    }
    for (int i = 0; i < 26; ++i) {
        if (mask & (1u << i)) {
            std::string drive = std::string(1, static_cast<char>('A' + i)) + ":\\";
            roots.emplace_back(drive);
        }
    }
#else
    roots.emplace_back("/");
#endif
    return roots;
}

std::vector<std::string> parse_filter(const char* filter) {
    std::vector<std::string> out;
    if (!filter || filter[0] == '\0') {
        return out;
    }
    std::string s(filter);
    std::string current;
    for (char c : s) {
        if (c == ';' || c == ',' || c == ' ') {
            if (!current.empty()) {
                if (current[0] != '.') {
                    current = "." + current;
                }
                out.push_back(client::fmt::to_lower(current));
                current.clear();
            }
            continue;
        }
        current.push_back(c);
    }
    if (!current.empty()) {
        if (current[0] != '.') {
            current = "." + current;
        }
        out.push_back(client::fmt::to_lower(current));
    }
    return out;
}

} // namespace

FileBrowser::FileBrowser(AppContext& context) : context_(context) {}

bool FileBrowser::render(bool* open, std::string& out_path) {
    if (!open || !*open) {
        return false;
    }

    auto& fb_state = context_.state().file_browser();
    bool selected = false;

    ImGui::SetNextWindowSize(ImVec2(900, 560), ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Open Binary", open)) {
        return false;
    }

    ensure_initialized();
    if (fb_state.dirty) {
        refresh_entries();
    }

    // Top bar
    bool can_back = fb_state.history_index > 0;
    bool can_forward = fb_state.history_index + 1 < static_cast<int>(fb_state.history.size());

    if (ImGui::Button("Back") && can_back) {
        navigate_history(fb_state.history_index - 1);
    }
    ImGui::SameLine();
    if (ImGui::Button("Forward") && can_forward) {
        navigate_history(fb_state.history_index + 1);
    }
    ImGui::SameLine();
    if (ImGui::Button("Up")) {
        namespace fs = std::filesystem;
        fs::path dir = fb_state.current_dir.empty() ? fs::path() : fs::path(fb_state.current_dir);
        auto parent = dir.parent_path();
        if (!parent.empty() && parent != dir) {
            change_directory(parent.string(), true);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        fb_state.dirty = true;
    }

    if (ImGui::InputText("Directory", fb_state.dir, sizeof(fb_state.dir))) {
        change_directory(fb_state.dir, true);
    }

    if (!fb_state.status.empty()) {
        ImGui::TextUnformatted(fb_state.status.c_str());
    }

    ImGui::Separator();

    ImGui::Columns(2, nullptr, true);
    
    // Left pane: Navigation
    ImGui::BeginChild("navigation", ImVec2(0, 0), true);
    render_navigation_pane();
    ImGui::EndChild();

    ImGui::NextColumn();
    
    // Right pane: Files
    ImGui::BeginChild("files", ImVec2(0, 0), true);
    render_file_list(&selected, out_path);
    ImGui::EndChild();

    ImGui::Columns(1);
    ImGui::Separator();
    
    ImGui::TextDisabled("Select a file to open it.");
    if (ImGui::Button("Cancel")) {
        *open = false;
        ImGui::CloseCurrentPopup();
    }

    if (selected) {
        *open = false;
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
    return selected;
}

void FileBrowser::ensure_initialized() {
    auto& fb_state = context_.state().file_browser();
    if (!fb_state.history.empty()) {
        return;
    }
    std::string initial = fb_state.dir[0] ? std::string(fb_state.dir) : std::string();
    if (!initial.empty()) {
        change_directory(initial, true);
    } else {
        change_directory(std::filesystem::current_path().string(), true);
    }
}

void FileBrowser::refresh_entries() {
    auto& fb_state = context_.state().file_browser();
    namespace fs = std::filesystem;
    entries_.clear();
    
    fb_state.dirty = false;
    std::error_code ec;
    fs::path dir = fb_state.current_dir.empty() ? fs::current_path(ec) : fs::path(fb_state.current_dir);
    if (ec) {
        fb_state.status = "invalid directory";
        return;
    }
    dir = fs::weakly_canonical(dir, ec);
    if (ec) {
        fb_state.status = "invalid directory";
        return;
    }
    fb_state.current_dir = dir.string();
    std::snprintf(fb_state.dir, sizeof(fb_state.dir), "%s", fb_state.current_dir.c_str());

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) {
            fb_state.status = "failed to read directory";
            return;
        }
        FileEntry item;
        item.is_dir = entry.is_directory();
        item.name = entry.path().filename().string();
        if (item.is_dir) {
            item.name.append("/");
            item.size = 0;
        } else {
            item.size = entry.file_size(ec);
            if (ec) {
                item.size = 0;
            }
        }
        item.path = entry.path().string();
        entries_.push_back(std::move(item));
    }
    fb_state.status.clear();
    
    sort_entries();
}

void FileBrowser::change_directory(const std::string& path_hint, bool record_history) {
    auto& fb_state = context_.state().file_browser();
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path target = path_hint.empty() ? fs::current_path(ec) : fs::path(path_hint);
    if (ec) {
        fb_state.status = "invalid directory";
        return;
    }
    target = fs::weakly_canonical(target, ec);
    if (ec || target.empty() || !fs::is_directory(target, ec)) {
        fb_state.status = "invalid directory";
        return;
    }
    
    auto canonical = target.string();
    fb_state.current_dir = canonical;
    std::snprintf(fb_state.dir, sizeof(fb_state.dir), "%s", canonical.c_str());
    fb_state.status.clear();
    
    if (record_history) {
        if (fb_state.history_index + 1 < static_cast<int>(fb_state.history.size())) {
            fb_state.history.resize(fb_state.history_index + 1);
        }
        fb_state.history.push_back(canonical);
        fb_state.history_index = static_cast<int>(fb_state.history.size()) - 1;
    }
    fb_state.dirty = true;
}

void FileBrowser::navigate_history(int new_index) {
    auto& fb_state = context_.state().file_browser();
    if (new_index < 0 || new_index >= static_cast<int>(fb_state.history.size())) {
        return;
    }
    fb_state.history_index = new_index;
    change_directory(fb_state.history[new_index], false);
}

void FileBrowser::sort_entries() {
    auto cmp_name = [](const FileEntry& a, const FileEntry& b) { return a.name < b.name; };
    auto cmp_name_desc = [](const FileEntry& a, const FileEntry& b) { return a.name > b.name; };
    auto cmp_size = [](const FileEntry& a, const FileEntry& b) { return a.size < b.size; };
    auto cmp_size_desc = [](const FileEntry& a, const FileEntry& b) { return a.size > b.size; };
    auto cmp_type = [](const FileEntry& a, const FileEntry& b) {
        if (a.is_dir != b.is_dir) {
            return a.is_dir > b.is_dir;
        }
        return a.name < b.name;
    };

    switch (sort_mode_) {
        case SortMode::NameAsc: std::sort(entries_.begin(), entries_.end(), cmp_name); break;
        case SortMode::NameDesc: std::sort(entries_.begin(), entries_.end(), cmp_name_desc); break;
        case SortMode::SizeAsc: std::sort(entries_.begin(), entries_.end(), cmp_size); break;
        case SortMode::SizeDesc: std::sort(entries_.begin(), entries_.end(), cmp_size_desc); break;
        case SortMode::Type: std::sort(entries_.begin(), entries_.end(), cmp_type); break;
    }
}

void FileBrowser::render_navigation_pane() {
    auto& fb_state = context_.state().file_browser();
    ImGui::Text("Quick Access");
    auto quick_access = build_quick_access();
    for (const auto& entry : quick_access) {
        bool active = entry.second == fb_state.current_dir;
        if (ImGui::Selectable(entry.first.c_str(), active)) {
            change_directory(entry.second, true);
        }
    }
    ImGui::Separator();
    ImGui::Text("Path");
    auto path_chain = build_path_chain(fb_state.current_dir);
    for (const auto& path : path_chain) {
        std::string label = path.filename().string();
        if (label.empty()) label = path.root_path().string();
        if (label.empty()) label = path.string();
        
        bool is_current = path.string() == fb_state.current_dir;
        if (ImGui::Selectable(label.c_str(), is_current)) {
            change_directory(path.string(), true);
        }
    }
}

void FileBrowser::render_file_list(bool* selected, std::string& out_path) {
    auto& fb_state = context_.state().file_browser();
    
    if (ImGui::InputText("Filter", fb_state.filter, sizeof(fb_state.filter))) {
        fb_state.dirty = true;
    }
    if (ImGui::InputText("Search", fb_state.search, sizeof(fb_state.search))) {
        fb_state.dirty = true;
    }

    const char* sort_items[] = {"Type", "Name Asc", "Name Desc", "Size Asc", "Size Desc"};
    int sort_index = static_cast<int>(sort_mode_);
    if (ImGui::Combo("Sort", &sort_index, sort_items, IM_ARRAYSIZE(sort_items))) {
        sort_mode_ = static_cast<SortMode>(sort_index);
        sort_entries();
    }

    auto filters = parse_filter(fb_state.filter);
    auto search = client::fmt::to_lower(fb_state.search);

    ImGui::Separator();
    for (const auto& entry : entries_) {
        bool match_filter = true;
        if (!entry.is_dir && !filters.empty()) {
            match_filter = false;
            auto lower_name = client::fmt::to_lower(entry.name);
            for (const auto& ext : filters) {
                if (lower_name.size() >= ext.size() &&
                    lower_name.compare(lower_name.size() - ext.size(), ext.size(), ext) == 0) {
                    match_filter = true;
                    break;
                }
            }
        }
        
        if (!match_filter) continue;
        if (!search.empty()) {
            auto name = client::fmt::to_lower(entry.name);
            if (name.find(search) == std::string::npos) continue;
        }

        if (ImGui::Selectable(entry.name.c_str())) {
            if (entry.is_dir) {
                change_directory(entry.path, true);
            } else {
                out_path = entry.path;
                *selected = true;
            }
        }
    }
}

std::vector<std::pair<std::string, std::string>> FileBrowser::build_quick_access() {
    auto& fb_state = context_.state().file_browser();
    namespace fs = std::filesystem;
    std::vector<std::pair<std::string, std::string>> entries;
    std::vector<std::string> seen;
    
    auto add_entry = [&](const std::string& label, const std::string& path) {
        if (path.empty()) return;
        if (std::find(seen.begin(), seen.end(), path) != seen.end()) return;
        seen.push_back(path);
        entries.emplace_back(label, path);
    };

    auto home = get_home_directory();
    add_entry("Home", home);
    if (!home.empty()) {
        fs::path desktop = fs::path(home) / "Desktop";
        if (fs::exists(desktop)) add_entry("Desktop", desktop.string());
    }

    if (!fb_state.current_dir.empty()) {
        fs::path current(fb_state.current_dir);
        add_entry("Current Path", current.string());
        add_entry("Root", current.root_path().string());
    }

    auto roots = enumerate_drive_roots();
    for (const auto& root : roots) {
        add_entry(root + " Drive", root);
    }
    return entries;
}

std::vector<std::filesystem::path> FileBrowser::build_path_chain(const std::string& path) {
    namespace fs = std::filesystem;
    std::vector<fs::path> chain;
    fs::path current(path);
    if (current.empty()) return chain;
    
    while (true) {
        chain.push_back(current);
        auto parent = current.parent_path();
        if (parent.empty() || parent == current) break;
        current = parent;
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

}  // namespace client