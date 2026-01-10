#include "file_browser.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <utility>

#include "imgui.h"

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

std::vector<std::pair<std::string, std::string>> build_quick_access(const FileBrowserState& state) {
    namespace fs = std::filesystem;
    std::vector<std::pair<std::string, std::string>> entries;
    std::vector<std::string> seen;
    auto add_entry = [&](const std::string& label, const std::string& path) {
        if (path.empty()) {
            return;
        }
        if (std::find(seen.begin(), seen.end(), path) != seen.end()) {
            return;
        }
        seen.push_back(path);
        entries.emplace_back(label, path);
    };

    auto home = get_home_directory();
    add_entry("Home", home);
    if (!home.empty()) {
        fs::path desktop = fs::path(home) / "Desktop";
        if (fs::exists(desktop)) {
            add_entry("Desktop", desktop.string());
        }
    }

    if (!state.current_dir.empty()) {
        fs::path current(state.current_dir);
        add_entry("Current Path", current.string());
        add_entry("Root", current.root_path().string());
    }

    auto roots = enumerate_drive_roots();
    for (const auto& root : roots) {
        add_entry(root + " Drive", root);
    }
    return entries;
}

std::vector<std::filesystem::path> build_path_chain(const std::string& path) {
    namespace fs = std::filesystem;
    std::vector<fs::path> chain;
    fs::path current(path);
    if (current.empty()) {
        return chain;
    }
    while (true) {
        chain.push_back(current);
        auto parent = current.parent_path();
        if (parent.empty() || parent == current) {
            break;
        }
        current = parent;
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

bool change_directory(FileBrowserState& state, const std::string& path_hint, bool record_history = true) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path target = path_hint.empty() ? fs::current_path(ec) : fs::path(path_hint);
    if (ec) {
        state.status = "invalid directory";
        return false;
    }
    target = fs::weakly_canonical(target, ec);
    if (ec) {
        state.status = "invalid directory";
        return false;
    }
    if (target.empty() || !fs::is_directory(target, ec) || ec) {
        state.status = "invalid directory";
        return false;
    }
    auto canonical = target.string();
    state.current_dir = canonical;
    std::snprintf(state.dir, sizeof(state.dir), "%s", canonical.c_str());
    state.status.clear();
    if (record_history) {
        if (state.history_index + 1 < static_cast<int>(state.history.size())) {
            state.history.resize(state.history_index + 1);
        }
        state.history.push_back(canonical);
        state.history_index = static_cast<int>(state.history.size()) - 1;
    }
    state.dirty = true;
    return true;
}

void navigate_history(FileBrowserState& state, int new_index) {
    if (new_index < 0 || new_index >= static_cast<int>(state.history.size())) {
        return;
    }
    state.history_index = new_index;
    change_directory(state, state.history[new_index], false);
}

void ensure_directory_initialized(FileBrowserState& state) {
    if (!state.history.empty()) {
        return;
    }
    std::string initial = state.dir[0] ? std::string(state.dir) : std::string();
    if (!change_directory(state, initial, true)) {
        change_directory(state, std::string(), true);
    }
}


std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
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
                out.push_back(to_lower(current));
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
        out.push_back(to_lower(current));
    }
    return out;
}

bool matches_filters(const FileEntry& entry, const std::vector<std::string>& filters) {
    if (entry.is_dir || filters.empty()) {
        return true;
    }
    auto lower_name = to_lower(entry.name);
    for (const auto& ext : filters) {
        if (lower_name.size() >= ext.size() &&
            lower_name.compare(lower_name.size() - ext.size(), ext.size(), ext) == 0) {
            return true;
        }
    }
    return false;
}

bool matches_search(const FileEntry& entry, const std::string& search) {
    if (search.empty()) {
        return true;
    }
    auto name = to_lower(entry.name);
    return name.find(search) != std::string::npos;
}

void refresh_entries(FileBrowserState& state) {
    namespace fs = std::filesystem;
    state.entries.clear();
    state.dirty = false;
    std::error_code ec;
    fs::path dir = state.current_dir.empty() ? fs::current_path(ec) : fs::path(state.current_dir);
    if (ec) {
        state.status = "invalid directory";
        return;
    }
    dir = fs::weakly_canonical(dir, ec);
    if (ec) {
        state.status = "invalid directory";
        return;
    }
    state.current_dir = dir.string();
    std::snprintf(state.dir, sizeof(state.dir), "%s", state.current_dir.c_str());

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) {
            state.status = "failed to read directory";
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
        state.entries.push_back(std::move(item));
    }
    state.status.clear();
}

void sort_entries(FileBrowserState& state) {
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

    switch (state.sort) {
        case SortMode::NameAsc:
            std::sort(state.entries.begin(), state.entries.end(), cmp_name);
            break;
        case SortMode::NameDesc:
            std::sort(state.entries.begin(), state.entries.end(), cmp_name_desc);
            break;
        case SortMode::SizeAsc:
            std::sort(state.entries.begin(), state.entries.end(), cmp_size);
            break;
        case SortMode::SizeDesc:
            std::sort(state.entries.begin(), state.entries.end(), cmp_size_desc);
            break;
        case SortMode::Type:
            std::sort(state.entries.begin(), state.entries.end(), cmp_type);
            break;
    }
}

}  // namespace

bool render_file_browser(FileBrowserState& state, std::string& selected_path, bool* open) {
    bool selected = false;
    if (!open || !*open) {
        return false;
    }

    ImGui::SetNextWindowSize(ImVec2(900, 560), ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Open Binary", open)) {
        return false;
    }

    ensure_directory_initialized(state);
    if (state.dirty) {
        refresh_entries(state);
    }

    bool can_back = state.history_index > 0;
    bool can_forward = state.history_index + 1 < static_cast<int>(state.history.size());

    if (ImGui::Button("Back") && can_back) {
        navigate_history(state, state.history_index - 1);
    }
    ImGui::SameLine();
    if (ImGui::Button("Forward") && can_forward) {
        navigate_history(state, state.history_index + 1);
    }
    ImGui::SameLine();
    if (ImGui::Button("Up")) {
        namespace fs = std::filesystem;
        fs::path dir = state.current_dir.empty() ? fs::path() : fs::path(state.current_dir);
        auto parent = dir.parent_path();
        if (!parent.empty() && parent != dir) {
            change_directory(state, parent.string(), true);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        state.dirty = true;
    }

    if (ImGui::InputText("Directory", state.dir, sizeof(state.dir))) {
        change_directory(state, state.dir, true);
    }

    if (!state.status.empty()) {
        ImGui::TextUnformatted(state.status.c_str());
    }

    ImGui::Separator();

    ImGui::Columns(2, nullptr, true);
    ImGui::BeginChild("navigation", ImVec2(0, 0), true);
    ImGui::Text("Quick Access");
    auto quick_access = build_quick_access(state);
    for (const auto& entry : quick_access) {
        bool active = entry.second == state.current_dir;
        if (ImGui::Selectable(entry.first.c_str(), active)) {
            change_directory(state, entry.second, true);
        }
    }
    ImGui::Separator();
    ImGui::Text("Path");
    auto path_chain = build_path_chain(state.current_dir);
    for (const auto& path : path_chain) {
        std::string label = path.filename().string();
        if (label.empty()) {
            label = path.root_path().string();
        }
        if (label.empty()) {
            label = path.string();
        }
        bool is_current = path.string() == state.current_dir;
        if (ImGui::Selectable(label.c_str(), is_current)) {
            change_directory(state, path.string(), true);
        }
    }
    ImGui::EndChild();

    ImGui::NextColumn();
    ImGui::BeginChild("files", ImVec2(0, 0), true);
    if (ImGui::InputText("Filter", state.filter, sizeof(state.filter))) {
        state.dirty = true;
    }
    if (ImGui::InputText("Search", state.search, sizeof(state.search))) {
        state.dirty = true;
    }

    const char* sort_items[] = {"Type", "Name Asc", "Name Desc", "Size Asc", "Size Desc"};
    int sort_index = 0;
    switch (state.sort) {
        case SortMode::Type: sort_index = 0; break;
        case SortMode::NameAsc: sort_index = 1; break;
        case SortMode::NameDesc: sort_index = 2; break;
        case SortMode::SizeAsc: sort_index = 3; break;
        case SortMode::SizeDesc: sort_index = 4; break;
    }
    if (ImGui::Combo("Sort", &sort_index, sort_items, IM_ARRAYSIZE(sort_items))) {
        switch (sort_index) {
            case 0: state.sort = SortMode::Type; break;
            case 1: state.sort = SortMode::NameAsc; break;
            case 2: state.sort = SortMode::NameDesc; break;
            case 3: state.sort = SortMode::SizeAsc; break;
            case 4: state.sort = SortMode::SizeDesc; break;
        }
        state.dirty = true;
    }

    auto filters = parse_filter(state.filter);
    auto search = to_lower(state.search);

    if (!state.dirty) {
        sort_entries(state);
    }

    ImGui::Separator();
    for (const auto& entry : state.entries) {
        if (!matches_filters(entry, filters) || !matches_search(entry, search)) {
            continue;
        }
        if (ImGui::Selectable(entry.name.c_str())) {
            if (entry.is_dir) {
                change_directory(state, entry.path, true);
            } else {
                selected_path = entry.path;
                selected = true;
            }
        }
    }
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

}  // namespace client
