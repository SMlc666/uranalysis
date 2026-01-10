#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace client {

struct FileEntry {
    std::string name;
    std::string path;
    bool is_dir = false;
    std::uintmax_t size = 0;
};

enum class SortMode {
    NameAsc,
    NameDesc,
    SizeAsc,
    SizeDesc,
    Type,
};

struct FileBrowserState {
    char dir[512] = {};
    char filter[128] = ".elf;.so";
    char search[128] = {};
    SortMode sort = SortMode::Type;
    std::string status;
    std::vector<FileEntry> entries;
    bool dirty = true;
    std::string current_dir;
    std::vector<std::string> history;
    int history_index = -1;
};

bool render_file_browser(FileBrowserState& state, std::string& selected_path, bool* open);

}  // namespace client
