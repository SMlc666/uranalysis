#pragma once

#include <string>
#include <vector>
#include <filesystem>

#include "../../core/context.h"
#include "../../core/state.h"

namespace client {

class FileBrowser {
public:
    explicit FileBrowser(AppContext& context);
    
    // Renders the modal and returns true if a file was selected.
    // The selected path is written to out_path.
    bool render(bool* open, std::string& out_path);
    
private:
    struct FileEntry {
        std::string name;
        std::string path;
        bool is_dir = false;
        std::uintmax_t size = 0;
    };

    enum class SortMode {
        Type,
        NameAsc,
        NameDesc,
        SizeAsc,
        SizeDesc,
    };

    void ensure_initialized();
    void refresh_entries();
    void change_directory(const std::string& path_hint, bool record_history = true);
    void navigate_history(int new_index);
    void sort_entries();
    
    // UI Helpers
    void render_navigation_pane();
    void render_file_list(bool* selected, std::string& out_path);
    std::vector<std::pair<std::string, std::string>> build_quick_access();
    std::vector<std::filesystem::path> build_path_chain(const std::string& path);

    AppContext& context_;
    
    // Local transient state (could be in AppState if persistence needed across sessions)
    // Actually using AppState::FileBrowserState for persistence
    std::vector<FileEntry> entries_;
    SortMode sort_mode_ = SortMode::Type;
};

}  // namespace client