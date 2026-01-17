#pragma once

#include <vector>
#include <string>
#include <functional>
#include "imgui.h"
#include "core/context.h"
#include "client/command.h"

namespace client {

class CommandPalette {
public:
    explicit CommandPalette(AppContext& context);
    
    void render();
    void open();
    bool is_open() const { return open_; }

private:
    void update_filter(const char* text);
    void execute_selected();

    AppContext& context_;
    bool open_ = false;
    bool just_opened_ = false;
    char filter_buf_[256] = {};
    int selected_index_ = 0;
    
    struct CachedCommand {
        std::string name;
        std::string help;
    };
    std::vector<CachedCommand> all_commands_;
    std::vector<CachedCommand*> filtered_commands_;
};

}  // namespace client
