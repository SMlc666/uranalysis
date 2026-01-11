#pragma once

#include <cstdint>
#include <string>

namespace client::events {

// 导航事件
struct NavigateToAddress {
    std::uint64_t address;
    bool open_in_new_tab = false;
};

// 会话事件
struct SessionOpened {
    std::string path;
};

struct SessionClosed {};

struct SessionReloaded {};

// 选择事件
struct FunctionSelected {
    std::uint64_t address;
    std::string name;
};

struct SymbolSelected {
    std::uint64_t address;
    std::string name;
};

// UI事件
struct RequestOpenFile {};
struct LayoutReset {};
struct ThemeChanged { std::string theme_name; };

struct StatusMessage {
    std::string message;
    bool is_error = false;
};

}  // namespace client::events