#pragma once

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "imgui.h"

namespace client::imgui {

// 只读文本渲染
void render_readonly_text(const char* label, std::string_view text, const ImVec2& size);

// 错误/信息文本
void render_error_text(std::string_view message);
void render_info_text(std::string_view message);

// 地址输入（包装 client::fmt::parse_u64）
bool address_input(const char* label, char* buffer, std::size_t size, std::uint64_t* parsed = nullptr);

// 剪贴板
void copy_to_clipboard(std::string_view text);

// 表格辅助
void table_setup_columns(std::initializer_list<std::pair<const char*, float>> columns);

// 字符串工具
std::string join_lines(const std::vector<std::string>& lines);
std::string format_address_list(const std::vector<std::uint64_t>& addrs);

}  // namespace client::imgui