#pragma once

#include <initializer_list>
#include <functional>
#include <string>
#include <vector>
#include <utility>

#include "imgui.h"
#include "../utils/imgui_helpers.h"

namespace client {

template<typename TItem>
class TableWidget {
public:
    using Column = std::pair<const char*, float>;
    using RowRenderer = std::function<void(const TItem&, int)>;

    TableWidget(const char* id, std::initializer_list<Column> columns)
        : id_(id), columns_(columns) {}

    void set_renderer(RowRenderer renderer) { renderer_ = renderer; }

    void render(const std::vector<TItem>& items) {
        ImGuiTableFlags flags = ImGuiTableColumnFlags_WidthStretch | ImGuiTableFlags_RowBg | 
                                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_BordersOuter | 
                                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;
        
        std::string table_id = std::string("Table##") + id_;
        if (ImGui::BeginTable(table_id.c_str(), static_cast<int>(columns_.size()), flags)) {
            for (const auto& col : columns_) {
                ImGuiTableColumnFlags col_flags = ImGuiTableColumnFlags_None;
                if (col.second > 0.0f) {
                    col_flags |= ImGuiTableColumnFlags_WidthFixed;
                    ImGui::TableSetupColumn(col.first, col_flags, col.second);
                } else {
                    ImGui::TableSetupColumn(col.first);
                }
            }
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(items.size()));
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    ImGui::TableNextRow();
                    if (renderer_) {
                        renderer_(items[i], i);
                    }
                }
            }
            ImGui::EndTable();
        }
    }

private:
    const char* id_;
    std::vector<Column> columns_;
    RowRenderer renderer_;
};

}  // namespace client