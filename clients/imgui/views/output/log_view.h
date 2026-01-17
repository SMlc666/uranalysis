#pragma once

#include "views/view_base.h"
#include "utils/log_sink.h"
#include <imgui.h>
#include <memory>

namespace client {

class LogView : public ViewBase {
public:
    explicit LogView(AppContext& context);
    
    void on_render() override;
    
    // Set the sink to read logs from
    void set_sink(std::shared_ptr<ImGuiLogSinkMt> sink);

private:
    std::shared_ptr<ImGuiLogSinkMt> sink_;
    bool auto_scroll_ = true;
    ImGuiTextFilter filter_;
    bool show_info_ = true;
    bool show_warn_ = true;
    bool show_error_ = true;
    bool show_debug_ = false;
    bool show_trace_ = false;
};

} // namespace client
