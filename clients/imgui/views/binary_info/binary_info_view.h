#pragma once

#include "../view_base.h"
#include "../../core/state.h"

namespace client {

class BinaryInfoView : public ViewBase {
public:
    explicit BinaryInfoView(AppContext& context);
    
    void on_render() override;
    
private:
    void render_summary();
    void render_xrefs();
    void render_segments();
    void render_sections();
    
    // Xrefs state helper functions
    void refresh_xrefs_state(std::uint64_t target);
    std::string build_summary_clipboard();
    std::string build_segments_clipboard();
    std::string build_sections_clipboard();
    std::string build_xrefs_clipboard();
};

}  // namespace client