#pragma once

#include "views/view_base.h"
#include "core/state.h"

namespace client {

class OutputView : public ViewBase {
public:
    explicit OutputView(AppContext& context);
    
    void on_render() override;
    
private:
    std::string build_output_clipboard();
};

}  // namespace client