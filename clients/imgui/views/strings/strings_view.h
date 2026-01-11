#pragma once

#include "../view_base.h"
#include "../../widgets/filter_widget.h"
#include "../../core/state.h"

namespace client {

class StringsView : public ViewBase {
public:
    explicit StringsView(AppContext& context);
    
    void on_render() override;
    
private:
    FilterWidget filter_widget_;
};

}  // namespace client