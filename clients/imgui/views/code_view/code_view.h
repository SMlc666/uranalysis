#pragma once

#include "views/view_base.h"
#include "views/code_view/disasm_tab.h"
#include "views/code_view/ir_tabs.h"
#include "core/events.h"

namespace client {

class CodeView : public ViewBase {
public:
    explicit CodeView(AppContext& context);
    
    void on_attach() override;
    void on_detach() override;
    void on_render() override;
    
private:
    void render_toolbar();
    void render_tabs();
    
    // Child tabs
    DisasmTab disasm_tab_;
    IrTabs ir_tabs_;
    
    // Event subscriptions
    EventBus::SubscriptionId nav_sub_id_ = 0;
};

}  // namespace client