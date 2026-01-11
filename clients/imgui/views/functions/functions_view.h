#pragma once

#include "views/view_base.h"
#include "widgets/filter_widget.h"
#include "widgets/table_widget.h"
#include "core/state.h"

namespace client {

class FunctionsView : public ViewBase {
public:
    explicit FunctionsView(AppContext& context);
    
    void on_render() override;
    
private:
    void render_toolbar();
    void render_discovery_options();
    void render_functions_table();
    
    void discover_functions();
    void on_function_selected(const DiscoveredFunction& entry);
    void on_symbol_selected(const engine::symbols::SymbolEntry& entry);
    
    FilterWidget filter_widget_;
    
    // We need different table types or a unified way to render
    // Since TableWidget is templated, we might need two instances or use a common adapter
    // For simplicity, let's use direct ImGui table rendering inside on_render or helper methods
    // to handle the switch between discovered and symbol view
};

}  // namespace client