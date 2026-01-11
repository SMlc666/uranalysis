#pragma once

#include "core/context.h"

namespace client {

class IrTabs {
public:
    explicit IrTabs(AppContext& context);
    void render(CodeViewState& state);

private:
    void render_llir_tab(CodeViewState& state);
    void render_mlil_tab(CodeViewState& state);
    void render_hlil_tab(CodeViewState& state);
    void render_pseudoc_tab(CodeViewState& state);
    
    void refresh_ir(CodeViewState& state, std::uint64_t address);

    AppContext& context_;
};

}  // namespace client