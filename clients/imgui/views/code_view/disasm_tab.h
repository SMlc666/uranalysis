#pragma once

#include "../../core/context.h"
#include "../../widgets/address_input.h"
#include "../../widgets/text_view_widget.h"

namespace client {

class DisasmTab {
public:
    explicit DisasmTab(AppContext& context);
    void render(CodeViewState& state);

private:
    void refresh_disasm(CodeViewState& state, std::uint64_t address);
    void render_disasm_list(CodeViewState& state);
    void render_bytes_view(CodeViewState& state);

    AppContext& context_;
    // Formatters are available via client::fmt namespace, no member needed for stateless ones
};

}  // namespace client