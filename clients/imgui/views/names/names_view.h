#pragma once

#include "views/view_base.h"
#include "widgets/filter_widget.h"
#include "core/state.h"

namespace client {

class NamesView : public ViewBase {
public:
    explicit NamesView(AppContext& context);
    
    void on_render() override;
    
private:
    struct NameEntry {
        enum class Kind { Symbol, TypeInfo, Vtable } kind;
        std::string name;
        std::uint64_t address = 0;
        std::uint64_t size = 0;
        std::string detail;
    };

    FilterWidget filter_widget_;
};

}  // namespace client