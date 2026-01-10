#include "function_discovery_internal.h"

namespace engine::analysis::detail {

void collect_tailcall_entry_points(const llir::Function& function, std::vector<std::uint64_t>& out) {
    for (const auto& block : function.blocks) {
        if (block.instructions.empty()) {
            continue;
        }
        const auto& last = block.instructions.back();
        if (last.branch != llir::BranchKind::kJump || last.conditional) {
            continue;
        }
        if (last.targets.empty()) {
            continue;
        }
        out.push_back(last.targets.front());
    }
}

}  // namespace engine::analysis::detail
