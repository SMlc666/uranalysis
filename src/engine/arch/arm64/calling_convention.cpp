#include "engine/arch/arm64/calling_convention.h"

namespace engine::arch::arm64 {

namespace {

CallingConvention make_aapcs64() {
    CallingConvention cc;
    cc.int_args = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    cc.float_args = {"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"};
    cc.int_return = "x0";
    cc.float_return = "v0";
    cc.callee_saved = {"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
                       "v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15"};
    cc.caller_saved = {"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",
                       "x9",  "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
                       "x30", "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v16",
                       "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
                       "v27", "v28", "v29", "v30", "v31"};
    return cc;
}

}  // namespace

const CallingConvention& aapcs64() {
    static CallingConvention cc = make_aapcs64();
    return cc;
}

const std::vector<llir::RegRef>& call_clobbers() {
    static std::vector<llir::RegRef> regs = []() {
        std::vector<llir::RegRef> out;
        const auto& cc = aapcs64();
        out.reserve(cc.caller_saved.size());
        for (const auto& name : cc.caller_saved) {
            llir::RegRef reg;
            reg.name = name;
            reg.version = -1;
            out.push_back(std::move(reg));
        }
        return out;
    }();
    return regs;
}

}  // namespace engine::arch::arm64
