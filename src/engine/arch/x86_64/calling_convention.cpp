#include "engine/arch/x86_64/calling_convention.h"

namespace engine::arch::x86_64 {

namespace {

CallingConvention make_sysv() {
    CallingConvention cc;
    cc.int_args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    cc.float_args = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"};
    cc.int_return = "rax";
    cc.float_return = "xmm0";
    cc.callee_saved = {"rbx", "rbp", "r12", "r13", "r14", "r15"};
    cc.caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8",  "r9",
                       "r10", "r11", "xmm0", "xmm1", "xmm2", "xmm3",
                       "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
                       "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"};
    return cc;
}

CallingConvention make_win64() {
    CallingConvention cc;
    cc.int_args = {"rcx", "rdx", "r8", "r9"};
    cc.float_args = {"xmm0", "xmm1", "xmm2", "xmm3"};
    cc.int_return = "rax";
    cc.float_return = "xmm0";
    cc.callee_saved = {"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15",
                       "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11",
                       "xmm12", "xmm13", "xmm14", "xmm15"};
    cc.caller_saved = {"rax", "rcx", "rdx", "r8",  "r9",  "r10", "r11",
                       "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"};
    return cc;
}

std::vector<llir::RegRef> make_clobbers(const CallingConvention& cc) {
    std::vector<llir::RegRef> out;
    out.reserve(cc.caller_saved.size());
    for (const auto& name : cc.caller_saved) {
        llir::RegRef reg;
        reg.name = name;
        reg.version = -1;
        out.push_back(std::move(reg));
    }
    return out;
}

}  // namespace

const CallingConvention& sysv() {
    static CallingConvention cc = make_sysv();
    return cc;
}

const CallingConvention& win64() {
    static CallingConvention cc = make_win64();
    return cc;
}

const std::vector<llir::RegRef>& call_clobbers_sysv() {
    static std::vector<llir::RegRef> regs = make_clobbers(sysv());
    return regs;
}

const std::vector<llir::RegRef>& call_clobbers_win64() {
    static std::vector<llir::RegRef> regs = make_clobbers(win64());
    return regs;
}

}  // namespace engine::arch::x86_64
