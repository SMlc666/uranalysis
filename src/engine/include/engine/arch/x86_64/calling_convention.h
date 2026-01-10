#pragma once

#include <string>
#include <vector>

#include "engine/llir.h"

namespace engine::arch::x86_64 {

struct CallingConvention {
    std::vector<std::string> int_args;
    std::vector<std::string> float_args;
    std::string int_return;
    std::string float_return;
    std::vector<std::string> caller_saved;
    std::vector<std::string> callee_saved;
};

const CallingConvention& sysv();
const CallingConvention& win64();
const std::vector<llir::RegRef>& call_clobbers_sysv();
const std::vector<llir::RegRef>& call_clobbers_win64();

}  // namespace engine::arch::x86_64
