#pragma once

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "engine/llir.h"

namespace engine::llir::x86_64 {

void lift_instruction(csh handle, const cs_insn& insn, Instruction& out);

}  // namespace engine::llir::x86_64
