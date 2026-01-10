#pragma once

#include <capstone/arm64.h>
#include <capstone/capstone.h>

#include "engine/llir.h"

namespace engine::llir::arm64 {

void lift_instruction(csh handle, const cs_insn& insn, Instruction& out);

}  // namespace engine::llir::arm64
