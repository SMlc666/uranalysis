#pragma once

#include <string>

#include "engine/hlil.h"
#include "engine/mlil.h"

namespace engine::hlil {

bool build_hlil_from_mlil(const mlil::Function& mlil_function,
                          Function& hlil_function,
                          std::string& error);

}  // namespace engine::hlil

