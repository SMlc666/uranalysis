#pragma once

#include <string>
#include <vector>

#include "engine/decompiler.h"

namespace engine::decompiler::types {

bool lookup_signature(const std::string& name,
                      std::vector<VarDecl>& params,
                      std::string& return_type);

}  // namespace engine::decompiler::types
