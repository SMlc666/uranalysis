#pragma once

#include "engine/hlil.h"
#include <vector>
#include <string>

namespace engine::hlil {

// Abstract base class for all HLIL optimization passes
class HlilPass {
public:
    virtual ~HlilPass() = default;

    // Returns true if the pass modified the function
    virtual bool run(Function& function) = 0;

    // Pass name for debugging/logging
    virtual const char* name() const = 0;
};

}  // namespace engine::hlil
