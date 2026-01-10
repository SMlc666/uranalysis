#include "engine/demangle.h"

#include "llvm/Demangle/Demangle.h"

#include <string>

namespace engine::demangle {

std::string symbol(const std::string& name) {
    if (name.empty()) {
        return name;
    }
    return llvm::demangle(name);
}

}  // namespace engine::demangle
