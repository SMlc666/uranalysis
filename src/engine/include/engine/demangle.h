#pragma once

#include <string>

namespace engine::demangle {

// Best-effort demangle; returns input if no demangler is available.
std::string symbol(const std::string& name);

}  // namespace engine::demangle
