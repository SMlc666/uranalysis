#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "engine/image.h"

namespace engine {

struct DisasmLine {
    std::uint64_t address = 0;
    std::uint32_t size = 0;
    std::string text;
};

bool disasm_arm64(const LoadedImage& image,
                  std::uint64_t start,
                  std::size_t max_bytes,
                  std::size_t max_instructions,
                  std::vector<DisasmLine>& out,
                  std::string& error);

bool disasm_x86_64(const LoadedImage& image,
                   std::uint64_t start,
                   std::size_t max_bytes,
                   std::size_t max_instructions,
                   std::vector<DisasmLine>& out,
                   std::string& error);

}  // namespace engine
