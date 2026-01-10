#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace engine {

enum class BinaryFormat {
    kUnknown,
    kElf,
    kPe
};

enum class BinaryMachine {
    kUnknown,
    kAarch64,
    kX86,
    kX86_64
};

struct BinaryInfo {
    BinaryFormat format = BinaryFormat::kUnknown;
    BinaryMachine machine = BinaryMachine::kUnknown;
    bool is_64 = false;
    bool little_endian = false;
    std::uint64_t entry = 0;
    std::uint64_t image_base = 0;
    std::uint16_t ph_num = 0;
    std::uint16_t sh_num = 0;
};

struct BinarySegment {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz = 0;
};

struct BinarySection {
    std::string name;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t addr = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
};

struct BinarySymbol {
    std::string name;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t info = 0;
    std::uint8_t other = 0;
    std::uint16_t shndx = 0;
};

struct BinaryRelocation {
    std::uint64_t offset = 0;
    std::uint64_t info = 0;
    std::int64_t addend = 0;
    std::uint32_t type = 0;
    std::uint32_t sym = 0;
    std::uint64_t symbol_value = 0;
    std::string symbol_name;
    std::string target_section;
};

}  // namespace engine
