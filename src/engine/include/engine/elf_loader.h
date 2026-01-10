#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "engine/binary_format.h"
#include "engine/image.h"

namespace engine {

struct ElfInfo {
    bool is_64 = false;
    bool little_endian = false;
    std::uint64_t entry = 0;
    std::uint64_t image_base = 0;
    std::uint16_t ph_num = 0;
    std::uint16_t sh_num = 0;
    BinaryMachine machine = BinaryMachine::kUnknown;
};

struct ElfSegment {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz = 0;
};

struct ElfSection {
    std::string name;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t addr = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
};

struct ElfSymbol {
    std::string name;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t info = 0;
    std::uint8_t other = 0;
    std::uint16_t shndx = 0;
};

struct ElfRelocation {
    std::uint64_t offset = 0;
    std::uint64_t info = 0;
    std::int64_t addend = 0;
    std::uint32_t type = 0;
    std::uint32_t sym = 0;
    std::uint64_t symbol_value = 0;
    std::string symbol_name;
    std::string target_section;
};

bool load_elf(const std::string& path, ElfInfo& info, std::vector<ElfSegment>& segments, std::string& error);

bool load_elf_image_with_symbols(const std::string& path,
                                 ElfInfo& info,
                                 std::vector<ElfSegment>& segments,
                                 std::vector<ElfSection>& sections,
                                 std::vector<ElfSymbol>& symbols,
                                 LoadedImage& image,
                                 std::string& error);

bool load_elf_image_with_symbols_and_relocations(const std::string& path,
                                                 ElfInfo& info,
                                                 std::vector<ElfSegment>& segments,
                                                 std::vector<ElfSection>& sections,
                                                 std::vector<ElfSymbol>& symbols,
                                                 std::vector<ElfRelocation>& relocations,
                                                 LoadedImage& image,
                                                 std::string& error);

bool load_elf_image(const std::string& path,
                    ElfInfo& info,
                    std::vector<ElfSegment>& segments,
                    std::vector<ElfSection>& sections,
                    LoadedImage& image,
                    std::string& error);

}  // namespace engine
