#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "engine/binary_format.h"
#include "engine/image.h"
#include "engine/symbols.h"

namespace engine::strings {

struct StringEntry {
    std::string text;
    std::uint64_t address = 0;
    std::size_t length = 0;
    std::string section_name;
    bool utf8 = false;
    std::string symbol_name;
};

class StringCatalog {
public:
    void reset();
    void discover(const std::vector<BinarySection>& sections, const LoadedImage& image, std::size_t min_length = 4);
    void attach_symbols(const symbols::SymbolTable& symbols);

    const std::vector<StringEntry>& entries() const;

private:
    std::vector<StringEntry> entries_;
};

}  // namespace engine::strings
