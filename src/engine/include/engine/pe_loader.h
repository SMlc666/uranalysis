#pragma once

#include <string>
#include <vector>

#include "engine/binary_format.h"
#include "engine/image.h"

namespace engine {

bool load_pe(const std::string& path,
             BinaryInfo& info,
             std::vector<BinarySegment>& segments,
             std::string& error);

bool load_pe_image_with_symbols(const std::string& path,
                                BinaryInfo& info,
                                std::vector<BinarySegment>& segments,
                                std::vector<BinarySection>& sections,
                                std::vector<BinarySymbol>& symbols,
                                LoadedImage& image,
                                std::string& error);

bool load_pe_image_with_symbols_and_relocations(const std::string& path,
                                                BinaryInfo& info,
                                                std::vector<BinarySegment>& segments,
                                                std::vector<BinarySection>& sections,
                                                std::vector<BinarySymbol>& symbols,
                                                std::vector<BinaryRelocation>& relocations,
                                                LoadedImage& image,
                                                std::string& error);

bool load_pe_image(const std::string& path,
                   BinaryInfo& info,
                   std::vector<BinarySegment>& segments,
                   std::vector<BinarySection>& sections,
                   LoadedImage& image,
                   std::string& error);

}  // namespace engine
