#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "engine/image.h"
#include "engine/binary_format.h"

namespace engine::rtti {

enum class Abi {
    kUnknown,
    kItanium,
    kMsvc,
};

struct TypeInfo {
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t name_address = 0;
    std::uint64_t vtable_address = 0;
    Abi abi = Abi::kUnknown;
    std::uint64_t descriptor_address = 0;
};

struct VtableInfo {
    std::uint64_t address = 0;
    std::string type_name;
    std::vector<std::uint64_t> entries;
};

class RttiCatalog {
public:
    void reset();
    void discover(const std::vector<BinarySection>& sections,
                  const std::vector<BinarySegment>& segments,
                  const LoadedImage& image,
                  const BinaryInfo& binary_info);

    const std::vector<TypeInfo>& types() const;
    const std::vector<VtableInfo>& vtables() const;
    const TypeInfo* find_typeinfo(std::uint64_t address) const;
    const VtableInfo* find_vtable(std::uint64_t address) const;

private:
    std::vector<TypeInfo> types_;
    std::unordered_map<std::uint64_t, std::size_t> typeinfo_index_;
    std::vector<VtableInfo> vtables_;
    std::unordered_map<std::uint64_t, std::size_t> vtable_index_;
};

}  // namespace engine::rtti
