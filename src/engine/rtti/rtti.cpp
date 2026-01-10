#include "engine/rtti.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

constexpr std::size_t kMaxTypeName = 256;
constexpr std::size_t kMaxVtableEntries = 128;
constexpr std::int64_t kMaxOffsetAbs = 0x4000;
constexpr std::uint64_t kShfAlloc = 0x2;
constexpr std::uint64_t kShfExecInstr = 0x4;
constexpr std::uint32_t kPfExec = 0x1;

bool read_pointer(const engine::LoadedImage& image,
                  std::uint64_t addr,
                  std::size_t pointer_size,
                  bool little_endian,
                  std::uint64_t& out) {
    if (pointer_size != sizeof(std::uint32_t) && pointer_size != sizeof(std::uint64_t)) {
        return false;
    }
    std::vector<std::uint8_t> buffer;
    if (!image.read_bytes(addr, pointer_size, buffer) || buffer.size() != pointer_size) {
        return false;
    }
    out = 0;
    if (little_endian) {
        for (std::size_t i = 0; i < pointer_size; ++i) {
            out |= static_cast<std::uint64_t>(buffer[i]) << (i * 8);
        }
    } else {
        for (std::size_t i = 0; i < pointer_size; ++i) {
            out = (out << 8) | buffer[i];
        }
    }
    if (pointer_size == sizeof(std::uint32_t)) {
        out = static_cast<std::uint32_t>(out);
    }
    return true;
}

bool read_u32(const engine::LoadedImage& image,
              std::uint64_t addr,
              bool little_endian,
              std::uint32_t& out) {
    std::vector<std::uint8_t> buffer;
    if (!image.read_bytes(addr, sizeof(std::uint32_t), buffer) || buffer.size() != sizeof(std::uint32_t)) {
        return false;
    }
    if (little_endian) {
        out = static_cast<std::uint32_t>(buffer[0]) |
              (static_cast<std::uint32_t>(buffer[1]) << 8) |
              (static_cast<std::uint32_t>(buffer[2]) << 16) |
              (static_cast<std::uint32_t>(buffer[3]) << 24);
    } else {
        out = static_cast<std::uint32_t>(buffer[3]) |
              (static_cast<std::uint32_t>(buffer[2]) << 8) |
              (static_cast<std::uint32_t>(buffer[1]) << 16) |
              (static_cast<std::uint32_t>(buffer[0]) << 24);
    }
    return true;
}

std::int64_t sign_extend_pointer(std::uint64_t value, std::size_t pointer_size) {
    if (pointer_size == sizeof(std::uint32_t)) {
        return static_cast<std::int32_t>(value);
    }
    return static_cast<std::int64_t>(value);
}

bool address_in_any_segment(const std::vector<engine::BinarySegment>& segments, std::uint64_t addr) {
    for (const auto& segment : segments) {
        if (addr >= segment.vaddr && addr < (segment.vaddr + segment.memsz)) {
            return true;
        }
    }
    return false;
}

bool address_in_executable_segment(const std::vector<engine::BinarySegment>& segments, std::uint64_t addr) {
    for (const auto& segment : segments) {
        if (addr >= segment.vaddr && addr < (segment.vaddr + segment.memsz)) {
            return (segment.flags & kPfExec) != 0;
        }
    }
    return false;
}

bool section_is_data(const engine::BinarySection& section) {
    return (section.flags & kShfAlloc) != 0 && (section.flags & kShfExecInstr) == 0;
}

bool read_cstring(const engine::LoadedImage& image,
                  std::uint64_t addr,
                  std::string& out,
                  std::size_t max_len = kMaxTypeName) {
    out.clear();
    std::uint64_t current = addr;
    while (out.size() < max_len) {
        const std::size_t chunk = std::min<std::size_t>(32, max_len - out.size());
        std::vector<std::uint8_t> buffer;
        if (!image.read_bytes(current, chunk, buffer) || buffer.empty()) {
            return false;
        }
        for (std::size_t i = 0; i < buffer.size(); ++i) {
            const char c = static_cast<char>(buffer[i]);
            if (c == '\0') {
                return true;
            }
            out.push_back(c);
        }
        current += buffer.size();
        if (buffer.size() < chunk) {
            return false;
        }
    }
    return false;
}

struct TypeParseResult {
    std::string name;
    std::uint64_t name_address = 0;
    std::uint64_t descriptor_address = 0;
    engine::rtti::Abi abi = engine::rtti::Abi::kUnknown;
};

bool parse_gcc_typeinfo(const engine::LoadedImage& image,
                        std::uint64_t typeinfo_addr,
                        std::size_t pointer_size,
                        bool little_endian,
                        TypeParseResult& out) {
    if (typeinfo_addr == 0) {
        return false;
    }
    std::uint64_t name_ptr = 0;
    if (!read_pointer(image, typeinfo_addr + pointer_size, pointer_size, little_endian, name_ptr)) {
        return false;
    }
    std::string name;
    if (!read_cstring(image, name_ptr, name)) {
        return false;
    }
    out.name = std::move(name);
    out.name_address = name_ptr;
    out.descriptor_address = typeinfo_addr;
    out.abi = engine::rtti::Abi::kItanium;
    return true;
}

bool parse_msvc_typeinfo(const engine::LoadedImage& image,
                         std::uint64_t locator_addr,
                         std::size_t pointer_size,
                         bool little_endian,
                         const std::vector<engine::BinarySegment>& segments,
                         TypeParseResult& out) {
    if (locator_addr == 0) {
        return false;
    }
    std::uint32_t signature = 0;
    if (!read_u32(image, locator_addr, little_endian, signature)) {
        return false;
    }
    std::uint32_t offset = 0;
    std::uint32_t cd_offset = 0;
    if (!read_u32(image, locator_addr + 4, little_endian, offset)) {
        return false;
    }
    if (!read_u32(image, locator_addr + 8, little_endian, cd_offset)) {
        return false;
    }
    (void)signature;
    (void)offset;
    (void)cd_offset;
    const std::array<std::size_t, 2> descriptor_offsets = {12, 16};
    for (std::size_t descriptor_offset : descriptor_offsets) {
        std::uint64_t descriptor = 0;
        if (!read_pointer(image, locator_addr + descriptor_offset, pointer_size, little_endian, descriptor)) {
            continue;
        }
        if (descriptor == 0 || !address_in_any_segment(segments, descriptor)) {
            continue;
        }
        std::uint64_t name_addr = descriptor + 2 * pointer_size;
        std::string name;
        if (!read_cstring(image, name_addr, name)) {
            continue;
        }
        out.name = std::move(name);
        out.name_address = name_addr;
        out.descriptor_address = descriptor;
        out.abi = engine::rtti::Abi::kMsvc;
        return true;
    }
    return false;
}

bool try_scan_itanium_candidate(const engine::LoadedImage& image,
                                std::uint64_t entry_addr,
                                std::size_t pointer_size,
                                bool little_endian,
                                const std::vector<engine::BinarySegment>& segments,
                                TypeParseResult& out,
                                std::uint64_t& typeinfo_ptr,
                                std::size_t& func_offset) {
    std::uint64_t offset_value = 0;
    if (!read_pointer(image, entry_addr, pointer_size, little_endian, offset_value)) {
        return false;
    }
    const std::int64_t signed_offset = sign_extend_pointer(offset_value, pointer_size);
    if (signed_offset < -kMaxOffsetAbs || signed_offset > kMaxOffsetAbs) {
        return false;
    }
    typeinfo_ptr = 0;
    if (!read_pointer(image, entry_addr + pointer_size, pointer_size, little_endian, typeinfo_ptr)) {
        return false;
    }
    if (typeinfo_ptr == 0 || !address_in_any_segment(segments, typeinfo_ptr)) {
        return false;
    }
    if (!parse_gcc_typeinfo(image, typeinfo_ptr, pointer_size, little_endian, out)) {
        return false;
    }
    func_offset = 2 * pointer_size;
    return true;
}

bool try_scan_msvc_candidate(const engine::LoadedImage& image,
                             std::uint64_t entry_addr,
                             std::size_t pointer_size,
                             bool little_endian,
                             const std::vector<engine::BinarySegment>& segments,
                             TypeParseResult& out,
                             std::uint64_t& typeinfo_ptr,
                             std::size_t& func_offset) {
    typeinfo_ptr = 0;
    if (!read_pointer(image, entry_addr, pointer_size, little_endian, typeinfo_ptr)) {
        return false;
    }
    if (typeinfo_ptr == 0 || !address_in_any_segment(segments, typeinfo_ptr)) {
        return false;
    }
    if (!parse_msvc_typeinfo(image, typeinfo_ptr, pointer_size, little_endian, segments, out)) {
        return false;
    }
    func_offset = pointer_size;
    return true;
}

void scan_rtti_sections(const std::vector<engine::BinarySection>& sections,
                        const std::vector<engine::BinarySegment>& segments,
                        const engine::LoadedImage& image,
                        const engine::BinaryInfo& binary_info,
                        std::vector<engine::rtti::TypeInfo>& types,
                        std::unordered_map<std::uint64_t, std::size_t>& typeinfo_index,
                        std::vector<engine::rtti::VtableInfo>& vtables,
                        std::unordered_map<std::uint64_t, std::size_t>& vtable_index) {
    const std::size_t pointer_size = binary_info.is_64 ? sizeof(std::uint64_t) : sizeof(std::uint32_t);
    if (pointer_size != sizeof(std::uint32_t) && pointer_size != sizeof(std::uint64_t)) {
        return;
    }
    const bool little_endian = binary_info.little_endian;
    std::unordered_set<std::uint64_t> seen;
    for (const auto& section : sections) {
        if (!section_is_data(section) || section.size < pointer_size) {
            continue;
        }
        for (std::size_t offset = 0; offset + pointer_size <= section.size; offset += pointer_size) {
            const std::uint64_t entry_addr = section.addr + offset;
            TypeParseResult parsed;
            std::uint64_t typeinfo_ptr = 0;
            std::size_t func_offset = 0;
            bool is_candidate = try_scan_itanium_candidate(image,
                                                          entry_addr,
                                                          pointer_size,
                                                          little_endian,
                                                          segments,
                                                          parsed,
                                                          typeinfo_ptr,
                                                          func_offset) ||
                                try_scan_msvc_candidate(image,
                                                        entry_addr,
                                                        pointer_size,
                                                        little_endian,
                                                        segments,
                                                        parsed,
                                                        typeinfo_ptr,
                                                        func_offset);
            if (!is_candidate) {
                continue;
            }
            if (seen.find(entry_addr) != seen.end()) {
                continue;
            }
            std::vector<std::uint64_t> functions;
            std::uint64_t func_addr = entry_addr + func_offset;
            for (std::size_t i = 0; i < kMaxVtableEntries; ++i) {
                std::uint64_t candidate = 0;
                if (!read_pointer(image, func_addr, pointer_size, little_endian, candidate)) {
                    break;
                }
                if (candidate == 0) {
                    break;
                }
                if (!address_in_executable_segment(segments, candidate)) {
                    break;
                }
                functions.push_back(candidate);
                func_addr += pointer_size;
            }
            if (functions.empty()) {
                continue;
            }
            seen.insert(entry_addr);
            std::size_t type_index = 0;
            const auto it = typeinfo_index.find(typeinfo_ptr);
            if (it == typeinfo_index.end()) {
                type_index = types.size();
                engine::rtti::TypeInfo info;
                info.name = std::move(parsed.name);
                info.name_address = parsed.name_address;
                info.address = typeinfo_ptr;
                info.vtable_address = entry_addr;
                info.abi = parsed.abi;
                info.descriptor_address = parsed.descriptor_address;
                typeinfo_index[typeinfo_ptr] = type_index;
                types.push_back(std::move(info));
            } else {
                type_index = it->second;
            }
            engine::rtti::VtableInfo vt;
            vt.address = entry_addr;
            vt.type_name = types[type_index].name;
            vt.entries = std::move(functions);
            vtable_index[entry_addr] = vtables.size();
            vtables.push_back(std::move(vt));
        }
    }
}

}  // namespace

namespace engine::rtti {

void RttiCatalog::reset() {
    types_.clear();
    typeinfo_index_.clear();
    vtables_.clear();
    vtable_index_.clear();
}

void RttiCatalog::discover(const std::vector<BinarySection>& sections,
                           const std::vector<BinarySegment>& segments,
                           const LoadedImage& image,
                           const BinaryInfo& binary_info) {
    reset();
    scan_rtti_sections(sections, segments, image, binary_info, types_, typeinfo_index_, vtables_, vtable_index_);
}

const std::vector<TypeInfo>& RttiCatalog::types() const {
    return types_;
}

const std::vector<VtableInfo>& RttiCatalog::vtables() const {
    return vtables_;
}

const TypeInfo* RttiCatalog::find_typeinfo(std::uint64_t address) const {
    const auto it = typeinfo_index_.find(address);
    if (it == typeinfo_index_.end()) {
        return nullptr;
    }
    return &types_[it->second];
}

const VtableInfo* RttiCatalog::find_vtable(std::uint64_t address) const {
    const auto it = vtable_index_.find(address);
    if (it == vtable_index_.end()) {
        return nullptr;
    }
    return &vtables_[it->second];
}

}  // namespace engine::rtti
