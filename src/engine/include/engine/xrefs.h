#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "engine/binary_format.h"
#include "engine/image.h"

namespace engine::llir {
struct Function;
}

namespace engine::xrefs {

enum class XrefKind {
    kDataPointer,
    kCodeCall,
    kCodeJump,
    kCodeCallIndirect,
    kCodeJumpIndirect
};

struct XrefEntry {
    std::uint64_t source = 0;
    std::uint64_t target = 0;
    XrefKind kind = XrefKind::kDataPointer;
};

bool find_xrefs_to_address(const LoadedImage& image,
                           std::uint64_t target,
                           std::size_t max_results,
                           std::vector<XrefEntry>& out);
bool find_xrefs_to_address(const LoadedImage& image,
                           const std::vector<BinaryRelocation>& relocations,
                           const std::vector<BinarySegment>& segments,
                           std::uint64_t target,
                           std::size_t max_results,
                           std::vector<XrefEntry>& out);

void collect_code_xrefs(const LoadedImage& image, const llir::Function& function, std::vector<XrefEntry>& out);
void collect_code_xrefs(const LoadedImage& image,
                        const std::vector<llir::Function>& functions,
                        std::vector<XrefEntry>& out);
void collect_code_xrefs(const LoadedImage& image,
                        const std::vector<BinarySegment>& segments,
                        const llir::Function& function,
                        std::vector<XrefEntry>& out);
void collect_code_xrefs(const LoadedImage& image,
                        const std::vector<BinarySegment>& segments,
                        const std::vector<llir::Function>& functions,
                        std::vector<XrefEntry>& out);

}  // namespace engine::xrefs
