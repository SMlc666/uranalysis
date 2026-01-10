#include "engine/image.h"

namespace engine {

bool LoadedImage::read_bytes(std::uint64_t vaddr, std::size_t size, std::vector<std::uint8_t>& out) const {
    out.clear();
    if (size == 0) {
        return true;
    }

    for (const auto& seg : segments) {
        if (vaddr < seg.vaddr) {
            continue;
        }
        const std::uint64_t offset = vaddr - seg.vaddr;
        if (offset + size > seg.memsz) {
            continue;
        }
        if (offset + size > seg.data.size()) {
            return false;
        }
        out.insert(out.end(), seg.data.begin() + static_cast<std::ptrdiff_t>(offset),
                   seg.data.begin() + static_cast<std::ptrdiff_t>(offset + size));
        return true;
    }

    return false;
}

bool LoadedImage::write_bytes(std::uint64_t vaddr, const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        return true;
    }
    for (auto& seg : segments) {
        if (vaddr < seg.vaddr) {
            continue;
        }
        const std::uint64_t offset = vaddr - seg.vaddr;
        if (offset + data.size() > seg.memsz) {
            continue;
        }
        if (offset + data.size() > seg.data.size()) {
            return false;
        }
        std::copy(data.begin(), data.end(), seg.data.begin() + static_cast<std::ptrdiff_t>(offset));
        return true;
    }
    return false;
}

}  // namespace engine
