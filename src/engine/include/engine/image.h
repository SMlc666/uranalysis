#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace engine {

struct LoadedSegment {
    std::uint64_t vaddr = 0;
    std::uint64_t memsz = 0;
    std::vector<std::uint8_t> data;
};

struct LoadedImage {
    std::vector<LoadedSegment> segments;

    bool read_bytes(std::uint64_t vaddr, std::size_t size, std::vector<std::uint8_t>& out) const;
    bool write_bytes(std::uint64_t vaddr, const std::vector<std::uint8_t>& data);
};

}  // namespace engine
