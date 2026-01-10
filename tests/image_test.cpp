#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

#include "engine/image.h"

TEST_CASE("LoadedImage read/write respects segment bounds", "[image]") {
    engine::LoadedImage image;
    engine::LoadedSegment seg;
    seg.vaddr = 0x1000;
    seg.memsz = 16;
    seg.data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    image.segments.push_back(seg);

    std::vector<std::uint8_t> out;
    REQUIRE(image.read_bytes(0x1000, 4, out));
    CHECK(out == std::vector<std::uint8_t>({0, 1, 2, 3}));

    out.clear();
    CHECK(image.read_bytes(0x1004, 0, out));
    CHECK(out.empty());

    out.clear();
    CHECK_FALSE(image.read_bytes(0x100e, 4, out));
    CHECK(out.empty());

    engine::LoadedImage short_image;
    engine::LoadedSegment short_seg;
    short_seg.vaddr = 0x2000;
    short_seg.memsz = 16;
    short_seg.data = {1, 2, 3, 4, 5, 6, 7, 8};
    short_image.segments.push_back(short_seg);
    CHECK_FALSE(short_image.read_bytes(0x2006, 4, out));

    std::vector<std::uint8_t> patch = {42, 43, 44};
    CHECK(image.write_bytes(0x1002, patch));
    REQUIRE(image.read_bytes(0x1000, 5, out));
    CHECK(out == std::vector<std::uint8_t>({0, 1, 42, 43, 44}));

    CHECK_FALSE(image.write_bytes(0x100e, patch));
}
