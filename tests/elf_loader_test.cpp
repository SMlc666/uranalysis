#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "engine/elf_loader.h"
#include "test_helpers.h"

namespace {

struct Elf64Header {
    std::uint8_t e_ident[16];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint64_t e_entry;
    std::uint64_t e_phoff;
    std::uint64_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
};

static_assert(sizeof(Elf64Header) == 64, "ELF header size must match ELF64");

std::vector<std::uint8_t> make_header(std::uint8_t elf_class,
                                      std::uint8_t data,
                                      std::uint64_t phoff,
                                      std::uint16_t phentsize,
                                      std::uint16_t phnum) {
    Elf64Header header = {};
    header.e_ident[0] = 0x7f;
    header.e_ident[1] = 'E';
    header.e_ident[2] = 'L';
    header.e_ident[3] = 'F';
    header.e_ident[4] = elf_class;
    header.e_ident[5] = data;
    header.e_ehsize = static_cast<std::uint16_t>(sizeof(Elf64Header));
    header.e_phoff = phoff;
    header.e_phentsize = phentsize;
    header.e_phnum = phnum;
    std::vector<std::uint8_t> bytes(sizeof(header));
    std::memcpy(bytes.data(), &header, sizeof(header));
    return bytes;
}

}  // namespace

TEST_CASE("ELF loader handles bad headers", "[elf]") {
    engine::ElfInfo info;
    std::vector<engine::ElfSegment> segments;
    std::string error;

    {
        std::vector<std::uint8_t> bytes(sizeof(Elf64Header), 0);
        test_helpers::ScopedTempFile file("elf_bad_magic", bytes);
        bool ok = engine::load_elf(file.path().string(), info, segments, error);
        REQUIRE_FALSE(ok);
        CHECK(error.find("ELF") != std::string::npos);
    }

    {
        auto bytes = make_header(1, 1, 0, 0, 0);
        test_helpers::ScopedTempFile file("elf_class32", bytes);
        bool ok = engine::load_elf(file.path().string(), info, segments, error);
        REQUIRE_FALSE(ok);
        CHECK(error.find("ELF64") != std::string::npos);
    }

    {
        auto bytes = make_header(2, 2, 0, 0, 0);
        test_helpers::ScopedTempFile file("elf_big_endian", bytes);
        bool ok = engine::load_elf(file.path().string(), info, segments, error);
        REQUIRE_FALSE(ok);
        CHECK(error.find("little-endian") != std::string::npos);
    }

    {
        auto bytes = make_header(2, 1, sizeof(Elf64Header), 1, 1);
        test_helpers::ScopedTempFile file("elf_bad_phentsize", bytes);
        bool ok = engine::load_elf(file.path().string(), info, segments, error);
        REQUIRE_FALSE(ok);
        CHECK(error.find("program header entry size") != std::string::npos);
    }
}

TEST_CASE("ELF loader reads sample binaries", "[elf]") {
    const auto sample = test_helpers::find_sample_path("tests/samples/arm64/binaryO0Opt.elf");
    REQUIRE(sample.has_value());

    engine::ElfInfo info;
    std::vector<engine::ElfSegment> segments;
    std::string error;
    REQUIRE(engine::load_elf(sample->string(), info, segments, error));

    CHECK(info.is_64);
    CHECK(info.little_endian);
    CHECK(info.entry != 0);
    CHECK_FALSE(segments.empty());
}
