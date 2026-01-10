#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "engine/pe_loader.h"
#include "test_helpers.h"

namespace {

constexpr std::uint16_t kMachineX86 = 0x14c;
constexpr std::uint16_t kMachineX64 = 0x8664;
constexpr std::uint32_t kPeSignature = 0x00004550;
constexpr std::uint16_t kPeMagic32 = 0x10b;
constexpr std::uint16_t kPeMagic64 = 0x20b;

constexpr std::uint32_t kImageScnMemRead = 0x40000000;
constexpr std::uint32_t kImageScnMemWrite = 0x80000000;

struct ByteWriter {
    std::vector<std::uint8_t> data;

    void ensure(std::size_t size) {
        if (data.size() < size) {
            data.resize(size, 0);
        }
    }

    void write_u16(std::size_t offset, std::uint16_t value) {
        ensure(offset + 2);
        data[offset] = static_cast<std::uint8_t>(value & 0xff);
        data[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    }

    void write_u32(std::size_t offset, std::uint32_t value) {
        ensure(offset + 4);
        data[offset] = static_cast<std::uint8_t>(value & 0xff);
        data[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
        data[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
        data[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
    }

    void write_u64(std::size_t offset, std::uint64_t value) {
        ensure(offset + 8);
        for (std::size_t i = 0; i < 8; ++i) {
            data[offset + i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
        }
    }

    void write_bytes(std::size_t offset, const std::string& text, bool with_null = true) {
        ensure(offset + text.size() + (with_null ? 1 : 0));
        std::memcpy(data.data() + offset, text.data(), text.size());
        if (with_null) {
            data[offset + text.size()] = 0;
        }
    }
};

std::vector<std::uint8_t> make_minimal_pe32() {
    ByteWriter w;
    const std::size_t dos_offset = 0;
    const std::size_t nt_offset = 0x80;
    const std::size_t file_header_offset = nt_offset + 4;
    const std::size_t optional_offset = file_header_offset + 20;
    const std::size_t section_offset = optional_offset + 0xe0;

    // DOS header
    w.write_u16(dos_offset, 0x5a4d);
    w.write_u32(dos_offset + 0x3c, static_cast<std::uint32_t>(nt_offset));

    // PE signature
    w.write_u32(nt_offset, kPeSignature);

    // File header
    w.write_u16(file_header_offset + 0, kMachineX86);
    w.write_u16(file_header_offset + 2, 1); // sections
    w.write_u16(file_header_offset + 16, 0xe0); // optional header size

    // Optional header
    w.write_u16(optional_offset + 0, kPeMagic32);
    w.write_u32(optional_offset + 16, 0x1000); // entry
    w.write_u32(optional_offset + 28, 0x400000); // image base
    w.write_u32(optional_offset + 56, 0x2000); // size of image
    w.write_u32(optional_offset + 60, 0x200); // size of headers
    w.write_u32(optional_offset + 92, 16); // number of RVA and sizes

    const std::size_t dir_offset = optional_offset + 96;
    // Export directory (index 0)
    w.write_u32(dir_offset + 0, 0x1800);
    w.write_u32(dir_offset + 4, 0x28);
    // Import directory (index 1)
    w.write_u32(dir_offset + 8, 0x1900);
    w.write_u32(dir_offset + 12, 0x28);
    // Base reloc (index 5)
    w.write_u32(dir_offset + 5 * 8 + 0, 0x1a00);
    w.write_u32(dir_offset + 5 * 8 + 4, 0x0c);

    // Section header (.rdata)
    const std::string sec_name = ".rdata";
    w.ensure(section_offset + 40);
    std::memcpy(w.data.data() + section_offset, sec_name.c_str(), sec_name.size());
    w.write_u32(section_offset + 8, 0x1000); // virtual size
    w.write_u32(section_offset + 12, 0x1000); // virtual address
    w.write_u32(section_offset + 16, 0x1000); // raw size
    w.write_u32(section_offset + 20, 0x200); // raw ptr
    w.write_u32(section_offset + 36, kImageScnMemRead | kImageScnMemWrite);

    // Export directory data at RVA 0x1800 (file offset 0x200 + 0x800 = 0xa00)
    const std::size_t export_offset = 0x200 + 0x800;
    w.write_u32(export_offset + 0, 0); // characteristics
    w.write_u32(export_offset + 12, 0x1840); // name
    w.write_u32(export_offset + 16, 1); // base
    w.write_u32(export_offset + 20, 1); // number of functions
    w.write_u32(export_offset + 24, 1); // number of names
    w.write_u32(export_offset + 28, 0x1850); // address_of_functions
    w.write_u32(export_offset + 32, 0x1860); // address_of_names
    w.write_u32(export_offset + 36, 0x1870); // address_of_name_ordinals
    w.write_bytes(0x200 + 0x840, "testdll", true);
    w.write_u32(0x200 + 0x850, 0x1100); // function rva
    w.write_u32(0x200 + 0x860, 0x1880); // name rva
    w.write_u16(0x200 + 0x870, 0); // ordinal index
    w.write_bytes(0x200 + 0x880, "TestExport", true);

    // Import descriptor at RVA 0x1900 (file offset 0x200 + 0x900 = 0xb00)
    const std::size_t import_offset = 0x200 + 0x900;
    w.write_u32(import_offset + 0, 0x1920); // original first thunk
    w.write_u32(import_offset + 12, 0x1940); // name
    w.write_u32(import_offset + 16, 0x1960); // first thunk
    // null descriptor follows
    w.write_u32(import_offset + 20, 0);

    w.write_bytes(0x200 + 0x940, "KERNEL32.dll", true);
    w.write_u32(0x200 + 0x920, 0x1980); // thunk: import by name
    w.write_u32(0x200 + 0x924, 0);
    w.write_bytes(0x200 + 0x980 + 2, "ExitProcess", true);
    w.write_u32(0x200 + 0x960, 0);

    // Base relocation block at RVA 0x1a00 (file offset 0x200 + 0xa00 = 0xc00)
    const std::size_t reloc_offset = 0x200 + 0xa00;
    w.write_u32(reloc_offset + 0, 0x1000);
    w.write_u32(reloc_offset + 4, 0x0c);
    w.write_u16(reloc_offset + 8, static_cast<std::uint16_t>((3u << 12) | 0x034));
    w.write_u16(reloc_offset + 10, 0);

    // Fill reloc target in section (RVA 0x1034 -> file offset 0x200 + 0x34 = 0x234)
    w.write_u32(0x200 + 0x34, 0x401234);

    return w.data;
}

std::vector<std::uint8_t> make_minimal_pe64() {
    ByteWriter w;
    const std::size_t dos_offset = 0;
    const std::size_t nt_offset = 0x80;
    const std::size_t file_header_offset = nt_offset + 4;
    const std::size_t optional_offset = file_header_offset + 20;
    const std::size_t section_offset = optional_offset + 0xf0;

    // DOS header
    w.write_u16(dos_offset, 0x5a4d);
    w.write_u32(dos_offset + 0x3c, static_cast<std::uint32_t>(nt_offset));

    // PE signature
    w.write_u32(nt_offset, kPeSignature);

    // File header
    w.write_u16(file_header_offset + 0, kMachineX64);
    w.write_u16(file_header_offset + 2, 1); // sections
    w.write_u16(file_header_offset + 16, 0xf0); // optional header size

    // Optional header (PE32+)
    w.write_u16(optional_offset + 0, kPeMagic64);
    w.write_u32(optional_offset + 16, 0x1000); // entry
    w.write_u64(optional_offset + 24, 0x140000000ull); // image base
    w.write_u32(optional_offset + 56, 0x2000); // size of image
    w.write_u32(optional_offset + 60, 0x200); // size of headers
    w.write_u32(optional_offset + 108, 16); // number of RVA and sizes

    const std::size_t dir_offset = optional_offset + 112;
    // Export directory (index 0)
    w.write_u32(dir_offset + 0, 0x1800);
    w.write_u32(dir_offset + 4, 0x28);
    // Import directory (index 1)
    w.write_u32(dir_offset + 8, 0x1900);
    w.write_u32(dir_offset + 12, 0x28);
    // Base reloc (index 5)
    w.write_u32(dir_offset + 5 * 8 + 0, 0x1a00);
    w.write_u32(dir_offset + 5 * 8 + 4, 0x0c);

    // Section header (.rdata)
    const std::string sec_name = ".rdata";
    w.ensure(section_offset + 40);
    std::memcpy(w.data.data() + section_offset, sec_name.c_str(), sec_name.size());
    w.write_u32(section_offset + 8, 0x1000); // virtual size
    w.write_u32(section_offset + 12, 0x1000); // virtual address
    w.write_u32(section_offset + 16, 0x1000); // raw size
    w.write_u32(section_offset + 20, 0x200); // raw ptr
    w.write_u32(section_offset + 36, kImageScnMemRead | kImageScnMemWrite);

    // Export directory data at RVA 0x1800 (file offset 0x200 + 0x800 = 0xa00)
    const std::size_t export_offset = 0x200 + 0x800;
    w.write_u32(export_offset + 0, 0);
    w.write_u32(export_offset + 12, 0x1840); // name
    w.write_u32(export_offset + 16, 1); // base
    w.write_u32(export_offset + 20, 1); // number of functions
    w.write_u32(export_offset + 24, 1); // number of names
    w.write_u32(export_offset + 28, 0x1850); // address_of_functions
    w.write_u32(export_offset + 32, 0x1860); // address_of_names
    w.write_u32(export_offset + 36, 0x1870); // address_of_name_ordinals
    w.write_bytes(0x200 + 0x840, "testdll64", true);
    w.write_u32(0x200 + 0x850, 0x1100); // function rva
    w.write_u32(0x200 + 0x860, 0x1880); // name rva
    w.write_u16(0x200 + 0x870, 0);
    w.write_bytes(0x200 + 0x880, "TestExport64", true);

    // Import descriptor at RVA 0x1900 (file offset 0x200 + 0x900 = 0xb00)
    const std::size_t import_offset = 0x200 + 0x900;
    w.write_u32(import_offset + 0, 0x1920); // original first thunk
    w.write_u32(import_offset + 12, 0x1940); // name
    w.write_u32(import_offset + 16, 0x1960); // first thunk
    w.write_u32(import_offset + 20, 0);

    w.write_bytes(0x200 + 0x940, "KERNEL32.dll", true);
    w.write_u64(0x200 + 0x920, 0x1980); // thunk: import by name
    w.write_u64(0x200 + 0x928, 0);
    w.write_bytes(0x200 + 0x980 + 2, "GetLastError", true);
    w.write_u64(0x200 + 0x960, 0);

    // Base relocation block at RVA 0x1a00 (file offset 0x200 + 0xa00 = 0xc00)
    const std::size_t reloc_offset = 0x200 + 0xa00;
    w.write_u32(reloc_offset + 0, 0x1000);
    w.write_u32(reloc_offset + 4, 0x0c);
    w.write_u16(reloc_offset + 8, static_cast<std::uint16_t>((10u << 12) | 0x040));
    w.write_u16(reloc_offset + 10, 0);

    // Fill reloc target in section (RVA 0x1040 -> file offset 0x200 + 0x40 = 0x240)
    w.write_u64(0x200 + 0x40, 0x140001234ull);

    return w.data;
}

}  // namespace

TEST_CASE("PE loader reads minimal PE32 with symbols/relocs", "[pe]") {
    auto bytes = make_minimal_pe32();
    test_helpers::ScopedTempFile file("pe_minimal", bytes);

    engine::BinaryInfo info;
    std::vector<engine::BinarySegment> segments;
    std::vector<engine::BinarySection> sections;
    std::vector<engine::BinarySymbol> symbols;
    std::vector<engine::BinaryRelocation> relocs;
    engine::LoadedImage image;
    std::string error;

    REQUIRE(engine::load_pe_image_with_symbols_and_relocations(file.path().string(),
                                                              info,
                                                              segments,
                                                              sections,
                                                              symbols,
                                                              relocs,
                                                              image,
                                                              error));

    CHECK(info.format == engine::BinaryFormat::kPe);
    CHECK(info.is_64 == false);
    CHECK(info.machine == engine::BinaryMachine::kX86);
    CHECK(info.entry == 0x401000);
    CHECK(info.image_base == 0x400000);
    CHECK_FALSE(segments.empty());
    CHECK_FALSE(sections.empty());
    CHECK_FALSE(symbols.empty());
    CHECK_FALSE(relocs.empty());
    if (!relocs.empty()) {
        CHECK(relocs.front().addend == 0x1234);
    }
    if (!relocs.empty()) {
        CHECK(relocs.front().addend == 0x1234);
    }

    bool found_export = false;
    bool found_import = false;
    for (const auto& sym : symbols) {
        if (sym.name == "TestExport") {
            found_export = true;
        }
        if (sym.name.find("KERNEL32.dll!ExitProcess") != std::string::npos) {
            found_import = true;
        }
    }
    CHECK(found_export);
    CHECK(found_import);
}

TEST_CASE("PE loader reads minimal PE32+ with symbols/relocs", "[pe]") {
    auto bytes = make_minimal_pe64();
    test_helpers::ScopedTempFile file("pe64_minimal", bytes);

    engine::BinaryInfo info;
    std::vector<engine::BinarySegment> segments;
    std::vector<engine::BinarySection> sections;
    std::vector<engine::BinarySymbol> symbols;
    std::vector<engine::BinaryRelocation> relocs;
    engine::LoadedImage image;
    std::string error;

    REQUIRE(engine::load_pe_image_with_symbols_and_relocations(file.path().string(),
                                                              info,
                                                              segments,
                                                              sections,
                                                              symbols,
                                                              relocs,
                                                              image,
                                                              error));

    CHECK(info.format == engine::BinaryFormat::kPe);
    CHECK(info.is_64);
    CHECK(info.machine == engine::BinaryMachine::kX86_64);
    CHECK(info.entry == 0x140001000ull);
    CHECK(info.image_base == 0x140000000ull);
    CHECK_FALSE(segments.empty());
    CHECK_FALSE(sections.empty());
    CHECK_FALSE(symbols.empty());
    CHECK_FALSE(relocs.empty());

    bool found_export = false;
    bool found_import = false;
    for (const auto& sym : symbols) {
        if (sym.name == "TestExport64") {
            found_export = true;
        }
        if (sym.name.find("KERNEL32.dll!GetLastError") != std::string::npos) {
            found_import = true;
        }
    }
    CHECK(found_export);
    CHECK(found_import);
}
