#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include "engine/pdb_loader.h"
#include "test_helpers.h"

TEST_CASE("is_valid_pdb returns true for valid PDB files", "[pdb]") {
    // Find sample PDB files
    auto pdb_x64 = test_helpers::find_sample_path("tests/samples/x64/binaryO2.pdb");
    auto pdb_x86 = test_helpers::find_sample_path("tests/samples/x86/binaryO2.pdb");

    if (pdb_x64) {
        CHECK(engine::is_valid_pdb(pdb_x64->string()));
    }
    if (pdb_x86) {
        CHECK(engine::is_valid_pdb(pdb_x86->string()));
    }
}

TEST_CASE("is_valid_pdb returns false for non-PDB files", "[pdb]") {
    // PE file is not a PDB
    auto exe = test_helpers::find_sample_path("tests/samples/x64/binaryO2.exe");
    if (exe) {
        CHECK_FALSE(engine::is_valid_pdb(exe->string()));
    }

    // Non-existent file
    CHECK_FALSE(engine::is_valid_pdb("nonexistent_file.pdb"));
}

TEST_CASE("find_pdb_for_pe finds PDB next to PE file", "[pdb]") {
    auto exe = test_helpers::find_sample_path("tests/samples/x64/binaryO2.exe");
    if (!exe) {
        SKIP("Sample PE file not found");
    }

    std::string pdb_path;
    REQUIRE(engine::find_pdb_for_pe(exe->string(), pdb_path));
    CHECK_FALSE(pdb_path.empty());
    CHECK(engine::is_valid_pdb(pdb_path));
}

TEST_CASE("find_pdb_for_pe returns false when no PDB exists", "[pdb]") {
    // Create a temp PE file without a corresponding PDB
    std::vector<std::uint8_t> fake_pe = {'M', 'Z', 0, 0};
    test_helpers::ScopedTempFile temp("no_pdb_test.exe", fake_pe);

    std::string pdb_path;
    CHECK_FALSE(engine::find_pdb_for_pe(temp.path().string(), pdb_path));
}

TEST_CASE("load_pdb_symbols extracts symbols from valid PDB", "[pdb]") {
    auto pdb = test_helpers::find_sample_path("tests/samples/x64/binaryO2.pdb");
    if (!pdb) {
        SKIP("Sample PDB file not found");
    }

    std::vector<engine::BinarySymbol> symbols;
    const std::uint64_t image_base = 0x140000000;

    engine::PdbLoadResult result = engine::load_pdb_symbols(pdb->string(), image_base, symbols);

    REQUIRE(result.success);
    CHECK(result.error.empty());
    CHECK(result.public_symbols > 0);
    CHECK(result.function_symbols > 0);
    CHECK_FALSE(symbols.empty());

    // Verify some symbols have reasonable addresses (above image base)
    bool found_valid_addr = false;
    for (const auto& sym : symbols) {
        if (sym.value >= image_base && sym.value < image_base + 0x100000) {
            found_valid_addr = true;
            break;
        }
    }
    CHECK(found_valid_addr);
}

TEST_CASE("load_pdb_symbols returns failure for invalid PDB", "[pdb]") {
    std::vector<engine::BinarySymbol> symbols;

    engine::PdbLoadResult result = engine::load_pdb_symbols("nonexistent.pdb", 0x140000000, symbols);

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.error.empty());
    CHECK(symbols.empty());
}

TEST_CASE("load_pdb_symbols respects loading options", "[pdb]") {
    auto pdb = test_helpers::find_sample_path("tests/samples/x64/binaryO2.pdb");
    if (!pdb) {
        SKIP("Sample PDB file not found");
    }

    const std::uint64_t image_base = 0x140000000;

    // Load with all options enabled (baseline)
    std::vector<engine::BinarySymbol> all_symbols;
    engine::PdbLoadOptions all_opts;
    engine::PdbLoadResult all_result = engine::load_pdb_symbols(pdb->string(), image_base, all_symbols, all_opts);
    REQUIRE(all_result.success);

    // Load with only public symbols
    std::vector<engine::BinarySymbol> public_only;
    engine::PdbLoadOptions public_opts;
    public_opts.load_global_symbols = false;
    public_opts.load_function_symbols = false;
    public_opts.load_module_symbols = false;
    engine::PdbLoadResult public_result = engine::load_pdb_symbols(pdb->string(), image_base, public_only, public_opts);
    REQUIRE(public_result.success);

    // Public-only should have fewer symbols than all
    CHECK(public_only.size() <= all_symbols.size());
    CHECK(public_result.global_symbols == 0);
    CHECK(public_result.function_symbols == 0);
    CHECK(public_result.module_symbols == 0);
}

TEST_CASE("load_pdb_symbols extracts function symbols with sizes", "[pdb]") {
    auto pdb = test_helpers::find_sample_path("tests/samples/x64/binaryO2.pdb");
    if (!pdb) {
        SKIP("Sample PDB file not found");
    }

    std::vector<engine::BinarySymbol> symbols;
    const std::uint64_t image_base = 0x140000000;

    engine::PdbLoadResult result = engine::load_pdb_symbols(pdb->string(), image_base, symbols);
    REQUIRE(result.success);

    // Find function symbols with size > 0
    // Note: BinarySymbol doesn't have a type field, but PDB provides size for functions
    std::size_t syms_with_size = 0;
    for (const auto& sym : symbols) {
        if (sym.size > 0) {
            ++syms_with_size;
        }
    }

    // PDB should provide function sizes for at least some symbols
    CHECK(syms_with_size > 0);
}

TEST_CASE("load_pdb_symbols handles x86 PDB", "[pdb]") {
    auto pdb = test_helpers::find_sample_path("tests/samples/x86/binaryO2.pdb");
    if (!pdb) {
        SKIP("x86 sample PDB file not found");
    }

    std::vector<engine::BinarySymbol> symbols;
    const std::uint64_t image_base = 0x400000;  // Typical x86 image base

    engine::PdbLoadResult result = engine::load_pdb_symbols(pdb->string(), image_base, symbols);

    REQUIRE(result.success);
    CHECK_FALSE(symbols.empty());

    // Verify addresses are in reasonable x86 range
    bool found_valid_addr = false;
    for (const auto& sym : symbols) {
        if (sym.value >= image_base && sym.value < image_base + 0x100000) {
            found_valid_addr = true;
            break;
        }
    }
    CHECK(found_valid_addr);
}
