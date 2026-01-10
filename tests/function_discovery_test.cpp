#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include "engine/arch/arm64/calling_convention.h"
#include "engine/arch/arm64/function_prologue.h"
#include "engine/binary_loader.h"
#include "engine/function_discovery.h"
#include "engine/llir.h"
#include "test_helpers.h"

namespace {

constexpr std::uint32_t kPfExec = 0x1;

}  // namespace

TEST_CASE("Function discovery collects seeds and functions", "[analysis][arm64]") {
    const auto sample = test_helpers::find_sample_path("tests/samples/arm64/binaryO0Opt.elf");
    REQUIRE(sample.has_value());

    engine::BinaryInfo info;
    std::vector<engine::BinarySegment> segments;
    std::vector<engine::BinarySection> sections;
    std::vector<engine::BinarySymbol> symbols;
    std::vector<engine::BinaryRelocation> relocations;
    engine::LoadedImage image;
    std::string error;
    REQUIRE(engine::load_binary_image_with_symbols_and_relocations(sample->string(),
                                                                   info,
                                                                   segments,
                                                                   sections,
                                                                   symbols,
                                                                   relocations,
                                                                   image,
                                                                   error));

    engine::analysis::FunctionDiscoveryOptions options;
    options.symbols = &symbols;
    options.sections = &sections;
    options.segments = &segments;
    options.relocations = &relocations;
    options.binary_info = &info;

    std::vector<engine::analysis::SeedEntry> seeds;
    engine::analysis::collect_seed_entries(image, info.entry, options, seeds);
    CHECK_FALSE(seeds.empty());
    bool saw_entry = false;
    for (const auto& seed : seeds) {
        if (seed.address == info.entry && seed.kind == engine::analysis::SeedKind::kEntry) {
            saw_entry = true;
            break;
        }
    }
    CHECK(saw_entry);

    std::vector<engine::llir::Function> functions;
    REQUIRE(engine::analysis::discover_functions_arm64(image, info.entry, 2000, options, functions, error));
    CHECK_FALSE(functions.empty());
    for (const auto& func : functions) {
        CHECK(test_helpers::addr_in_any_segment(func.entry, segments, kPfExec));
    }
}

TEST_CASE("ARM64 calling convention metadata is populated", "[arm64]") {
    const auto& cc = engine::arch::arm64::aapcs64();
    CHECK(cc.int_args.size() == 8);
    CHECK(cc.float_args.size() == 8);
    CHECK(cc.int_return == "x0");
    CHECK(cc.float_return == "v0");
    CHECK_FALSE(cc.caller_saved.empty());
    CHECK_FALSE(cc.callee_saved.empty());

    const auto& clobbers = engine::arch::arm64::call_clobbers();
    CHECK(clobbers.size() == cc.caller_saved.size());
    if (!clobbers.empty()) {
        CHECK(clobbers.front().name == cc.caller_saved.front());
    }
}

TEST_CASE("ARM64 prologue scan returns executable entry candidates", "[arm64]") {
    const auto sample = test_helpers::find_sample_path("tests/samples/arm64/binaryO0Opt.elf");
    REQUIRE(sample.has_value());

    engine::BinaryInfo info;
    std::vector<engine::BinarySegment> segments;
    std::vector<engine::BinarySection> sections;
    engine::LoadedImage image;
    std::string error;
    REQUIRE(engine::load_binary_image(sample->string(), info, segments, sections, image, error));

    std::vector<std::uint64_t> entries;
    engine::arch::arm64::collect_prologue_entry_points(image, sections, &segments, entries);
    for (const auto& addr : entries) {
        CHECK(test_helpers::addr_in_any_segment(addr, segments, kPfExec));
    }
}
