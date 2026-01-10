#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include "engine/binary_loader.h"
#include "engine/function_boundaries.h"
#include "test_helpers.h"

namespace {

constexpr std::uint32_t kPfExec = 0x1;

}  // namespace

TEST_CASE("Function range discovery yields bounded ranges", "[analysis][function]") {
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

    std::vector<engine::analysis::FunctionRange> ranges;
    bool ok = engine::analysis::discover_function_ranges_arm64(image, info.entry, 2000, options, ranges, error);
    INFO("function range discovery failed: " + error);
    CHECK(ok);
    REQUIRE_FALSE(ranges.empty());

    for (std::size_t i = 0; i < ranges.size(); ++i) {
        const auto& range = ranges[i];
        CHECK(range.end > range.start);
        CHECK(test_helpers::addr_in_any_segment(range.start, segments, kPfExec));
        if (i > 0) {
            CHECK(ranges[i].start >= ranges[i - 1].start);
        }
    }
}
