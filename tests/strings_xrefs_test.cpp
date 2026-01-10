#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include "engine/binary_loader.h"
#include "engine/strings.h"
#include "engine/xrefs.h"
#include "test_helpers.h"

namespace {

constexpr std::uint32_t kPfRead = 0x4;

}  // namespace

TEST_CASE("String catalog discovers readable strings and xrefs", "[strings][xrefs]") {
    const auto sample = test_helpers::find_sample_path("tests/samples/arm64/binaryO0Opt.elf");
    REQUIRE(sample.has_value());

    engine::BinaryInfo info;
    std::vector<engine::BinarySegment> segments;
    std::vector<engine::BinarySection> sections;
    engine::LoadedImage image;
    std::string error;
    REQUIRE(engine::load_binary_image(sample->string(), info, segments, sections, image, error));

    CHECK(info.is_64);

    engine::strings::StringCatalog catalog;
    catalog.discover(sections, image, 4);
    const auto& entries = catalog.entries();
    REQUIRE_FALSE(entries.empty());

    const auto& entry = entries.front();
    CHECK(entry.length >= 4);
    CHECK(entry.length == entry.text.size());
    CHECK_FALSE(entry.section_name.empty());
    CHECK(test_helpers::addr_in_any_segment(entry.address, segments, kPfRead));

    std::vector<engine::xrefs::XrefEntry> xrefs;
    bool ok = engine::xrefs::find_xrefs_to_address(image, entry.address, 64, xrefs);
    CHECK(ok);
    for (const auto& ref : xrefs) {
        CHECK(test_helpers::addr_in_any_segment(ref.source, segments, kPfRead));
    }
}
