#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include "engine/dwarf.h"
#include "engine/eh_frame.h"
#include "engine/binary_loader.h"
#include "engine/rtti.h"
#include "engine/symbols.h"
#include "test_helpers.h"

namespace {

constexpr std::uint32_t kPfExec = 0x1;

const engine::BinarySymbol* find_named_symbol(const std::vector<engine::BinarySymbol>& symbols) {
    for (const auto& sym : symbols) {
        if (!sym.name.empty()) {
            return &sym;
        }
    }
    return nullptr;
}

}  // namespace

TEST_CASE("Symbols, RTTI, DWARF, and EH frame catalogs expose invariants", "[symbols][rtti][dwarf][ehframe]") {
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

    engine::symbols::SymbolTable table;
    table.populate(symbols, sections);
    CHECK(table.entries().size() == symbols.size());

    const engine::BinarySymbol* named = find_named_symbol(symbols);
    if (named) {
        const auto* entry = table.lookup_by_name(named->name);
        REQUIRE(entry != nullptr);
        CHECK(entry->address == named->value);
        if (entry->size > 0) {
            const auto within = table.within_range(entry->address, 4);
            CHECK_FALSE(within.empty());
        }
    }

    engine::rtti::RttiCatalog rtti;
    rtti.discover(sections, segments, image, info);
    for (const auto& type : rtti.types()) {
        CHECK(test_helpers::addr_in_any_segment(type.address, segments));
        CHECK(test_helpers::addr_in_any_segment(type.vtable_address, segments));
    }
    for (const auto& vt : rtti.vtables()) {
        CHECK(test_helpers::addr_in_any_segment(vt.address, segments));
        CHECK_FALSE(vt.type_name.empty());
    }

    engine::dwarf::DwarfCatalog dwarf;
    dwarf.discover(sample->string(), sections, image, info, relocations);
    for (const auto& sec : dwarf.sections()) {
        CHECK_FALSE(sec.name.empty());
        CHECK(sec.name.rfind(".debug", 0) == 0);
        CHECK_FALSE(sec.view.empty());
    }
    if (!dwarf.line_rows().empty()) {
        const auto addr = dwarf.line_rows().front().address;
        const auto* row = dwarf.find_line_for_address(addr);
        REQUIRE(row != nullptr);
        CHECK(row->address == addr);
    }
    if (!dwarf.functions().empty()) {
        const engine::dwarf::DwarfFunction* sample_func = nullptr;
        for (const auto& func : dwarf.functions()) {
            if (func.low_pc != 0 && (func.high_pc > func.low_pc || !func.ranges.empty())) {
                sample_func = &func;
                break;
            }
        }
        if (sample_func) {
            std::uint64_t addr = sample_func->low_pc;
            if (addr == 0 && !sample_func->ranges.empty()) {
                addr = sample_func->ranges.front().start;
            }
            if (addr != 0) {
                const auto* found = dwarf.find_function_by_address(addr);
                REQUIRE(found != nullptr);
                CHECK(found->low_pc == sample_func->low_pc);
            }
        }
    }

    engine::ehframe::EhFrameCatalog ehframe;
    ehframe.discover(sections, image, info);
    for (const auto& entry : ehframe.entries()) {
        CHECK(entry.size > 0);
        CHECK(test_helpers::addr_in_any_segment(entry.start, segments, kPfExec));
    }
    const engine::ehframe::FdeEntry* sample_fde = nullptr;
    for (const auto& entry : ehframe.entries()) {
        if (entry.start != 0 && entry.size > 0) {
            sample_fde = &entry;
            break;
        }
    }
    if (sample_fde) {
        const auto* found = ehframe.find_fde_for_address(sample_fde->start);
        REQUIRE(found != nullptr);
        CHECK(found->start == sample_fde->start);
        if (!sample_fde->rows.empty()) {
            const auto* row = ehframe.find_cfa_row(sample_fde->start);
            REQUIRE(row != nullptr);
            CHECK(row->pc <= sample_fde->start);
        }
    }
}
