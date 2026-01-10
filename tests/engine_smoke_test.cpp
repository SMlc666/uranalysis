#define CATCH_CONFIG_RUNNER
#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "engine/session.h"
#include "test_helpers.h"

namespace {

constexpr std::uint32_t kPfExec = 0x1;
constexpr std::uint32_t kPfRead = 0x4;

void run_session_smoke(const std::filesystem::path& path) {
    INFO("Sample: " + path.string());

    engine::Session session;
    std::string error;

    bool opened = session.open(path.string(), error);
    INFO("Session::open failed: " + error);
    REQUIRE(opened);

    REQUIRE(session.loaded());

    const auto& info = session.binary_info();
    CHECK(info.is_64);
    CHECK(info.little_endian);

    const auto& segments = session.segments();
    REQUIRE_FALSE(segments.empty());

    bool has_exec = false;
    bool has_read = false;
    for (const auto& seg : segments) {
        CHECK(seg.memsz >= seg.filesz);
        if ((seg.flags & kPfExec) != 0 && seg.memsz > 0) {
            has_exec = true;
        }
        if ((seg.flags & kPfRead) != 0 && seg.memsz > 0) {
            has_read = true;
        }
    }

    CHECK(has_exec);
    CHECK(has_read);
    CHECK(test_helpers::addr_in_any_segment(info.entry, segments, kPfExec));

    std::vector<std::uint8_t> entry_bytes;
    bool read_ok = session.image().read_bytes(info.entry, 4, entry_bytes);
    INFO("failed to read entrypoint bytes");
    CHECK(read_ok);

    const auto& symbols = session.symbols();
    const auto& sym_entries = session.symbol_table().entries();
    if (!symbols.empty()) {
        CHECK_FALSE(sym_entries.empty());
    }

    const auto& strings = session.string_catalog().entries();
    CHECK_FALSE(strings.empty());

    if (!strings.empty()) {
        const auto& entry = strings.front();
        CHECK(entry.length != 0);
        CHECK(test_helpers::addr_in_any_segment(entry.address, segments, kPfRead));

        std::vector<engine::xrefs::XrefEntry> refs;
        bool xref_ok = session.find_xrefs_to_address(entry.address, 32, refs);
        INFO("xrefs lookup failed");
        CHECK(xref_ok);
        for (const auto& ref : refs) {
            CHECK(test_helpers::addr_in_any_segment(ref.source, segments, kPfRead));
            CHECK(ref.kind == engine::xrefs::XrefKind::kDataPointer);
        }
    }

    std::vector<engine::DisasmLine> lines;
    std::uint64_t disasm_start = info.entry;
    bool disasm_ok = session.disasm_arm64(disasm_start, 256, 64, lines, error);
    if (!disasm_ok) {
        bool retried = false;
        for (const auto& seg : segments) {
            if ((seg.flags & kPfExec) == 0 || seg.memsz == 0) {
                continue;
            }
            if (seg.vaddr == disasm_start) {
                continue;
            }
            retried = true;
            lines.clear();
            error.clear();
            if (session.disasm_arm64(seg.vaddr, 256, 64, lines, error)) {
                disasm_start = seg.vaddr;
                break;
            }
        }
        if (lines.empty()) {
            if (error.find("no instructions") != std::string::npos) {
                std::ostringstream oss;
                oss << "disasm skipped at 0x" << std::hex
                    << static_cast<unsigned long long>(disasm_start) << ": " << error;
                WARN(oss.str());
            } else if (retried) {
                INFO("disasm failed after retry: " + error);
                CHECK(false);
            } else {
                INFO("disasm failed: " + error);
                CHECK(false);
            }
        }
    }

    if (!lines.empty()) {
        for (std::size_t i = 0; i < lines.size(); ++i) {
            CHECK((lines[i].address & 0x3u) == 0);
            CHECK(test_helpers::addr_in_any_segment(lines[i].address, segments, kPfExec));
            if (i > 0) {
                CHECK(lines[i].address > lines[i - 1].address);
            }
        }
    }

    engine::llir::Function cfg;
    bool cfg_ok = session.build_llir_cfg_arm64(info.entry, 2000, cfg, error);
    INFO("llir cfg build failed: " + error);
    CHECK(cfg_ok);
    if (cfg_ok) {
        CHECK_FALSE(cfg.blocks.empty());
        for (const auto& block : cfg.blocks) {
            CHECK(block.end >= block.start);
            for (const auto& inst : block.instructions) {
                CHECK((inst.address & 0x3u) == 0);
                CHECK(test_helpers::addr_in_any_segment(inst.address, segments, kPfExec));
            }
        }
    }

    std::vector<engine::llir::Function> functions;
    engine::analysis::FunctionDiscoveryOptions options;
    bool discovery_ok = session.discover_llir_functions_arm64(info.entry, 2000, options, functions, error);
    INFO("function discovery failed: " + error);
    CHECK(discovery_ok);
    if (discovery_ok) {
        CHECK_FALSE(functions.empty());
        for (const auto& func : functions) {
            CHECK(test_helpers::addr_in_any_segment(func.entry, segments, kPfExec));
        }
    }
}

}  // namespace

TEST_CASE("Engine session smoke tests", "[engine][smoke]") {
    const std::vector<std::string> samples = {
        "tests/samples/arm64/O0OptStrip.elf",
        "tests/samples/arm64/O2OptStrip.elf",
        "tests/samples/arm64/O2OptSharedStrip.elf",
        "tests/samples/arm64/binaryO0Opt.elf",
        "tests/samples/arm64/binaryO2Opt.elf",
        "tests/samples/arm64/binaryO2OptShared.elf",
    };

    for (const auto& relative : samples) {
        DYNAMIC_SECTION("Sample: " << relative) {
            auto path = test_helpers::find_sample_path(relative);
            REQUIRE(path.has_value());
            run_session_smoke(*path);
        }
    }
}

int main(int argc, char* argv[]) {
    return Catch::Session().run(argc, argv);
}
