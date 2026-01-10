#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "client/command.h"
#include "client/output.h"
#include "test_helpers.h"

namespace {

constexpr std::uint32_t kPfExec = 0x1;

class CaptureOutput final : public client::Output {
public:
    void write_line(const std::string& line) override {
        lines.push_back(line);
    }

    std::vector<std::string> lines;
};

std::string to_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

std::uint64_t first_exec_addr(const client::Session& session) {
    for (const auto& seg : session.segments()) {
        if ((seg.flags & kPfExec) != 0 && seg.memsz > 0) {
            return seg.vaddr;
        }
    }
    return session.binary_info().entry;
}

}  // namespace

TEST_CASE("Default command registry handles common flows", "[client]") {
    const auto sample = test_helpers::find_sample_path("tests/samples/arm64/binaryO0Opt.elf");
    REQUIRE(sample.has_value());

    client::Session session;
    CaptureOutput output;
    auto registry = client::make_default_registry();

    REQUIRE(registry.execute_line("open " + sample->string(), session, output));
    REQUIRE(session.loaded());
    REQUIRE(output.lines.size() >= 2);
    CHECK(output.lines[0].find("loaded:") != std::string::npos);
    output.lines.clear();

    REQUIRE(registry.execute_line("info", session, output));
    CHECK_FALSE(output.lines.empty());
    CHECK(output.lines[0].find("Format:") != std::string::npos);
    bool has_bitness = false;
    for (const auto& line : output.lines) {
        if (line.find("64-bit:") != std::string::npos) {
            has_bitness = true;
            break;
        }
    }
    CHECK(has_bitness);
    output.lines.clear();

    const std::string addr = to_hex(first_exec_addr(session));
    REQUIRE(registry.execute_line("seek " + addr, session, output));
    CHECK_FALSE(output.lines.empty());
    CHECK(output.lines[0].find("cursor") != std::string::npos);
    output.lines.clear();

    REQUIRE(registry.execute_line("pd 1", session, output));
    REQUIRE_FALSE(output.lines.empty());
    const std::string& line = output.lines[0];
    const bool has_output = (line.find("0x") != std::string::npos) ||
                            (line.find("disasm error") != std::string::npos);
    CHECK(has_output);
}

TEST_CASE("Command registry reports invalid input", "[client]") {
    const auto sample = test_helpers::find_sample_path("tests/samples/arm64/binaryO0Opt.elf");
    REQUIRE(sample.has_value());

    client::Session session;
    CaptureOutput output;
    auto registry = client::make_default_registry();

    REQUIRE(registry.execute_line("open " + sample->string(), session, output));
    output.lines.clear();

    REQUIRE(registry.execute_line("unknowncmd", session, output));
    REQUIRE_FALSE(output.lines.empty());
    CHECK(output.lines.back().find("unknown command") != std::string::npos);
    output.lines.clear();

    REQUIRE(registry.execute_line("seek", session, output));
    REQUIRE_FALSE(output.lines.empty());
    CHECK(output.lines.back().find("usage: seek") != std::string::npos);
    output.lines.clear();

    REQUIRE(registry.execute_line("seek 0xZZ", session, output));
    REQUIRE_FALSE(output.lines.empty());
    CHECK(output.lines.back().find("invalid address") != std::string::npos);
    output.lines.clear();

    CHECK_FALSE(registry.execute_line("quit", session, output));
}
