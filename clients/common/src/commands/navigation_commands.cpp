#include "client/commands/commands.h"

#include <iomanip>
#include <sstream>

#include "client/formatters/address.h"
#include "engine/disasm.h"

namespace client::commands {

namespace {

bool require_loaded(const Session& session, Output& output) {
    if (!session.loaded()) {
        output.write_line("no file loaded, use: open <path>");
        return false;
    }
    return true;
}

}  // namespace

void register_navigation_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "seek",
        {"s"},
        "seek <addr>   set current address",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2) {
                output.write_line("usage: seek <addr>");
                return true;
            }
            std::uint64_t addr = 0;
            if (!fmt::parse_u64(args[1], addr)) {
                output.write_line("invalid address: " + args[1]);
                return true;
            }
            session.set_cursor(addr);
            std::ostringstream oss;
            oss << "cursor = 0x" << std::hex << session.cursor();
            output.write_line(oss.str());
            return true;
        }});

    registry.register_command(Command{
        "pd",
        {},
        "pd [n]        disassemble n instructions (default 20)",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            std::size_t count = 20;
            if (args.size() >= 2) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[1], parsed)) {
                    output.write_line("invalid count: " + args[1]);
                    return true;
                }
                count = static_cast<std::size_t>(parsed);
            }
            std::vector<engine::DisasmLine> disasm;
            std::string error;
            const auto machine = session.binary_info().machine;
            const std::size_t max_bytes =
                count * ((machine == engine::BinaryMachine::kAarch64) ? 4U : 15U);
            bool ok = false;
            if (machine == engine::BinaryMachine::kAarch64) {
                ok = session.disasm_arm64(session.cursor(), max_bytes, count, disasm, error);
            } else if (machine == engine::BinaryMachine::kX86_64) {
                ok = session.disasm_x86_64(session.cursor(), max_bytes, count, disasm, error);
            } else {
                error = "unsupported architecture for disasm";
            }
            if (ok) {
                for (const auto& line : disasm) {
                    std::ostringstream oss;
                    oss << "  0x" << std::hex << line.address << std::dec << ": " << line.text;
                    output.write_line(oss.str());
                }
                if (!disasm.empty()) {
                    const auto& last = disasm.back();
                    const std::uint64_t advance = last.size != 0 ? last.size : 4;
                    session.set_cursor(last.address + advance);
                }
            } else {
                output.write_line("disasm error: " + error);
            }
            return true;
        }});

    registry.register_command(Command{
        "px",
        {"xd"},
        "px <addr> [len]  hex dump bytes",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2 || args.size() > 3) {
                output.write_line("usage: px <addr> [len]");
                return true;
            }
            std::uint64_t addr = 0;
            if (!fmt::parse_u64(args[1], addr)) {
                output.write_line("invalid address: " + args[1]);
                return true;
            }
            std::size_t length = 64;
            if (args.size() == 3) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[2], parsed)) {
                    output.write_line("invalid length: " + args[2]);
                    return true;
                }
                length = static_cast<std::size_t>(parsed);
            }
            std::vector<std::uint8_t> bytes;
            if (!session.image().read_bytes(addr, length, bytes)) {
                output.write_line("read error");
                return true;
            }
            if (bytes.empty()) {
                output.write_line("no bytes");
                return true;
            }
            const std::size_t per_line = 16;
            for (std::size_t offset = 0; offset < bytes.size(); offset += per_line) {
                std::ostringstream oss;
                oss << fmt::hex(addr + offset) << ": ";
                for (std::size_t i = 0; i < per_line; ++i) {
                    if (offset + i < bytes.size()) {
                        oss << std::setw(2) << std::setfill('0') << std::hex
                            << static_cast<int>(bytes[offset + i]);
                    } else {
                        oss << "  ";
                    }
                    if (i + 1 < per_line) {
                        oss << " ";
                    }
                }
                output.write_line(oss.str());
            }
            return true;
        }});
}

}  // namespace client::commands