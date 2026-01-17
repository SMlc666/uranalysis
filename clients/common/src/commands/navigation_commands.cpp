#include "client/commands/commands.h"
#include "client/formatters/address.h"
#include "client/util/address_resolver.h"

#include <iomanip>
#include <sstream>

namespace client::commands {

void register_navigation_commands(CommandRegistry& registry) {
    // ==========================================================================
    // seek - Navigate to an address or symbol
    // ==========================================================================
    registry.register_command(
        CommandV2("seek", {"s", "goto", "g"})
            .description("Seek to an address or symbol")
            .requires_file()
            .positional("target", "Address, symbol, or special: . $ entry +/-offset", true)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                std::string target = m.get<std::string>("target");
                auto result = util::resolve_address(target, session);
                if (!result.success) {
                    output.write_line(result.error);
                    return true;
                }
                
                session.set_cursor(result.address);
                std::ostringstream oss;
                oss << "cursor = 0x" << std::hex << session.cursor();
                if (!result.resolved_name.empty()) {
                    oss << " (" << result.resolved_name << ")";
                }
                output.write_line(oss.str());
                return true;
            }));

    // ==========================================================================
    // pd - Disassemble instructions
    // ==========================================================================
    registry.register_command(
        CommandV2("pd", {"disasm", "dis", "u"})
            .description("Disassemble instructions at current cursor")
            .requires_file()
            .positional("count", "Number of instructions (default: 20)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                size_t count = static_cast<size_t>(m.get_or<uint64_t>("count", 20));
                
                std::vector<engine::DisasmLine> disasm;
                std::string error;
                const auto machine = session.binary_info().machine;
                const size_t max_bytes = count * ((machine == engine::BinaryMachine::kAarch64) ? 4U : 15U);
                
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
                        const uint64_t advance = last.size != 0 ? last.size : 4;
                        session.set_cursor(last.address + advance);
                    }
                } else {
                    output.write_line("disasm error: " + error);
                }
                return true;
            }));

    // ==========================================================================
    // px - Hex dump
    // ==========================================================================
    registry.register_command(
        CommandV2("px", {"xd", "hexdump", "hd", "x"})
            .description("Hex dump bytes at an address")
            .requires_file()
            .positional("address", "Start address or symbol", true)
            .positional("length", "Number of bytes (default: 64)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                auto result = util::resolve_address(m.get<std::string>("address"), session);
                if (!result.success) {
                    output.write_line(result.error);
                    return true;
                }
                uint64_t addr = result.address;
                size_t length = static_cast<size_t>(m.get_or<uint64_t>("length", 64));
                
                std::vector<uint8_t> bytes;
                if (!session.image().read_bytes(addr, length, bytes)) {
                    output.write_line("read error");
                    return true;
                }
                if (bytes.empty()) {
                    output.write_line("no bytes");
                    return true;
                }
                
                const size_t per_line = 16;
                for (size_t offset = 0; offset < bytes.size(); offset += per_line) {
                    std::ostringstream oss;
                    oss << fmt::hex(addr + offset) << ": ";
                    for (size_t i = 0; i < per_line; ++i) {
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
                    // ASCII representation
                    oss << "  ";
                    for (size_t i = 0; i < per_line && offset + i < bytes.size(); ++i) {
                        char c = static_cast<char>(bytes[offset + i]);
                        oss << (c >= 32 && c < 127 ? c : '.');
                    }
                    output.write_line(oss.str());
                }
                return true;
            }));

    // ==========================================================================
    // where / cursor - Show current cursor position
    // ==========================================================================
    registry.register_command(
        CommandV2("where", {"cursor", "pos", "?"})
            .description("Show current cursor position")
            .requires_file()
            .handler([](Session& session, Output& output, const args::ArgMatches&) {
                std::ostringstream oss;
                oss << "cursor = 0x" << std::hex << session.cursor();
                
                // Try to find symbol at cursor
                auto symbols = session.symbol_table().within_range(session.cursor(), 1);
                if (!symbols.empty() && symbols.front()) {
                    const auto* sym = symbols.front();
                    std::string name = !sym->demangled_name.empty() ? sym->demangled_name : sym->name;
                    if (!name.empty()) {
                        uint64_t offset = session.cursor() - sym->address;
                        oss << " (" << name;
                        if (offset > 0) {
                            oss << "+0x" << std::hex << offset;
                        }
                        oss << ")";
                    }
                }
                output.write_line(oss.str());
                return true;
            }));
}

}  // namespace client::commands
