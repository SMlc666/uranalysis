#include "client/commands/commands.h"
#include "client/formatters/address.h"

#include <iomanip>
#include <sstream>

namespace client::commands {

void register_file_commands(CommandRegistry& registry) {
    // ==========================================================================
    // open - Load a binary file
    // ==========================================================================
    registry.register_command(
        CommandV2("open", {"o", "load", "ld"})
            .description("Load a binary file for analysis")
            .positional("path", "Path to binary file (ELF, PE)", true)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                std::string path = m.get<std::string>("path");
                std::string error;
                if (!session.open(path, error)) {
                    output.write_line("load error: " + error);
                    return true;
                }
                std::ostringstream oss;
                oss << "loaded: " << session.path();
                output.write_line(oss.str());
                oss.str("");
                oss << "entry: 0x" << std::hex << session.binary_info().entry;
                output.write_line(oss.str());
                return true;
            }));

    // ==========================================================================
    // close - Unload current file
    // ==========================================================================
    registry.register_command(
        CommandV2("close", {"unload"})
            .description("Unload the current binary file")
            .handler([](Session& session, Output& output, const args::ArgMatches&) {
                if (!session.loaded()) {
                    output.write_line("no file loaded");
                    return true;
                }
                session.close();
                output.write_line("closed");
                return true;
            }));

    // ==========================================================================
    // info - Show binary info
    // ==========================================================================
    registry.register_command(
        CommandV2("info", {"i", "file", "fi"})
            .description("Show binary file information")
            .requires_file()
            .handler([](Session& session, Output& output, const args::ArgMatches&) {
                std::ostringstream oss;
                switch (session.binary_info().format) {
                    case engine::BinaryFormat::kElf:
                        oss << "Format: ELF";
                        break;
                    case engine::BinaryFormat::kPe:
                        oss << "Format: PE";
                        break;
                    default:
                        oss << "Format: unknown";
                        break;
                }
                output.write_line(oss.str());
                oss.str("");
                oss << "64-bit: " << (session.binary_info().is_64 ? "yes" : "no");
                output.write_line(oss.str());
                oss.str("");
                oss << "Little endian: " << (session.binary_info().little_endian ? "yes" : "no");
                output.write_line(oss.str());
                oss.str("");
                oss << "Entry: 0x" << std::hex << session.binary_info().entry;
                output.write_line(oss.str());
                oss.str("");
                oss << "Program headers: " << std::dec << session.binary_info().ph_num;
                output.write_line(oss.str());
                oss.str("");
                oss << "Section headers: " << session.binary_info().sh_num;
                output.write_line(oss.str());
                return true;
            }));

    // ==========================================================================
    // ph - List program headers / segments
    // ==========================================================================
    registry.register_command(
        CommandV2("ph", {"segments", "segs"})
            .description("List program headers (segments)")
            .requires_file()
            .handler([](Session& session, Output& output, const args::ArgMatches&) {
                for (size_t i = 0; i < session.segments().size(); ++i) {
                    const auto& seg = session.segments()[i];
                    std::ostringstream oss;
                    oss << "PH[" << i << "] type=" << seg.type << " flags=0x" << std::hex << seg.flags
                        << std::dec << " off=0x" << std::hex << seg.offset << " vaddr=0x" << seg.vaddr
                        << std::dec << " filesz=0x" << std::hex << seg.filesz << " memsz=0x" << seg.memsz
                        << std::dec;
                    output.write_line(oss.str());
                }
                return true;
            }));

    // ==========================================================================
    // sh - List section headers
    // ==========================================================================
    registry.register_command(
        CommandV2("sh", {"sections", "secs"})
            .description("List section headers")
            .requires_file()
            .handler([](Session& session, Output& output, const args::ArgMatches&) {
                for (size_t i = 0; i < session.sections().size(); ++i) {
                    const auto& sec = session.sections()[i];
                    std::ostringstream oss;
                    oss << "SH[" << i << "] name=" << (sec.name.empty() ? "<noname>" : sec.name)
                        << " type=" << sec.type << " flags=0x" << std::hex << sec.flags << std::dec
                        << " addr=0x" << std::hex << sec.addr << std::dec << " off=0x" << std::hex
                        << sec.offset << " size=0x" << sec.size << std::dec;
                    output.write_line(oss.str());
                }
                return true;
            }));

    // ==========================================================================
    // relocs - List relocations
    // ==========================================================================
    registry.register_command(
        CommandV2("relocs", {"rl", "relocations"})
            .description("List relocations")
            .requires_file()
            .handler([](Session& session, Output& output, const args::ArgMatches&) {
                const auto& relocs = session.relocations();
                if (relocs.empty()) {
                    output.write_line("no relocations");
                    return true;
                }
                for (const auto& reloc : relocs) {
                    std::ostringstream oss;
                    oss << fmt::hex(reloc.offset) << " type=" << reloc.type;
                    oss << " sym=" << reloc.sym;
                    oss << " value=" << fmt::hex(reloc.symbol_value);
                    oss << " addend=" << reloc.addend;
                    if (!reloc.symbol_name.empty()) {
                        oss << " name=" << reloc.symbol_name;
                    }
                    output.write_line(oss.str());
                }
                return true;
            }));
}

}  // namespace client::commands
