#include "client/commands/commands.h"

#include <iomanip>
#include <sstream>

#include "client/formatters/address.h"

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

void register_file_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "open",
        {},
        "open <path>   load binary file",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (args.size() < 2) {
                output.write_line("usage: open <path>");
                return true;
            }
            std::string error;
            if (!session.open(args[1], error)) {
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
        }});

    registry.register_command(Command{
        "close",
        {},
        "close         unload current file",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!session.loaded()) {
                output.write_line("no file loaded");
                return true;
            }
            session.close();
            output.write_line("closed");
            return true;
        }});

    registry.register_command(Command{
        "info",
        {},
        "info          show binary info",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
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
        }});

    registry.register_command(Command{
        "ph",
        {},
        "ph            list program headers",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
            for (std::size_t i = 0; i < session.segments().size(); ++i) {
                const auto& seg = session.segments()[i];
                std::ostringstream oss;
                oss << "PH[" << i << "] type=" << seg.type << " flags=0x" << std::hex << seg.flags
                    << std::dec << " off=0x" << std::hex << seg.offset << " vaddr=0x" << seg.vaddr
                    << std::dec << " filesz=0x" << std::hex << seg.filesz << " memsz=0x" << seg.memsz
                    << std::dec;
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "sh",
        {},
        "sh            list section headers",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
            for (std::size_t i = 0; i < session.sections().size(); ++i) {
                const auto& sec = session.sections()[i];
                std::ostringstream oss;
                oss << "SH[" << i << "] name=" << (sec.name.empty() ? "<noname>" : sec.name)
                    << " type=" << sec.type << " flags=0x" << std::hex << sec.flags << std::dec
                    << " addr=0x" << std::hex << sec.addr << std::dec << " off=0x" << std::hex
                    << sec.offset << " size=0x" << sec.size << std::dec;
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "relocs",
        {"rl"},
        "relocs        list relocations",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
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
        }});
}

}  // namespace client::commands