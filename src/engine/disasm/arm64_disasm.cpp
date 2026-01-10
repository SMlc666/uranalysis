#include "engine/disasm.h"

#include <capstone/capstone.h>

#include <sstream>

namespace engine {

bool disasm_arm64(const LoadedImage& image,
                  std::uint64_t start,
                  std::size_t max_bytes,
                  std::size_t max_instructions,
                  std::vector<DisasmLine>& out,
                  std::string& error) {
    out.clear();
    error.clear();

    std::vector<std::uint8_t> bytes;
    if (!image.read_bytes(start, max_bytes, bytes)) {
        error = "failed to read bytes from image";
        return false;
    }

    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        error = "failed to initialize capstone";
        return false;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    cs_insn* insn = nullptr;
    const std::size_t count = cs_disasm(handle, bytes.data(), bytes.size(), start,
                                        static_cast<size_t>(max_instructions), &insn);
    if (count == 0) {
        cs_close(&handle);
        error = "capstone disasm returned no instructions";
        return false;
    }

    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::ostringstream line;
        line << insn[i].mnemonic;
        if (insn[i].op_str && insn[i].op_str[0] != '\0') {
            line << " " << insn[i].op_str;
        }
        DisasmLine entry;
        entry.address = static_cast<std::uint64_t>(insn[i].address);
        entry.size = static_cast<std::uint32_t>(insn[i].size);
        entry.text = line.str();
        out.push_back(std::move(entry));
    }

    cs_free(insn, count);
    cs_close(&handle);
    return true;
}

}  // namespace engine
