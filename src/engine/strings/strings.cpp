#include "engine/strings.h"

#include <cctype>

namespace engine::strings {

namespace {

constexpr std::uint64_t kShfAlloc = 0x2;
constexpr std::uint64_t kShfExecInstr = 0x4;

bool is_ascii_printable(unsigned char c) {
    return std::isprint(c) != 0 || c == '\t';
}

bool is_valid_utf8_start(unsigned char c, std::size_t& length) {
    if (c < 0x80) {
        length = 1;
        return is_ascii_printable(c);
    }
    if (c >= 0xC2 && c <= 0xDF) {
        length = 2;
        return true;
    }
    if (c >= 0xE0 && c <= 0xEF) {
        length = 3;
        return true;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        length = 4;
        return true;
    }
    return false;
}

bool is_valid_utf8_sequence(const std::vector<std::uint8_t>& buffer, std::size_t offset, std::size_t& length) {
    length = 0;
    if (offset >= buffer.size()) {
        return false;
    }
    const unsigned char lead = buffer[offset];
    std::size_t seq_len = 0;
    if (!is_valid_utf8_start(lead, seq_len)) {
        return false;
    }
    if (seq_len == 1) {
        length = 1;
        return true;
    }
    if (offset + seq_len > buffer.size()) {
        return false;
    }
    const unsigned char b1 = buffer[offset + 1];
    if ((b1 & 0xC0) != 0x80) {
        return false;
    }
    if (seq_len == 2) {
        length = 2;
        return true;
    }
    const unsigned char b2 = buffer[offset + 2];
    if ((b2 & 0xC0) != 0x80) {
        return false;
    }
    if (lead == 0xE0 && b1 < 0xA0) {
        return false;
    }
    if (lead == 0xED && b1 >= 0xA0) {
        return false;
    }
    if (seq_len == 3) {
        length = 3;
        return true;
    }
    const unsigned char b3 = buffer[offset + 3];
    if ((b3 & 0xC0) != 0x80) {
        return false;
    }
    if (lead == 0xF0 && b1 < 0x90) {
        return false;
    }
    if (lead == 0xF4 && b1 >= 0x90) {
        return false;
    }
    length = 4;
    return true;
}

}  // namespace

void StringCatalog::reset() {
    entries_.clear();
}

void StringCatalog::discover(const std::vector<BinarySection>& sections,
                             const LoadedImage& image,
                             std::size_t min_length) {
    reset();
    if (min_length == 0) {
        min_length = 1;
    }

    std::vector<std::uint8_t> buffer;

    for (const auto& section : sections) {
        if ((section.flags & kShfAlloc) == 0) {
            continue;
        }
        if ((section.flags & kShfExecInstr) != 0) {
            continue;
        }
        if (section.size == 0 || section.addr == 0) {
            continue;
        }
        if (!image.read_bytes(section.addr, static_cast<std::size_t>(section.size), buffer)) {
            continue;
        }
        if (buffer.empty()) {
            continue;
        }

        std::size_t i = 0;
        while (i < buffer.size()) {
            if (buffer[i] == 0) {
                ++i;
                continue;
            }
            std::size_t seq_len = 0;
            if (!is_valid_utf8_sequence(buffer, i, seq_len)) {
                ++i;
                continue;
            }
            const std::size_t start = i;
            bool saw_multibyte = (seq_len > 1);
            i += seq_len;
            while (i < buffer.size() && buffer[i] != 0) {
                if (!is_valid_utf8_sequence(buffer, i, seq_len)) {
                    break;
                }
                if (seq_len > 1) {
                    saw_multibyte = true;
                }
                i += seq_len;
            }
            const std::size_t length = i - start;
            if (length >= min_length) {
                StringEntry entry;
                entry.text.assign(reinterpret_cast<const char*>(buffer.data() + start), length);
                entry.address = section.addr + start;
                entry.length = length;
                entry.section_name = section.name;
                entry.utf8 = saw_multibyte;
                entries_.push_back(std::move(entry));
            }
            while (i < buffer.size() && buffer[i] != 0) {
                ++i;
            }
        }
    }
}

void StringCatalog::attach_symbols(const symbols::SymbolTable& symbols) {
    for (auto& entry : entries_) {
        entry.symbol_name.clear();
        auto matches = symbols.within_range(entry.address, 1);
        if (matches.empty()) {
            continue;
        }
        const auto* sym = matches.front();
        if (!sym || sym->address != entry.address) {
            continue;
        }
        if (!sym->demangled_name.empty()) {
            entry.symbol_name = sym->demangled_name;
        } else {
            entry.symbol_name = sym->name;
        }
    }
}

const std::vector<StringEntry>& StringCatalog::entries() const {
    return entries_;
}

}  // namespace engine::strings
