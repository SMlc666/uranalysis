#include "engine/binary_loader.h"

#include <fstream>

#include "engine/elf_loader.h"
#include "engine/pe_loader.h"

namespace engine {

namespace {

enum class FileKind {
    kUnknown,
    kElf,
    kPe
};

bool read_exact(std::ifstream& stream, void* out, std::size_t size) {
    stream.read(static_cast<char*>(out), static_cast<std::streamsize>(size));
    return stream.good();
}

FileKind detect_file_kind(const std::string& path, std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "failed to open file";
        return FileKind::kUnknown;
    }
    std::uint8_t magic[4] = {};
    if (!read_exact(file, magic, sizeof(magic))) {
        error = "failed to read file header";
        return FileKind::kUnknown;
    }
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        return FileKind::kElf;
    }
    if (magic[0] == 'M' && magic[1] == 'Z') {
        return FileKind::kPe;
    }
    error = "unknown binary format";
    return FileKind::kUnknown;
}

BinaryInfo to_binary_info(const ElfInfo& in) {
    BinaryInfo out;
    out.format = BinaryFormat::kElf;
    out.machine = in.machine;
    out.is_64 = in.is_64;
    out.little_endian = in.little_endian;
    out.entry = in.entry;
    out.image_base = in.image_base;
    out.ph_num = in.ph_num;
    out.sh_num = in.sh_num;
    return out;
}

std::vector<BinarySegment> to_binary_segments(const std::vector<ElfSegment>& in) {
    std::vector<BinarySegment> out;
    out.reserve(in.size());
    for (const auto& seg : in) {
        BinarySegment s;
        s.type = seg.type;
        s.flags = seg.flags;
        s.offset = seg.offset;
        s.vaddr = seg.vaddr;
        s.filesz = seg.filesz;
        s.memsz = seg.memsz;
        out.push_back(std::move(s));
    }
    return out;
}

std::vector<BinarySection> to_binary_sections(const std::vector<ElfSection>& in) {
    std::vector<BinarySection> out;
    out.reserve(in.size());
    for (const auto& sec : in) {
        BinarySection s;
        s.name = sec.name;
        s.type = sec.type;
        s.flags = sec.flags;
        s.addr = sec.addr;
        s.offset = sec.offset;
        s.size = sec.size;
        out.push_back(std::move(s));
    }
    return out;
}

std::vector<BinarySymbol> to_binary_symbols(const std::vector<ElfSymbol>& in) {
    std::vector<BinarySymbol> out;
    out.reserve(in.size());
    for (const auto& sym : in) {
        BinarySymbol s;
        s.name = sym.name;
        s.value = sym.value;
        s.size = sym.size;
        s.info = sym.info;
        s.other = sym.other;
        s.shndx = sym.shndx;
        out.push_back(std::move(s));
    }
    return out;
}

std::vector<BinaryRelocation> to_binary_relocations(const std::vector<ElfRelocation>& in) {
    std::vector<BinaryRelocation> out;
    out.reserve(in.size());
    for (const auto& reloc : in) {
        BinaryRelocation r;
        r.offset = reloc.offset;
        r.info = reloc.info;
        r.addend = reloc.addend;
        r.type = reloc.type;
        r.sym = reloc.sym;
        r.symbol_value = reloc.symbol_value;
        r.symbol_name = reloc.symbol_name;
        r.target_section = reloc.target_section;
        out.push_back(std::move(r));
    }
    return out;
}

}  // namespace

bool load_binary(const std::string& path,
                 BinaryInfo& info,
                 std::vector<BinarySegment>& segments,
                 std::string& error) {
    std::string detect_error;
    const FileKind kind = detect_file_kind(path, detect_error);
    if (kind == FileKind::kElf) {
        ElfInfo elf_info;
        std::vector<ElfSegment> elf_segments;
        if (!load_elf(path, elf_info, elf_segments, error)) {
            return false;
        }
        info = to_binary_info(elf_info);
        segments = to_binary_segments(elf_segments);
        return true;
    }
    if (kind == FileKind::kPe) {
        return load_pe(path, info, segments, error);
    }
    error = detect_error;
    return false;
}

bool load_binary_image_with_symbols(const std::string& path,
                                    BinaryInfo& info,
                                    std::vector<BinarySegment>& segments,
                                    std::vector<BinarySection>& sections,
                                    std::vector<BinarySymbol>& symbols,
                                    LoadedImage& image,
                                    std::string& error) {
    std::string detect_error;
    const FileKind kind = detect_file_kind(path, detect_error);
    if (kind == FileKind::kElf) {
        ElfInfo elf_info;
        std::vector<ElfSegment> elf_segments;
        std::vector<ElfSection> elf_sections;
        std::vector<ElfSymbol> elf_symbols;
        if (!load_elf_image_with_symbols(path, elf_info, elf_segments, elf_sections, elf_symbols, image, error)) {
            return false;
        }
        info = to_binary_info(elf_info);
        segments = to_binary_segments(elf_segments);
        sections = to_binary_sections(elf_sections);
        symbols = to_binary_symbols(elf_symbols);
        return true;
    }
    if (kind == FileKind::kPe) {
        return load_pe_image_with_symbols(path, info, segments, sections, symbols, image, error);
    }
    error = detect_error;
    return false;
}

bool load_binary_image_with_symbols_and_relocations(const std::string& path,
                                                    BinaryInfo& info,
                                                    std::vector<BinarySegment>& segments,
                                                    std::vector<BinarySection>& sections,
                                                    std::vector<BinarySymbol>& symbols,
                                                    std::vector<BinaryRelocation>& relocations,
                                                    LoadedImage& image,
                                                    std::string& error) {
    std::string detect_error;
    const FileKind kind = detect_file_kind(path, detect_error);
    if (kind == FileKind::kElf) {
        ElfInfo elf_info;
        std::vector<ElfSegment> elf_segments;
        std::vector<ElfSection> elf_sections;
        std::vector<ElfSymbol> elf_symbols;
        std::vector<ElfRelocation> elf_relocs;
        if (!load_elf_image_with_symbols_and_relocations(path,
                                                         elf_info,
                                                         elf_segments,
                                                         elf_sections,
                                                         elf_symbols,
                                                         elf_relocs,
                                                         image,
                                                         error)) {
            return false;
        }
        info = to_binary_info(elf_info);
        segments = to_binary_segments(elf_segments);
        sections = to_binary_sections(elf_sections);
        symbols = to_binary_symbols(elf_symbols);
        relocations = to_binary_relocations(elf_relocs);
        return true;
    }
    if (kind == FileKind::kPe) {
        return load_pe_image_with_symbols_and_relocations(path,
                                                          info,
                                                          segments,
                                                          sections,
                                                          symbols,
                                                          relocations,
                                                          image,
                                                          error);
    }
    error = detect_error;
    return false;
}

bool load_binary_image(const std::string& path,
                       BinaryInfo& info,
                       std::vector<BinarySegment>& segments,
                       std::vector<BinarySection>& sections,
                       LoadedImage& image,
                       std::string& error) {
    std::string detect_error;
    const FileKind kind = detect_file_kind(path, detect_error);
    if (kind == FileKind::kElf) {
        ElfInfo elf_info;
        std::vector<ElfSegment> elf_segments;
        std::vector<ElfSection> elf_sections;
        if (!load_elf_image(path, elf_info, elf_segments, elf_sections, image, error)) {
            return false;
        }
        info = to_binary_info(elf_info);
        segments = to_binary_segments(elf_segments);
        sections = to_binary_sections(elf_sections);
        return true;
    }
    if (kind == FileKind::kPe) {
        return load_pe_image(path, info, segments, sections, image, error);
    }
    error = detect_error;
    return false;
}

}  // namespace engine
