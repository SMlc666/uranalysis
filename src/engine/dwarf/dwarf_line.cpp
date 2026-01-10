#include "dwarf_internal.h"

namespace engine::dwarf::detail {
namespace {

struct LineFileEntry {
  std::string name;
  std::uint64_t dir_index = 0;
};

std::string join_path(const std::string &dir, const std::string &name) {
  if (dir.empty()) {
    return name;
  }
  if (name.empty()) {
    return dir;
  }
  if (dir.back() == '/' || dir.back() == '\\') {
    return dir + name;
  }
  return dir + "/" + name;
}

}  // namespace

bool parse_line_table(std::span<const std::uint8_t> debug_line,
                      std::span<const std::uint8_t> debug_str,
                      std::span<const std::uint8_t> debug_str_offsets,
                      std::span<const std::uint8_t> debug_line_str,
                      std::uint64_t offset, std::uint64_t cu_offset,
                      std::uint8_t cu_address_size, std::size_t offset_size,
                      std::uint64_t str_offsets_base,
                      std::vector<DwarfLineRow> &out) {
  (void)offset_size;
  if (debug_line.empty() || offset >= debug_line.size()) {
    return false;
  }
  Cursor cur{debug_line, static_cast<std::size_t>(offset)};

  std::uint32_t unit_length32 = 0;
  if (!read_u32(cur, unit_length32)) {
    return false;
  }
  if (unit_length32 == 0) {
    return false;
  }
  bool is_64 = false;
  std::uint64_t unit_length = unit_length32;
  if (unit_length32 == 0xffffffffu) {
    if (!read_u64(cur, unit_length)) {
      return false;
    }
    is_64 = true;
  }
  const std::size_t line_offset_size = is_64 ? 8U : 4U;
  const std::size_t header_start = cur.offset;
  const std::size_t unit_end =
      header_start + static_cast<std::size_t>(unit_length);
  if (unit_end > debug_line.size()) {
    return false;
  }

  std::uint16_t version = 0;
  if (!read_u16(cur, version)) {
    return false;
  }

  std::uint8_t address_size = cu_address_size;
  std::uint8_t segment_selector_size = 0;
  if (version >= 5) {
    if (!read_u8(cur, address_size)) {
      return false;
    }
    if (!read_u8(cur, segment_selector_size)) {
      return false;
    }
  }
  (void)segment_selector_size;

  auto read_offset = [&](std::uint64_t &out_val) -> bool {
    if (is_64) {
      return read_u64(cur, out_val);
    }
    std::uint32_t v = 0;
    if (!read_u32(cur, v)) {
      return false;
    }
    out_val = v;
    return true;
  };

  std::uint64_t header_length = 0;
  if (!read_offset(header_length)) {
    return false;
  }
  const std::size_t prologue_end =
      cur.offset + static_cast<std::size_t>(header_length);
  if (prologue_end > unit_end) {
    return false;
  }

  std::uint8_t min_inst_length = 1;
  if (!read_u8(cur, min_inst_length)) {
    return false;
  }
  std::uint8_t max_ops_per_insn = 1;
  if (version >= 4) {
    if (!read_u8(cur, max_ops_per_insn)) {
      return false;
    }
  }
  (void)max_ops_per_insn;
  std::uint8_t default_is_stmt = 0;
  if (!read_u8(cur, default_is_stmt)) {
    return false;
  }
  std::uint8_t line_base_u = 0;
  if (!read_u8(cur, line_base_u)) {
    return false;
  }
  const std::int8_t line_base = static_cast<std::int8_t>(line_base_u);
  std::uint8_t line_range = 0;
  if (!read_u8(cur, line_range)) {
    return false;
  }
  std::uint8_t opcode_base = 0;
  if (!read_u8(cur, opcode_base)) {
    return false;
  }
  for (std::uint8_t i = 1; i < opcode_base; ++i) {
    std::uint8_t tmp = 0;
    if (!read_u8(cur, tmp)) {
      return false;
    }
  }

  std::vector<std::string> directories;
  std::vector<LineFileEntry> files;

  if (version < 5) {
    while (cur.offset < prologue_end) {
      std::string dir;
      if (!read_cstring(cur, dir)) {
        return false;
      }
      if (dir.empty()) {
        break;
      }
      directories.push_back(dir);
    }

    while (cur.offset < prologue_end) {
      std::string name;
      if (!read_cstring(cur, name)) {
        return false;
      }
      if (name.empty()) {
        break;
      }
      std::uint64_t dir_index = 0;
      std::uint64_t time = 0;
      std::uint64_t size = 0;
      if (!read_uleb128(cur, dir_index) || !read_uleb128(cur, time) ||
          !read_uleb128(cur, size)) {
        return false;
      }
      (void)time;
      (void)size;
      files.push_back({name, dir_index});
    }
  } else {
    std::uint64_t dir_fmt_count = 0;
    if (!read_uleb128(cur, dir_fmt_count)) {
      return false;
    }
    struct LineFormat {
      std::uint64_t content = 0;
      std::uint64_t form = 0;
    };
    std::vector<LineFormat> dir_formats;
    for (std::uint64_t i = 0; i < dir_fmt_count; ++i) {
      LineFormat fmt;
      if (!read_uleb128(cur, fmt.content) || !read_uleb128(cur, fmt.form)) {
        return false;
      }
      dir_formats.push_back(fmt);
    }
    std::uint64_t dir_count = 0;
    if (!read_uleb128(cur, dir_count)) {
      return false;
    }
    for (std::uint64_t i = 0; i < dir_count; ++i) {
      std::string path;
      for (const auto &fmt : dir_formats) {
        std::uint64_t uval = 0;
        std::int64_t sval = 0;
        std::string sval_str;
        std::vector<std::uint8_t> block;
        bool is_signed = false;
        bool is_string = false;
        bool is_block = false;
        bool is_addr_index = false;
        if (!read_form_value(cur, fmt.form, address_size, line_offset_size,
                             debug_str, debug_str_offsets, debug_line_str,
                             str_offsets_base, uval, sval, sval_str, block,
                             is_signed, is_string, is_block, is_addr_index,
                             nullptr)) {
          return false;
        }
        if (fmt.content == kDwLnctPath && is_string) {
          path = sval_str;
        }
      }
      if (!path.empty()) {
        directories.push_back(path);
      }
    }

    std::uint64_t file_fmt_count = 0;
    if (!read_uleb128(cur, file_fmt_count)) {
      return false;
    }
    std::vector<LineFormat> file_formats;
    for (std::uint64_t i = 0; i < file_fmt_count; ++i) {
      LineFormat fmt;
      if (!read_uleb128(cur, fmt.content) || !read_uleb128(cur, fmt.form)) {
        return false;
      }
      file_formats.push_back(fmt);
    }
    std::uint64_t file_count = 0;
    if (!read_uleb128(cur, file_count)) {
      return false;
    }
    for (std::uint64_t i = 0; i < file_count; ++i) {
      std::string path;
      std::uint64_t dir_index = 0;
      for (const auto &fmt : file_formats) {
        std::uint64_t uval = 0;
        std::int64_t sval = 0;
        std::string sval_str;
        std::vector<std::uint8_t> block;
        bool is_signed = false;
        bool is_string = false;
        bool is_block = false;
        bool is_addr_index = false;
        if (!read_form_value(cur, fmt.form, address_size, line_offset_size,
                             debug_str, debug_str_offsets, debug_line_str,
                             str_offsets_base, uval, sval, sval_str, block,
                             is_signed, is_string, is_block, is_addr_index,
                             nullptr)) {
          return false;
        }
        const std::uint64_t value =
            is_signed ? static_cast<std::uint64_t>(sval) : uval;
        if (fmt.content == kDwLnctPath && is_string) {
          path = sval_str;
        } else if (fmt.content == kDwLnctDirectoryIndex) {
          dir_index = value;
        }
      }
      if (!path.empty()) {
        files.push_back({path, dir_index});
      }
    }
  }

  if (cur.offset < prologue_end) {
    cur.offset = prologue_end;
  }

  auto resolve_file = [&](std::uint64_t index) -> std::string {
    if (index == 0 || index > files.size()) {
      return {};
    }
    const auto &entry = files[static_cast<std::size_t>(index - 1)];
    if (entry.dir_index == 0 || entry.dir_index > directories.size()) {
      return entry.name;
    }
    return join_path(directories[entry.dir_index - 1], entry.name);
  };

  std::uint64_t address = 0;
  std::uint32_t line = 1;
  std::uint64_t file = 1;
  bool is_stmt = default_is_stmt != 0;
  bool end_sequence = false;

  while (cur.offset < unit_end) {
    std::uint8_t opcode = 0;
    if (!read_u8(cur, opcode)) {
      return false;
    }
    if (opcode == 0) {
      std::uint64_t ext_len = 0;
      if (!read_uleb128(cur, ext_len)) {
        return false;
      }
      if (ext_len == 0) {
        continue;
      }
      const std::size_t ext_start = cur.offset;
      std::uint8_t sub_opcode = 0;
      if (!read_u8(cur, sub_opcode)) {
        return false;
      }
      switch (sub_opcode) {
      case kDwLneEndSequence:
        end_sequence = true;
        out.push_back({address, line, resolve_file(file), cu_offset});
        address = 0;
        line = 1;
        file = 1;
        is_stmt = default_is_stmt != 0;
        end_sequence = false;
        break;
      case kDwLneSetAddress: {
        std::uint64_t addr = 0;
        if (!read_address(cur, address_size, addr)) {
          return false;
        }
        address = addr;
        break;
      }
      case kDwLneDefineFile: {
        std::string name;
        if (!read_cstring(cur, name)) {
          return false;
        }
        std::uint64_t dir_index = 0;
        std::uint64_t time = 0;
        std::uint64_t size = 0;
        if (!read_uleb128(cur, dir_index) || !read_uleb128(cur, time) ||
            !read_uleb128(cur, size)) {
          return false;
        }
        (void)time;
        (void)size;
        files.push_back({name, dir_index});
        break;
      }
      case kDwLneSetDiscriminator: {
        std::uint64_t discard = 0;
        if (!read_uleb128(cur, discard)) {
          return false;
        }
        (void)discard;
        break;
      }
      default:
        cur.offset = ext_start + static_cast<std::size_t>(ext_len);
        break;
      }
      if (end_sequence) {
        break;
      }
      continue;
    }
    if (opcode < opcode_base) {
      switch (opcode) {
      case kDwLnsCopy:
        out.push_back({address, line, resolve_file(file), cu_offset});
        break;
      case kDwLnsAdvancePc: {
        std::uint64_t advance = 0;
        if (!read_uleb128(cur, advance)) {
          return false;
        }
        address += advance * min_inst_length;
        break;
      }
      case kDwLnsAdvanceLine: {
        std::int64_t delta = 0;
        if (!read_sleb128(cur, delta)) {
          return false;
        }
        line = static_cast<std::uint32_t>(
            static_cast<std::int64_t>(line) + delta);
        break;
      }
      case kDwLnsSetFile: {
        std::uint64_t index = 0;
        if (!read_uleb128(cur, index)) {
          return false;
        }
        file = index;
        break;
      }
      case kDwLnsSetColumn: {
        std::uint64_t column = 0;
        if (!read_uleb128(cur, column)) {
          return false;
        }
        (void)column;
        break;
      }
      case kDwLnsNegateStmt:
        is_stmt = !is_stmt;
        break;
      case kDwLnsSetBasicBlock:
        break;
      case kDwLnsConstAddPc:
        address +=
            ((255 - opcode_base) / line_range) * min_inst_length;
        break;
      case kDwLnsFixedAdvancePc: {
        std::uint16_t advance = 0;
        if (!read_u16(cur, advance)) {
          return false;
        }
        address += advance;
        break;
      }
      default:
        break;
      }
      continue;
    }

    const std::uint8_t adjusted_opcode = opcode - opcode_base;
    const std::uint64_t addr_increment =
        (adjusted_opcode / line_range) * min_inst_length;
    const std::int64_t line_increment =
        line_base + (adjusted_opcode % line_range);
    address += addr_increment;
    line = static_cast<std::uint32_t>(
        static_cast<std::int64_t>(line) + line_increment);
    out.push_back({address, line, resolve_file(file), cu_offset});
  }

  return true;
}

}  // namespace engine::dwarf::detail
