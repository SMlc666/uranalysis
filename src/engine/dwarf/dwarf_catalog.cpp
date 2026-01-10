#include "dwarf_internal.h"

#include <algorithm>
#include <fstream>
#include <unordered_map>

#include "engine/mapped_file.h"

namespace {

bool read_section(const engine::LoadedImage &image,
                  const engine::BinarySection &section,
                  const engine::MappedFile *mapped_file, std::ifstream *file,
                  std::vector<std::uint8_t> &buffer,
                  std::span<const std::uint8_t> &view) {
  buffer.clear();
  view = {};
  if (section.size == 0) {
    return false;
  }
  if (mapped_file) {
    if (mapped_file->slice(section.offset, static_cast<std::size_t>(section.size),
                           view)) {
      return true;
    }
  }
  bool ok = false;
  if (section.addr != 0) {
    ok = image.read_bytes(section.addr, static_cast<std::size_t>(section.size),
                          buffer);
    if (ok) {
      view = std::span<const std::uint8_t>(buffer.data(), buffer.size());
      return true;
    }
    buffer.clear();
  }
  if (!file || !(*file)) {
    return false;
  }
  file->clear();
  file->seekg(static_cast<std::streamoff>(section.offset), std::ios::beg);
  if (!file->good()) {
    return false;
  }
  buffer.resize(static_cast<std::size_t>(section.size));
  file->read(reinterpret_cast<char *>(buffer.data()),
             static_cast<std::streamsize>(buffer.size()));
  if (!file->good()) {
    buffer.clear();
    return false;
  }
  view = std::span<const std::uint8_t>(buffer.data(), buffer.size());
  return true;
}

bool is_dwarf_section(const std::string &name) {
  return name.rfind(".debug", 0) == 0;
}

constexpr std::uint32_t kRelocAarch64Abs64 = 257;
constexpr std::uint32_t kRelocAarch64Abs32 = 258;
constexpr std::uint32_t kRelocAarch64Abs16 = 259;
constexpr std::uint32_t kRelocAarch64Prel32 = 261;

void write_u16_le(std::vector<std::uint8_t> &data, std::size_t offset,
                  std::uint16_t value) {
  data[offset] = static_cast<std::uint8_t>(value & 0xff);
  data[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
}

void write_u32_le(std::vector<std::uint8_t> &data, std::size_t offset,
                  std::uint32_t value) {
  data[offset] = static_cast<std::uint8_t>(value & 0xff);
  data[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
  data[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
  data[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

void write_u64_le(std::vector<std::uint8_t> &data, std::size_t offset,
                  std::uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i) {
    data[offset + i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
  }
}

bool apply_relocations_to_section(
    const engine::BinaryInfo &binary_info,
    const engine::BinarySection &section,
    const std::vector<const engine::BinaryRelocation *> &relocations,
    std::vector<std::uint8_t> &data) {
  if (!binary_info.little_endian) {
    return false;
  }
  if (data.empty() || relocations.empty()) {
    return true;
  }
  for (const auto *reloc : relocations) {
    if (!reloc) {
      continue;
    }
    std::uint64_t local_offset = reloc->offset;
    if (section.addr != 0 && reloc->offset >= section.addr) {
      local_offset = reloc->offset - section.addr;
    }
    std::uint64_t place = local_offset;
    if (section.addr != 0) {
      place = section.addr + local_offset;
    }
    std::size_t width = 0;
    std::uint64_t value = 0;
    switch (reloc->type) {
      case kRelocAarch64Abs64:
        width = 8;
        value = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(reloc->symbol_value) + reloc->addend);
        break;
      case kRelocAarch64Abs32:
        width = 4;
        value = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(reloc->symbol_value) + reloc->addend);
        break;
      case kRelocAarch64Abs16:
        width = 2;
        value = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(reloc->symbol_value) + reloc->addend);
        break;
      case kRelocAarch64Prel32:
        width = 4;
        value = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(reloc->symbol_value) + reloc->addend -
            static_cast<std::int64_t>(place));
        break;
      default:
        continue;
    }
    if (local_offset + width > data.size()) {
      continue;
    }
    switch (width) {
      case 2:
        write_u16_le(data, static_cast<std::size_t>(local_offset),
                     static_cast<std::uint16_t>(value));
        break;
      case 4:
        write_u32_le(data, static_cast<std::size_t>(local_offset),
                     static_cast<std::uint32_t>(value));
        break;
      case 8:
        write_u64_le(data, static_cast<std::size_t>(local_offset), value);
        break;
      default:
        break;
    }
  }
  return true;
}

std::span<const std::uint8_t>
find_section(const std::vector<engine::dwarf::SectionData> &sections,
             const std::string &name) {
  for (const auto &section : sections) {
    if (section.name == name) {
      return section.view;
    }
  }
  return {};
}

}  // namespace

namespace engine::dwarf {

DwarfCatalog::~DwarfCatalog() = default;

void DwarfCatalog::reset() {
  mapped_file_.reset();
  binary_info_ = {};
  debug_info_ = {};
  debug_abbrev_ = {};
  debug_str_ = {};
  debug_str_offsets_ = {};
  debug_line_str_ = {};
  debug_line_ = {};
  debug_ranges_ = {};
  debug_rnglists_ = {};
  debug_addr_ = {};
  debug_loc_ = {};
  debug_loclists_ = {};
  units_.clear();
  sections_.clear();
  functions_.clear();
  variables_.clear();
  line_rows_.clear();
  lines_sorted_ = false;
  errors_.clear();
  last_error_ = {};
}

void DwarfCatalog::record_error(DwarfErrorCode code,
                                const std::string &section,
                                std::uint64_t offset,
                                const std::string &message) {
  DwarfError err;
  err.code = code;
  err.message = message;
  err.section = section;
  err.offset = offset;
  errors_.push_back(err);
  last_error_ = err;
}

void DwarfCatalog::build_unit_index() {
  using namespace engine::dwarf::detail;

  units_.clear();
  lines_sorted_ = false;
  if (debug_info_.empty() || debug_abbrev_.empty()) {
    return;
  }

  Cursor cur{debug_info_, 0};
  while (cur.offset + 4 <= debug_info_.size()) {
    Unit unit;
    unit.offset = cur.offset;

    std::uint32_t unit_length32 = 0;
    if (!read_u32(cur, unit_length32)) {
      record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                   "failed to read unit length");
      break;
    }
    if (unit_length32 == 0) {
      break;
    }
    std::uint64_t unit_length = unit_length32;
    if (unit_length32 == 0xffffffffu) {
      unit.is_64 = true;
      if (!read_u64(cur, unit_length)) {
        record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                     "failed to read 64-bit unit length");
        break;
      }
    }
    const std::size_t header_start = cur.offset;
    unit.end = header_start + static_cast<std::size_t>(unit_length);
    if (unit.end > debug_info_.size()) {
      record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                   "unit length exceeds section size");
      break;
    }

    if (!read_u16(cur, unit.version)) {
      record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                   "failed to read unit version");
      cur.offset = unit.end;
      continue;
    }

    if (unit.version >= 5) {
      std::uint8_t unit_type = 0;
      if (!read_u8(cur, unit_type)) {
        record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                     "failed to read unit type");
        cur.offset = unit.end;
        continue;
      }
      if (!read_u8(cur, unit.address_size)) {
        record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                     "failed to read address size");
        cur.offset = unit.end;
        continue;
      }
      if (unit.is_64) {
        if (!read_u64(cur, unit.abbrev_offset)) {
          record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                       "failed to read abbrev offset");
          cur.offset = unit.end;
          continue;
        }
      } else {
        std::uint32_t off = 0;
        if (!read_u32(cur, off)) {
          record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                       "failed to read abbrev offset");
          cur.offset = unit.end;
          continue;
        }
        unit.abbrev_offset = off;
      }
      (void)unit_type;
    } else {
      if (unit.is_64) {
        if (!read_u64(cur, unit.abbrev_offset)) {
          record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                       "failed to read abbrev offset");
          cur.offset = unit.end;
          continue;
        }
      } else {
        std::uint32_t off = 0;
        if (!read_u32(cur, off)) {
          record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                       "failed to read abbrev offset");
          cur.offset = unit.end;
          continue;
        }
        unit.abbrev_offset = off;
      }
      if (!read_u8(cur, unit.address_size)) {
        record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                     "failed to read address size");
        cur.offset = unit.end;
        continue;
      }
    }

    if (unit.address_size == 0) {
      unit.address_size = binary_info_.is_64 ? 8 : 4;
    }

    unit.die_offset = cur.offset;

    AbbrevTable table;
    if (!parse_abbrev_table(debug_abbrev_,
                            static_cast<std::size_t>(unit.abbrev_offset),
                            table)) {
      record_error(DwarfErrorCode::kParse, ".debug_abbrev",
                   unit.abbrev_offset, "failed to parse abbrev table");
      cur.offset = unit.end;
      continue;
    }

    std::uint64_t abbrev_code = 0;
    if (!read_uleb128(cur, abbrev_code)) {
      record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                   "failed to read abbrev code");
      cur.offset = unit.end;
      continue;
    }
    if (abbrev_code != 0) {
      auto it = table.find(abbrev_code);
      if (it == table.end()) {
        record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                     "unknown abbrev code");
        cur.offset = unit.end;
        continue;
      }
      const AbbrevEntry &abbrev = it->second;
      const bool is_compile_unit = (abbrev.tag == kDwTagCompileUnit);
      AddrTable addr_table;

      for (const auto &attr : abbrev.attrs) {
        std::uint64_t uval = 0;
        std::int64_t sval = 0;
        std::string sval_str;
        std::vector<std::uint8_t> block;
        bool is_signed = false;
        bool is_string = false;
        bool is_block = false;
        bool is_addr_index = false;
        std::uint64_t unsupported_form = 0;
        if (!read_form_value(cur, attr.form, unit.address_size,
                             unit.is_64 ? 8 : 4, debug_str_, debug_str_offsets_,
                             debug_line_str_, unit.str_offsets_base, uval, sval,
                             sval_str, block, is_signed, is_string, is_block,
                             is_addr_index, &unsupported_form)) {
          if (unsupported_form != 0) {
            record_error(DwarfErrorCode::kUnsupportedForm, ".debug_info",
                         cur.offset,
                         "unsupported DWARF form " +
                             std::to_string(unsupported_form));
          } else {
            record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                         "failed to parse DWARF attribute");
          }
          cur.offset = unit.end;
          break;
        }

        std::uint64_t value =
            is_signed ? static_cast<std::uint64_t>(sval) : uval;
        if (is_addr_index) {
          std::uint64_t resolved = 0;
          if (resolve_addr_index(addr_table.valid ? &addr_table : nullptr, value,
                                 resolved)) {
            value = resolved;
          } else {
            value = 0;
          }
        }

        switch (attr.name) {
          case kDwAtLowPc:
            unit.low_pc = value;
            unit.has_low_pc = true;
            break;
          case kDwAtHighPc:
            unit.high_pc = value;
            unit.has_high_pc = true;
            unit.high_pc_is_addr = (attr.form == kDwFormAddr || is_addr_index);
            break;
          case kDwAtRanges:
            unit.has_ranges = true;
            unit.ranges_offset = value;
            unit.ranges_is_index = (attr.form == kDwFormRnglistx);
            break;
          case kDwAtStmtList:
            unit.has_stmt_list = true;
            unit.stmt_list_offset = value;
            break;
          case kDwAtStrOffsetsBase:
            unit.str_offsets_base = value;
            break;
          case kDwAtAddrBase:
            if (is_compile_unit) {
              unit.addr_base = value;
              if (!debug_addr_.empty()) {
                read_addr_table(debug_addr_, unit.addr_base, addr_table);
              }
            }
            break;
          case kDwAtRnglistsBase:
            unit.rnglists_base = value;
            break;
          case kDwAtLoclistsBase:
            unit.loclists_base = value;
            break;
          default:
            break;
        }
      }

      if (unit.has_low_pc && unit.has_high_pc) {
        if (!unit.high_pc_is_addr) {
          unit.high_pc = unit.low_pc + unit.high_pc;
        }
      }

      if (unit.has_ranges) {
        const std::uint64_t base = unit.has_low_pc ? unit.low_pc : 0;
        if (unit.version >= 5 && !debug_rnglists_.empty()) {
          std::uint64_t list_offset = unit.ranges_offset;
          if (unit.ranges_is_index) {
            std::uint64_t resolved = 0;
            if (!resolve_indexed_offset(debug_rnglists_, unit.rnglists_base,
                                        unit.ranges_offset,
                                        unit.is_64 ? 8U : 4U, resolved)) {
              cur.offset = unit.end;
              break;
            }
            list_offset = resolved;
          }
          parse_rnglists_v5(debug_rnglists_, list_offset, unit.address_size,
                            base, addr_table.valid ? &addr_table : nullptr,
                            unit.ranges);
        } else if (!debug_ranges_.empty()) {
          parse_ranges_v4(debug_ranges_, unit.ranges_offset, unit.address_size,
                          base, unit.ranges);
        }
      }
    }

    units_.push_back(std::move(unit));
    cur.offset = unit.end;
  }
}

void DwarfCatalog::parse_unit(Unit &unit) {
  using namespace engine::dwarf::detail;

  if (unit.parsed) {
    return;
  }
  if (debug_info_.empty() || debug_abbrev_.empty()) {
    return;
  }

  AbbrevTable table;
  if (!parse_abbrev_table(debug_abbrev_,
                          static_cast<std::size_t>(unit.abbrev_offset),
                          table)) {
    record_error(DwarfErrorCode::kParse, ".debug_abbrev", unit.abbrev_offset,
                 "failed to parse abbrev table");
    unit.parsed = true;
    return;
  }

  AddrTable addr_table;
  if (unit.addr_base != 0 && !debug_addr_.empty()) {
    read_addr_table(debug_addr_, unit.addr_base, addr_table);
  }

  Cursor cur{debug_info_, unit.die_offset};
  std::vector<bool> child_stack;
  std::uint64_t str_offsets_base = unit.str_offsets_base;
  std::uint64_t rnglists_base = unit.rnglists_base;
  std::uint64_t loclists_base = unit.loclists_base;
  std::uint64_t cu_base = unit.has_low_pc ? unit.low_pc : 0;

  while (cur.offset < unit.end) {
    std::uint64_t abbrev_code = 0;
    if (!read_uleb128(cur, abbrev_code)) {
      record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                   "failed to read abbrev code");
      break;
    }
    if (abbrev_code == 0) {
      if (!child_stack.empty()) {
        child_stack.pop_back();
      }
      continue;
    }
    auto it = table.find(abbrev_code);
    if (it == table.end()) {
      record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                   "unknown abbrev code");
      break;
    }
    const AbbrevEntry &abbrev = it->second;

    bool is_subprogram = (abbrev.tag == kDwTagSubprogram);
    bool is_variable =
        (abbrev.tag == kDwTagVariable || abbrev.tag == kDwTagFormalParameter);
    bool is_compile_unit = (abbrev.tag == kDwTagCompileUnit);
    DwarfFunction func;
    DwarfVariable var;
    func.cu_offset = unit.offset;
    var.cu_offset = unit.offset;
    bool has_low_pc = false;
    bool high_pc_is_addr = false;
    std::uint64_t high_pc_value = 0;
    bool has_ranges = false;
    std::uint64_t ranges_offset = 0;
    bool ranges_is_index = false;

    for (const auto &attr : abbrev.attrs) {
      std::uint64_t uval = 0;
      std::int64_t sval = 0;
      std::string sval_str;
      std::vector<std::uint8_t> block;
      bool is_signed = false;
      bool is_string = false;
      bool is_block = false;
      bool is_addr_index = false;
      std::uint64_t unsupported_form = 0;
      if (!read_form_value(cur, attr.form, unit.address_size,
                           unit.is_64 ? 8 : 4, debug_str_, debug_str_offsets_,
                           debug_line_str_, str_offsets_base, uval, sval,
                           sval_str, block, is_signed, is_string, is_block,
                           is_addr_index, &unsupported_form)) {
        if (unsupported_form != 0) {
          record_error(DwarfErrorCode::kUnsupportedForm, ".debug_info",
                       cur.offset,
                       "unsupported DWARF form " +
                           std::to_string(unsupported_form));
        } else {
          record_error(DwarfErrorCode::kParse, ".debug_info", cur.offset,
                       "failed to parse DWARF attribute");
        }
        cur.offset = unit.end;
        break;
      }

      std::uint64_t value =
          is_signed ? static_cast<std::uint64_t>(sval) : uval;
      if (is_addr_index) {
        std::uint64_t resolved = 0;
        if (resolve_addr_index(addr_table.valid ? &addr_table : nullptr, value,
                               resolved)) {
          value = resolved;
        } else {
          value = 0;
        }
      }

      switch (attr.name) {
        case kDwAtName:
          if (is_string) {
            func.name = sval_str;
            var.name = sval_str;
          }
          break;
        case kDwAtLinkageName:
        case kDwAtMipsLinkageName:
          if (is_string) {
            func.linkage_name = sval_str;
            var.linkage_name = sval_str;
          }
          break;
        case kDwAtLowPc:
          func.low_pc = value;
          has_low_pc = true;
          break;
        case kDwAtHighPc:
          high_pc_value = value;
          high_pc_is_addr = (attr.form == kDwFormAddr || is_addr_index);
          break;
        case kDwAtType:
          func.type_offset = value;
          var.type_offset = value;
          break;
        case kDwAtLocation:
          if (is_block) {
            var.location_expr = std::move(block);
            var.location_list.clear();
          } else if ((attr.form == kDwFormSecOffset ||
                      attr.form == kDwFormLoclistx) &&
                     (!debug_loc_.empty() || !debug_loclists_.empty())) {
            var.location_expr.clear();
            var.location_list.clear();
            std::uint64_t list_offset = value;
            if (unit.version >= 5 && !debug_loclists_.empty()) {
              if (attr.form == kDwFormLoclistx) {
                std::uint64_t resolved = 0;
                if (resolve_indexed_offset(debug_loclists_, loclists_base, value,
                                           unit.is_64 ? 8U : 4U, resolved)) {
                  list_offset = resolved;
                } else {
                  break;
                }
              }
              parse_loclists_v5(
                  debug_loclists_, list_offset, unit.address_size, cu_base,
                  addr_table.valid ? &addr_table : nullptr, var.location_list);
            } else if (!debug_loc_.empty()) {
              parse_loc_v4(debug_loc_, list_offset, unit.address_size, cu_base,
                           var.location_list);
            }
          }
          break;
        case kDwAtDeclFile:
          func.decl_file = static_cast<std::uint16_t>(value);
          break;
        case kDwAtDeclLine:
          func.decl_line = static_cast<std::uint32_t>(value);
          break;
        case kDwAtRanges:
          has_ranges = true;
          ranges_offset = value;
          ranges_is_index = (attr.form == kDwFormRnglistx);
          break;
        case kDwAtStrOffsetsBase:
          str_offsets_base = value;
          break;
        case kDwAtAddrBase:
          if (is_compile_unit) {
            unit.addr_base = value;
            if (!debug_addr_.empty()) {
              read_addr_table(debug_addr_, unit.addr_base, addr_table);
            }
          }
          break;
        case kDwAtRnglistsBase:
          rnglists_base = value;
          break;
        case kDwAtLoclistsBase:
          loclists_base = value;
          break;
        default:
          break;
      }
    }

    auto parse_ranges = [&](DwarfFunction &target) {
      if (!has_ranges) {
        return;
      }
      if (unit.version >= 5 && !debug_rnglists_.empty()) {
        std::uint64_t list_offset = ranges_offset;
        if (ranges_is_index) {
          std::uint64_t resolved = 0;
          if (!resolve_indexed_offset(debug_rnglists_, rnglists_base,
                                      ranges_offset, unit.is_64 ? 8U : 4U,
                                      resolved)) {
            return;
          }
          list_offset = resolved;
        }
        parse_rnglists_v5(debug_rnglists_, list_offset, unit.address_size,
                          cu_base, addr_table.valid ? &addr_table : nullptr,
                          target.ranges);
      } else if (!debug_ranges_.empty()) {
        parse_ranges_v4(debug_ranges_, ranges_offset, unit.address_size, cu_base,
                        target.ranges);
      }
    };

    if (is_compile_unit && has_low_pc) {
      cu_base = func.low_pc;
    }

    if (is_subprogram && has_low_pc) {
      func.high_pc =
          high_pc_is_addr ? high_pc_value : (func.low_pc + high_pc_value);
      parse_ranges(func);
      functions_.push_back(std::move(func));
    } else if (is_variable) {
      if (!var.name.empty() || !var.linkage_name.empty()) {
        variables_.push_back(std::move(var));
      }
    } else if (is_subprogram && has_ranges) {
      parse_ranges(func);
      if (!func.ranges.empty()) {
        std::uint64_t min_pc = func.ranges.front().start;
        std::uint64_t max_pc = func.ranges.front().end;
        for (const auto &range : func.ranges) {
          if (range.start < min_pc) {
            min_pc = range.start;
          }
          if (range.end > max_pc) {
            max_pc = range.end;
          }
        }
        func.low_pc = min_pc;
        func.high_pc = max_pc;
        functions_.push_back(std::move(func));
      }
    } else if (is_compile_unit) {
      // base attributes handled above
    }

    if (abbrev.has_children) {
      child_stack.push_back(true);
    }
  }

  unit.parsed = true;
}

void DwarfCatalog::parse_line_table_for_unit(Unit &unit) {
  using namespace engine::dwarf::detail;

  if (unit.lines_parsed) {
    return;
  }
  if (!unit.has_stmt_list || debug_line_.empty()) {
    unit.lines_parsed = true;
    return;
  }
  if (!parse_line_table(debug_line_, debug_str_, debug_str_offsets_,
                        debug_line_str_, unit.stmt_list_offset, unit.offset,
                        unit.address_size, unit.is_64 ? 8U : 4U,
                        unit.str_offsets_base, line_rows_)) {
    record_error(DwarfErrorCode::kParse, ".debug_line",
                 unit.stmt_list_offset, "failed to parse line table");
  }
  unit.lines_parsed = true;
  lines_sorted_ = false;
}

void DwarfCatalog::ensure_all_units_parsed() {
  for (auto &unit : units_) {
    parse_unit(unit);
  }
}

void DwarfCatalog::ensure_units_for_address(std::uint64_t addr) {
  bool parsed_any = false;
  for (auto &unit : units_) {
    if (unit.parsed) {
      continue;
    }
    bool matches = false;
    for (const auto &range : unit.ranges) {
      if (addr >= range.start && addr < range.end) {
        matches = true;
        break;
      }
    }
    if (!matches && unit.has_low_pc && unit.has_high_pc &&
        unit.high_pc > unit.low_pc) {
      matches = (addr >= unit.low_pc && addr < unit.high_pc);
    }
    if (matches) {
      parse_unit(unit);
      parsed_any = true;
    }
  }
  if (!parsed_any) {
    ensure_all_units_parsed();
  }
}

void DwarfCatalog::ensure_all_lines_parsed() {
  for (auto &unit : units_) {
    parse_line_table_for_unit(unit);
  }
  ensure_lines_sorted();
}

void DwarfCatalog::ensure_lines_for_address(std::uint64_t addr) {
  bool parsed_any = false;
  for (auto &unit : units_) {
    if (unit.lines_parsed) {
      continue;
    }
    bool matches = false;
    for (const auto &range : unit.ranges) {
      if (addr >= range.start && addr < range.end) {
        matches = true;
        break;
      }
    }
    if (!matches && unit.has_low_pc && unit.has_high_pc &&
        unit.high_pc > unit.low_pc) {
      matches = (addr >= unit.low_pc && addr < unit.high_pc);
    }
    if (matches) {
      parse_line_table_for_unit(unit);
      parsed_any = true;
    }
  }
  if (!parsed_any) {
    ensure_all_lines_parsed();
  }
}

void DwarfCatalog::ensure_lines_sorted() {
  if (lines_sorted_ || line_rows_.empty()) {
    return;
  }
  std::sort(line_rows_.begin(), line_rows_.end(),
            [](const DwarfLineRow &lhs, const DwarfLineRow &rhs) {
              if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
              }
              if (lhs.cu_offset != rhs.cu_offset) {
                return lhs.cu_offset < rhs.cu_offset;
              }
              return lhs.line < rhs.line;
            });
  lines_sorted_ = true;
}

void DwarfCatalog::discover(const std::string &path,
                            const std::vector<BinarySection> &sections,
                            const LoadedImage &image,
                            const BinaryInfo &binary_info,
                            const std::vector<BinaryRelocation> &relocations) {
  reset();
  std::vector<std::uint8_t> buffer;
  std::ifstream file;
  if (!path.empty()) {
    mapped_file_ = std::make_unique<engine::MappedFile>();
    std::string map_error;
    if (!mapped_file_->open(path, map_error)) {
      mapped_file_.reset();
      file.open(path, std::ios::binary);
    }
  }

  std::unordered_map<std::string,
                     std::vector<const engine::BinaryRelocation *>>
      relocations_by_section;
  relocations_by_section.reserve(relocations.size());
  for (const auto &reloc : relocations) {
    if (reloc.target_section.empty()) {
      continue;
    }
    relocations_by_section[reloc.target_section].push_back(&reloc);
  }

  for (const auto &section : sections) {
    if (!is_dwarf_section(section.name)) {
      continue;
    }
    std::span<const std::uint8_t> view;
    if (!read_section(image, section, mapped_file_.get(), file ? &file : nullptr,
                      buffer, view)) {
      continue;
    }
    SectionData data;
    data.name = section.name;
    data.address = section.addr;
    auto reloc_it = relocations_by_section.find(section.name);
    if (reloc_it != relocations_by_section.end() &&
        !reloc_it->second.empty()) {
      if (buffer.empty()) {
        buffer.assign(view.begin(), view.end());
      }
      apply_relocations_to_section(binary_info, section, reloc_it->second,
                                   buffer);
    }
    if (!buffer.empty()) {
      data.data = buffer;
      data.view =
          std::span<const std::uint8_t>(data.data.data(), data.data.size());
    } else {
      data.view = view;
    }
    sections_.push_back(std::move(data));
  }

  const auto debug_info = find_section(sections_, ".debug_info");
  const auto debug_abbrev = find_section(sections_, ".debug_abbrev");
  const auto debug_str = find_section(sections_, ".debug_str");
  const auto debug_str_offsets = find_section(sections_, ".debug_str_offsets");
  const auto debug_line_str = find_section(sections_, ".debug_line_str");
  const auto debug_line = find_section(sections_, ".debug_line");
  const auto debug_ranges = find_section(sections_, ".debug_ranges");
  const auto debug_rnglists = find_section(sections_, ".debug_rnglists");
  const auto debug_addr = find_section(sections_, ".debug_addr");
  const auto debug_loc = find_section(sections_, ".debug_loc");
  const auto debug_loclists = find_section(sections_, ".debug_loclists");
  if (debug_info.empty() || debug_abbrev.empty()) {
    record_error(DwarfErrorCode::kMissingSection,
                 debug_info.empty() ? ".debug_info" : ".debug_abbrev", 0,
                 "missing DWARF section");
    return;
  }

  binary_info_ = binary_info;
  debug_info_ = debug_info;
  debug_abbrev_ = debug_abbrev;
  debug_str_ = debug_str;
  debug_str_offsets_ = debug_str_offsets;
  debug_line_str_ = debug_line_str;
  debug_line_ = debug_line;
  debug_ranges_ = debug_ranges;
  debug_rnglists_ = debug_rnglists;
  debug_addr_ = debug_addr;
  debug_loc_ = debug_loc;
  debug_loclists_ = debug_loclists;

  build_unit_index();
  if (!lazy_parse_) {
    ensure_all_units_parsed();
    ensure_all_lines_parsed();
  }
}

const std::vector<SectionData> &DwarfCatalog::sections() const {
  return sections_;
}

const std::vector<DwarfFunction> &DwarfCatalog::functions() const {
  auto *self = const_cast<DwarfCatalog *>(this);
  self->ensure_all_units_parsed();
  return functions_;
}

const std::vector<DwarfVariable> &DwarfCatalog::variables() const {
  auto *self = const_cast<DwarfCatalog *>(this);
  self->ensure_all_units_parsed();
  return variables_;
}

const std::vector<DwarfLineRow> &DwarfCatalog::line_rows() const {
  auto *self = const_cast<DwarfCatalog *>(this);
  self->ensure_all_lines_parsed();
  return line_rows_;
}

const DwarfFunction *
DwarfCatalog::find_function_by_address(std::uint64_t addr) const {
  auto *self = const_cast<DwarfCatalog *>(this);
  self->ensure_units_for_address(addr);
  for (const auto &func : functions_) {
    if (func.low_pc != 0 && func.high_pc > func.low_pc) {
      if (addr >= func.low_pc && addr < func.high_pc) {
        return &func;
      }
    }
    for (const auto &range : func.ranges) {
      if (addr >= range.start && addr < range.end) {
        return &func;
      }
    }
  }
  return nullptr;
}

const DwarfLineRow *
DwarfCatalog::find_line_for_address(std::uint64_t addr) const {
  auto *self = const_cast<DwarfCatalog *>(this);
  self->ensure_lines_for_address(addr);
  self->ensure_lines_sorted();
  if (line_rows_.empty()) {
    return nullptr;
  }
  auto it = std::upper_bound(line_rows_.begin(), line_rows_.end(), addr,
                             [](std::uint64_t value, const DwarfLineRow &row) {
                               return value < row.address;
                             });
  if (it == line_rows_.begin()) {
    return nullptr;
  }
  --it;
  return &(*it);
}

const DwarfError *DwarfCatalog::last_error() const {
  if (last_error_.code == DwarfErrorCode::kNone) {
    return nullptr;
  }
  return &last_error_;
}

const std::vector<DwarfError> &DwarfCatalog::errors() const {
  return errors_;
}

}  // namespace engine::dwarf
