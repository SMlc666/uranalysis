#include "dwarf_internal.h"

namespace engine::dwarf::detail {

bool read_u8(Cursor &cur, std::uint8_t &out) {
  if (cur.data.empty() || cur.offset + 1 > cur.data.size()) {
    return false;
  }
  out = cur.data[cur.offset++];
  return true;
}

bool read_u16(Cursor &cur, std::uint16_t &out) {
  if (cur.data.empty() || cur.offset + 2 > cur.data.size()) {
    return false;
  }
  out = static_cast<std::uint16_t>(cur.data[cur.offset]) |
        static_cast<std::uint16_t>(cur.data[cur.offset + 1] << 8);
  cur.offset += 2;
  return true;
}

bool read_u32(Cursor &cur, std::uint32_t &out) {
  if (cur.data.empty() || cur.offset + 4 > cur.data.size()) {
    return false;
  }
  out = static_cast<std::uint32_t>(cur.data[cur.offset]) |
        (static_cast<std::uint32_t>(cur.data[cur.offset + 1]) << 8) |
        (static_cast<std::uint32_t>(cur.data[cur.offset + 2]) << 16) |
        (static_cast<std::uint32_t>(cur.data[cur.offset + 3]) << 24);
  cur.offset += 4;
  return true;
}

bool read_u64(Cursor &cur, std::uint64_t &out) {
  if (cur.data.empty() || cur.offset + 8 > cur.data.size()) {
    return false;
  }
  out = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    out |= static_cast<std::uint64_t>(cur.data[cur.offset + i]) << (i * 8);
  }
  cur.offset += 8;
  return true;
}

bool read_u24(Cursor &cur, std::uint32_t &out) {
  if (cur.data.empty() || cur.offset + 3 > cur.data.size()) {
    return false;
  }
  out = static_cast<std::uint32_t>(cur.data[cur.offset]) |
        (static_cast<std::uint32_t>(cur.data[cur.offset + 1]) << 8) |
        (static_cast<std::uint32_t>(cur.data[cur.offset + 2]) << 16);
  cur.offset += 3;
  return true;
}

bool read_uleb128(Cursor &cur, std::uint64_t &out) {
  out = 0;
  std::uint32_t shift = 0;
  while (!cur.data.empty() && cur.offset < cur.data.size()) {
    std::uint8_t byte = cur.data[cur.offset++];
    out |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
    if ((byte & 0x80) == 0) {
      return true;
    }
    shift += 7;
    if (shift >= 64) {
      return false;
    }
  }
  return false;
}

bool read_sleb128(Cursor &cur, std::int64_t &out) {
  out = 0;
  std::uint32_t shift = 0;
  std::uint8_t byte = 0;
  while (!cur.data.empty() && cur.offset < cur.data.size()) {
    byte = cur.data[cur.offset++];
    out |= static_cast<std::int64_t>(byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) == 0) {
      break;
    }
    if (shift >= 64) {
      return false;
    }
  }
  if ((shift < 64) && (byte & 0x40)) {
    out |= -((static_cast<std::int64_t>(1)) << shift);
  }
  return true;
}

bool read_address(Cursor &cur, std::uint8_t address_size, std::uint64_t &out) {
  if (address_size == 8) {
    return read_u64(cur, out);
  }
  std::uint32_t value = 0;
  if (!read_u32(cur, value)) {
    return false;
  }
  out = value;
  return true;
}

bool read_cstring(Cursor &cur, std::string &out) {
  if (cur.data.empty()) {
    return false;
  }
  out.clear();
  while (cur.offset < cur.data.size()) {
    char ch = static_cast<char>(cur.data[cur.offset++]);
    if (ch == '\0') {
      return true;
    }
    out.push_back(ch);
  }
  return false;
}

bool read_string_at(std::span<const std::uint8_t> data, std::uint64_t offset,
                    std::string &out) {
  if (data.empty() || offset >= data.size()) {
    return false;
  }
  std::size_t pos = static_cast<std::size_t>(offset);
  out.clear();
  while (pos < data.size()) {
    char ch = static_cast<char>(data[pos++]);
    if (ch == '\0') {
      return true;
    }
    out.push_back(ch);
  }
  return false;
}

bool read_offset_at(std::span<const std::uint8_t> data, std::uint64_t offset,
                    std::size_t size, std::uint64_t &out) {
  if (data.empty() || offset + size > data.size()) {
    return false;
  }
  out = 0;
  for (std::size_t i = 0; i < size; ++i) {
    out |= static_cast<std::uint64_t>(data[static_cast<std::size_t>(offset) + i])
           << (i * 8);
  }
  return true;
}

bool resolve_strx(std::span<const std::uint8_t> debug_str_offsets,
                  std::span<const std::uint8_t> debug_str,
                  std::uint64_t str_offsets_base, std::uint64_t index,
                  std::size_t offset_size, std::string &out) {
  if (debug_str_offsets.empty() || debug_str.empty() || offset_size == 0) {
    return false;
  }
  std::uint64_t str_offset = 0;
  const std::uint64_t entry_offset = str_offsets_base + (index * offset_size);
  if (!read_offset_at(debug_str_offsets, entry_offset, offset_size,
                      str_offset)) {
    return false;
  }
  return read_string_at(debug_str, str_offset, out);
}

bool resolve_indexed_offset(std::span<const std::uint8_t> data,
                            std::uint64_t base, std::uint64_t index,
                            std::size_t offset_size, std::uint64_t &out) {
  if (data.empty() || offset_size == 0) {
    return false;
  }
  const std::uint64_t entry_offset = base + (index * offset_size);
  return read_offset_at(data, entry_offset, offset_size, out);
}

bool read_addr_table(std::span<const std::uint8_t> debug_addr,
                     std::uint64_t base_offset, AddrTable &out) {
  out = {};
  if (debug_addr.empty() || base_offset >= debug_addr.size()) {
    return false;
  }
  Cursor cur{debug_addr, static_cast<std::size_t>(base_offset)};
  std::uint32_t unit_length32 = 0;
  if (!read_u32(cur, unit_length32) || unit_length32 == 0) {
    return false;
  }
  std::uint64_t unit_length = unit_length32;
  if (unit_length32 == 0xffffffffu) {
    if (!read_u64(cur, unit_length)) {
      return false;
    }
  }
  const std::size_t header_start = cur.offset;
  const std::size_t unit_end =
      header_start + static_cast<std::size_t>(unit_length);
  if (unit_end > debug_addr.size()) {
    return false;
  }
  std::uint16_t version = 0;
  if (!read_u16(cur, version)) {
    return false;
  }
  (void)version;
  std::uint8_t address_size = 0;
  if (!read_u8(cur, address_size)) {
    return false;
  }
  std::uint8_t segment_selector_size = 0;
  if (!read_u8(cur, segment_selector_size)) {
    return false;
  }
  (void)segment_selector_size;
  std::uint32_t entry_count = 0;
  if (!read_u32(cur, entry_count)) {
    return false;
  }
  const std::size_t table_start = cur.offset;
  const std::size_t table_end =
      table_start + (static_cast<std::size_t>(entry_count) * address_size);
  if (table_end > unit_end) {
    return false;
  }
  out.data = debug_addr;
  out.base_offset = base_offset;
  out.table_start = table_start;
  out.table_end = table_end;
  out.address_size = address_size;
  out.valid = true;
  return true;
}

bool resolve_addr_index(const AddrTable *table, std::uint64_t index,
                        std::uint64_t &out) {
  if (!table || !table->valid || table->data.empty()) {
    return false;
  }
  const std::size_t entry_size = table->address_size;
  const std::size_t offset =
      table->table_start + (static_cast<std::size_t>(index) * entry_size);
  if (offset + entry_size > table->table_end) {
    return false;
  }
  if (entry_size == 8) {
  Cursor cur{table->data, offset};
  return read_u64(cur, out);
  }
  std::uint32_t value = 0;
  Cursor cur{table->data, offset};
  if (!read_u32(cur, value)) {
    return false;
  }
  out = value;
  return true;
}

bool parse_abbrev_table(std::span<const std::uint8_t> data, std::size_t offset,
                        AbbrevTable &out) {
  out.clear();
  if (data.empty() || offset >= data.size()) {
    return false;
  }
  Cursor cur{data, offset};
  while (cur.offset < data.size()) {
    std::uint64_t code = 0;
    if (!read_uleb128(cur, code)) {
      return false;
    }
    if (code == 0) {
      break;
    }
    std::uint64_t tag = 0;
    if (!read_uleb128(cur, tag)) {
      return false;
    }
    std::uint8_t children = 0;
    if (!read_u8(cur, children)) {
      return false;
    }
    AbbrevEntry entry;
    entry.code = code;
    entry.tag = tag;
    entry.has_children = (children != 0);
    while (cur.offset < data.size()) {
      std::uint64_t name = 0;
      std::uint64_t form = 0;
      if (!read_uleb128(cur, name)) {
        return false;
      }
      if (!read_uleb128(cur, form)) {
        return false;
      }
      if (name == 0 && form == 0) {
        break;
      }
      entry.attrs.push_back({name, form});
    }
    out.emplace(entry.code, std::move(entry));
  }
  return true;
}

bool read_block(Cursor &cur, std::size_t size, std::vector<std::uint8_t> &out) {
  if (cur.data.empty() || cur.offset + size > cur.data.size()) {
    return false;
  }
  out.assign(cur.data.begin() + static_cast<std::ptrdiff_t>(cur.offset),
             cur.data.begin() +
                 static_cast<std::ptrdiff_t>(cur.offset + size));
  cur.offset += size;
  return true;
}

bool read_form_value(Cursor &cur, std::uint64_t form, std::uint8_t address_size,
                     std::size_t offset_size,
                     std::span<const std::uint8_t> debug_str,
                     std::span<const std::uint8_t> debug_str_offsets,
                     std::span<const std::uint8_t> debug_line_str,
                     std::uint64_t str_offsets_base, std::uint64_t &out_u,
                     std::int64_t &out_s, std::string &out_str,
                     std::vector<std::uint8_t> &out_block, bool &is_signed,
                     bool &is_string, bool &is_block, bool &is_addr_index,
                     std::uint64_t* unsupported_form) {
  out_u = 0;
  out_s = 0;
  out_str.clear();
  out_block.clear();
  is_signed = false;
  is_string = false;
  is_block = false;
  is_addr_index = false;
  if (unsupported_form) {
    *unsupported_form = 0;
  }

  auto read_data = [&](std::size_t size) -> bool {
    if (size == 1) {
      std::uint8_t v = 0;
      if (!read_u8(cur, v)) {
        return false;
      }
      out_u = v;
      return true;
    }
    if (size == 2) {
      std::uint16_t v = 0;
      if (!read_u16(cur, v)) {
        return false;
      }
      out_u = v;
      return true;
    }
    if (size == 4) {
      std::uint32_t v = 0;
      if (!read_u32(cur, v)) {
        return false;
      }
      out_u = v;
      return true;
    }
    if (size == 8) {
      std::uint64_t v = 0;
      if (!read_u64(cur, v)) {
        return false;
      }
      out_u = v;
      return true;
    }
    return false;
  };

  if (form == kDwFormIndirect) {
    std::uint64_t actual_form = 0;
    if (!read_uleb128(cur, actual_form)) {
      return false;
    }
    form = actual_form;
  }

  switch (form) {
  case kDwFormAddr:
    return read_address(cur, address_size, out_u);
  case kDwFormData1:
    return read_data(1);
  case kDwFormData2:
    return read_data(2);
  case kDwFormData4:
    return read_data(4);
  case kDwFormData8:
    return read_data(8);
  case kDwFormUdata:
    return read_uleb128(cur, out_u);
  case kDwFormSdata:
    is_signed = true;
    return read_sleb128(cur, out_s);
  case kDwFormString:
    is_string = true;
    return read_cstring(cur, out_str);
  case kDwFormStrp:
  case kDwFormLineStrp: {
    std::uint64_t offset = 0;
    if (!read_data(offset_size)) {
      return false;
    }
    is_string = true;
    const auto pool = (form == kDwFormLineStrp && !debug_line_str.empty())
                           ? debug_line_str
                           : debug_str;
    if (pool.empty()) {
      out_str.clear();
      return true;
    }
    return read_string_at(pool, offset, out_str);
  }
  case kDwFormSecOffset:
  case kDwFormRefAddr:
  case kDwFormRef4:
  case kDwFormRef8:
  case kDwFormRefUdata:
  case kDwFormRefSig8:
    return read_data(offset_size);
  case kDwFormBlock1: {
    std::uint8_t size = 0;
    if (!read_u8(cur, size)) {
      return false;
    }
    is_block = true;
    return read_block(cur, size, out_block);
  }
  case kDwFormBlock2: {
    std::uint16_t size = 0;
    if (!read_u16(cur, size)) {
      return false;
    }
    is_block = true;
    return read_block(cur, size, out_block);
  }
  case kDwFormBlock4: {
    std::uint32_t size = 0;
    if (!read_u32(cur, size)) {
      return false;
    }
    is_block = true;
    return read_block(cur, size, out_block);
  }
  case kDwFormBlock: {
    std::uint64_t size = 0;
    if (!read_uleb128(cur, size)) {
      return false;
    }
    is_block = true;
    return read_block(cur, static_cast<std::size_t>(size), out_block);
  }
  case kDwFormExprloc: {
    std::uint64_t size = 0;
    if (!read_uleb128(cur, size)) {
      return false;
    }
    is_block = true;
    return read_block(cur, static_cast<std::size_t>(size), out_block);
  }
  case kDwFormFlag: {
    std::uint8_t v = 0;
    if (!read_u8(cur, v)) {
      return false;
    }
    out_u = v;
    return true;
  }
  case kDwFormFlagPresent:
    out_u = 1;
    return true;
  case kDwFormStrx:
  case kDwFormStrx1:
  case kDwFormStrx2:
  case kDwFormStrx3:
  case kDwFormStrx4: {
    std::uint64_t index = 0;
    if (form == kDwFormStrx) {
      if (!read_uleb128(cur, index)) {
        return false;
      }
    } else if (form == kDwFormStrx1) {
      std::uint8_t v = 0;
      if (!read_u8(cur, v)) {
        return false;
      }
      index = v;
    } else if (form == kDwFormStrx2) {
      std::uint16_t v = 0;
      if (!read_u16(cur, v)) {
        return false;
      }
      index = v;
    } else if (form == kDwFormStrx3) {
      std::uint32_t v = 0;
      if (!read_u24(cur, v)) {
        return false;
      }
      index = v;
    } else {
      std::uint32_t v = 0;
      if (!read_u32(cur, v)) {
        return false;
      }
      index = v;
    }
    out_u = index;
    if (resolve_strx(debug_str_offsets, debug_str, str_offsets_base, index,
                     offset_size, out_str)) {
      is_string = true;
    }
    return true;
  }
  case kDwFormAddrx:
  case kDwFormAddrx1:
  case kDwFormAddrx2:
  case kDwFormAddrx3:
  case kDwFormAddrx4: {
    std::uint64_t index = 0;
    if (form == kDwFormAddrx) {
      if (!read_uleb128(cur, index)) {
        return false;
      }
    } else if (form == kDwFormAddrx1) {
      std::uint8_t v = 0;
      if (!read_u8(cur, v)) {
        return false;
      }
      index = v;
    } else if (form == kDwFormAddrx2) {
      std::uint16_t v = 0;
      if (!read_u16(cur, v)) {
        return false;
      }
      index = v;
    } else if (form == kDwFormAddrx3) {
      std::uint32_t v = 0;
      if (!read_u24(cur, v)) {
        return false;
      }
      index = v;
    } else {
      std::uint32_t v = 0;
      if (!read_u32(cur, v)) {
        return false;
      }
      index = v;
    }
    out_u = index;
    is_addr_index = true;
    return true;
  }
  case kDwFormRnglistx:
  case kDwFormLoclistx: {
    std::uint64_t index = 0;
    if (!read_uleb128(cur, index)) {
      return false;
    }
    out_u = index;
    return true;
  }
  default:
    if (unsupported_form) {
      *unsupported_form = form;
    }
    return false;
  }
}

}  // namespace engine::dwarf::detail
