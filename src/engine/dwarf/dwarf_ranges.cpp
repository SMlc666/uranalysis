#include "dwarf_internal.h"

namespace engine::dwarf::detail {

bool parse_ranges_v4(std::span<const std::uint8_t> debug_ranges,
                     std::uint64_t offset, std::uint8_t address_size,
                     std::uint64_t base_addr, std::vector<DwarfRange> &out) {
  if (debug_ranges.empty() || offset >= debug_ranges.size()) {
    return false;
  }
  Cursor cur{debug_ranges, static_cast<std::size_t>(offset)};
  while (cur.offset + (address_size * 2) <= debug_ranges.size()) {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    if (!read_address(cur, address_size, begin) ||
        !read_address(cur, address_size, end)) {
      return false;
    }
    if (begin == 0 && end == 0) {
      break;
    }
    if (begin == static_cast<std::uint64_t>(-1)) {
      base_addr = end;
      continue;
    }
    DwarfRange range;
    range.start = base_addr + begin;
    range.end = base_addr + end;
    if (range.end > range.start) {
      out.push_back(range);
    }
  }
  return true;
}

bool parse_rnglists_v5(std::span<const std::uint8_t> debug_rnglists,
                       std::uint64_t offset, std::uint8_t address_size,
                       std::uint64_t base_addr, const AddrTable *addr_table,
                       std::vector<DwarfRange> &out) {
  if (debug_rnglists.empty() || offset >= debug_rnglists.size()) {
    return false;
  }
  Cursor cur{debug_rnglists, static_cast<std::size_t>(offset)};
  while (cur.offset < debug_rnglists.size()) {
    std::uint8_t opcode = 0;
    if (!read_u8(cur, opcode)) {
      return false;
    }
    switch (opcode) {
    case kDwRleEndOfList:
      return true;
    case kDwRleBaseAddressx: {
      std::uint64_t idx = 0;
      if (!read_uleb128(cur, idx)) {
        return false;
      }
      std::uint64_t addr = 0;
      if (!resolve_addr_index(addr_table, idx, addr)) {
        return false;
      }
      base_addr = addr;
      break;
    }
    case kDwRleStartxEndx: {
      std::uint64_t start_idx = 0;
      std::uint64_t end_idx = 0;
      if (!read_uleb128(cur, start_idx) || !read_uleb128(cur, end_idx)) {
        return false;
      }
      std::uint64_t start = 0;
      std::uint64_t end = 0;
      if (!resolve_addr_index(addr_table, start_idx, start) ||
          !resolve_addr_index(addr_table, end_idx, end)) {
        return false;
      }
      DwarfRange range;
      range.start = start;
      range.end = end;
      if (range.end > range.start) {
        out.push_back(range);
      }
      break;
    }
    case kDwRleStartxLength: {
      std::uint64_t start_idx = 0;
      std::uint64_t length = 0;
      if (!read_uleb128(cur, start_idx) || !read_uleb128(cur, length)) {
        return false;
      }
      std::uint64_t start = 0;
      if (!resolve_addr_index(addr_table, start_idx, start)) {
        return false;
      }
      DwarfRange range;
      range.start = start;
      range.end = start + length;
      if (range.end > range.start) {
        out.push_back(range);
      }
      break;
    }
    case kDwRleOffsetPair: {
      std::uint64_t start = 0;
      std::uint64_t end = 0;
      if (!read_uleb128(cur, start) || !read_uleb128(cur, end)) {
        return false;
      }
      DwarfRange range;
      range.start = base_addr + start;
      range.end = base_addr + end;
      if (range.end > range.start) {
        out.push_back(range);
      }
      break;
    }
    case kDwRleBaseAddress: {
      std::uint64_t addr = 0;
      if (!read_address(cur, address_size, addr)) {
        return false;
      }
      base_addr = addr;
      break;
    }
    case kDwRleStartEnd: {
      std::uint64_t start = 0;
      std::uint64_t end = 0;
      if (!read_address(cur, address_size, start) ||
          !read_address(cur, address_size, end)) {
        return false;
      }
      DwarfRange range;
      range.start = start;
      range.end = end;
      if (range.end > range.start) {
        out.push_back(range);
      }
      break;
    }
    case kDwRleStartLength: {
      std::uint64_t start = 0;
      std::uint64_t length = 0;
      if (!read_address(cur, address_size, start) ||
          !read_uleb128(cur, length)) {
        return false;
      }
      DwarfRange range;
      range.start = start;
      range.end = start + length;
      if (range.end > range.start) {
        out.push_back(range);
      }
      break;
    }
    default:
      return false;
    }
  }
  return true;
}

}  // namespace engine::dwarf::detail
