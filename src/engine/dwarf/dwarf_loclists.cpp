#include "dwarf_internal.h"

#include <limits>

namespace engine::dwarf::detail {

bool read_expr_block(Cursor &cur, std::vector<std::uint8_t> &out) {
  std::uint64_t size = 0;
  if (!read_uleb128(cur, size)) {
    return false;
  }
  return read_block(cur, static_cast<std::size_t>(size), out);
}

bool parse_loc_v4(std::span<const std::uint8_t> debug_loc,
                  std::uint64_t offset, std::uint8_t address_size,
                  std::uint64_t base_addr,
                  std::vector<DwarfLocationRange> &out) {
  if (debug_loc.empty() || offset >= debug_loc.size()) {
    return false;
  }
  Cursor cur{debug_loc, static_cast<std::size_t>(offset)};
  const std::uint64_t max_addr =
      (address_size >= 8)
          ? std::numeric_limits<std::uint64_t>::max()
          : ((static_cast<std::uint64_t>(1) << (address_size * 8)) - 1);
  std::uint64_t base = base_addr;
  while (cur.offset < debug_loc.size()) {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    if (!read_address(cur, address_size, start) ||
        !read_address(cur, address_size, end)) {
      return false;
    }
    if (start == 0 && end == 0) {
      break;
    }
    if (start == max_addr) {
      base = end;
      continue;
    }
    std::uint16_t expr_len = 0;
    if (!read_u16(cur, expr_len)) {
      return false;
    }
    std::vector<std::uint8_t> expr;
    if (!read_block(cur, expr_len, expr)) {
      return false;
    }
    DwarfLocationRange range;
    range.start = base + start;
    range.end = base + end;
    range.expr = std::move(expr);
    out.push_back(std::move(range));
  }
  return true;
}

bool parse_loclists_v5(std::span<const std::uint8_t> debug_loclists,
                       std::uint64_t offset, std::uint8_t address_size,
                       std::uint64_t base_addr, const AddrTable *addr_table,
                       std::vector<DwarfLocationRange> &out) {
  if (debug_loclists.empty() || offset >= debug_loclists.size()) {
    return false;
  }
  Cursor cur{debug_loclists, static_cast<std::size_t>(offset)};
  std::uint64_t base = base_addr;
  while (cur.offset < debug_loclists.size()) {
    std::uint8_t opcode = 0;
    if (!read_u8(cur, opcode)) {
      return false;
    }
    switch (opcode) {
    case kDwLleEndOfList:
      return true;
    case kDwLleBaseAddressx: {
      std::uint64_t idx = 0;
      if (!read_uleb128(cur, idx)) {
        return false;
      }
      std::uint64_t addr = 0;
      if (!resolve_addr_index(addr_table, idx, addr)) {
        return false;
      }
      base = addr;
      break;
    }
    case kDwLleBaseAddress: {
      std::uint64_t addr = 0;
      if (!read_address(cur, address_size, addr)) {
        return false;
      }
      base = addr;
      break;
    }
    case kDwLleOffsetPair: {
      std::uint64_t start = 0;
      std::uint64_t end = 0;
      if (!read_uleb128(cur, start) || !read_uleb128(cur, end)) {
        return false;
      }
      std::vector<std::uint8_t> expr;
      if (!read_expr_block(cur, expr)) {
        return false;
      }
      DwarfLocationRange range;
      range.start = base + start;
      range.end = base + end;
      range.expr = std::move(expr);
      out.push_back(std::move(range));
      break;
    }
    case kDwLleStartxEndx: {
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
      std::vector<std::uint8_t> expr;
      if (!read_expr_block(cur, expr)) {
        return false;
      }
      DwarfLocationRange range;
      range.start = start;
      range.end = end;
      range.expr = std::move(expr);
      out.push_back(std::move(range));
      break;
    }
    case kDwLleStartxLength: {
      std::uint64_t start_idx = 0;
      std::uint64_t length = 0;
      if (!read_uleb128(cur, start_idx) || !read_uleb128(cur, length)) {
        return false;
      }
      std::uint64_t start = 0;
      if (!resolve_addr_index(addr_table, start_idx, start)) {
        return false;
      }
      std::vector<std::uint8_t> expr;
      if (!read_expr_block(cur, expr)) {
        return false;
      }
      DwarfLocationRange range;
      range.start = start;
      range.end = start + length;
      range.expr = std::move(expr);
      out.push_back(std::move(range));
      break;
    }
    case kDwLleStartEnd: {
      std::uint64_t start = 0;
      std::uint64_t end = 0;
      if (!read_address(cur, address_size, start) ||
          !read_address(cur, address_size, end)) {
        return false;
      }
      std::vector<std::uint8_t> expr;
      if (!read_expr_block(cur, expr)) {
        return false;
      }
      DwarfLocationRange range;
      range.start = start;
      range.end = end;
      range.expr = std::move(expr);
      out.push_back(std::move(range));
      break;
    }
    case kDwLleStartLength: {
      std::uint64_t start = 0;
      std::uint64_t length = 0;
      if (!read_address(cur, address_size, start) ||
          !read_uleb128(cur, length)) {
        return false;
      }
      std::vector<std::uint8_t> expr;
      if (!read_expr_block(cur, expr)) {
        return false;
      }
      DwarfLocationRange range;
      range.start = start;
      range.end = start + length;
      range.expr = std::move(expr);
      out.push_back(std::move(range));
      break;
    }
    case kDwLleDefaultLocation: {
      std::vector<std::uint8_t> expr;
      if (!read_expr_block(cur, expr)) {
        return false;
      }
      DwarfLocationRange range;
      range.is_default = true;
      range.expr = std::move(expr);
      out.push_back(std::move(range));
      break;
    }
    default:
      return false;
    }
  }
  return true;
}

}  // namespace engine::dwarf::detail
