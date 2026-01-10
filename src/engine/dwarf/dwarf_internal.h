#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "engine/dwarf.h"

namespace engine::dwarf::detail {

inline constexpr std::uint32_t kDwTagSubprogram = 0x2e;
inline constexpr std::uint32_t kDwTagVariable = 0x34;
inline constexpr std::uint32_t kDwTagFormalParameter = 0x05;
inline constexpr std::uint32_t kDwTagCompileUnit = 0x11;

inline constexpr std::uint32_t kDwAtName = 0x03;
inline constexpr std::uint32_t kDwAtLocation = 0x02;
inline constexpr std::uint32_t kDwAtLowPc = 0x11;
inline constexpr std::uint32_t kDwAtHighPc = 0x12;
inline constexpr std::uint32_t kDwAtType = 0x49;
inline constexpr std::uint32_t kDwAtLinkageName = 0x6e;
inline constexpr std::uint32_t kDwAtMipsLinkageName = 0x2007;
inline constexpr std::uint32_t kDwAtDeclFile = 0x3a;
inline constexpr std::uint32_t kDwAtDeclLine = 0x3b;
inline constexpr std::uint32_t kDwAtStmtList = 0x10;
inline constexpr std::uint32_t kDwAtRanges = 0x55;
inline constexpr std::uint32_t kDwAtStrOffsetsBase = 0x72;
inline constexpr std::uint32_t kDwAtAddrBase = 0x73;
inline constexpr std::uint32_t kDwAtRnglistsBase = 0x74;
inline constexpr std::uint32_t kDwAtLoclistsBase = 0x8c;

inline constexpr std::uint32_t kDwFormAddr = 0x01;
inline constexpr std::uint32_t kDwFormBlock2 = 0x03;
inline constexpr std::uint32_t kDwFormBlock4 = 0x04;
inline constexpr std::uint32_t kDwFormData2 = 0x05;
inline constexpr std::uint32_t kDwFormData4 = 0x06;
inline constexpr std::uint32_t kDwFormData8 = 0x07;
inline constexpr std::uint32_t kDwFormString = 0x08;
inline constexpr std::uint32_t kDwFormBlock = 0x09;
inline constexpr std::uint32_t kDwFormBlock1 = 0x0a;
inline constexpr std::uint32_t kDwFormData1 = 0x0b;
inline constexpr std::uint32_t kDwFormFlag = 0x0c;
inline constexpr std::uint32_t kDwFormSdata = 0x0d;
inline constexpr std::uint32_t kDwFormStrp = 0x0e;
inline constexpr std::uint32_t kDwFormUdata = 0x0f;
inline constexpr std::uint32_t kDwFormRefAddr = 0x10;
inline constexpr std::uint32_t kDwFormRef4 = 0x13;
inline constexpr std::uint32_t kDwFormRef8 = 0x14;
inline constexpr std::uint32_t kDwFormRefUdata = 0x15;
inline constexpr std::uint32_t kDwFormIndirect = 0x16;
inline constexpr std::uint32_t kDwFormSecOffset = 0x17;
inline constexpr std::uint32_t kDwFormExprloc = 0x18;
inline constexpr std::uint32_t kDwFormFlagPresent = 0x19;
inline constexpr std::uint32_t kDwFormRefSig8 = 0x20;
inline constexpr std::uint32_t kDwFormLineStrp = 0x1f;
inline constexpr std::uint32_t kDwFormStrx = 0x1a;
inline constexpr std::uint32_t kDwFormStrx1 = 0x25;
inline constexpr std::uint32_t kDwFormStrx2 = 0x26;
inline constexpr std::uint32_t kDwFormStrx3 = 0x27;
inline constexpr std::uint32_t kDwFormStrx4 = 0x28;
inline constexpr std::uint32_t kDwFormAddrx = 0x1b;
inline constexpr std::uint32_t kDwFormAddrx1 = 0x29;
inline constexpr std::uint32_t kDwFormAddrx2 = 0x2a;
inline constexpr std::uint32_t kDwFormAddrx3 = 0x2b;
inline constexpr std::uint32_t kDwFormAddrx4 = 0x2c;
inline constexpr std::uint32_t kDwFormLoclistx = 0x22;
inline constexpr std::uint32_t kDwFormRnglistx = 0x23;

inline constexpr std::uint32_t kDwLnctPath = 0x01;
inline constexpr std::uint32_t kDwLnctDirectoryIndex = 0x02;

inline constexpr std::uint8_t kDwLnsCopy = 0x01;
inline constexpr std::uint8_t kDwLnsAdvancePc = 0x02;
inline constexpr std::uint8_t kDwLnsAdvanceLine = 0x03;
inline constexpr std::uint8_t kDwLnsSetFile = 0x04;
inline constexpr std::uint8_t kDwLnsSetColumn = 0x05;
inline constexpr std::uint8_t kDwLnsNegateStmt = 0x06;
inline constexpr std::uint8_t kDwLnsSetBasicBlock = 0x07;
inline constexpr std::uint8_t kDwLnsConstAddPc = 0x08;
inline constexpr std::uint8_t kDwLnsFixedAdvancePc = 0x09;

inline constexpr std::uint8_t kDwLneEndSequence = 0x01;
inline constexpr std::uint8_t kDwLneSetAddress = 0x02;
inline constexpr std::uint8_t kDwLneDefineFile = 0x03;
inline constexpr std::uint8_t kDwLneSetDiscriminator = 0x04;

inline constexpr std::uint8_t kDwRleEndOfList = 0x00;
inline constexpr std::uint8_t kDwRleBaseAddressx = 0x01;
inline constexpr std::uint8_t kDwRleStartxEndx = 0x02;
inline constexpr std::uint8_t kDwRleStartxLength = 0x03;
inline constexpr std::uint8_t kDwRleOffsetPair = 0x04;
inline constexpr std::uint8_t kDwRleBaseAddress = 0x05;
inline constexpr std::uint8_t kDwRleStartEnd = 0x06;
inline constexpr std::uint8_t kDwRleStartLength = 0x07;

inline constexpr std::uint8_t kDwLleEndOfList = 0x00;
inline constexpr std::uint8_t kDwLleBaseAddressx = 0x01;
inline constexpr std::uint8_t kDwLleStartxEndx = 0x02;
inline constexpr std::uint8_t kDwLleStartxLength = 0x03;
inline constexpr std::uint8_t kDwLleOffsetPair = 0x04;
inline constexpr std::uint8_t kDwLleDefaultLocation = 0x05;
inline constexpr std::uint8_t kDwLleBaseAddress = 0x06;
inline constexpr std::uint8_t kDwLleStartEnd = 0x07;
inline constexpr std::uint8_t kDwLleStartLength = 0x08;

struct Cursor {
    std::span<const std::uint8_t> data{};
    std::size_t offset = 0;
};

struct AddrTable {
    std::span<const std::uint8_t> data{};
    std::uint64_t base_offset = 0;
    std::uint64_t table_start = 0;
    std::uint64_t table_end = 0;
    std::uint8_t address_size = 0;
    bool valid = false;
};

struct AbbrevAttr {
    std::uint64_t name = 0;
    std::uint64_t form = 0;
};

struct AbbrevEntry {
    std::uint64_t code = 0;
    std::uint64_t tag = 0;
    bool has_children = false;
    std::vector<AbbrevAttr> attrs;
};

using AbbrevTable = std::unordered_map<std::uint64_t, AbbrevEntry>;

bool read_u8(Cursor& cur, std::uint8_t& out);
bool read_u16(Cursor& cur, std::uint16_t& out);
bool read_u32(Cursor& cur, std::uint32_t& out);
bool read_u64(Cursor& cur, std::uint64_t& out);
bool read_u24(Cursor& cur, std::uint32_t& out);
bool read_uleb128(Cursor& cur, std::uint64_t& out);
bool read_sleb128(Cursor& cur, std::int64_t& out);
bool read_address(Cursor& cur, std::uint8_t address_size, std::uint64_t& out);
bool read_cstring(Cursor& cur, std::string& out);

bool read_string_at(std::span<const std::uint8_t> data,
                    std::uint64_t offset,
                    std::string& out);
bool read_offset_at(std::span<const std::uint8_t> data,
                    std::uint64_t offset,
                    std::size_t size,
                    std::uint64_t& out);
bool resolve_strx(std::span<const std::uint8_t> debug_str_offsets,
                  std::span<const std::uint8_t> debug_str,
                  std::uint64_t str_offsets_base,
                  std::uint64_t index,
                  std::size_t offset_size,
                  std::string& out);
bool resolve_indexed_offset(std::span<const std::uint8_t> data,
                            std::uint64_t base,
                            std::uint64_t index,
                            std::size_t offset_size,
                            std::uint64_t& out);

bool read_addr_table(std::span<const std::uint8_t> debug_addr,
                     std::uint64_t base_offset,
                     AddrTable& out);
bool resolve_addr_index(const AddrTable* table, std::uint64_t index, std::uint64_t& out);

bool parse_abbrev_table(std::span<const std::uint8_t> data,
                        std::size_t offset,
                        AbbrevTable& out);

bool read_block(Cursor& cur, std::size_t size, std::vector<std::uint8_t>& out);
bool read_form_value(Cursor& cur,
                     std::uint64_t form,
                     std::uint8_t address_size,
                     std::size_t offset_size,
                     std::span<const std::uint8_t> debug_str,
                     std::span<const std::uint8_t> debug_str_offsets,
                     std::span<const std::uint8_t> debug_line_str,
                     std::uint64_t str_offsets_base,
                     std::uint64_t& out_u,
                     std::int64_t& out_s,
                     std::string& out_str,
                     std::vector<std::uint8_t>& out_block,
                     bool& is_signed,
                     bool& is_string,
                     bool& is_block,
                     bool& is_addr_index,
                     std::uint64_t* unsupported_form);

bool parse_line_table(std::span<const std::uint8_t> debug_line,
                      std::span<const std::uint8_t> debug_str,
                      std::span<const std::uint8_t> debug_str_offsets,
                      std::span<const std::uint8_t> debug_line_str,
                      std::uint64_t offset,
                      std::uint64_t cu_offset,
                      std::uint8_t cu_address_size,
                      std::size_t offset_size,
                      std::uint64_t str_offsets_base,
                      std::vector<DwarfLineRow>& out);

bool parse_ranges_v4(std::span<const std::uint8_t> debug_ranges,
                     std::uint64_t offset,
                     std::uint8_t address_size,
                     std::uint64_t base_addr,
                     std::vector<DwarfRange>& out);
bool parse_rnglists_v5(std::span<const std::uint8_t> debug_rnglists,
                       std::uint64_t offset,
                       std::uint8_t address_size,
                       std::uint64_t base_addr,
                       const AddrTable* addr_table,
                       std::vector<DwarfRange>& out);

bool read_expr_block(Cursor& cur, std::vector<std::uint8_t>& out);
bool parse_loc_v4(std::span<const std::uint8_t> debug_loc,
                  std::uint64_t offset,
                  std::uint8_t address_size,
                  std::uint64_t base_addr,
                  std::vector<DwarfLocationRange>& out);
bool parse_loclists_v5(std::span<const std::uint8_t> debug_loclists,
                       std::uint64_t offset,
                       std::uint8_t address_size,
                       std::uint64_t base_addr,
                       const AddrTable* addr_table,
                       std::vector<DwarfLocationRange>& out);

}  // namespace engine::dwarf::detail
