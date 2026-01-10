#include "engine/eh_frame.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace {

constexpr std::uint8_t kDwEhPeAbsptr = 0x00;
constexpr std::uint8_t kDwEhPeUleb128 = 0x01;
constexpr std::uint8_t kDwEhPeUdata2 = 0x02;
constexpr std::uint8_t kDwEhPeUdata4 = 0x03;
constexpr std::uint8_t kDwEhPeUdata8 = 0x04;
constexpr std::uint8_t kDwEhPeSleb128 = 0x09;
constexpr std::uint8_t kDwEhPeSdata2 = 0x0a;
constexpr std::uint8_t kDwEhPeSdata4 = 0x0b;
constexpr std::uint8_t kDwEhPeSdata8 = 0x0c;
constexpr std::uint8_t kDwEhPePcrel = 0x10;
constexpr std::uint8_t kDwEhPeIndirect = 0x80;
constexpr std::uint8_t kDwEhPeOmit = 0xff;

constexpr std::uint8_t kDwCfaNop = 0x00;
constexpr std::uint8_t kDwCfaSetLoc = 0x01;
constexpr std::uint8_t kDwCfaAdvanceLoc1 = 0x02;
constexpr std::uint8_t kDwCfaAdvanceLoc2 = 0x03;
constexpr std::uint8_t kDwCfaAdvanceLoc4 = 0x04;
constexpr std::uint8_t kDwCfaOffsetExtended = 0x05;
constexpr std::uint8_t kDwCfaRestoreExtended = 0x06;
constexpr std::uint8_t kDwCfaUndefined = 0x07;
constexpr std::uint8_t kDwCfaSameValue = 0x08;
constexpr std::uint8_t kDwCfaDefCfa = 0x0c;
constexpr std::uint8_t kDwCfaDefCfaRegister = 0x0d;
constexpr std::uint8_t kDwCfaDefCfaOffset = 0x0e;
constexpr std::uint8_t kDwCfaDefCfaExpression = 0x0f;
constexpr std::uint8_t kDwCfaExpression = 0x10;
constexpr std::uint8_t kDwCfaDefCfaSf = 0x12;
constexpr std::uint8_t kDwCfaDefCfaOffsetSf = 0x13;
constexpr std::uint8_t kDwCfaValOffset = 0x14;
constexpr std::uint8_t kDwCfaValOffsetSf = 0x15;
constexpr std::uint8_t kDwCfaValExpression = 0x16;
constexpr std::uint8_t kDwCfaRememberState = 0x0a;
constexpr std::uint8_t kDwCfaRestoreState = 0x0b;

struct Cursor {
    const std::vector<std::uint8_t>& data;
    std::size_t offset = 0;
    bool little_endian = true;
};

bool read_u8(Cursor& cur, std::uint8_t& out) {
    if (cur.offset + 1 > cur.data.size()) {
        return false;
    }
    out = cur.data[cur.offset];
    cur.offset += 1;
    return true;
}

bool read_u16(Cursor& cur, std::uint16_t& out) {
    if (cur.offset + 2 > cur.data.size()) {
        return false;
    }
    if (cur.little_endian) {
        out = static_cast<std::uint16_t>(cur.data[cur.offset]) |
              static_cast<std::uint16_t>(cur.data[cur.offset + 1] << 8);
    } else {
        out = static_cast<std::uint16_t>(cur.data[cur.offset] << 8) |
              static_cast<std::uint16_t>(cur.data[cur.offset + 1]);
    }
    cur.offset += 2;
    return true;
}

bool read_u32(Cursor& cur, std::uint32_t& out) {
    if (cur.offset + 4 > cur.data.size()) {
        return false;
    }
    if (cur.little_endian) {
        out = static_cast<std::uint32_t>(cur.data[cur.offset]) |
              (static_cast<std::uint32_t>(cur.data[cur.offset + 1]) << 8) |
              (static_cast<std::uint32_t>(cur.data[cur.offset + 2]) << 16) |
              (static_cast<std::uint32_t>(cur.data[cur.offset + 3]) << 24);
    } else {
        out = (static_cast<std::uint32_t>(cur.data[cur.offset]) << 24) |
              (static_cast<std::uint32_t>(cur.data[cur.offset + 1]) << 16) |
              (static_cast<std::uint32_t>(cur.data[cur.offset + 2]) << 8) |
              static_cast<std::uint32_t>(cur.data[cur.offset + 3]);
    }
    cur.offset += 4;
    return true;
}

bool read_u64(Cursor& cur, std::uint64_t& out) {
    if (cur.offset + 8 > cur.data.size()) {
        return false;
    }
    out = 0;
    if (cur.little_endian) {
        for (std::size_t i = 0; i < 8; ++i) {
            out |= static_cast<std::uint64_t>(cur.data[cur.offset + i]) << (i * 8);
        }
    } else {
        for (std::size_t i = 0; i < 8; ++i) {
            out = (out << 8) | static_cast<std::uint64_t>(cur.data[cur.offset + i]);
        }
    }
    cur.offset += 8;
    return true;
}

bool read_uleb128(Cursor& cur, std::uint64_t& out) {
    out = 0;
    std::uint32_t shift = 0;
    while (cur.offset < cur.data.size()) {
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

bool read_sleb128(Cursor& cur, std::int64_t& out) {
    out = 0;
    std::uint32_t shift = 0;
    std::uint8_t byte = 0;
    while (cur.offset < cur.data.size()) {
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

bool read_block(Cursor& cur, std::size_t size, std::vector<std::uint8_t>& out) {
    if (cur.offset + size > cur.data.size()) {
        return false;
    }
    out.assign(cur.data.begin() + static_cast<std::ptrdiff_t>(cur.offset),
               cur.data.begin() + static_cast<std::ptrdiff_t>(cur.offset + size));
    cur.offset += size;
    return true;
}

bool read_pointer(Cursor& cur, const engine::BinaryInfo& binary_info, std::uint64_t& out) {
    if (binary_info.is_64) {
        return read_u64(cur, out);
    }
    std::uint32_t value = 0;
    if (!read_u32(cur, value)) {
        return false;
    }
    out = value;
    return true;
}

bool read_address_size(Cursor& cur, std::size_t address_size, std::uint64_t& out) {
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

bool read_encoded_value(Cursor& cur,
                        std::uint8_t format,
                        const engine::BinaryInfo& binary_info,
                        std::uint64_t& out,
                        bool& is_signed,
                        std::int64_t& signed_value) {
    is_signed = false;
    signed_value = 0;
    switch (format) {
        case kDwEhPeAbsptr:
            return read_pointer(cur, binary_info, out);
        case kDwEhPeUleb128: {
            std::uint64_t value = 0;
            if (!read_uleb128(cur, value)) {
                return false;
            }
            out = value;
            return true;
        }
        case kDwEhPeUdata2: {
            std::uint16_t value = 0;
            if (!read_u16(cur, value)) {
                return false;
            }
            out = value;
            return true;
        }
        case kDwEhPeUdata4: {
            std::uint32_t value = 0;
            if (!read_u32(cur, value)) {
                return false;
            }
            out = value;
            return true;
        }
        case kDwEhPeUdata8: {
            std::uint64_t value = 0;
            if (!read_u64(cur, value)) {
                return false;
            }
            out = value;
            return true;
        }
        case kDwEhPeSleb128: {
            std::int64_t value = 0;
            if (!read_sleb128(cur, value)) {
                return false;
            }
            out = static_cast<std::uint64_t>(value);
            is_signed = true;
            signed_value = value;
            return true;
        }
        case kDwEhPeSdata2: {
            std::uint16_t value = 0;
            if (!read_u16(cur, value)) {
                return false;
            }
            signed_value = static_cast<std::int16_t>(value);
            out = static_cast<std::uint64_t>(signed_value);
            is_signed = true;
            return true;
        }
        case kDwEhPeSdata4: {
            std::uint32_t value = 0;
            if (!read_u32(cur, value)) {
                return false;
            }
            signed_value = static_cast<std::int32_t>(value);
            out = static_cast<std::uint64_t>(signed_value);
            is_signed = true;
            return true;
        }
        case kDwEhPeSdata8: {
            std::uint64_t value = 0;
            if (!read_u64(cur, value)) {
                return false;
            }
            signed_value = static_cast<std::int64_t>(value);
            out = static_cast<std::uint64_t>(signed_value);
            is_signed = true;
            return true;
        }
        default:
            return false;
    }
}

bool read_encoded_pointer(Cursor& cur,
                          std::uint8_t encoding,
                          const engine::BinaryInfo& binary_info,
                          const engine::LoadedImage& image,
                          std::uint64_t field_addr,
                          std::uint64_t& out) {
    if (encoding == kDwEhPeOmit) {
        return false;
    }
    const std::uint8_t format = static_cast<std::uint8_t>(encoding & 0x0f);
    const std::uint8_t application = static_cast<std::uint8_t>(encoding & 0x70);
    const bool indirect = (encoding & kDwEhPeIndirect) != 0;

    std::uint64_t value = 0;
    bool is_signed = false;
    std::int64_t signed_value = 0;
    if (!read_encoded_value(cur, format, binary_info, value, is_signed, signed_value)) {
        return false;
    }

    if (application == kDwEhPePcrel) {
        const std::int64_t rel = is_signed ? signed_value : static_cast<std::int64_t>(value);
        value = static_cast<std::uint64_t>(static_cast<std::int64_t>(field_addr) + rel);
    } else if (application != 0) {
        return false;
    }

    if (indirect) {
        std::vector<std::uint8_t> buffer;
        const std::size_t ptr_size = binary_info.is_64 ? 8 : 4;
        if (!image.read_bytes(value, ptr_size, buffer) || buffer.size() < ptr_size) {
            return false;
        }
        Cursor mem{buffer, 0, binary_info.little_endian};
        if (!read_pointer(mem, binary_info, value)) {
            return false;
        }
    }

    out = value;
    return true;
}

bool read_encoded_range(Cursor& cur,
                        std::uint8_t encoding,
                        const engine::BinaryInfo& binary_info,
                        std::uint64_t& out) {
    if (encoding == kDwEhPeOmit) {
        return false;
    }
    const std::uint8_t format = static_cast<std::uint8_t>(encoding & 0x0f);
    std::uint64_t value = 0;
    bool is_signed = false;
    std::int64_t signed_value = 0;
    if (!read_encoded_value(cur, format, binary_info, value, is_signed, signed_value)) {
        return false;
    }
    if (is_signed && signed_value < 0) {
        return false;
    }
    out = value;
    return true;
}

void apply_cfi_program(const std::vector<std::uint8_t>& program,
                       const engine::ehframe::CieEntry& cie,
                       bool little_endian,
                       engine::ehframe::CfaState& state) {
    Cursor cur{program, 0, little_endian};
    std::vector<engine::ehframe::CfaState> state_stack;
    while (cur.offset < program.size()) {
        std::uint8_t opcode = 0;
        if (!read_u8(cur, opcode)) {
            break;
        }
        const std::uint8_t primary = opcode & 0xc0;
        if (primary == 0x40) {
            continue;
        }
        if (primary == 0x80) {
            const std::uint8_t reg = opcode & 0x3f;
            std::uint64_t offset = 0;
            if (!read_uleb128(cur, offset)) {
                break;
            }
            const std::int64_t scaled = static_cast<std::int64_t>(offset) * cie.data_align;
            state.saved[reg] = static_cast<int>(scaled);
            state.expr.erase(reg);
            state.val_expr.erase(reg);
            state.same_value.erase(reg);
            state.undefined.erase(reg);
            continue;
        }
        if (primary == 0xc0) {
            const std::uint8_t reg = opcode & 0x3f;
            state.saved.erase(reg);
            state.expr.erase(reg);
            state.val_expr.erase(reg);
            state.same_value.erase(reg);
            state.undefined.erase(reg);
            continue;
        }

        switch (opcode) {
            case kDwCfaNop:
                break;
            case kDwCfaOffsetExtended: {
                std::uint64_t reg = 0;
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, offset)) {
                    return;
                }
                const std::int64_t scaled = static_cast<std::int64_t>(offset) * cie.data_align;
                state.saved[static_cast<int>(reg)] = static_cast<int>(scaled);
                state.expr.erase(static_cast<int>(reg));
                state.val_expr.erase(static_cast<int>(reg));
                state.same_value.erase(static_cast<int>(reg));
                state.undefined.erase(static_cast<int>(reg));
                break;
            }
            case kDwCfaRestoreExtended: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.saved.erase(r);
                state.expr.erase(r);
                state.val_expr.erase(r);
                state.same_value.erase(r);
                state.undefined.erase(r);
                break;
            }
            case kDwCfaUndefined: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.undefined.insert(r);
                state.saved.erase(r);
                state.expr.erase(r);
                state.val_expr.erase(r);
                state.same_value.erase(r);
                break;
            }
            case kDwCfaSameValue: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.same_value.insert(r);
                state.saved.erase(r);
                state.expr.erase(r);
                state.val_expr.erase(r);
                state.undefined.erase(r);
                break;
            }
            case kDwCfaDefCfa: {
                std::uint64_t reg = 0;
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, offset)) {
                    return;
                }
                state.cfa_reg = static_cast<int>(reg);
                state.cfa_offset = static_cast<int>(offset);
                state.cfa_expr.clear();
                break;
            }
            case kDwCfaDefCfaRegister: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                state.cfa_reg = static_cast<int>(reg);
                state.cfa_expr.clear();
                break;
            }
            case kDwCfaDefCfaOffset: {
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, offset)) {
                    return;
                }
                state.cfa_offset = static_cast<int>(offset);
                state.cfa_expr.clear();
                break;
            }
            case kDwCfaDefCfaSf: {
                std::uint64_t reg = 0;
                std::int64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_sleb128(cur, offset)) {
                    return;
                }
                state.cfa_reg = static_cast<int>(reg);
                state.cfa_offset = static_cast<int>(offset * cie.data_align);
                state.cfa_expr.clear();
                break;
            }
            case kDwCfaDefCfaOffsetSf: {
                std::int64_t offset = 0;
                if (!read_sleb128(cur, offset)) {
                    return;
                }
                state.cfa_offset = static_cast<int>(offset * cie.data_align);
                state.cfa_expr.clear();
                break;
            }
            case kDwCfaValOffset: {
                std::uint64_t reg = 0;
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, offset)) {
                    return;
                }
                const std::int64_t scaled = static_cast<std::int64_t>(offset) * cie.data_align;
                state.saved[static_cast<int>(reg)] = static_cast<int>(scaled);
                state.expr.erase(static_cast<int>(reg));
                state.val_expr.erase(static_cast<int>(reg));
                break;
            }
            case kDwCfaValOffsetSf: {
                std::uint64_t reg = 0;
                std::int64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_sleb128(cur, offset)) {
                    return;
                }
                state.saved[static_cast<int>(reg)] = static_cast<int>(offset * cie.data_align);
                state.expr.erase(static_cast<int>(reg));
                state.val_expr.erase(static_cast<int>(reg));
                break;
            }
            case kDwCfaRememberState:
                state_stack.push_back(state);
                break;
            case kDwCfaRestoreState:
                if (!state_stack.empty()) {
                    state = state_stack.back();
                    state_stack.pop_back();
                }
                break;
            case kDwCfaDefCfaExpression: {
                std::uint64_t length = 0;
                if (!read_uleb128(cur, length)) {
                    return;
                }
                std::vector<std::uint8_t> expr;
                if (!read_block(cur, static_cast<std::size_t>(length), expr)) {
                    return;
                }
                state.cfa_expr = std::move(expr);
                state.cfa_reg = -1;
                state.cfa_offset = 0;
                break;
            }
            case kDwCfaExpression: {
                std::uint64_t reg = 0;
                std::uint64_t length = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, length)) {
                    return;
                }
                std::vector<std::uint8_t> expr;
                if (!read_block(cur, static_cast<std::size_t>(length), expr)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.expr[r] = std::move(expr);
                state.saved.erase(r);
                state.val_expr.erase(r);
                state.same_value.erase(r);
                state.undefined.erase(r);
                break;
            }
            case kDwCfaValExpression: {
                std::uint64_t reg = 0;
                std::uint64_t length = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, length)) {
                    return;
                }
                std::vector<std::uint8_t> expr;
                if (!read_block(cur, static_cast<std::size_t>(length), expr)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.val_expr[r] = std::move(expr);
                state.saved.erase(r);
                state.expr.erase(r);
                state.same_value.erase(r);
                state.undefined.erase(r);
                break;
            }
            default:
                break;
        }
    }
}

void update_row(std::vector<engine::ehframe::CfaRow>& rows,
                std::uint64_t pc,
                const engine::ehframe::CfaState& state) {
    if (!rows.empty() && rows.back().pc == pc) {
        rows.back().state = state;
        return;
    }
    rows.push_back({pc, state});
}

void apply_cfi_with_rows(const std::vector<std::uint8_t>& program,
                         const engine::ehframe::CieEntry& cie,
                         std::size_t address_size,
                         std::uint64_t start_pc,
                         bool little_endian,
                         engine::ehframe::CfaState& state,
                         std::vector<engine::ehframe::CfaRow>& rows) {
    Cursor cur{program, 0, little_endian};
    std::vector<engine::ehframe::CfaState> state_stack;
    std::uint64_t pc = start_pc;
    update_row(rows, pc, state);

    while (cur.offset < program.size()) {
        std::uint8_t opcode = 0;
        if (!read_u8(cur, opcode)) {
            break;
        }
        const std::uint8_t primary = opcode & 0xc0;
        if (primary == 0x40) {
            const std::uint8_t delta = opcode & 0x3f;
            pc += static_cast<std::uint64_t>(delta) * cie.code_align;
            update_row(rows, pc, state);
            continue;
        }
        if (primary == 0x80) {
            const std::uint8_t reg = opcode & 0x3f;
            std::uint64_t offset = 0;
            if (!read_uleb128(cur, offset)) {
                break;
            }
            const std::int64_t scaled = static_cast<std::int64_t>(offset) * cie.data_align;
            state.saved[reg] = static_cast<int>(scaled);
            state.expr.erase(reg);
            state.val_expr.erase(reg);
            state.same_value.erase(reg);
            state.undefined.erase(reg);
            update_row(rows, pc, state);
            continue;
        }
        if (primary == 0xc0) {
            const std::uint8_t reg = opcode & 0x3f;
            state.saved.erase(reg);
            state.expr.erase(reg);
            state.val_expr.erase(reg);
            state.same_value.erase(reg);
            state.undefined.erase(reg);
            update_row(rows, pc, state);
            continue;
        }

        switch (opcode) {
            case kDwCfaNop:
                break;
            case kDwCfaSetLoc: {
                std::uint64_t new_pc = 0;
                if (!read_address_size(cur, address_size, new_pc)) {
                    return;
                }
                pc = new_pc;
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaAdvanceLoc1: {
                std::uint8_t delta = 0;
                if (!read_u8(cur, delta)) {
                    return;
                }
                pc += static_cast<std::uint64_t>(delta) * cie.code_align;
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaAdvanceLoc2: {
                std::uint16_t delta = 0;
                if (!read_u16(cur, delta)) {
                    return;
                }
                pc += static_cast<std::uint64_t>(delta) * cie.code_align;
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaAdvanceLoc4: {
                std::uint32_t delta = 0;
                if (!read_u32(cur, delta)) {
                    return;
                }
                pc += static_cast<std::uint64_t>(delta) * cie.code_align;
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaOffsetExtended: {
                std::uint64_t reg = 0;
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, offset)) {
                    return;
                }
                const std::int64_t scaled = static_cast<std::int64_t>(offset) * cie.data_align;
                state.saved[static_cast<int>(reg)] = static_cast<int>(scaled);
                state.expr.erase(static_cast<int>(reg));
                state.val_expr.erase(static_cast<int>(reg));
                state.same_value.erase(static_cast<int>(reg));
                state.undefined.erase(static_cast<int>(reg));
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaRestoreExtended: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.saved.erase(r);
                state.expr.erase(r);
                state.val_expr.erase(r);
                state.same_value.erase(r);
                state.undefined.erase(r);
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaUndefined: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.undefined.insert(r);
                state.saved.erase(r);
                state.expr.erase(r);
                state.val_expr.erase(r);
                state.same_value.erase(r);
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaSameValue: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.same_value.insert(r);
                state.saved.erase(r);
                state.expr.erase(r);
                state.val_expr.erase(r);
                state.undefined.erase(r);
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaDefCfa: {
                std::uint64_t reg = 0;
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, offset)) {
                    return;
                }
                state.cfa_reg = static_cast<int>(reg);
                state.cfa_offset = static_cast<int>(offset);
                state.cfa_expr.clear();
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaDefCfaRegister: {
                std::uint64_t reg = 0;
                if (!read_uleb128(cur, reg)) {
                    return;
                }
                state.cfa_reg = static_cast<int>(reg);
                state.cfa_expr.clear();
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaDefCfaOffset: {
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, offset)) {
                    return;
                }
                state.cfa_offset = static_cast<int>(offset);
                state.cfa_expr.clear();
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaDefCfaSf: {
                std::uint64_t reg = 0;
                std::int64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_sleb128(cur, offset)) {
                    return;
                }
                state.cfa_reg = static_cast<int>(reg);
                state.cfa_offset = static_cast<int>(offset * cie.data_align);
                state.cfa_expr.clear();
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaDefCfaOffsetSf: {
                std::int64_t offset = 0;
                if (!read_sleb128(cur, offset)) {
                    return;
                }
                state.cfa_offset = static_cast<int>(offset * cie.data_align);
                state.cfa_expr.clear();
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaValOffset: {
                std::uint64_t reg = 0;
                std::uint64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, offset)) {
                    return;
                }
                const std::int64_t scaled = static_cast<std::int64_t>(offset) * cie.data_align;
                state.saved[static_cast<int>(reg)] = static_cast<int>(scaled);
                state.expr.erase(static_cast<int>(reg));
                state.val_expr.erase(static_cast<int>(reg));
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaValOffsetSf: {
                std::uint64_t reg = 0;
                std::int64_t offset = 0;
                if (!read_uleb128(cur, reg) || !read_sleb128(cur, offset)) {
                    return;
                }
                state.saved[static_cast<int>(reg)] = static_cast<int>(offset * cie.data_align);
                state.expr.erase(static_cast<int>(reg));
                state.val_expr.erase(static_cast<int>(reg));
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaRememberState:
                state_stack.push_back(state);
                break;
            case kDwCfaRestoreState:
                if (!state_stack.empty()) {
                    state = state_stack.back();
                    state_stack.pop_back();
                    update_row(rows, pc, state);
                }
                break;
            case kDwCfaDefCfaExpression: {
                std::uint64_t length = 0;
                if (!read_uleb128(cur, length)) {
                    return;
                }
                std::vector<std::uint8_t> expr;
                if (!read_block(cur, static_cast<std::size_t>(length), expr)) {
                    return;
                }
                state.cfa_expr = std::move(expr);
                state.cfa_reg = -1;
                state.cfa_offset = 0;
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaExpression: {
                std::uint64_t reg = 0;
                std::uint64_t length = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, length)) {
                    return;
                }
                std::vector<std::uint8_t> expr;
                if (!read_block(cur, static_cast<std::size_t>(length), expr)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.expr[r] = std::move(expr);
                state.saved.erase(r);
                state.val_expr.erase(r);
                state.same_value.erase(r);
                state.undefined.erase(r);
                update_row(rows, pc, state);
                break;
            }
            case kDwCfaValExpression: {
                std::uint64_t reg = 0;
                std::uint64_t length = 0;
                if (!read_uleb128(cur, reg) || !read_uleb128(cur, length)) {
                    return;
                }
                std::vector<std::uint8_t> expr;
                if (!read_block(cur, static_cast<std::size_t>(length), expr)) {
                    return;
                }
                const int r = static_cast<int>(reg);
                state.val_expr[r] = std::move(expr);
                state.saved.erase(r);
                state.expr.erase(r);
                state.same_value.erase(r);
                state.undefined.erase(r);
                update_row(rows, pc, state);
                break;
            }
            default:
                break;
        }
    }
}

struct CieInfo {
    engine::ehframe::CieEntry entry;
    bool has_z = false;
};

bool parse_cie(Cursor& cur,
               std::size_t entry_end,
               const engine::BinaryInfo& binary_info,
               const engine::LoadedImage& image,
               std::uint64_t section_addr,
               CieInfo& cie) {
    if (cur.offset >= entry_end) {
        return false;
    }
    std::uint8_t version = 0;
    if (!read_u8(cur, version)) {
        return false;
    }
    (void)version;

    std::string augmentation;
    while (cur.offset < entry_end) {
        std::uint8_t ch = 0;
        if (!read_u8(cur, ch)) {
            return false;
        }
        if (ch == 0) {
            break;
        }
        augmentation.push_back(static_cast<char>(ch));
    }

    std::uint64_t code_align = 0;
    std::int64_t data_align = 0;
    std::uint64_t return_reg = 0;
    if (!read_uleb128(cur, code_align)) {
        return false;
    }
    if (!read_sleb128(cur, data_align)) {
        return false;
    }
    if (!read_uleb128(cur, return_reg)) {
        return false;
    }
    cie.entry.code_align = code_align;
    cie.entry.data_align = data_align;
    cie.entry.return_reg = return_reg;

    if (!augmentation.empty() && augmentation[0] == 'z') {
        cie.has_z = true;
        std::uint64_t aug_length = 0;
        if (!read_uleb128(cur, aug_length)) {
            return false;
        }
        const std::size_t aug_start = cur.offset;
        if (aug_start + static_cast<std::size_t>(aug_length) > entry_end) {
            return false;
        }
        for (std::size_t i = 1; i < augmentation.size(); ++i) {
            char tag = augmentation[i];
            if (cur.offset >= aug_start + aug_length) {
                break;
            }
            if (tag == 'L') {
                std::uint8_t lsda_encoding = 0;
                if (!read_u8(cur, lsda_encoding)) {
                    return false;
                }
                (void)lsda_encoding;
            } else if (tag == 'R') {
                std::uint8_t fde_encoding = 0;
                if (!read_u8(cur, fde_encoding)) {
                    return false;
                }
                cie.entry.fde_encoding = fde_encoding;
            } else if (tag == 'P') {
                std::uint8_t personality_encoding = 0;
                if (!read_u8(cur, personality_encoding)) {
                    return false;
                }
                std::uint64_t personality = 0;
                const std::uint64_t field_addr = section_addr + cur.offset;
                if (!read_encoded_pointer(cur, personality_encoding, binary_info, image, field_addr, personality)) {
                    return false;
                }
            }
        }
        cur.offset = aug_start + static_cast<std::size_t>(aug_length);
    }

    if (cur.offset < entry_end) {
        cie.entry.instructions.assign(cur.data.begin() + static_cast<std::ptrdiff_t>(cur.offset),
                                       cur.data.begin() + static_cast<std::ptrdiff_t>(entry_end));
    }
    if (!cie.entry.instructions.empty()) {
        apply_cfi_program(cie.entry.instructions, cie.entry, binary_info.little_endian, cie.entry.initial);
    }

    return true;
}

}  // namespace

namespace engine::ehframe {

void EhFrameCatalog::reset() {
    cies_.clear();
    entries_.clear();
}

void EhFrameCatalog::discover(const std::vector<BinarySection>& sections,
                              const LoadedImage& image,
                              const BinaryInfo& binary_info) {
    reset();
    std::unordered_map<std::uint64_t, CieInfo> cie_map;

    for (const auto& section : sections) {
        if (section.name != ".eh_frame") {
            continue;
        }
        if (section.size == 0 || section.addr == 0) {
            continue;
        }

        std::vector<std::uint8_t> buffer;
        if (!image.read_bytes(section.addr, static_cast<std::size_t>(section.size), buffer)) {
            continue;
        }

        Cursor cur{buffer, 0, binary_info.little_endian};
        while (cur.offset + 4 <= buffer.size()) {
            const std::size_t entry_start = cur.offset;
            std::uint32_t length32 = 0;
            if (!read_u32(cur, length32)) {
                break;
            }
            if (length32 == 0) {
                break;
            }

            bool is_64 = false;
            std::uint64_t length = length32;
            if (length32 == 0xffffffffu) {
                if (!read_u64(cur, length)) {
                    break;
                }
                is_64 = true;
            }

            const std::size_t content_start = cur.offset;
            const std::size_t entry_end = content_start + static_cast<std::size_t>(length);
            if (entry_end > buffer.size()) {
                break;
            }

            const std::size_t id_offset = cur.offset;
            std::int64_t cie_pointer = 0;
            if (is_64) {
                std::uint64_t raw = 0;
                if (!read_u64(cur, raw)) {
                    break;
                }
                cie_pointer = static_cast<std::int64_t>(raw);
            } else {
                std::uint32_t raw = 0;
                if (!read_u32(cur, raw)) {
                    break;
                }
                cie_pointer = static_cast<std::int32_t>(raw);
            }

            if (cie_pointer == 0) {
                Cursor cie_cur = cur;
                CieInfo cie;
                const std::uint64_t cie_addr = section.addr + entry_start;
                cie.entry.address = cie_addr;
                cie.entry.fde_encoding = kDwEhPeAbsptr;
                if (parse_cie(cie_cur, entry_end, binary_info, image, section.addr, cie)) {
                    cie_map[cie_addr] = cie;
                    cies_.push_back(cie.entry);
                }
            } else {
                const std::uint64_t id_addr = section.addr + id_offset;
                const std::uint64_t cie_addr =
                    static_cast<std::uint64_t>(static_cast<std::int64_t>(id_addr) + cie_pointer);
                auto it = cie_map.find(cie_addr);
                if (it != cie_map.end()) {
                    const std::uint8_t encoding = it->second.entry.fde_encoding;
                    const std::uint64_t start_addr_field = section.addr + cur.offset;
                    std::uint64_t start = 0;
                    if (read_encoded_pointer(cur, encoding, binary_info, image, start_addr_field, start)) {
                        std::uint64_t range = 0;
                        if (read_encoded_range(cur, encoding, binary_info, range)) {
                            if (it->second.has_z) {
                                std::uint64_t aug_length = 0;
                                if (read_uleb128(cur, aug_length)) {
                                    const std::size_t aug_end = cur.offset + static_cast<std::size_t>(aug_length);
                                    if (aug_end <= entry_end) {
                                        cur.offset = aug_end;
                                    }
                                }
                            }
                            if (start != 0 && range != 0) {
                                FdeEntry entry;
                                entry.start = start;
                                entry.size = range;
                                entry.cie = cie_addr;
                                if (cur.offset < entry_end) {
                                    entry.instructions.assign(cur.data.begin() + static_cast<std::ptrdiff_t>(cur.offset),
                                                              cur.data.begin() +
                                                                  static_cast<std::ptrdiff_t>(entry_end));
                                }
                                entry.cfa = it->second.entry.initial;
                                if (!entry.instructions.empty()) {
                                    apply_cfi_with_rows(entry.instructions,
                                                        it->second.entry,
                                                        binary_info.is_64 ? 8U : 4U,
                                                        entry.start,
                                                        binary_info.little_endian,
                                                        entry.cfa,
                                                        entry.rows);
                                }
                                entries_.push_back(entry);
                            }
                        }
                    }
                }
            }

            cur.offset = entry_end;
        }
    }
}

const std::vector<FdeEntry>& EhFrameCatalog::entries() const {
    return entries_;
}

const std::vector<CieEntry>& EhFrameCatalog::cies() const {
    return cies_;
}

const FdeEntry* EhFrameCatalog::find_fde_for_address(std::uint64_t addr) const {
    for (const auto& entry : entries_) {
        if (entry.start == 0 || entry.size == 0) {
            continue;
        }
        if (addr >= entry.start && addr < (entry.start + entry.size)) {
            return &entry;
        }
    }
    return nullptr;
}

const CfaRow* EhFrameCatalog::find_cfa_row(std::uint64_t addr) const {
    const auto* fde = find_fde_for_address(addr);
    if (!fde || fde->rows.empty()) {
        return nullptr;
    }
    auto it = std::upper_bound(fde->rows.begin(),
                               fde->rows.end(),
                               addr,
                               [](std::uint64_t value, const CfaRow& row) { return value < row.pc; });
    if (it == fde->rows.begin()) {
        return &fde->rows.front();
    }
    --it;
    return &(*it);
}

}  // namespace engine::ehframe
