#include "engine/decompiler/types/type_system.h"

#include <algorithm>
#include <functional>

namespace engine::decompiler::types {

Type make_unknown() {
    return {};
}

Type make_int(std::uint32_t bits) {
    Type t;
    t.kind = TypeKind::kInt;
    t.bits = bits;
    return t;
}

Type make_uint(std::uint32_t bits) {
    Type t;
    t.kind = TypeKind::kUInt;
    t.bits = bits;
    return t;
}

Type make_ptr(std::uint32_t pointee_bits) {
    Type t;
    t.kind = TypeKind::kPtr;
    t.pointee_bits = pointee_bits;
    return t;
}

Type merge(const Type& a, const Type& b) {
    if (a.kind == TypeKind::kUnknown) {
        return b;
    }
    if (b.kind == TypeKind::kUnknown) {
        return a;
    }
    if (a.kind == TypeKind::kPtr || b.kind == TypeKind::kPtr) {
        Type out;
        out.kind = TypeKind::kPtr;
        out.pointee_bits = std::max(a.pointee_bits, b.pointee_bits);
        return out;
    }
    Type out;
    if (a.kind == TypeKind::kUInt || b.kind == TypeKind::kUInt) {
        out.kind = TypeKind::kUInt;
    } else {
        out.kind = TypeKind::kInt;
    }
    out.bits = std::max(a.bits, b.bits);
    return out;
}

static std::string uint_type_for_bits(std::uint32_t bits) {
    switch (bits) {
        case 8: return "uint8_t";
        case 16: return "uint16_t";
        case 32: return "uint32_t";
        case 64: return "uint64_t";
        default: return "uint64_t";
    }
}

static std::string int_type_for_bits(std::uint32_t bits) {
    switch (bits) {
        case 8: return "int8_t";
        case 16: return "int16_t";
        case 32: return "int32_t";
        case 64: return "int64_t";
        default: return "int64_t";
    }
}

std::string to_c_type(const Type& type) {
    if (type.kind == TypeKind::kPtr) {
        const std::string base = uint_type_for_bits(type.pointee_bits == 0 ? 8 : type.pointee_bits);
        return base + "*";
    }
    if (type.kind == TypeKind::kInt) {
        return int_type_for_bits(type.bits);
    }
    if (type.kind == TypeKind::kUInt) {
        return uint_type_for_bits(type.bits);
    }
    return "uint64_t";
}

std::size_t SsaVarKeyHash::operator()(const SsaVarKey& key) const {
    std::size_t h = std::hash<std::string>{}(key.name);
    h ^= static_cast<std::size_t>(std::hash<int>{}(key.version)) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

bool SsaVarKeyEq::operator()(const SsaVarKey& a, const SsaVarKey& b) const {
    return a.version == b.version && a.name == b.name;
}

}  // namespace engine::decompiler::types
