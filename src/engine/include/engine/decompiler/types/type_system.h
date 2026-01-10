#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace engine::decompiler::types {

enum class TypeKind {
    kUnknown,
    kInt,
    kUInt,
    kPtr,
};

struct Type {
    TypeKind kind = TypeKind::kUnknown;
    std::uint32_t bits = 0;
    std::uint32_t pointee_bits = 0;
};

Type make_unknown();
Type make_int(std::uint32_t bits);
Type make_uint(std::uint32_t bits);
Type make_ptr(std::uint32_t pointee_bits);
Type merge(const Type& a, const Type& b);
std::string to_c_type(const Type& type);

struct SsaVarKey {
    std::string name;
    int version = -1;
};

struct SsaVarKeyHash {
    std::size_t operator()(const SsaVarKey& key) const;
};

struct SsaVarKeyEq {
    bool operator()(const SsaVarKey& a, const SsaVarKey& b) const;
};

}  // namespace engine::decompiler::types
