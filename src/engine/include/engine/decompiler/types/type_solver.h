#pragma once

#include <unordered_map>
#include <vector>

#include "engine/decompiler/types/type_system.h"

namespace engine::decompiler::types {

class TypeSolver {
  public:
    void add_var(const SsaVarKey& key);
    void add_equal(const SsaVarKey& a, const SsaVarKey& b);
    void hint_size(const SsaVarKey& key, std::uint32_t bits, bool is_signed);
    void hint_uint(const SsaVarKey& key, std::uint32_t bits);
    void hint_int(const SsaVarKey& key, std::uint32_t bits);
    void hint_ptr(const SsaVarKey& key, std::uint32_t pointee_bits);

    Type get_type(const SsaVarKey& key) const;
    bool has_type(const SsaVarKey& key) const;

  private:
    std::size_t ensure_index(const SsaVarKey& key);
    std::size_t find_root(std::size_t index) const;
    std::size_t find_root_mut(std::size_t index);
    void merge_types(std::size_t root, const Type& type);
    void unite(std::size_t a, std::size_t b);

    std::unordered_map<SsaVarKey, std::size_t, SsaVarKeyHash, SsaVarKeyEq> indices_;
    std::vector<std::size_t> parent_;
    std::vector<std::size_t> rank_;
    std::vector<Type> types_;
};

}  // namespace engine::decompiler::types
