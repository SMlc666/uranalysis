#include "engine/decompiler/types/type_solver.h"

namespace engine::decompiler::types {

void TypeSolver::add_var(const SsaVarKey& key) {
    ensure_index(key);
}

void TypeSolver::add_equal(const SsaVarKey& a, const SsaVarKey& b) {
    const std::size_t ia = ensure_index(a);
    const std::size_t ib = ensure_index(b);
    unite(ia, ib);
}

void TypeSolver::hint_size(const SsaVarKey& key, std::uint32_t bits, bool is_signed) {
    if (bits == 0) {
        return;
    }
    if (is_signed) {
        hint_int(key, bits);
    } else {
        hint_uint(key, bits);
    }
}

void TypeSolver::hint_uint(const SsaVarKey& key, std::uint32_t bits) {
    if (bits == 0) {
        return;
    }
    const std::size_t index = ensure_index(key);
    merge_types(find_root_mut(index), make_uint(bits));
}

void TypeSolver::hint_int(const SsaVarKey& key, std::uint32_t bits) {
    if (bits == 0) {
        return;
    }
    const std::size_t index = ensure_index(key);
    merge_types(find_root_mut(index), make_int(bits));
}

void TypeSolver::hint_ptr(const SsaVarKey& key, std::uint32_t pointee_bits) {
    const std::size_t index = ensure_index(key);
    merge_types(find_root_mut(index), make_ptr(pointee_bits));
}

Type TypeSolver::get_type(const SsaVarKey& key) const {
    auto it = indices_.find(key);
    if (it == indices_.end()) {
        return make_unknown();
    }
    const std::size_t root = find_root(it->second);
    return types_[root];
}

bool TypeSolver::has_type(const SsaVarKey& key) const {
    auto it = indices_.find(key);
    if (it == indices_.end()) {
        return false;
    }
    const std::size_t root = find_root(it->second);
    return types_[root].kind != TypeKind::kUnknown;
}

std::size_t TypeSolver::ensure_index(const SsaVarKey& key) {
    auto it = indices_.find(key);
    if (it != indices_.end()) {
        return it->second;
    }
    const std::size_t index = parent_.size();
    indices_.emplace(key, index);
    parent_.push_back(index);
    rank_.push_back(0);
    types_.push_back(make_unknown());
    return index;
}

std::size_t TypeSolver::find_root(std::size_t index) const {
    while (parent_[index] != index) {
        index = parent_[index];
    }
    return index;
}

std::size_t TypeSolver::find_root_mut(std::size_t index) {
    if (parent_[index] == index) {
        return index;
    }
    parent_[index] = find_root_mut(parent_[index]);
    return parent_[index];
}

void TypeSolver::merge_types(std::size_t root, const Type& type) {
    types_[root] = merge(types_[root], type);
}

void TypeSolver::unite(std::size_t a, std::size_t b) {
    std::size_t ra = find_root_mut(a);
    std::size_t rb = find_root_mut(b);
    if (ra == rb) {
        return;
    }
    if (rank_[ra] < rank_[rb]) {
        std::swap(ra, rb);
    }
    parent_[rb] = ra;
    types_[ra] = merge(types_[ra], types_[rb]);
    if (rank_[ra] == rank_[rb]) {
        ++rank_[ra];
    }
}

}  // namespace engine::decompiler::types
