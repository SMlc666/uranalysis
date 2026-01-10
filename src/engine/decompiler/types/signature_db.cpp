#include "engine/decompiler/types/signature_db.h"

#include <unordered_map>

namespace engine::decompiler::types {

namespace {

std::string normalize_name(std::string name) {
    if (!name.empty() && name.front() == '_') {
        name.erase(0, 1);
    }
    auto pos = name.find('(');
    if (pos != std::string::npos) {
        name = name.substr(0, pos);
    }
    return name;
}

using Sig = std::pair<std::string, std::vector<VarDecl>>;

const std::unordered_map<std::string, Sig>& signature_db() {
    static const std::unordered_map<std::string, Sig> kDb = {
        {"memcpy", {"void*", { {"dst", "uint8_t*"}, {"src", "const uint8_t*"}, {"n", "uint64_t"} }}},
        {"memmove", {"void*", { {"dst", "uint8_t*"}, {"src", "const uint8_t*"}, {"n", "uint64_t"} }}},
        {"memset", {"void*", { {"dst", "uint8_t*"}, {"c", "int32_t"}, {"n", "uint64_t"} }}},
        {"memcmp", {"int32_t", { {"a", "const uint8_t*"}, {"b", "const uint8_t*"}, {"n", "uint64_t"} }}},
        {"strlen", {"uint64_t", { {"s", "const uint8_t*"} }}},
        {"strcpy", {"uint8_t*", { {"dst", "uint8_t*"}, {"src", "const uint8_t*"} }}},
        {"strncpy", {"uint8_t*", { {"dst", "uint8_t*"}, {"src", "const uint8_t*"}, {"n", "uint64_t"} }}},
        {"strcat", {"uint8_t*", { {"dst", "uint8_t*"}, {"src", "const uint8_t*"} }}},
        {"strncat", {"uint8_t*", { {"dst", "uint8_t*"}, {"src", "const uint8_t*"}, {"n", "uint64_t"} }}},
        {"strcmp", {"int32_t", { {"a", "const uint8_t*"}, {"b", "const uint8_t*"} }}},
        {"strncmp", {"int32_t", { {"a", "const uint8_t*"}, {"b", "const uint8_t*"}, {"n", "uint64_t"} }}},
        {"strchr", {"uint8_t*", { {"s", "const uint8_t*"}, {"c", "int32_t"} }}},
        {"strrchr", {"uint8_t*", { {"s", "const uint8_t*"}, {"c", "int32_t"} }}},
        {"strstr", {"uint8_t*", { {"s", "const uint8_t*"}, {"sub", "const uint8_t*"} }}},
        {"atoi", {"int32_t", { {"s", "const uint8_t*"} }}},
        {"atol", {"int64_t", { {"s", "const uint8_t*"} }}},
        {"concat_limited", {"void", { {"out", "uint8_t*"}, {"cap", "uint64_t"},
                                         {"a", "const uint8_t*"}, {"b", "const uint8_t*"} }}},
    };
    return kDb;
}

}  // namespace

bool lookup_signature(const std::string& name,
                      std::vector<VarDecl>& params,
                      std::string& return_type) {
    params.clear();
    return_type.clear();
    const std::string key = normalize_name(name);
    const auto& db = signature_db();
    auto it = db.find(key);
    if (it == db.end()) {
        return false;
    }
    return_type = it->second.first;
    params = it->second.second;
    return true;
}

}  // namespace engine::decompiler::types
