#pragma once

#include "arg_spec.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <stdexcept>

namespace client::args {

/**
 * @brief Result of parsing arguments. Holds matched values.
 * 
 * Usage:
 *   if (matches.has("verbose")) { ... }
 *   uint64_t addr = matches.get<uint64_t>("address");
 *   std::string name = matches.get_or("name", "default");
 */
class ArgMatches {
public:
    /**
     * @brief Check if an argument was provided (or has a default).
     */
    bool has(const std::string& name) const;

    /**
     * @brief Get value by name. Throws if not present or wrong type.
     */
    template<typename T>
    T get(const std::string& name) const {
        auto it = values_.find(name);
        if (it == values_.end()) {
            throw std::runtime_error("Argument not found: " + name);
        }
        if (!std::holds_alternative<T>(it->second)) {
            throw std::runtime_error("Type mismatch for argument: " + name);
        }
        return std::get<T>(it->second);
    }

    /**
     * @brief Get value with fallback default.
     */
    template<typename T>
    T get_or(const std::string& name, T fallback) const {
        auto it = values_.find(name);
        if (it == values_.end() || std::holds_alternative<std::monostate>(it->second)) {
            return fallback;
        }
        if (!std::holds_alternative<T>(it->second)) {
            return fallback;
        }
        return std::get<T>(it->second);
    }

    /**
     * @brief Get as string regardless of stored type (for display).
     */
    std::string get_string(const std::string& name) const;

    /**
     * @brief Access remaining positional arguments not matched to specs.
     */
    const std::vector<std::string>& remaining() const { return remaining_; }

private:
    friend class ArgParser;
    std::unordered_map<std::string, Value> values_;
    std::vector<std::string> remaining_;

    void set(const std::string& name, Value val);
    void add_remaining(std::string val);
};

} // namespace client::args
