#pragma once

#include <string>
#include <optional>
#include <variant>
#include <vector>

namespace client::args {

/**
 * @brief Supported value types for arguments.
 */
enum class ValueType {
    String,     // Default, any string
    Integer,    // Signed 64-bit integer
    Unsigned,   // Unsigned 64-bit (good for addresses: 0x...)
    Float,      // Double precision
    Bool        // Flag only, presence = true
};

/**
 * @brief Runtime value holder.
 */
using Value = std::variant<std::monostate, bool, std::string, int64_t, uint64_t, double>;

/**
 * @brief Specification for a single argument.
 * 
 * Use the builder pattern:
 *   ArgSpec("address")
 *       .help("Target address")
 *       .type(ValueType::Unsigned)
 *       .required()
 */
class ArgSpec {
public:
    explicit ArgSpec(std::string name);

    // Builder methods (return *this for chaining)
    ArgSpec& help(std::string text);
    ArgSpec& type(ValueType t);
    ArgSpec& required(bool val = true);
    ArgSpec& positional(bool val = true);
    ArgSpec& short_name(char c);           // e.g., 'f' for -f
    ArgSpec& long_name(std::string name);  // e.g., "force" for --force
    ArgSpec& default_value(Value val);
    ArgSpec& choices(std::vector<std::string> vals);  // Restrict to specific values

    // Accessors
    const std::string& name() const { return name_; }
    const std::string& help_text() const { return help_; }
    ValueType value_type() const { return type_; }
    bool is_required() const { return required_; }
    bool is_positional() const { return positional_; }
    char get_short_name() const { return short_; }
    const std::string& get_long_name() const { return long_; }
    const std::optional<Value>& get_default() const { return default_; }
    const std::vector<std::string>& get_choices() const { return choices_; }

private:
    std::string name_;
    std::string help_;
    ValueType type_ = ValueType::String;
    bool required_ = false;
    bool positional_ = false;
    char short_ = 0;
    std::string long_;
    std::optional<Value> default_;
    std::vector<std::string> choices_;
};

} // namespace client::args
