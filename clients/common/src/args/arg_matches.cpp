#include "client/args/arg_matches.h"
#include <sstream>

namespace client::args {

bool ArgMatches::has(const std::string& name) const {
    auto it = values_.find(name);
    return it != values_.end() && !std::holds_alternative<std::monostate>(it->second);
}

std::string ArgMatches::get_string(const std::string& name) const {
    auto it = values_.find(name);
    if (it == values_.end()) {
        return "";
    }
    
    return std::visit([](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return "";
        } else if constexpr (std::is_same_v<T, bool>) {
            return arg ? "true" : "false";
        } else if constexpr (std::is_same_v<T, std::string>) {
            return arg;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return std::to_string(arg);
        } else if constexpr (std::is_same_v<T, uint64_t>) {
            std::ostringstream oss;
            oss << "0x" << std::hex << arg;
            return oss.str();
        } else if constexpr (std::is_same_v<T, double>) {
            return std::to_string(arg);
        }
        return "";
    }, it->second);
}

void ArgMatches::set(const std::string& name, Value val) {
    values_[name] = std::move(val);
}

void ArgMatches::add_remaining(std::string val) {
    remaining_.push_back(std::move(val));
}

} // namespace client::args
