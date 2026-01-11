#include "client/formatters/address.h"

#include <cctype>
#include <iomanip>
#include <sstream>

namespace client::fmt {

std::string hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

std::string hex_padded(std::uint64_t value, int width) {
    std::ostringstream oss;
    oss << "0x" << std::setw(width) << std::setfill('0') << std::hex << value;
    return oss.str();
}

bool parse_u64(const std::string& text, std::uint64_t& out) {
    out = 0;
    if (text.empty()) {
        return false;
    }
    std::string s = text;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
        if (s.empty()) {
            return false;
        }
        std::istringstream iss(s);
        iss >> std::hex >> out;
        return !iss.fail();
    }
    std::istringstream iss(s);
    iss >> out;
    return !iss.fail();
}

std::string to_lower(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    for (unsigned char c : input) {
        result.push_back(static_cast<char>(std::tolower(c)));
    }
    return result;
}

bool matches_filter(const std::string& filter, const std::string& text) {
    if (filter.empty()) {
        return true;
    }
    const std::string filter_lower = to_lower(filter);
    const std::string target = to_lower(text);
    return target.find(filter_lower) != std::string::npos;
}

}  // namespace client::fmt