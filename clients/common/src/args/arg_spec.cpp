#include "client/args/arg_spec.h"

namespace client::args {

ArgSpec::ArgSpec(std::string name) : name_(std::move(name)) {}

ArgSpec& ArgSpec::help(std::string text) {
    help_ = std::move(text);
    return *this;
}

ArgSpec& ArgSpec::type(ValueType t) {
    type_ = t;
    return *this;
}

ArgSpec& ArgSpec::required(bool val) {
    required_ = val;
    return *this;
}

ArgSpec& ArgSpec::positional(bool val) {
    positional_ = val;
    return *this;
}

ArgSpec& ArgSpec::short_name(char c) {
    short_ = c;
    return *this;
}

ArgSpec& ArgSpec::long_name(std::string name) {
    long_ = std::move(name);
    return *this;
}

ArgSpec& ArgSpec::default_value(Value val) {
    default_ = std::move(val);
    return *this;
}

ArgSpec& ArgSpec::choices(std::vector<std::string> vals) {
    choices_ = std::move(vals);
    return *this;
}

} // namespace client::args
