#include "client/args/arg_parser.h"
#include <sstream>
#include <algorithm>
#include <charconv>
#include <cstdlib>

namespace client::args {

ArgParser::ArgParser(std::string command_name) : name_(std::move(command_name)) {}

ArgParser& ArgParser::description(std::string desc) {
    description_ = std::move(desc);
    return *this;
}

ArgParser& ArgParser::add(ArgSpec spec) {
    specs_.push_back(std::move(spec));
    return *this;
}

ArgParser& ArgParser::flag(const std::string& name, char short_name, 
                           const std::string& long_name, const std::string& help_text) {
    return add(ArgSpec(name)
        .short_name(short_name)
        .long_name(long_name)
        .help(help_text)
        .type(ValueType::Bool)
        .default_value(false));
}

ArgParser& ArgParser::option(const std::string& name, char short_name,
                             const std::string& long_name, const std::string& help_text,
                             ValueType type) {
    return add(ArgSpec(name)
        .short_name(short_name)
        .long_name(long_name)
        .help(help_text)
        .type(type));
}

ArgParser& ArgParser::positional(const std::string& name, const std::string& help_text,
                                  bool required_flag, ValueType type) {
    return add(ArgSpec(name)
        .positional(true)
        .required(required_flag)
        .help(help_text)
        .type(type));
}

const ArgSpec* ArgParser::find_by_short(char c) const {
    for (const auto& spec : specs_) {
        if (spec.get_short_name() == c) return &spec;
    }
    return nullptr;
}

const ArgSpec* ArgParser::find_by_long(const std::string& name) const {
    for (const auto& spec : specs_) {
        if (spec.get_long_name() == name) return &spec;
    }
    return nullptr;
}

const ArgSpec* ArgParser::find_positional(size_t index) const {
    size_t pos_count = 0;
    for (const auto& spec : specs_) {
        if (spec.is_positional()) {
            if (pos_count == index) return &spec;
            ++pos_count;
        }
    }
    return nullptr;
}

Value ArgParser::parse_value(const std::string& str, ValueType type) const {
    switch (type) {
    case ValueType::Bool:
        if (str == "true" || str == "1" || str == "yes") return true;
        if (str == "false" || str == "0" || str == "no") return false;
        return true;
        
    case ValueType::String:
        return str;
        
    case ValueType::Integer: {
        int64_t val = 0;
        if (str.size() > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
            val = std::strtoll(str.c_str() + 2, nullptr, 16);
        } else {
            val = std::strtoll(str.c_str(), nullptr, 10);
        }
        return val;
    }
    
    case ValueType::Unsigned: {
        uint64_t val = 0;
        if (str.size() > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
            val = std::strtoull(str.c_str() + 2, nullptr, 16);
        } else {
            val = std::strtoull(str.c_str(), nullptr, 10);
        }
        return val;
    }
    
    case ValueType::Float:
        return std::strtod(str.c_str(), nullptr);
    }
    return str;
}

ArgParser::ParseResult ArgParser::parse(const std::vector<std::string>& args) const {
    ParseResult result;
    
    size_t start = args.empty() ? 0 : 1;
    size_t positional_index = 0;
    
    for (const auto& spec : specs_) {
        if (spec.get_default().has_value()) {
            result.matches_.set(spec.name(), *spec.get_default());
        }
    }
    
    for (size_t i = start; i < args.size(); ++i) {
        const std::string& arg = args[i];
        
        if (arg == "-h" || arg == "--help") {
            result.help_requested_ = true;
            result.success_ = true;
            return result;
        }
        
        if (arg.size() > 2 && arg[0] == '-' && arg[1] == '-') {
            std::string opt_name;
            std::string opt_value;
            bool has_value = false;
            
            auto eq_pos = arg.find('=', 2);
            if (eq_pos != std::string::npos) {
                opt_name = arg.substr(2, eq_pos - 2);
                opt_value = arg.substr(eq_pos + 1);
                has_value = true;
            } else {
                opt_name = arg.substr(2);
            }
            
            const ArgSpec* spec = find_by_long(opt_name);
            if (!spec) {
                result.error_ = "Unknown option: --" + opt_name;
                return result;
            }
            
            if (spec->value_type() == ValueType::Bool) {
                result.matches_.set(spec->name(), true);
            } else {
                if (!has_value) {
                    if (i + 1 >= args.size()) {
                        result.error_ = "Option --" + opt_name + " requires a value";
                        return result;
                    }
                    opt_value = args[++i];
                }
                result.matches_.set(spec->name(), parse_value(opt_value, spec->value_type()));
            }
            continue;
        }
        
        if (arg.size() >= 2 && arg[0] == '-' && arg[1] != '-') {
            for (size_t j = 1; j < arg.size(); ++j) {
                char c = arg[j];
                const ArgSpec* spec = find_by_short(c);
                if (!spec) {
                    result.error_ = std::string("Unknown option: -") + c;
                    return result;
                }
                
                if (spec->value_type() == ValueType::Bool) {
                    result.matches_.set(spec->name(), true);
                } else {
                    std::string opt_value;
                    if (j + 1 < arg.size()) {
                        opt_value = arg.substr(j + 1);
                        j = arg.size();
                    } else if (i + 1 < args.size()) {
                        opt_value = args[++i];
                    } else {
                        result.error_ = std::string("Option -") + c + " requires a value";
                        return result;
                    }
                    result.matches_.set(spec->name(), parse_value(opt_value, spec->value_type()));
                }
            }
            continue;
        }
        
        const ArgSpec* pos_spec = find_positional(positional_index);
        if (pos_spec) {
            const auto& choices = pos_spec->get_choices();
            if (!choices.empty()) {
                bool valid = std::find(choices.begin(), choices.end(), arg) != choices.end();
                if (!valid) {
                    std::ostringstream oss;
                    oss << "Invalid value '" << arg << "' for " << pos_spec->name() << ". Must be one of: ";
                    for (size_t k = 0; k < choices.size(); ++k) {
                        if (k > 0) oss << ", ";
                        oss << choices[k];
                    }
                    result.error_ = oss.str();
                    return result;
                }
            }
            result.matches_.set(pos_spec->name(), parse_value(arg, pos_spec->value_type()));
            ++positional_index;
        } else {
            result.matches_.add_remaining(arg);
        }
    }
    
    for (const auto& spec : specs_) {
        if (spec.is_required() && !result.matches_.has(spec.name())) {
            result.error_ = "Missing required argument: " + spec.name();
            return result;
        }
    }
    
    result.success_ = true;
    return result;
}

std::string ArgParser::usage() const {
    std::ostringstream oss;
    oss << name_;
    
    for (const auto& spec : specs_) {
        if (spec.is_positional()) {
            if (spec.is_required()) {
                oss << " <" << spec.name() << ">";
            } else {
                oss << " [" << spec.name() << "]";
            }
        }
    }
    
    bool has_opts = false;
    for (const auto& spec : specs_) {
        if (!spec.is_positional()) {
            has_opts = true;
            break;
        }
    }
    if (has_opts) {
        oss << " [options]";
    }
    
    return oss.str();
}

std::string ArgParser::help() const {
    std::ostringstream oss;
    
    oss << "Usage: " << usage() << "\n";
    
    if (!description_.empty()) {
        oss << "\n" << description_ << "\n";
    }
    
    std::vector<const ArgSpec*> positional_specs;
    std::vector<const ArgSpec*> option_specs;
    for (const auto& spec : specs_) {
        if (spec.is_positional()) {
            positional_specs.push_back(&spec);
        } else {
            option_specs.push_back(&spec);
        }
    }
    
    if (!positional_specs.empty()) {
        oss << "\nArguments:\n";
        for (const auto* spec : positional_specs) {
            oss << "  " << spec->name();
            if (!spec->help_text().empty()) {
                oss << "\n        " << spec->help_text();
            }
            if (spec->is_required()) {
                oss << " (required)";
            }
            oss << "\n";
        }
    }
    
    if (!option_specs.empty()) {
        oss << "\nOptions:\n";
        for (const auto* spec : option_specs) {
            oss << "  ";
            if (spec->get_short_name()) {
                oss << "-" << spec->get_short_name();
                if (!spec->get_long_name().empty()) {
                    oss << ", ";
                }
            }
            if (!spec->get_long_name().empty()) {
                oss << "--" << spec->get_long_name();
            }
            if (spec->value_type() != ValueType::Bool) {
                oss << " <value>";
            }
            if (!spec->help_text().empty()) {
                oss << "\n        " << spec->help_text();
            }
            oss << "\n";
        }
    }
    
    oss << "  -h, --help\n        Show this help message\n";
    
    return oss.str();
}

} // namespace client::args
