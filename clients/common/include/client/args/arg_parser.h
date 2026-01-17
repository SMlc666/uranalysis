#pragma once

#include "arg_spec.h"
#include "arg_matches.h"
#include <string>
#include <vector>
#include <optional>

namespace client::args {

/**
 * @brief Parses command arguments against a specification.
 * 
 * Example:
 *   ArgParser parser("seek");
 *   parser.description("Seek to an address or symbol")
 *         .add(ArgSpec("target").positional().required().help("Address or symbol name"))
 *         .add(ArgSpec("verbose").short_name('v').long_name("verbose").type(ValueType::Bool));
 *   
 *   auto result = parser.parse(tokens);
 *   if (!result) {
 *       output.write_line(result.error());
 *       return true;
 *   }
 *   auto& m = result.matches();
 *   uint64_t addr = m.get<uint64_t>("target");
 */
class ArgParser {
public:
    explicit ArgParser(std::string command_name);

    // Builder methods
    ArgParser& description(std::string desc);
    ArgParser& add(ArgSpec spec);

    // Convenience builders
    ArgParser& flag(const std::string& name, char short_name, const std::string& long_name, 
                    const std::string& help);
    ArgParser& option(const std::string& name, char short_name, const std::string& long_name,
                      const std::string& help, ValueType type = ValueType::String);
    ArgParser& positional(const std::string& name, const std::string& help, 
                          bool required = true, ValueType type = ValueType::String);

    /**
     * @brief Result of a parse operation.
     */
    class ParseResult {
    public:
        explicit operator bool() const { return success_; }
        bool ok() const { return success_; }
        bool help_requested() const { return help_requested_; }
        const std::string& error() const { return error_; }
        const ArgMatches& matches() const { return matches_; }
        ArgMatches& matches() { return matches_; }

    private:
        friend class ArgParser;
        bool success_ = false;
        bool help_requested_ = false;
        std::string error_;
        ArgMatches matches_;
    };

    /**
     * @brief Parse arguments. First element is expected to be the command name (skipped).
     */
    ParseResult parse(const std::vector<std::string>& args) const;

    /**
     * @brief Generate help text for this command.
     */
    std::string help() const;

    /**
     * @brief Generate short usage line (e.g., "seek <target> [-v|--verbose]").
     */
    std::string usage() const;

    // Accessors
    const std::string& name() const { return name_; }
    const std::vector<ArgSpec>& specs() const { return specs_; }

private:
    std::string name_;
    std::string description_;
    std::vector<ArgSpec> specs_;

    // Helpers
    const ArgSpec* find_by_short(char c) const;
    const ArgSpec* find_by_long(const std::string& name) const;
    const ArgSpec* find_positional(size_t index) const;
    Value parse_value(const std::string& str, ValueType type) const;
};

} // namespace client::args
