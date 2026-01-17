#pragma once

#include <string>
#include <vector>
#include <stdexcept>

namespace client {

/**
 * @brief Tokenizer for command line input.
 * 
 * Converts a raw command string into a list of tokens, properly handling:
 * - Whitespace as delimiters
 * - Double quotes ("...") preserving internal whitespace
 * - Single quotes ('...') for literal strings (no escape processing)
 * - Backslash escapes: \\, \", \', \n, \t, \r
 * 
 * Example:
 *   Input:  open "my file.exe" --format=pe
 *   Output: ["open", "my file.exe", "--format=pe"]
 */
class Tokenizer {
public:
    struct Token {
        std::string value;
        size_t start_pos;  // byte offset in original string
        size_t end_pos;
    };

    class ParseError : public std::runtime_error {
    public:
        ParseError(const std::string& msg, size_t pos)
            : std::runtime_error(msg), position_(pos) {}
        size_t position() const { return position_; }
    private:
        size_t position_;
    };

    /**
     * @brief Tokenize input string into arguments.
     * @param input The raw command line string.
     * @return Vector of string arguments.
     * @throws ParseError on syntax errors (unclosed quotes, etc.)
     */
    static std::vector<std::string> tokenize(const std::string& input);
    
    /**
     * @brief Tokenize with position information for error reporting.
     */
    static std::vector<Token> tokenize_detailed(const std::string& input);

private:
    enum class State {
        Normal,
        InDoubleQuote,
        InSingleQuote,
        Escape
    };
};

} // namespace client
