#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

namespace engine::emit {

/// Token kinds for lexical output.
enum class TokenKind : std::uint8_t {
    Keyword,      // if, while, return, for, switch, case, default, break, continue
    Type,         // int, void, char*, uint64_t
    Identifier,   // variable names, function names
    Operator,     // +, -, *, /, ==, !=, &&, ||, etc.
    Literal,      // 0x1234, numeric constants
    Punctuation,  // {, }, (, ), [, ], ;, ,
    Comment,      // // comment text
    Whitespace,   // spaces for alignment
    Newline,      // line break
};

/// Metadata attached to tokens for interactive features.
struct TokenMeta {
    enum class Kind : std::uint8_t {
        None,
        Variable,   // references a variable
        Address,    // references an address (clickable)
        Function,   // references a function
    };

    Kind kind = Kind::None;

    // Variable reference
    std::string var_name;
    int var_version = -1;

    // Address reference
    std::uint64_t address = 0;

    static TokenMeta none() { return {}; }

    static TokenMeta variable(std::string_view name, int version = -1) {
        TokenMeta m;
        m.kind = Kind::Variable;
        m.var_name = name;
        m.var_version = version;
        return m;
    }

    static TokenMeta addr(std::uint64_t a) {
        TokenMeta m;
        m.kind = Kind::Address;
        m.address = a;
        return m;
    }

    static TokenMeta func(std::uint64_t a) {
        TokenMeta m;
        m.kind = Kind::Function;
        m.address = a;
        return m;
    }
};

/// A single token in the output stream.
struct Token {
    TokenKind kind = TokenKind::Whitespace;
    std::string text;
    TokenMeta meta;

    Token() = default;
    Token(TokenKind k, std::string t) : kind(k), text(std::move(t)) {}
    Token(TokenKind k, std::string t, TokenMeta m)
        : kind(k), text(std::move(t)), meta(std::move(m)) {}
};

}  // namespace engine::emit
