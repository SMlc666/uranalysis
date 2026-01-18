#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "engine/emit/token.h"

namespace engine::emit::lex {

/// Abstract writer interface for token emission.
/// Implementations decide how to render tokens (string, token stream, GUI, etc.)
class Writer {
public:
    virtual ~Writer() = default;

    // Keywords: if, while, return, for, switch, case, default, break, continue
    virtual void keyword(std::string_view k) = 0;

    // Type names: int, void, char*, etc.
    virtual void type(std::string_view t) = 0;

    // Identifiers: variable names, function names
    virtual void identifier(std::string_view name, const TokenMeta& meta = TokenMeta::none()) = 0;

    // Operators: +, -, *, ==, &&, etc.
    virtual void op(std::string_view o) = 0;

    // Numeric literals: 0x1234
    virtual void literal(std::string_view lit) = 0;

    // Single punctuation: {, }, (, ), [, ], ;, ,
    virtual void punct(char c) = 0;

    // Multiple punctuation: ->, ::
    virtual void punct(std::string_view p) = 0;

    // Whitespace
    virtual void space() = 0;
    virtual void spaces(int count) = 0;

    // Newline + auto-indent
    virtual void newline() = 0;

    // Indent control
    virtual void indent() = 0;    // increase indent level
    virtual void dedent() = 0;    // decrease indent level

    // Comments
    virtual void line_comment(std::string_view text) = 0;

    // Raw text (escape hatch)
    virtual void raw(std::string_view text) = 0;
};

/// Writer that builds a std::string.
class StringWriter final : public Writer {
public:
    explicit StringWriter(int indent_width = 4);

    void keyword(std::string_view k) override;
    void type(std::string_view t) override;
    void identifier(std::string_view name, const TokenMeta& meta) override;
    void op(std::string_view o) override;
    void literal(std::string_view lit) override;
    void punct(char c) override;
    void punct(std::string_view p) override;
    void space() override;
    void spaces(int count) override;
    void newline() override;
    void indent() override;
    void dedent() override;
    void line_comment(std::string_view text) override;
    void raw(std::string_view text) override;

    /// Get the accumulated string.
    std::string str() const { return buffer_; }

    /// Get lines (split by newline).
    std::vector<std::string> lines() const;

    /// Clear the buffer.
    void clear();

private:
    void emit_indent();

    std::string buffer_;
    int indent_level_ = 0;
    int indent_width_ = 4;
    bool at_line_start_ = true;
};

/// Writer that builds a token stream.
class TokenWriter final : public Writer {
public:
    void keyword(std::string_view k) override;
    void type(std::string_view t) override;
    void identifier(std::string_view name, const TokenMeta& meta) override;
    void op(std::string_view o) override;
    void literal(std::string_view lit) override;
    void punct(char c) override;
    void punct(std::string_view p) override;
    void space() override;
    void spaces(int count) override;
    void newline() override;
    void indent() override;
    void dedent() override;
    void line_comment(std::string_view text) override;
    void raw(std::string_view text) override;

    /// Get the token stream.
    const std::vector<Token>& tokens() const { return tokens_; }

    /// Move out the token stream.
    std::vector<Token> take_tokens() { return std::move(tokens_); }

    /// Clear the buffer.
    void clear();

private:
    void emit_indent();

    std::vector<Token> tokens_;
    int indent_level_ = 0;
    int indent_width_ = 4;
    bool at_line_start_ = true;
};

}  // namespace engine::emit::lex
