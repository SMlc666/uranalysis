#include "engine/emit/lex/writer.h"

#include <sstream>

namespace engine::emit::lex {

// =============================================================================
// StringWriter
// =============================================================================

StringWriter::StringWriter(int indent_width) : indent_width_(indent_width) {}

void StringWriter::emit_indent() {
    if (at_line_start_ && indent_level_ > 0) {
        buffer_.append(static_cast<std::size_t>(indent_level_ * indent_width_), ' ');
        at_line_start_ = false;
    }
}

void StringWriter::keyword(std::string_view k) {
    emit_indent();
    buffer_.append(k);
}

void StringWriter::type(std::string_view t) {
    emit_indent();
    buffer_.append(t);
}

void StringWriter::identifier(std::string_view name, const TokenMeta& /*meta*/) {
    emit_indent();
    buffer_.append(name);
}

void StringWriter::op(std::string_view o) {
    emit_indent();
    buffer_.append(o);
}

void StringWriter::literal(std::string_view lit) {
    emit_indent();
    buffer_.append(lit);
}

void StringWriter::punct(char c) {
    emit_indent();
    buffer_.push_back(c);
}

void StringWriter::punct(std::string_view p) {
    emit_indent();
    buffer_.append(p);
}

void StringWriter::space() {
    emit_indent();
    buffer_.push_back(' ');
}

void StringWriter::spaces(int count) {
    emit_indent();
    buffer_.append(static_cast<std::size_t>(count), ' ');
}

void StringWriter::newline() {
    buffer_.push_back('\n');
    at_line_start_ = true;
}

void StringWriter::indent() {
    ++indent_level_;
}

void StringWriter::dedent() {
    if (indent_level_ > 0) {
        --indent_level_;
    }
}

void StringWriter::line_comment(std::string_view text) {
    emit_indent();
    buffer_.append("// ");
    buffer_.append(text);
}

void StringWriter::raw(std::string_view text) {
    emit_indent();
    buffer_.append(text);
}

std::vector<std::string> StringWriter::lines() const {
    std::vector<std::string> result;
    std::istringstream stream(buffer_);
    std::string line;
    while (std::getline(stream, line)) {
        result.push_back(std::move(line));
    }
    return result;
}

void StringWriter::clear() {
    buffer_.clear();
    indent_level_ = 0;
    at_line_start_ = true;
}

// =============================================================================
// TokenWriter
// =============================================================================

void TokenWriter::emit_indent() {
    if (at_line_start_ && indent_level_ > 0) {
        std::string spaces(static_cast<std::size_t>(indent_level_ * indent_width_), ' ');
        tokens_.emplace_back(TokenKind::Whitespace, std::move(spaces));
        at_line_start_ = false;
    }
}

void TokenWriter::keyword(std::string_view k) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Keyword, std::string(k));
}

void TokenWriter::type(std::string_view t) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Type, std::string(t));
}

void TokenWriter::identifier(std::string_view name, const TokenMeta& meta) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Identifier, std::string(name), meta);
}

void TokenWriter::op(std::string_view o) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Operator, std::string(o));
}

void TokenWriter::literal(std::string_view lit) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Literal, std::string(lit));
}

void TokenWriter::punct(char c) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Punctuation, std::string(1, c));
}

void TokenWriter::punct(std::string_view p) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Punctuation, std::string(p));
}

void TokenWriter::space() {
    emit_indent();
    tokens_.emplace_back(TokenKind::Whitespace, " ");
}

void TokenWriter::spaces(int count) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Whitespace, std::string(static_cast<std::size_t>(count), ' '));
}

void TokenWriter::newline() {
    tokens_.emplace_back(TokenKind::Newline, "\n");
    at_line_start_ = true;
}

void TokenWriter::indent() {
    ++indent_level_;
}

void TokenWriter::dedent() {
    if (indent_level_ > 0) {
        --indent_level_;
    }
}

void TokenWriter::line_comment(std::string_view text) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Comment, "// " + std::string(text));
}

void TokenWriter::raw(std::string_view text) {
    emit_indent();
    tokens_.emplace_back(TokenKind::Whitespace, std::string(text));
}

void TokenWriter::clear() {
    tokens_.clear();
    indent_level_ = 0;
    at_line_start_ = true;
}

}  // namespace engine::emit::lex
