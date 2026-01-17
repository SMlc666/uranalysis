#include "client/tokenizer.h"

namespace client {

std::vector<std::string> Tokenizer::tokenize(const std::string& input) {
    auto detailed = tokenize_detailed(input);
    std::vector<std::string> result;
    result.reserve(detailed.size());
    for (auto& tok : detailed) {
        result.push_back(std::move(tok.value));
    }
    return result;
}

std::vector<Tokenizer::Token> Tokenizer::tokenize_detailed(const std::string& input) {
    std::vector<Token> tokens;
    std::string current;
    size_t token_start = 0;
    State state = State::Normal;
    State prev_state = State::Normal;

    auto flush_token = [&](size_t end_pos) {
        if (!current.empty()) {
            tokens.push_back({std::move(current), token_start, end_pos});
            current.clear();
        }
    };

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];

        switch (state) {
        case State::Normal:
            if (c == ' ' || c == '\t') {
                flush_token(i);
                token_start = i + 1;
            } else if (c == '"') {
                if (current.empty()) token_start = i;
                state = State::InDoubleQuote;
            } else if (c == '\'') {
                if (current.empty()) token_start = i;
                state = State::InSingleQuote;
            } else if (c == '\\') {
                if (current.empty()) token_start = i;
                prev_state = State::Normal;
                state = State::Escape;
            } else {
                if (current.empty()) token_start = i;
                current += c;
            }
            break;

        case State::InDoubleQuote:
            if (c == '"') {
                state = State::Normal;
            } else if (c == '\\') {
                prev_state = State::InDoubleQuote;
                state = State::Escape;
            } else {
                current += c;
            }
            break;

        case State::InSingleQuote:
            if (c == '\'') {
                state = State::Normal;
            } else {
                current += c;
            }
            break;

        case State::Escape:
            switch (c) {
            case 'n': current += '\n'; break;
            case 't': current += '\t'; break;
            case 'r': current += '\r'; break;
            case '\\': current += '\\'; break;
            case '"': current += '"'; break;
            case '\'': current += '\''; break;
            case ' ': current += ' '; break;
            default:
                current += '\\';
                current += c;
                break;
            }
            state = prev_state;
            break;
        }
    }

    if (state == State::InDoubleQuote) {
        throw ParseError("Unclosed double quote", token_start);
    }
    if (state == State::InSingleQuote) {
        throw ParseError("Unclosed single quote", token_start);
    }
    if (state == State::Escape) {
        throw ParseError("Trailing backslash", input.size() - 1);
    }

    flush_token(input.size());
    return tokens;
}

} // namespace client
