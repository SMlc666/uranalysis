#include <catch2/catch_test_macros.hpp>

#include "engine/emit/lex/writer.h"

using namespace engine::emit;
using namespace engine::emit::lex;

TEST_CASE("StringWriter basic output", "[emit][lex]") {
    StringWriter w;

    SECTION("simple tokens") {
        w.keyword("if");
        w.space();
        w.punct('(');
        w.identifier("x", {});
        w.punct(')');

        REQUIRE(w.str() == "if (x)");
    }

    SECTION("newline and indent") {
        w.keyword("if");
        w.space();
        w.punct('{');
        w.newline();
        w.indent();
        w.keyword("return");
        w.punct(';');
        w.newline();
        w.dedent();
        w.punct('}');

        auto lines = w.lines();
        REQUIRE(lines.size() == 3);
        REQUIRE(lines[0] == "if {");
        REQUIRE(lines[1] == "    return;");
        REQUIRE(lines[2] == "}");
    }

    SECTION("multiple indent levels") {
        w.indent();
        w.indent();
        w.identifier("x", {});

        REQUIRE(w.str() == "        x");
    }
}

TEST_CASE("TokenWriter token stream", "[emit][lex]") {
    TokenWriter w;

    SECTION("token types preserved") {
        w.keyword("while");
        w.space();
        w.punct('(');
        w.identifier("i", {});
        w.space();
        w.op("<");
        w.space();
        w.literal("0x10");
        w.punct(')');

        const auto& tokens = w.tokens();
        REQUIRE(tokens.size() == 9);
        REQUIRE(tokens[0].kind == TokenKind::Keyword);
        REQUIRE(tokens[0].text == "while");
        REQUIRE(tokens[3].kind == TokenKind::Identifier);
        REQUIRE(tokens[3].text == "i");
        REQUIRE(tokens[5].kind == TokenKind::Operator);
        REQUIRE(tokens[7].kind == TokenKind::Literal);
    }

    SECTION("metadata attached to identifiers") {
        w.identifier("ptr", TokenMeta::variable("ptr", 3));

        const auto& tokens = w.tokens();
        REQUIRE(tokens.size() == 1);
        REQUIRE(tokens[0].meta.kind == TokenMeta::Kind::Variable);
        REQUIRE(tokens[0].meta.var_name == "ptr");
        REQUIRE(tokens[0].meta.var_version == 3);
    }

    SECTION("newlines create separate tokens") {
        w.identifier("a", {});
        w.newline();
        w.identifier("b", {});

        const auto& tokens = w.tokens();
        REQUIRE(tokens.size() == 3);
        REQUIRE(tokens[1].kind == TokenKind::Newline);
    }
}
