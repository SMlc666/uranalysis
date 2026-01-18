#include <catch2/catch_test_macros.hpp>

#include "engine/emit/syn/formatter.h"
#include "engine/emit/syn/precedence.h"
#include "fixtures/ir_builder.h"

using namespace engine::emit;
using namespace engine::emit::syn;
using namespace test::emit;

TEST_CASE("Operator precedence values", "[emit][syn]") {
    // Multiplicative > Additive
    REQUIRE(static_cast<int>(get_precedence(engine::mlil::MlilOp::kMul)) >
            static_cast<int>(get_precedence(engine::mlil::MlilOp::kAdd)));

    // Additive > Relational
    REQUIRE(static_cast<int>(get_precedence(engine::mlil::MlilOp::kAdd)) >
            static_cast<int>(get_precedence(engine::mlil::MlilOp::kLt)));

    // Relational > Equality
    REQUIRE(static_cast<int>(get_precedence(engine::mlil::MlilOp::kLt)) >
            static_cast<int>(get_precedence(engine::mlil::MlilOp::kEq)));
}

TEST_CASE("Expression formatting with precedence", "[emit][syn]") {
    lex::StringWriter w;
    Formatter f(w);

    SECTION("simple variable") {
        f.expr(E::var("x").build());
        REQUIRE(w.str() == "x");
    }

    SECTION("simple literal") {
        f.expr(E::imm(0x42).build());
        REQUIRE(w.str() == "0x42");
    }

    SECTION("binary add no parens needed") {
        // a + b
        f.expr(E::var("a").add(E::var("b")).build());
        REQUIRE(w.str() == "a + b");
    }

    SECTION("nested add-mul needs parens") {
        // (a + b) * c
        f.expr(E::var("a").add(E::var("b")).mul(E::var("c")).build());
        // Inner add has lower precedence than outer mul, needs parens
        REQUIRE(w.str() == "(a + b) * c");
    }

    SECTION("mul-add no parens for mul") {
        // a * b + c
        f.expr(E::var("a").mul(E::var("b")).add(E::var("c")).build());
        REQUIRE(w.str() == "a * b + c");
    }

    SECTION("comparison") {
        // x < 10
        f.expr(E::var("x").lt(E::imm(10)).build());
        REQUIRE(w.str() == "x < 0xa");
    }

    SECTION("ternary select") {
        // cond ? a : b
        f.expr(E::var("cond").select(E::var("a"), E::var("b")).build());
        REQUIRE(w.str() == "cond ? a : b");
    }
}

TEST_CASE("Statement formatting", "[emit][syn]") {
    lex::StringWriter w;
    Formatter f(w);

    SECTION("assignment") {
        f.stmt(S::assign("x", E::imm(5)).build());
        auto lines = w.lines();
        REQUIRE(lines.size() == 1);
        REQUIRE(lines[0] == "x = 0x5;");
    }

    SECTION("return with value") {
        f.stmt(S::ret(E::var("result")).build());
        auto lines = w.lines();
        REQUIRE(lines.size() == 1);
        REQUIRE(lines[0] == "return result;");
    }

    SECTION("if statement") {
        auto stmt = S::if_(E::var("x").lt(E::imm(10)))
                        .then({S::ret(E::imm(1))})
                        .build();
        f.stmt(stmt);
        auto lines = w.lines();
        REQUIRE(lines.size() >= 3);
        REQUIRE(lines[0] == "if (x < 0xa) {");
        REQUIRE(lines[1] == "    return 0x1;");
        REQUIRE(lines[2] == "}");
    }

    SECTION("if-else statement") {
        auto stmt = S::if_(E::var("x"))
                        .then({S::ret(E::imm(1))})
                        .else_({S::ret(E::imm(0))})
                        .build();
        f.stmt(stmt);
        auto lines = w.lines();
        REQUIRE(lines.size() >= 5);
        REQUIRE(lines[0] == "if (x) {");
        REQUIRE(lines[1] == "    return 0x1;");
        REQUIRE(lines[2] == "} else {");
        REQUIRE(lines[3] == "    return 0x0;");
        REQUIRE(lines[4] == "}");
    }

    SECTION("while loop") {
        auto stmt = S::while_(E::var("i").lt(E::var("n")))
                        .body({S::assign("i", E::var("i").add(E::imm(1)))})
                        .build();
        f.stmt(stmt);
        auto lines = w.lines();
        REQUIRE(lines.size() >= 3);
        REQUIRE(lines[0] == "while (i < n) {");
    }
}

TEST_CASE("Function formatting", "[emit][syn]") {
    lex::StringWriter w;
    Formatter f(w);

    auto func = make_function("test_func", {
        S::assign("x", E::imm(0)),
        S::ret(E::var("x"))
    });
    
    f.function(func);
    auto lines = w.lines();
    
    REQUIRE(lines.size() >= 3);
    REQUIRE(lines[0] == "int test_func() {");
    // Body lines
    REQUIRE(lines.back() == "}");
}
