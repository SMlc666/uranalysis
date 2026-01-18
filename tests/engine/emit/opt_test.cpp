#include <catch2/catch_test_macros.hpp>

#include "engine/emit/opt/naming.h"
#include "engine/emit/opt/sugar.h"
#include "fixtures/ir_builder.h"

using namespace engine::emit::opt;
using namespace test::emit;

TEST_CASE("SSA suffix cleaning", "[emit][opt]") {
    NamingContext ctx;

    SECTION("clean _v suffix") {
        REQUIRE(ctx.resolve("x0_v3") == "x0");
    }

    SECTION("clean _ver_ suffix") {
        REQUIRE(ctx.resolve("arg0_ver_17") == "arg0");
    }

    SECTION("clean multiple suffixes") {
        // v28_2_v32 -> v28_2 (only removes trailing SSA suffix)
        // But our implementation recursively cleans, so it becomes v28
        REQUIRE(ctx.resolve("v28_2_v32") == "v28");
    }

    SECTION("no suffix unchanged") {
        REQUIRE(ctx.resolve("normal_var") == "normal_var");
    }

    SECTION("numeric suffix cleaned") {
        REQUIRE(ctx.resolve("x0_9") == "x0");
    }
}

TEST_CASE("Stack and arg normalization", "[emit][opt]") {
    NamingContext ctx;

    SECTION("stack variable") {
        REQUIRE(ctx.resolve("stack.28") == "v28");
    }

    SECTION("arg slot") {
        REQUIRE(ctx.resolve("arg.0") == "a0");
    }
}

TEST_CASE("Array access detection", "[emit][opt]") {
    SECTION("simple base + index") {
        auto load = E::var("buf").add(E::var("i")).load().build();
        auto result = match_array_access(load);
        REQUIRE(result.has_value());
        REQUIRE(result->base.var.name == "buf");
        REQUIRE(result->index.var.name == "i");
    }

    SECTION("scaled index") {
        // buf + i * 4
        auto load = E::var("buf").add(E::var("i").mul(E::imm(4))).load().build();
        auto result = match_array_access(load);
        REQUIRE(result.has_value());
        REQUIRE(result->base.var.name == "buf");
        REQUIRE(result->index.var.name == "i");
        REQUIRE(result->scale == 4);
    }

    SECTION("non-load returns nullopt") {
        auto expr = E::var("x").add(E::var("y")).build();
        auto result = match_array_access(expr);
        REQUIRE_FALSE(result.has_value());
    }
}

TEST_CASE("Compound assignment detection", "[emit][opt]") {
    engine::mlil::VarRef var;
    var.name = "x";

    SECTION("x = x + 1 -> increment") {
        auto expr = E::var("x").add(E::imm(1)).build();
        auto result = match_compound_assign(var, expr);
        REQUIRE(result.has_value());
        REQUIRE(result->kind == CompoundAssign::Kind::Increment);
    }

    SECTION("x = x - 1 -> decrement") {
        auto expr = E::var("x").sub(E::imm(1)).build();
        auto result = match_compound_assign(var, expr);
        REQUIRE(result.has_value());
        REQUIRE(result->kind == CompoundAssign::Kind::Decrement);
    }

    SECTION("x = x + y -> add assign") {
        auto expr = E::var("x").add(E::var("y")).build();
        auto result = match_compound_assign(var, expr);
        REQUIRE(result.has_value());
        REQUIRE(result->kind == CompoundAssign::Kind::AddAssign);
    }

    SECTION("x = x - y -> sub assign") {
        auto expr = E::var("x").sub(E::var("y")).build();
        auto result = match_compound_assign(var, expr);
        REQUIRE(result.has_value());
        REQUIRE(result->kind == CompoundAssign::Kind::SubAssign);
    }

    SECTION("x = y + z -> not compound") {
        auto expr = E::var("y").add(E::var("z")).build();
        auto result = match_compound_assign(var, expr);
        REQUIRE_FALSE(result.has_value());
    }
}

TEST_CASE("Condition simplification", "[emit][opt]") {
    SECTION("x == 0 -> !x") {
        auto cond = E::var("x").eq(E::imm(0)).build();
        auto result = simplify_condition(cond);
        REQUIRE(result.kind == engine::mlil::MlilExprKind::kOp);
        REQUIRE(result.op == engine::mlil::MlilOp::kNot);
        REQUIRE(result.args.size() == 1);
        REQUIRE(result.args[0].var.name == "x");
    }

    SECTION("x != 0 -> x") {
        auto cond = E::var("x").ne(E::imm(0)).build();
        auto result = simplify_condition(cond);
        REQUIRE(result.kind == engine::mlil::MlilExprKind::kVar);
        REQUIRE(result.var.name == "x");
    }

    SECTION("x < y unchanged") {
        auto cond = E::var("x").lt(E::var("y")).build();
        auto result = simplify_condition(cond);
        REQUIRE(result.kind == engine::mlil::MlilExprKind::kOp);
        REQUIRE(result.op == engine::mlil::MlilOp::kLt);
    }
}
