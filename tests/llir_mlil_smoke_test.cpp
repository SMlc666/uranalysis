#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>

#include "engine/llir.h"
#include "engine/llir_opt.h"
#include "engine/llir_passes.h"
#include "engine/llir_ssa.h"
#include "engine/mlil_lift.h"
#include "engine/mlil_ssa.h"

namespace {

engine::llir::LlilExpr make_imm(std::uint64_t value, std::size_t size = 8) {
    engine::llir::LlilExpr expr;
    expr.kind = engine::llir::LlilExprKind::kImm;
    expr.size = size;
    expr.imm = value;
    return expr;
}

engine::llir::LlilExpr make_reg(const std::string& name, int version = -1, std::size_t size = 8) {
    engine::llir::LlilExpr expr;
    expr.kind = engine::llir::LlilExprKind::kReg;
    expr.size = size;
    expr.reg.name = name;
    expr.reg.version = version;
    return expr;
}

engine::llir::LlilExpr make_binop(engine::llir::LlilOp op,
                                  engine::llir::LlilExpr lhs,
                                  engine::llir::LlilExpr rhs,
                                  std::size_t size) {
    engine::llir::LlilExpr expr;
    expr.kind = engine::llir::LlilExprKind::kOp;
    expr.op = op;
    expr.size = size;
    expr.args.push_back(std::move(lhs));
    expr.args.push_back(std::move(rhs));
    return expr;
}

engine::llir::Function make_single_block_function(engine::llir::Instruction inst) {
    engine::llir::Function func;
    func.entry = inst.address;
    engine::llir::BasicBlock block;
    block.start = inst.address;
    block.end = inst.address + 4;
    block.instructions.push_back(std::move(inst));
    func.blocks.push_back(std::move(block));
    return func;
}

}  // namespace

TEST_CASE("LLIL stack loads/stores lift to vars", "[llir][stack]") {
    engine::llir::Instruction inst;
    inst.address = 0x1000;

    engine::llir::LlilStmt store;
    store.kind = engine::llir::LlilStmtKind::kStore;
    store.target = make_binop(engine::llir::LlilOp::kAdd, make_reg("sp"), make_imm(16), 8);
    store.expr = make_imm(0x42, 8);
    inst.llil.push_back(store);

    engine::llir::LlilStmt load;
    load.kind = engine::llir::LlilStmtKind::kSetReg;
    load.reg.name = "x0";
    load.expr.kind = engine::llir::LlilExprKind::kLoad;
    load.expr.size = 8;
    load.expr.args.push_back(make_binop(engine::llir::LlilOp::kAdd, make_reg("sp"), make_imm(16), 8));
    inst.llil.push_back(load);

    auto func = make_single_block_function(std::move(inst));
    std::string error;
    REQUIRE(engine::llir::lift_stack_vars(func, error));

    const auto& stmts = func.blocks[0].instructions[0].llil;
    REQUIRE(stmts.size() == 2);
    CHECK(stmts[0].kind == engine::llir::LlilStmtKind::kSetVar);
    CHECK(stmts[0].var.name == "stack.16");
    CHECK(stmts[0].var.size == 8);
    CHECK(stmts[1].kind == engine::llir::LlilStmtKind::kSetReg);
    CHECK(stmts[1].expr.kind == engine::llir::LlilExprKind::kVar);
    CHECK(stmts[1].expr.var.name == "stack.16");
}

TEST_CASE("LLIL inline_flag_exprs folds flag uses", "[llir][opt]") {
    engine::llir::Instruction inst;
    inst.address = 0x2000;

    engine::llir::LlilStmt flag_set;
    flag_set.kind = engine::llir::LlilStmtKind::kSetReg;
    flag_set.reg.name = "flag_z";
    flag_set.reg.version = 1;
    flag_set.expr = make_imm(1, 1);

    engine::llir::LlilStmt cjump;
    cjump.kind = engine::llir::LlilStmtKind::kCJump;
    cjump.condition = make_reg("flag_z", 1, 1);
    cjump.target = make_imm(0x3000, 8);

    inst.llil_ssa.push_back(flag_set);
    inst.llil_ssa.push_back(cjump);

    auto func = make_single_block_function(std::move(inst));

    engine::llir::LlilOptOptions options;
    options.fold_constants = false;
    options.copy_propagation = false;
    options.dead_code_elim = false;
    options.inline_flag_exprs = true;

    std::string error;
    REQUIRE(engine::llir::optimize_llil_ssa(func, options, error));
    const auto& stmts = func.blocks[0].instructions[0].llil_ssa;
    REQUIRE(stmts.size() >= 2);
    CHECK(stmts[1].condition.kind == engine::llir::LlilExprKind::kImm);
    CHECK(stmts[1].condition.imm == 1);
}

TEST_CASE("LLIL resolves constant indirect branch targets", "[llir][cfg]") {
    engine::llir::Instruction inst;
    inst.address = 0x4000;

    engine::llir::LlilStmt jump;
    jump.kind = engine::llir::LlilStmtKind::kJump;
    jump.target = make_binop(engine::llir::LlilOp::kAdd, make_imm(0x5000, 8), make_imm(0x10, 8), 8);
    inst.llil.push_back(jump);

    auto func = make_single_block_function(std::move(inst));
    std::string error;
    REQUIRE(engine::llir::resolve_indirect_branches(func, error));
    CHECK(func.blocks[0].instructions[0].targets.size() == 1);
    CHECK(func.blocks[0].instructions[0].targets[0] == 0x5010);
    CHECK(func.blocks[0].successors.size() == 1);
    CHECK(func.blocks[0].successors[0] == 0x5010);
}

TEST_CASE("MLIL lift preserves call args/returns", "[mlil][call]") {
    engine::llir::Instruction inst;
    inst.address = 0x6000;

    engine::llir::LlilStmt call;
    call.kind = engine::llir::LlilStmtKind::kCall;
    call.target = make_imm(0x7000, 8);
    call.args.push_back(make_reg("x0"));
    call.args.push_back(make_imm(4, 8));
    engine::llir::RegRef ret;
    ret.name = "x0";
    ret.version = 3;
    call.returns.push_back(ret);
    inst.llil_ssa.push_back(call);

    auto func = make_single_block_function(std::move(inst));
    engine::mlil::Function mlil_func;
    std::string error;
    REQUIRE(engine::mlil::build_mlil_from_llil_ssa(func, mlil_func, error));

    const auto& stmt = mlil_func.blocks[0].instructions[0].stmts[0];
    REQUIRE(stmt.kind == engine::mlil::MlilStmtKind::kCall);
    CHECK(stmt.args.size() == 2);
    CHECK(stmt.returns.size() == 1);
    CHECK(stmt.returns[0].name == "reg.x0");
}

TEST_CASE("LLIL def-use records call returns", "[llir][call][ssa]") {
    engine::llir::LlilStmt call;
    call.kind = engine::llir::LlilStmtKind::kCall;
    call.target = make_imm(0x9000, 8);
    engine::llir::RegRef ret;
    ret.name = "x0";
    ret.version = 7;
    call.returns.push_back(ret);

    auto defuse = engine::llir::compute_def_use(call);
    REQUIRE_FALSE(defuse.defs.empty());
    CHECK(defuse.defs[0].name == "x0");
    CHECK(defuse.defs[0].version == 7);
}

TEST_CASE("MLIL def-use records call returns", "[mlil][call][ssa]") {
    engine::mlil::MlilStmt call;
    call.kind = engine::mlil::MlilStmtKind::kCall;
    call.target.kind = engine::mlil::MlilExprKind::kImm;
    call.target.size = 8;
    call.target.imm = 0x9000;
    engine::mlil::VarRef ret;
    ret.name = "reg.x0";
    ret.version = 7;
    call.returns.push_back(ret);

    auto defuse = engine::mlil::compute_def_use(call);
    REQUIRE_FALSE(defuse.defs.empty());
    CHECK(defuse.defs[0].name == "reg.x0");
    CHECK(defuse.defs[0].version == 7);
}

TEST_CASE("MLIL lift preserves return expression", "[mlil][ret]") {
    engine::llir::Instruction inst;
    inst.address = 0x8000;

    engine::llir::LlilStmt ret;
    ret.kind = engine::llir::LlilStmtKind::kRet;
    ret.expr = make_reg("x0", 5, 8);
    inst.llil_ssa.push_back(ret);

    auto func = make_single_block_function(std::move(inst));
    engine::mlil::Function mlil_func;
    std::string error;
    REQUIRE(engine::mlil::build_mlil_from_llil_ssa(func, mlil_func, error));

    const auto& stmt = mlil_func.blocks[0].instructions[0].stmts[0];
    REQUIRE(stmt.kind == engine::mlil::MlilStmtKind::kRet);
    CHECK(stmt.expr.kind == engine::mlil::MlilExprKind::kVar);
    CHECK(stmt.expr.var.name == "reg.x0");
}
