#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include "engine/llir.h"
#include "engine/llir_opt.h"
#include "engine/llir_ssa.h"
#include "engine/mlil_opt.h"
#include "engine/mlil_ssa.h"
#include "engine/mlil_lift.h"
#include "engine/session.h"
#include "test_helpers.h"

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

engine::mlil::MlilExpr make_mlil_imm(std::uint64_t value, std::size_t size = 8) {
    engine::mlil::MlilExpr expr;
    expr.kind = engine::mlil::MlilExprKind::kImm;
    expr.size = size;
    expr.imm = value;
    return expr;
}

engine::mlil::MlilExpr make_mlil_var(const std::string& name, int version = -1, std::size_t size = 8) {
    engine::mlil::MlilExpr expr;
    expr.kind = engine::mlil::MlilExprKind::kVar;
    expr.size = size;
    expr.var.name = name;
    expr.var.version = version;
    return expr;
}

engine::mlil::MlilExpr make_mlil_binop(engine::mlil::MlilOp op,
                                       engine::mlil::MlilExpr lhs,
                                       engine::mlil::MlilExpr rhs,
                                       std::size_t size) {
    engine::mlil::MlilExpr expr;
    expr.kind = engine::mlil::MlilExprKind::kOp;
    expr.op = op;
    expr.size = size;
    expr.args.push_back(std::move(lhs));
    expr.args.push_back(std::move(rhs));
    return expr;
}

}  // namespace

TEST_CASE("LLIR def-use tracking captures uses and defs", "[llir][ssa]") {
    engine::llir::LlilStmt stmt;
    stmt.kind = engine::llir::LlilStmtKind::kSetReg;
    stmt.reg.name = "x0";
    stmt.expr = make_binop(engine::llir::LlilOp::kAdd,
                           make_reg("x1"),
                           make_imm(4, 4),
                           8);

    auto defuse = engine::llir::compute_def_use(stmt);
    REQUIRE(defuse.defs.size() == 1);
    CHECK(defuse.defs[0].name == "x0");
    REQUIRE_FALSE(defuse.uses.empty());
    CHECK(defuse.uses[0].name == "x1");
}

TEST_CASE("LLIR SSA assigns register versions", "[llir][ssa]") {
    engine::llir::Function func;
    func.entry = 0x1000;

    engine::llir::BasicBlock block;
    block.start = 0x1000;
    block.end = 0x1004;

    engine::llir::Instruction inst;
    inst.address = 0x1000;
    engine::llir::LlilStmt stmt;
    stmt.kind = engine::llir::LlilStmtKind::kSetReg;
    stmt.reg.name = "x0";
    stmt.expr = make_imm(1, 4);
    inst.llil.push_back(stmt);
    block.instructions.push_back(inst);
    func.blocks.push_back(block);

    std::string error;
    REQUIRE(engine::llir::build_ssa(func, error));
    REQUIRE_FALSE(func.blocks[0].instructions[0].llil_ssa.empty());
    const auto& ssa_stmt = func.blocks[0].instructions[0].llil_ssa[0];
    CHECK(ssa_stmt.reg.name == "x0");
    CHECK(ssa_stmt.reg.version > 0);

    engine::llir::LlilSsaDefUse defuse;
    REQUIRE(engine::llir::build_ssa_def_use(func, defuse, error));
    engine::llir::RegRefKey key{"x0", ssa_stmt.reg.version};
    CHECK(defuse.defs.find(key) != defuse.defs.end());
}

TEST_CASE("LLIR SSA optimizer folds constants", "[llir][opt]") {
    engine::llir::Function func;
    func.entry = 0x2000;

    engine::llir::BasicBlock block;
    block.start = 0x2000;
    block.end = 0x2008;

    engine::llir::Instruction inst;
    inst.address = 0x2000;

    engine::llir::LlilStmt add_stmt;
    add_stmt.kind = engine::llir::LlilStmtKind::kSetReg;
    add_stmt.reg.name = "x0";
    add_stmt.reg.version = 1;
    add_stmt.expr = make_binop(engine::llir::LlilOp::kAdd,
                               make_imm(1, 4),
                               make_imm(2, 4),
                               4);

    engine::llir::LlilStmt use_stmt;
    use_stmt.kind = engine::llir::LlilStmtKind::kSetReg;
    use_stmt.reg.name = "x1";
    use_stmt.reg.version = 2;
    use_stmt.expr = make_reg("x0", 1, 4);

    inst.llil_ssa.push_back(add_stmt);
    inst.llil_ssa.push_back(use_stmt);
    block.instructions.push_back(inst);
    func.blocks.push_back(block);

    engine::llir::LlilOptOptions options;
    options.fold_constants = true;
    options.copy_propagation = false;
    options.dead_code_elim = false;

    std::string error;
    REQUIRE(engine::llir::optimize_llil_ssa(func, options, error));
    const auto& optimized = func.blocks[0].instructions[0].llil_ssa[0];
    CHECK(optimized.expr.kind == engine::llir::LlilExprKind::kImm);
    CHECK(optimized.expr.imm == 3);
}

TEST_CASE("MLIL lift succeeds from LLIR SSA", "[mlil]") {
    const auto sample = test_helpers::find_sample_path("tests/samples/arm64/binaryO0Opt.elf");
    REQUIRE(sample.has_value());

    engine::Session session;
    std::string error;
    REQUIRE(session.open(sample->string(), error));

    engine::llir::Function llir_func;
    REQUIRE(session.build_llir_ssa_arm64(session.binary_info().entry, 512, llir_func, error));

    engine::mlil::Function mlil_func;
    REQUIRE(engine::mlil::build_mlil_from_llil_ssa(llir_func, mlil_func, error));
    CHECK(mlil_func.entry == llir_func.entry);
    CHECK_FALSE(mlil_func.blocks.empty());
}

TEST_CASE("MLIL optimizer normalizes boolean conditions for structuring", "[mlil][opt]") {
    engine::mlil::Function func;
    func.entry = 0x1000;

    engine::mlil::BasicBlock block;
    block.start = 0x1000;
    block.end = 0x1004;

    engine::mlil::Instruction inst;
    inst.address = 0x1000;

    engine::mlil::MlilStmt stmt;
    stmt.kind = engine::mlil::MlilStmtKind::kCJump;

    const auto cap = [] { return make_mlil_var("reg.x1", 0, 8); };
    const auto idx = [] { return make_mlil_var("reg.x0", 0, 8); };
    const auto one = [] { return make_mlil_imm(1, 8); };
    const auto zero64 = [] { return make_mlil_imm(0, 8); };
    const auto zero1 = [] { return make_mlil_imm(0, 1); };

    // and(ge(cap, idx+1), eq(eq(sub(cap, idx+1), 0), 0))  ==> lt(idx+1, cap)
    engine::mlil::MlilExpr idx1 = make_mlil_binop(engine::mlil::MlilOp::kAdd, idx(), one(), 8);
    engine::mlil::MlilExpr ge = make_mlil_binop(engine::mlil::MlilOp::kGe, cap(), idx1, 1);
    engine::mlil::MlilExpr sub = make_mlil_binop(engine::mlil::MlilOp::kSub, cap(), make_mlil_binop(engine::mlil::MlilOp::kAdd, idx(), one(), 8), 8);
    engine::mlil::MlilExpr eq0 = make_mlil_binop(engine::mlil::MlilOp::kEq, std::move(sub), zero64(), 1);
    engine::mlil::MlilExpr eqeq = make_mlil_binop(engine::mlil::MlilOp::kEq, std::move(eq0), zero1(), 1);
    stmt.condition = make_mlil_binop(engine::mlil::MlilOp::kAnd, std::move(ge), std::move(eqeq), 1);

    inst.stmts.push_back(std::move(stmt));
    block.instructions.push_back(std::move(inst));
    func.blocks.push_back(std::move(block));

    engine::mlil::MlilOptOptions options;
    options.fold_constants = true;
    options.copy_propagation = false;
    options.dead_code_elim = false;

    std::string error;
    REQUIRE(engine::mlil::optimize_mlil_ssa(func, options, error));
    const auto& cond = func.blocks[0].instructions[0].stmts[0].condition;
    REQUIRE(cond.kind == engine::mlil::MlilExprKind::kOp);
    CHECK(cond.op == engine::mlil::MlilOp::kLt);
    REQUIRE(cond.args.size() == 2);
}

TEST_CASE("MLIL optimizer collapses le + (b-a)!=0 into lt", "[mlil][opt]") {
    engine::mlil::Function func;
    func.entry = 0x1000;

    engine::mlil::BasicBlock block;
    block.start = 0x1000;
    block.end = 0x1004;

    engine::mlil::Instruction inst;
    inst.address = 0x1000;

    engine::mlil::MlilStmt stmt;
    stmt.kind = engine::mlil::MlilStmtKind::kCJump;

    engine::mlil::MlilExpr a = make_mlil_var("reg.x0", 0, 8);
    engine::mlil::MlilExpr b = make_mlil_var("reg.x1", 0, 8);

    engine::mlil::MlilExpr le = make_mlil_binop(engine::mlil::MlilOp::kLe, a, b, 1);
    engine::mlil::MlilExpr sub = make_mlil_binop(engine::mlil::MlilOp::kSub, b, a, 8);
    engine::mlil::MlilExpr ne = make_mlil_binop(engine::mlil::MlilOp::kNe, std::move(sub), make_mlil_imm(0, 8), 1);
    stmt.condition = make_mlil_binop(engine::mlil::MlilOp::kAnd, std::move(le), std::move(ne), 1);

    inst.stmts.push_back(std::move(stmt));
    block.instructions.push_back(std::move(inst));
    func.blocks.push_back(std::move(block));

    engine::mlil::MlilOptOptions options;
    options.fold_constants = true;
    options.copy_propagation = false;
    options.dead_code_elim = false;

    std::string error;
    REQUIRE(engine::mlil::optimize_mlil_ssa(func, options, error));
    const auto& cond = func.blocks[0].instructions[0].stmts[0].condition;
    REQUIRE(cond.kind == engine::mlil::MlilExprKind::kOp);
    CHECK(cond.op == engine::mlil::MlilOp::kLt);
    REQUIRE(cond.args.size() == 2);
}

TEST_CASE("MLIL def-use tracking captures uses and defs", "[mlil][ssa]") {
    engine::mlil::MlilStmt stmt;
    stmt.kind = engine::mlil::MlilStmtKind::kAssign;
    stmt.var.name = "reg.x0";
    stmt.expr = make_mlil_binop(engine::mlil::MlilOp::kAdd,
                                make_mlil_var("reg.x1"),
                                make_mlil_imm(4, 4),
                                8);

    auto defuse = engine::mlil::compute_def_use(stmt);
    REQUIRE(defuse.defs.size() == 1);
    CHECK(defuse.defs[0].name == "reg.x0");
    REQUIRE_FALSE(defuse.uses.empty());
    CHECK(defuse.uses[0].name == "reg.x1");
}

TEST_CASE("MLIL SSA canonicalizes reg vars and inserts phis", "[mlil][ssa]") {
    engine::mlil::Function func;
    func.entry = 0x1000;

    engine::mlil::BasicBlock block0;
    block0.start = 0x1000;
    block0.end = 0x1004;
    block0.successors.push_back(0x3000);

    engine::mlil::Instruction inst0;
    inst0.address = 0x1000;
    engine::mlil::MlilStmt assign0;
    assign0.kind = engine::mlil::MlilStmtKind::kAssign;
    assign0.var.name = "reg.w0";
    assign0.expr = make_mlil_imm(1, 4);
    inst0.stmts.push_back(assign0);
    block0.instructions.push_back(inst0);

    engine::mlil::BasicBlock block1;
    block1.start = 0x2000;
    block1.end = 0x2004;
    block1.successors.push_back(0x3000);

    engine::mlil::Instruction inst1;
    inst1.address = 0x2000;
    engine::mlil::MlilStmt assign1;
    assign1.kind = engine::mlil::MlilStmtKind::kAssign;
    assign1.var.name = "reg.x0";
    assign1.expr = make_mlil_imm(2, 4);
    inst1.stmts.push_back(assign1);
    block1.instructions.push_back(inst1);

    engine::mlil::BasicBlock block2;
    block2.start = 0x3000;
    block2.end = 0x3004;
    block2.predecessors.push_back(0x1000);
    block2.predecessors.push_back(0x2000);

    func.blocks.push_back(block0);
    func.blocks.push_back(block1);
    func.blocks.push_back(block2);

    std::string error;
    REQUIRE(engine::mlil::build_ssa(func, error));
    REQUIRE(func.blocks.size() == 3);
    CHECK(func.blocks[0].instructions[0].stmts[0].var.name == "reg.x0");
    CHECK(func.blocks[1].instructions[0].stmts[0].var.name == "reg.x0");
    REQUIRE_FALSE(func.blocks[2].phis.empty());
    const auto& phi = func.blocks[2].phis.front();
    CHECK(phi.var.name == "reg.x0");
    CHECK(phi.var.version > 0);
    REQUIRE(phi.expr.args.size() == 2);
}

TEST_CASE("MLIL SSA optimizer folds constants", "[mlil][opt]") {
    engine::mlil::Function func;
    func.entry = 0x4000;

    engine::mlil::BasicBlock block;
    block.start = 0x4000;
    block.end = 0x4004;

    engine::mlil::Instruction inst;
    inst.address = 0x4000;

    engine::mlil::MlilStmt add_stmt;
    add_stmt.kind = engine::mlil::MlilStmtKind::kAssign;
    add_stmt.var.name = "reg.x0";
    add_stmt.var.version = 1;
    add_stmt.expr = make_mlil_binop(engine::mlil::MlilOp::kAdd,
                                    make_mlil_imm(1, 4),
                                    make_mlil_imm(2, 4),
                                    4);

    inst.stmts.push_back(add_stmt);
    block.instructions.push_back(inst);
    func.blocks.push_back(block);

    engine::mlil::MlilOptOptions options;
    options.fold_constants = true;
    options.copy_propagation = false;
    options.dead_code_elim = false;

    std::string error;
    REQUIRE(engine::mlil::optimize_mlil_ssa(func, options, error));
    const auto& optimized = func.blocks[0].instructions[0].stmts[0];
    CHECK(optimized.expr.kind == engine::mlil::MlilExprKind::kImm);
    CHECK(optimized.expr.imm == 3);
}
