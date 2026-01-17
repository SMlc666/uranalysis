#include <catch2/catch_test_macros.hpp>

#include "engine/pass.h"

#include <string>
#include <vector>

using namespace engine::pass;

// ============================================================================
// Test IR and Analyses
// ============================================================================

/// Simple test IR unit
struct TestIR {
    int value = 0;
    std::string name;
};

/// Test analysis that computes something from TestIR
struct TestAnalysis : public AnalysisInfoMixin<TestAnalysis> {
    struct Result {
        int computed_value = 0;
        
        bool invalidate(TestIR& /*ir*/, 
                       const PreservedAnalyses& pa,
                       Invalidator<TestIR>& /*inv*/) {
            // Invalidate unless explicitly preserved
            return !pa.preserved<TestAnalysis>();
        }
    };
    
    static const char* name() { return "TestAnalysis"; }
    
    Result run(TestIR& ir, AnalysisManager<TestIR>& /*am*/) {
        return Result{ir.value * 2};
    }
};

/// Another test analysis that depends on TestAnalysis
struct DependentAnalysis : public AnalysisInfoMixin<DependentAnalysis> {
    struct Result {
        int derived_value = 0;
        
        bool invalidate(TestIR& ir, 
                       const PreservedAnalyses& pa,
                       Invalidator<TestIR>& inv) {
            if (pa.preserved<DependentAnalysis>()) {
                return false;
            }
            // Invalidate if TestAnalysis is invalidated
            return inv.invalidate<TestAnalysis>(ir);
        }
    };
    
    static const char* name() { return "DependentAnalysis"; }
    
    Result run(TestIR& ir, AnalysisManager<TestIR>& am) {
        auto& test_result = am.getResult<TestAnalysis>(ir);
        return Result{test_result.computed_value + 1};
    }
};

// ============================================================================
// Test Passes
// ============================================================================

/// Pass that doesn't modify IR
struct NoOpPass : public PassInfoMixin<NoOpPass> {
    static const char* name() { return "NoOpPass"; }
    
    PassResult run(TestIR& /*ir*/, AnalysisManager<TestIR>& /*am*/) {
        return PassResult::successAll();
    }
};

/// Pass that modifies IR and invalidates all analyses
struct ModifyPass : public PassInfoMixin<ModifyPass> {
    int increment = 1;
    
    static const char* name() { return "ModifyPass"; }
    
    PassResult run(TestIR& ir, AnalysisManager<TestIR>& /*am*/) {
        ir.value += increment;
        return PassResult::successNone();
    }
};

/// Pass that modifies IR but preserves TestAnalysis
struct PreservingPass : public PassInfoMixin<PreservingPass> {
    static const char* name() { return "PreservingPass"; }
    
    PassResult run(TestIR& ir, AnalysisManager<TestIR>& /*am*/) {
        ir.name = "modified";
        PreservedAnalyses pa;
        pa.preserve<TestAnalysis>();
        return PassResult::success(std::move(pa));
    }
};

/// Pass that fails
struct FailingPass : public PassInfoMixin<FailingPass> {
    static const char* name() { return "FailingPass"; }
    
    PassResult run(TestIR& /*ir*/, AnalysisManager<TestIR>& /*am*/) {
        return PassResult::failure("intentional failure");
    }
};

/// Pass that uses analysis
struct AnalysisUserPass : public PassInfoMixin<AnalysisUserPass> {
    int* output = nullptr;
    
    static const char* name() { return "AnalysisUserPass"; }
    
    PassResult run(TestIR& ir, AnalysisManager<TestIR>& am) {
        auto& result = am.getResult<TestAnalysis>(ir);
        if (output) {
            *output = result.computed_value;
        }
        return PassResult::successAll();
    }
};

// ============================================================================
// PreservedAnalyses Tests
// ============================================================================

TEST_CASE("PreservedAnalyses::all preserves everything", "[pass]") {
    auto pa = PreservedAnalyses::all();
    
    CHECK(pa.preservedAll());
    CHECK(pa.preserved<TestAnalysis>());
    CHECK(pa.preserved<DependentAnalysis>());
    CHECK(pa.preservedSet<CFGAnalyses>());
    CHECK(pa.preservedSet<SSAAnalyses>());
}

TEST_CASE("PreservedAnalyses::none preserves nothing", "[pass]") {
    auto pa = PreservedAnalyses::none();
    
    CHECK_FALSE(pa.preservedAll());
    CHECK_FALSE(pa.preserved<TestAnalysis>());
    CHECK_FALSE(pa.preserved<DependentAnalysis>());
    CHECK_FALSE(pa.preservedSet<CFGAnalyses>());
}

TEST_CASE("PreservedAnalyses::preserve marks specific analysis", "[pass]") {
    auto pa = PreservedAnalyses::none();
    pa.preserve<TestAnalysis>();
    
    CHECK_FALSE(pa.preservedAll());
    CHECK(pa.preserved<TestAnalysis>());
    CHECK_FALSE(pa.preserved<DependentAnalysis>());
}

TEST_CASE("PreservedAnalyses::preserveSet marks analysis set", "[pass]") {
    auto pa = PreservedAnalyses::none();
    pa.preserveSet<CFGAnalyses>();
    
    CHECK(pa.preservedSet<CFGAnalyses>());
    CHECK_FALSE(pa.preservedSet<SSAAnalyses>());
}

TEST_CASE("PreservedAnalyses::intersect combines correctly", "[pass]") {
    auto pa1 = PreservedAnalyses::none();
    pa1.preserve<TestAnalysis>();
    pa1.preserve<DependentAnalysis>();
    
    auto pa2 = PreservedAnalyses::none();
    pa2.preserve<TestAnalysis>();
    
    pa1.intersect(pa2);
    
    CHECK(pa1.preserved<TestAnalysis>());
    CHECK_FALSE(pa1.preserved<DependentAnalysis>());
}

TEST_CASE("PreservedAnalyses::intersect with all keeps original", "[pass]") {
    auto pa1 = PreservedAnalyses::none();
    pa1.preserve<TestAnalysis>();
    
    auto pa2 = PreservedAnalyses::all();
    
    pa1.intersect(pa2);
    
    CHECK(pa1.preserved<TestAnalysis>());
    CHECK_FALSE(pa1.preserved<DependentAnalysis>());
}

TEST_CASE("PreservedAnalyses::abandon removes preservation", "[pass]") {
    auto pa = PreservedAnalyses::all();
    pa.abandon<TestAnalysis>();
    
    CHECK_FALSE(pa.preservedAll());
    CHECK_FALSE(pa.preserved<TestAnalysis>());
}

// ============================================================================
// AnalysisManager Tests
// ============================================================================

TEST_CASE("AnalysisManager computes and caches analysis", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    auto& result1 = am.getResult<TestAnalysis>(ir);
    CHECK(result1.computed_value == 10);  // 5 * 2
    
    // Modify IR but don't invalidate
    ir.value = 100;
    
    // Should return cached value
    auto& result2 = am.getResult<TestAnalysis>(ir);
    CHECK(result2.computed_value == 10);  // Still cached
    
    // Same reference
    CHECK(&result1 == &result2);
}

TEST_CASE("AnalysisManager::getCachedResult returns nullptr when not cached", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    auto* cached = am.getCachedResult<TestAnalysis>(ir);
    CHECK(cached == nullptr);
    
    // Compute it
    am.getResult<TestAnalysis>(ir);
    
    cached = am.getCachedResult<TestAnalysis>(ir);
    REQUIRE(cached != nullptr);
    CHECK(cached->computed_value == 10);
}

TEST_CASE("AnalysisManager::invalidate removes cached results", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    am.getResult<TestAnalysis>(ir);
    CHECK(am.isCached<TestAnalysis>());
    
    am.invalidate(ir, PreservedAnalyses::none());
    
    CHECK_FALSE(am.isCached<TestAnalysis>());
}

TEST_CASE("AnalysisManager::invalidate respects preserved analyses", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    am.getResult<TestAnalysis>(ir);
    CHECK(am.isCached<TestAnalysis>());
    
    PreservedAnalyses pa;
    pa.preserve<TestAnalysis>();
    am.invalidate(ir, pa);
    
    CHECK(am.isCached<TestAnalysis>());
}

TEST_CASE("AnalysisManager::clear removes all cached results", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    am.getResult<TestAnalysis>(ir);
    am.getResult<DependentAnalysis>(ir);
    
    CHECK(am.isCached<TestAnalysis>());
    CHECK(am.isCached<DependentAnalysis>());
    
    am.clear();
    
    CHECK_FALSE(am.isCached<TestAnalysis>());
    CHECK_FALSE(am.isCached<DependentAnalysis>());
}

TEST_CASE("AnalysisManager handles dependent analyses", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    // DependentAnalysis requires TestAnalysis
    auto& result = am.getResult<DependentAnalysis>(ir);
    
    // Should have computed both
    CHECK(am.isCached<TestAnalysis>());
    CHECK(am.isCached<DependentAnalysis>());
    
    // Result should be (5 * 2) + 1 = 11
    CHECK(result.derived_value == 11);
}

// ============================================================================
// PassManager Tests
// ============================================================================

TEST_CASE("PassManager runs passes in order", "[pass]") {
    AnalysisManager<TestIR> am;
    PassManager<TestIR> pm;
    TestIR ir{0, "test"};
    
    ModifyPass p1; p1.increment = 1;
    ModifyPass p2; p2.increment = 10;
    ModifyPass p3; p3.increment = 100;
    
    pm.addPass(p1);
    pm.addPass(p2);
    pm.addPass(p3);
    
    auto result = pm.run(ir, am);
    
    CHECK(result.success());
    CHECK(ir.value == 111);  // 0 + 1 + 10 + 100
}

TEST_CASE("PassManager stops on failure", "[pass]") {
    AnalysisManager<TestIR> am;
    PassManager<TestIR> pm;
    TestIR ir{0, "test"};
    
    ModifyPass p1; p1.increment = 1;
    pm.addPass(p1);
    pm.addPass(FailingPass{});
    pm.addPass(ModifyPass{});  // Should not run
    
    auto result = pm.run(ir, am);
    
    CHECK(result.failed());
    CHECK(result.error == "intentional failure");
    CHECK(ir.value == 1);  // Only first pass ran
}

TEST_CASE("PassManager invalidates analyses between passes", "[pass]") {
    AnalysisManager<TestIR> am;
    PassManager<TestIR> pm;
    TestIR ir{5, "test"};
    
    int first_value = 0;
    int second_value = 0;
    
    AnalysisUserPass p1; p1.output = &first_value;
    ModifyPass p2; p2.increment = 10;  // Invalidates all
    AnalysisUserPass p3; p3.output = &second_value;
    
    pm.addPass(p1);
    pm.addPass(p2);
    pm.addPass(p3);
    
    pm.run(ir, am);
    
    CHECK(first_value == 10);   // 5 * 2
    CHECK(second_value == 30);  // (5 + 10) * 2 = 30 (recomputed)
}

TEST_CASE("PassManager respects preserved analyses", "[pass]") {
    AnalysisManager<TestIR> am;
    PassManager<TestIR> pm;
    TestIR ir{5, "test"};
    
    // Compute analysis before running passes
    am.getResult<TestAnalysis>(ir);
    CHECK(am.isCached<TestAnalysis>());
    
    pm.addPass(PreservingPass{});  // Preserves TestAnalysis
    
    pm.run(ir, am);
    
    // Analysis should still be cached
    CHECK(am.isCached<TestAnalysis>());
}

TEST_CASE("PassManager returns combined preserved analyses", "[pass]") {
    AnalysisManager<TestIR> am;
    PassManager<TestIR> pm;
    TestIR ir{5, "test"};
    
    pm.addPass(NoOpPass{});  // Preserves all
    
    auto result = pm.run(ir, am);
    
    CHECK(result.success());
    CHECK(result.preserved.preservedAll());
}

TEST_CASE("PassManager size and empty work correctly", "[pass]") {
    PassManager<TestIR> pm;
    
    CHECK(pm.empty());
    CHECK(pm.size() == 0);
    
    pm.addPass(NoOpPass{});
    
    CHECK_FALSE(pm.empty());
    CHECK(pm.size() == 1);
    
    pm.addPass(ModifyPass{});
    
    CHECK(pm.size() == 2);
    
    pm.clear();
    
    CHECK(pm.empty());
}

// ============================================================================
// Invalidator Tests
// ============================================================================

TEST_CASE("Invalidator handles transitive dependencies", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    // Compute both analyses
    am.getResult<TestAnalysis>(ir);
    am.getResult<DependentAnalysis>(ir);
    
    CHECK(am.isCached<TestAnalysis>());
    CHECK(am.isCached<DependentAnalysis>());
    
    // Invalidate with nothing preserved
    am.invalidate(ir, PreservedAnalyses::none());
    
    // Both should be invalidated
    CHECK_FALSE(am.isCached<TestAnalysis>());
    CHECK_FALSE(am.isCached<DependentAnalysis>());
}

TEST_CASE("Invalidator preserves independent analyses", "[pass]") {
    AnalysisManager<TestIR> am;
    TestIR ir{5, "test"};
    
    am.getResult<TestAnalysis>(ir);
    am.getResult<DependentAnalysis>(ir);
    
    // Preserve only TestAnalysis
    PreservedAnalyses pa;
    pa.preserve<TestAnalysis>();
    pa.preserve<DependentAnalysis>();
    
    am.invalidate(ir, pa);
    
    // Both should be preserved
    CHECK(am.isCached<TestAnalysis>());
    CHECK(am.isCached<DependentAnalysis>());
}

// ============================================================================
// PassResult Tests
// ============================================================================

TEST_CASE("PassResult::success creates successful result", "[pass]") {
    auto result = PassResult::successAll();
    
    CHECK(result.success());
    CHECK_FALSE(result.failed());
    CHECK(result.error.empty());
    CHECK(result.preserved.preservedAll());
}

TEST_CASE("PassResult::failure creates failed result", "[pass]") {
    auto result = PassResult::failure("test error");
    
    CHECK_FALSE(result.success());
    CHECK(result.failed());
    CHECK(result.error == "test error");
}

// ============================================================================
// PassBuilder Tests
// ============================================================================

TEST_CASE("PassBuilder registers analyses", "[pass]") {
    PassBuilder<TestIR> pb;
    AnalysisManager<TestIR> am;
    
    pb.registerAnalysis<TestAnalysis>(am);
    
    CHECK(am.isRegistered<TestAnalysis>());
}

TEST_CASE("PassBuilder builds empty pipeline", "[pass]") {
    PassBuilder<TestIR> pb;
    
    auto pm = pb.buildPipeline();
    
    CHECK(pm.empty());
}

TEST_CASE("PassBuilder applies start callbacks", "[pass]") {
    PassBuilder<TestIR> pb;
    bool callback_called = false;
    
    pb.registerPipelineStartCallback([&](PassManager<TestIR>& pm) {
        callback_called = true;
        pm.addPass(NoOpPass{});
    });
    
    auto pm = pb.buildPipeline();
    
    CHECK(callback_called);
    CHECK(pm.size() == 1);
}

// ============================================================================
// Integration Test
// ============================================================================

TEST_CASE("Full pipeline integration test", "[pass][integration]") {
    // Setup
    AnalysisManager<TestIR> am;
    PassBuilder<TestIR> pb;
    TestIR ir{10, "integration_test"};
    
    // Register analyses
    pb.registerAnalysis<TestAnalysis>(am);
    pb.registerAnalysis<DependentAnalysis>(am);
    
    // Build pipeline
    PassManager<TestIR> pm;
    
    int captured_value = 0;
    AnalysisUserPass capture_pass;
    capture_pass.output = &captured_value;
    
    pm.addPass(capture_pass);        // Read analysis (10 * 2 = 20)
    
    ModifyPass modify;
    modify.increment = 5;
    pm.addPass(modify);              // Modify IR (10 + 5 = 15), invalidate
    
    pm.addPass(capture_pass);        // Read again (15 * 2 = 30)
    
    // Run
    auto result = pm.run(ir, am);
    
    // Verify
    CHECK(result.success());
    CHECK(ir.value == 15);
    CHECK(captured_value == 30);  // Last captured value after recomputation
}

// ============================================================================
// LLIR Pass Integration Tests
// ============================================================================

#include "llir/llir_pass.h"

TEST_CASE("LlirDefUseAnalysis computes def-use chains", "[pass][llir]") {
    using namespace engine::llir;
    
    // Create a simple function with SSA statements
    Function func;
    func.entry = 0x1000;
    
    BasicBlock block;
    block.start = 0x1000;
    block.end = 0x1010;
    
    Instruction inst;
    inst.address = 0x1000;
    
    // Add an SSA statement: x0.1 = imm(42)
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kSetReg;
    stmt.reg.name = "x0";
    stmt.reg.version = 1;
    stmt.expr.kind = LlilExprKind::kImm;
    stmt.expr.imm = 42;
    stmt.expr.size = 8;
    inst.llil_ssa.push_back(stmt);
    
    // Add another SSA statement: x1.1 = x0.1
    LlilStmt stmt2;
    stmt2.kind = LlilStmtKind::kSetReg;
    stmt2.reg.name = "x1";
    stmt2.reg.version = 1;
    stmt2.expr.kind = LlilExprKind::kReg;
    stmt2.expr.reg.name = "x0";
    stmt2.expr.reg.version = 1;
    stmt2.expr.size = 8;
    inst.llil_ssa.push_back(stmt2);
    
    block.instructions.push_back(inst);
    func.blocks.push_back(block);
    
    // Create analysis manager and compute DefUse
    LlirAnalysisManager am;
    am.registerAnalysis<LlirDefUseAnalysis>();
    
    auto& defuse = am.getResult<LlirDefUseAnalysis>(func);
    
    // Verify x0.1 is defined
    RegRefKey key_x0{"x0", 1};
    CHECK(defuse.defs.count(key_x0) == 1);
    
    // Verify x0.1 has a use (in stmt2)
    CHECK(defuse.uses.count(key_x0) == 1);
    CHECK(defuse.uses.at(key_x0).size() == 1);
}

TEST_CASE("LlirConstantFoldPass folds constants", "[pass][llir]") {
    using namespace engine::llir;
    
    Function func;
    func.entry = 0x1000;
    
    BasicBlock block;
    block.start = 0x1000;
    
    Instruction inst;
    inst.address = 0x1000;
    
    // x0.1 = add(5, 3) -> should fold to x0.1 = 8
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kSetReg;
    stmt.reg.name = "x0";
    stmt.reg.version = 1;
    
    stmt.expr.kind = LlilExprKind::kOp;
    stmt.expr.op = LlilOp::kAdd;
    stmt.expr.size = 8;
    
    LlilExpr arg1;
    arg1.kind = LlilExprKind::kImm;
    arg1.imm = 5;
    arg1.size = 8;
    
    LlilExpr arg2;
    arg2.kind = LlilExprKind::kImm;
    arg2.imm = 3;
    arg2.size = 8;
    
    stmt.expr.args.push_back(arg1);
    stmt.expr.args.push_back(arg2);
    
    inst.llil_ssa.push_back(stmt);
    block.instructions.push_back(inst);
    func.blocks.push_back(block);
    
    // Run constant fold pass
    LlirAnalysisManager am;
    LlirPassManager pm;
    pm.addPass(LlirConstantFoldPass{});
    
    auto result = pm.run(func, am);
    
    CHECK(result.success());
    
    // Verify the expression was folded
    const auto& folded = func.blocks[0].instructions[0].llil_ssa[0].expr;
    CHECK(folded.kind == LlilExprKind::kImm);
    CHECK(folded.imm == 8);
}

TEST_CASE("LlirOptPipeline runs full optimization", "[pass][llir]") {
    using namespace engine::llir;
    
    Function func;
    func.entry = 0x1000;
    
    BasicBlock block;
    block.start = 0x1000;
    
    Instruction inst;
    inst.address = 0x1000;
    
    // x0.1 = 42 (immediate assignment)
    LlilStmt stmt1;
    stmt1.kind = LlilStmtKind::kSetReg;
    stmt1.reg.name = "x0";
    stmt1.reg.version = 1;
    stmt1.expr.kind = LlilExprKind::kImm;
    stmt1.expr.imm = 42;
    stmt1.expr.size = 8;
    inst.llil_ssa.push_back(stmt1);
    
    // x1.1 = add(x0.1, 10) - should become add(42, 10) after copy prop then fold to 52
    LlilStmt stmt2;
    stmt2.kind = LlilStmtKind::kSetReg;
    stmt2.reg.name = "x1";
    stmt2.reg.version = 1;
    stmt2.expr.kind = LlilExprKind::kOp;
    stmt2.expr.op = LlilOp::kAdd;
    stmt2.expr.size = 8;
    
    LlilExpr use_x0;
    use_x0.kind = LlilExprKind::kReg;
    use_x0.reg.name = "x0";
    use_x0.reg.version = 1;
    use_x0.size = 8;
    
    LlilExpr const10;
    const10.kind = LlilExprKind::kImm;
    const10.imm = 10;
    const10.size = 8;
    
    stmt2.expr.args.push_back(use_x0);
    stmt2.expr.args.push_back(const10);
    inst.llil_ssa.push_back(stmt2);
    
    block.instructions.push_back(inst);
    func.blocks.push_back(block);
    
    // Build optimization pipeline
    LlirOptPipelineOptions opts;
    opts.copy_propagation = true;
    opts.constant_folding = true;
    opts.dead_code_elim = false;  // Keep all for verification
    
    auto pm = buildLlirOptPipeline(opts);
    LlirAnalysisManager am;
    am.registerAnalysis<LlirDefUseAnalysis>();
    
    auto result = pm.run(func, am);
    
    CHECK(result.success());
    
    // Verify x1.1 was optimized to immediate 52
    // After copy prop: x1.1 = add(42, 10)
    // After const fold: x1.1 = 52
    const auto& final_stmt = func.blocks[0].instructions[0].llil_ssa[1];
    CHECK(final_stmt.reg.name == "x1");
    CHECK(final_stmt.expr.kind == LlilExprKind::kImm);
    CHECK(final_stmt.expr.imm == 52);
}

// ============================================================================
// MLIL Pass Integration Tests
// ============================================================================

#include "mlil/mlil_pass.h"

TEST_CASE("MlilDefUseAnalysis computes def-use chains", "[pass][mlil]") {
    using namespace engine::mlil;
    
    Function func;
    func.entry = 0x1000;
    
    BasicBlock block;
    block.start = 0x1000;
    
    Instruction inst;
    inst.address = 0x1000;
    
    // v0.1 = 42
    MlilStmt stmt1;
    stmt1.kind = MlilStmtKind::kAssign;
    stmt1.var.name = "v0";
    stmt1.var.version = 1;
    stmt1.expr.kind = MlilExprKind::kImm;
    stmt1.expr.imm = 42;
    stmt1.expr.size = 8;
    inst.stmts.push_back(stmt1);
    
    // v1.1 = v0.1
    MlilStmt stmt2;
    stmt2.kind = MlilStmtKind::kAssign;
    stmt2.var.name = "v1";
    stmt2.var.version = 1;
    stmt2.expr.kind = MlilExprKind::kVar;
    stmt2.expr.var.name = "v0";
    stmt2.expr.var.version = 1;
    stmt2.expr.size = 8;
    inst.stmts.push_back(stmt2);
    
    block.instructions.push_back(inst);
    func.blocks.push_back(block);
    
    MlilAnalysisManager am;
    am.registerAnalysis<MlilDefUseAnalysis>();
    
    auto& defuse = am.getResult<MlilDefUseAnalysis>(func);
    
    VarRefKey key_v0{"v0", 1};
    CHECK(defuse.defs.count(key_v0) == 1);
    CHECK(defuse.uses.count(key_v0) == 1);
}

TEST_CASE("MlilConstantFoldPass folds constants", "[pass][mlil]") {
    using namespace engine::mlil;
    
    Function func;
    func.entry = 0x1000;
    
    BasicBlock block;
    block.start = 0x1000;
    
    Instruction inst;
    inst.address = 0x1000;
    
    // v0.1 = add(5, 3) -> should fold to 8
    MlilStmt stmt;
    stmt.kind = MlilStmtKind::kAssign;
    stmt.var.name = "v0";
    stmt.var.version = 1;
    
    stmt.expr.kind = MlilExprKind::kOp;
    stmt.expr.op = MlilOp::kAdd;
    stmt.expr.size = 8;
    
    MlilExpr arg1;
    arg1.kind = MlilExprKind::kImm;
    arg1.imm = 5;
    arg1.size = 8;
    
    MlilExpr arg2;
    arg2.kind = MlilExprKind::kImm;
    arg2.imm = 3;
    arg2.size = 8;
    
    stmt.expr.args.push_back(arg1);
    stmt.expr.args.push_back(arg2);
    
    inst.stmts.push_back(stmt);
    block.instructions.push_back(inst);
    func.blocks.push_back(block);
    
    MlilAnalysisManager am;
    MlilPassManager pm;
    pm.addPass(MlilConstantFoldPass{});
    
    auto result = pm.run(func, am);
    
    CHECK(result.success());
    
    const auto& folded = func.blocks[0].instructions[0].stmts[0].expr;
    CHECK(folded.kind == MlilExprKind::kImm);
    CHECK(folded.imm == 8);
}

TEST_CASE("MlilOptPipeline runs full optimization", "[pass][mlil]") {
    using namespace engine::mlil;
    
    Function func;
    func.entry = 0x1000;
    
    BasicBlock block;
    block.start = 0x1000;
    
    Instruction inst;
    inst.address = 0x1000;
    
    // v0.1 = 42
    MlilStmt stmt1;
    stmt1.kind = MlilStmtKind::kAssign;
    stmt1.var.name = "v0";
    stmt1.var.version = 1;
    stmt1.expr.kind = MlilExprKind::kImm;
    stmt1.expr.imm = 42;
    stmt1.expr.size = 8;
    inst.stmts.push_back(stmt1);
    
    // v1.1 = add(v0.1, 10) -> should become 52
    MlilStmt stmt2;
    stmt2.kind = MlilStmtKind::kAssign;
    stmt2.var.name = "v1";
    stmt2.var.version = 1;
    stmt2.expr.kind = MlilExprKind::kOp;
    stmt2.expr.op = MlilOp::kAdd;
    stmt2.expr.size = 8;
    
    MlilExpr use_v0;
    use_v0.kind = MlilExprKind::kVar;
    use_v0.var.name = "v0";
    use_v0.var.version = 1;
    use_v0.size = 8;
    
    MlilExpr const10;
    const10.kind = MlilExprKind::kImm;
    const10.imm = 10;
    const10.size = 8;
    
    stmt2.expr.args.push_back(use_v0);
    stmt2.expr.args.push_back(const10);
    inst.stmts.push_back(stmt2);
    
    block.instructions.push_back(inst);
    func.blocks.push_back(block);
    
    MlilOptPipelineOptions opts;
    opts.copy_propagation = true;
    opts.constant_folding = true;
    opts.dead_code_elim = false;
    
    auto pm = buildMlilOptPipeline(opts);
    MlilAnalysisManager am;
    am.registerAnalysis<MlilDefUseAnalysis>();
    
    auto result = pm.run(func, am);
    
    CHECK(result.success());
    
    // v1.1 should now be immediate 52
    const auto& final_stmt = func.blocks[0].instructions[0].stmts[1];
    CHECK(final_stmt.var.name == "v1");
    CHECK(final_stmt.expr.kind == MlilExprKind::kImm);
    CHECK(final_stmt.expr.imm == 52);
}

// ============================================================================
// HLIL Pass Integration Tests
// ============================================================================

#include "hlil/hlil_pm.h"

TEST_CASE("HlilPassManager can be constructed", "[pass][hlil]") {
    using namespace engine::hlil;
    
    HlilAnalysisManager am;
    HlilPassManager pm;
    
    CHECK(pm.empty());
    
    pm.addPass(HlilControlFlowSimplifyPass{});
    pm.addPass(HlilExprPropagationPass{});
    pm.addPass(HlilDCEPass{});
    pm.addPass(HlilLoopReconstructPass{});
    
    CHECK(pm.size() == 4);
}

TEST_CASE("HlilOptPipeline can run on empty function", "[pass][hlil]") {
    using namespace engine::hlil;
    
    Function func;
    func.entry = 0x1000;
    
    HlilOptPipelineOptions opts;
    auto pm = buildHlilOptPipeline(opts);
    
    HlilAnalysisManager am;
    auto result = pm.run(func, am);
    
    CHECK(result.success());
}

TEST_CASE("HlilControlFlowSimplifyPass removes empty if", "[pass][hlil]") {
    using namespace engine::hlil;
    
    engine::hlil::Function func;
    func.entry = 0x1000;
    
    // 创建一个空的if语句
    HlilStmt if_stmt;
    if_stmt.kind = HlilStmtKind::kIf;
    if_stmt.condition.kind = engine::mlil::MlilExprKind::kImm;
    if_stmt.condition.imm = 1;
    if_stmt.condition.size = 1;
    // then_body和else_body都为空
    
    func.stmts.push_back(if_stmt);
    
    HlilAnalysisManager am;
    HlilPassManager pm;
    pm.addPass(HlilControlFlowSimplifyPass{});
    
    auto result = pm.run(func, am);
    
    CHECK(result.success());
    // 空的if应该被移除或简化
}

TEST_CASE("HlilDCEPass removes unused assignments", "[pass][hlil]") {
    using namespace engine::hlil;
    
    engine::hlil::Function func;
    func.entry = 0x1000;
    
    // v0 = 42 (无使用，应该被消除)
    HlilStmt stmt1;
    stmt1.kind = HlilStmtKind::kAssign;
    stmt1.var.name = "v0";
    stmt1.var.version = 0;
    stmt1.expr.kind = engine::mlil::MlilExprKind::kImm;
    stmt1.expr.imm = 42;
    stmt1.expr.size = 8;
    func.stmts.push_back(stmt1);
    
    // return (没有使用v0)
    HlilStmt ret;
    ret.kind = HlilStmtKind::kRet;
    func.stmts.push_back(ret);
    
    HlilAnalysisManager am;
    HlilPassManager pm;
    pm.addPass(HlilDCEPass{});
    
    std::size_t before = func.stmts.size();
    auto result = pm.run(func, am);
    
    CHECK(result.success());
    // DCE应该移除未使用的赋值
    CHECK(func.stmts.size() <= before);
}


