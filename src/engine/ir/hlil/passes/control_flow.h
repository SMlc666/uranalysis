#pragma once

#include "hlil_pass.h"

namespace engine::hlil::passes {

class ControlFlowSimplifier : public HlilPass {
public:
    bool run(Function& function) override;
    const char* name() const override { return "ControlFlowSimplifier"; }

private:
    bool process_stmts(std::vector<HlilStmt>& stmts);
    void visit(HlilStmt& stmt, bool& modified);
    bool block_ends_in_terminator(const std::vector<HlilStmt>& stmts);
    void remove_nops(std::vector<HlilStmt>& stmts, bool& modified);
    bool is_empty_block(const std::vector<HlilStmt>& stmts);
    mlil::MlilExpr invert_condition(mlil::MlilExpr cond);
};

}  // namespace engine::hlil::passes
