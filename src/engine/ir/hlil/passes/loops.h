#pragma once

#include "hlil_pass.h"

namespace engine::hlil::passes {

class LoopReconstructor : public HlilPass {
public:
    bool run(Function& function) override;
    const char* name() const override { return "LoopReconstructor"; }

private:
    bool process_stmts(std::vector<HlilStmt>& stmts);
    void visit(HlilStmt& stmt, bool& modified);
};

}  // namespace engine::hlil::passes
