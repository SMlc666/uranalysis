#pragma once

#include "hlil_pass.h"
#include <unordered_map>

namespace engine::hlil::passes {

class DeadCodeEliminator : public HlilPass {
public:
    bool run(Function& function) override;
    const char* name() const override { return "DeadCodeEliminator"; }

private:
    void count_usages(const std::vector<HlilStmt>& stmts, std::unordered_map<std::string, int>& counts);
    void eliminate(std::vector<HlilStmt>& stmts, const std::unordered_map<std::string, int>& counts, bool& modified);
};

}  // namespace engine::hlil::passes
