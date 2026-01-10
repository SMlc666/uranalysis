#pragma once

#include "hlil_pass.h"
#include <unordered_map>
#include <unordered_set>

namespace engine::hlil::passes {

class ExpressionPropagator : public HlilPass {
public:
    bool run(Function& function) override;
    const char* name() const override { return "ExpressionPropagator"; }

private:
    struct VersionState {
        std::unordered_map<std::string, int> versions;
    };

    std::unordered_map<std::string, int> global_counts_;
    std::unordered_map<std::string, int> def_counts_;
    std::unordered_map<std::string, mlil::MlilExpr> available_exprs_;
    std::unordered_set<std::string> modified_in_scope_;
    bool has_ssa_ = false;

    void count_usages(const std::vector<HlilStmt>& stmts);
    void count_definitions(const std::vector<HlilStmt>& stmts);
    void collect_modified_vars(const std::vector<HlilStmt>& stmts, std::unordered_set<std::string>& out);
    
    void propagate_block(std::vector<HlilStmt>& stmts, bool& modified);
    void process_stmt(HlilStmt& stmt, bool& modified);
    
    void substitute_in_stmt(HlilStmt& stmt, bool& modified);
    void substitute_recursive(mlil::MlilExpr& expr, bool& modified);
    
    bool is_simple_expr(const mlil::MlilExpr& expr);
    bool is_well_formed_expr(const mlil::MlilExpr& expr);
    int get_expr_depth(const mlil::MlilExpr& expr);
    void fold_expr(mlil::MlilExpr& expr);
    
    // Helper to check if an expression uses a specific variable
    bool uses_var(const mlil::MlilExpr& expr, const mlil::VarRef& var);
    bool uses_any_var(const mlil::MlilExpr& expr, const std::unordered_set<std::string>& vars);
    
    void invalidate_modified(const std::unordered_set<std::string>& modified);

    void assign_versions(Function& function);
    void assign_versions_block(std::vector<HlilStmt>& stmts, VersionState& state);
    void assign_versions_stmt(HlilStmt& stmt, VersionState& state);
    void assign_versions_expr(mlil::MlilExpr& expr, VersionState& state);
    void merge_versions(VersionState& out, const VersionState& a, const VersionState& b);

    std::string make_key(const mlil::VarRef& var) const;
    bool key_matches_name(const std::string& key, const std::string& name) const;
};

}  // namespace engine::hlil::passes
