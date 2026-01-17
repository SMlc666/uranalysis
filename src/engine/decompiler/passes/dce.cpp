#include "engine/decompiler/passes/dce.h"
#include "engine/decompiler/transforms.h"
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <spdlog/spdlog.h>

namespace engine::decompiler::passes {

namespace {

// Helper to check if an expression has side effects
bool has_side_effects(const mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kCall || 
        expr.kind == mlil::MlilExprKind::kLoad) { // Loads might be volatile
        return true;
    }
    for (const auto& arg : expr.args) {
        if (has_side_effects(arg)) {
            return true;
        }
    }
    return false;
}

// Collect all used variables in a statement
void collect_used_vars(const Stmt& stmt, std::unordered_set<std::string>& used) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            collect_expr_vars(stmt.expr, used);
            break;
        case StmtKind::kStore:
            collect_expr_vars(stmt.target, used);
            collect_expr_vars(stmt.expr, used);
            break;
        case StmtKind::kCall:
            for (const auto& arg : stmt.args) {
                collect_expr_vars(arg, used);
            }
            break;
        case StmtKind::kReturn:
            collect_expr_vars(stmt.expr, used);
            break;
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
            collect_expr_vars(stmt.condition, used);
            for (const auto& s : stmt.then_body) collect_used_vars(s, used);
            for (const auto& s : stmt.else_body) collect_used_vars(s, used);
            for (const auto& s : stmt.body) collect_used_vars(s, used);
            break;
        case StmtKind::kFor:
            collect_expr_vars(stmt.condition, used);
            for (const auto& s : stmt.then_body) collect_used_vars(s, used); // Init
            for (const auto& s : stmt.else_body) collect_used_vars(s, used); // Increment
            for (const auto& s : stmt.body) collect_used_vars(s, used);
            break;
        case StmtKind::kSwitch:
            collect_expr_vars(stmt.condition, used);
            for (const auto& case_body : stmt.case_bodies) {
                for (const auto& s : case_body) collect_used_vars(s, used);
            }
            for (const auto& s : stmt.default_body) collect_used_vars(s, used);
            break;
        default:
            break;
    }
}

// Collect all variables defined in a statement block (for loop liveness analysis)
void collect_defined_vars(const std::vector<Stmt>& stmts, std::unordered_set<std::string>& defined) {
    for (const auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kAssign && !stmt.var.name.empty()) {
            defined.insert(stmt.var.name);
        } else if (stmt.kind == StmtKind::kCall) {
            for (const auto& ret : stmt.returns) {
                if (!ret.name.empty()) {
                    defined.insert(ret.name);
                }
            }
        } else if (stmt.kind == StmtKind::kIf) {
            collect_defined_vars(stmt.then_body, defined);
            collect_defined_vars(stmt.else_body, defined);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile) {
            collect_defined_vars(stmt.body, defined);
        } else if (stmt.kind == StmtKind::kFor) {
            collect_defined_vars(stmt.then_body, defined);
            collect_defined_vars(stmt.body, defined);
            collect_defined_vars(stmt.else_body, defined);
        } else if (stmt.kind == StmtKind::kSwitch) {
            for (const auto& case_body : stmt.case_bodies) {
                collect_defined_vars(case_body, defined);
            }
            collect_defined_vars(stmt.default_body, defined);
        }
    }
}

// Recursive function to process a block of statements
void process_block(std::vector<Stmt>& stmts, std::unordered_set<std::string>& used_vars, 
                   bool& changed, const std::unordered_set<std::string>* loop_live_vars = nullptr) {
    // Iterate backwards to propagate usage info
    for (int i = (int)stmts.size() - 1; i >= 0; --i) {
        Stmt& stmt = stmts[i];
        
        // Process nested blocks first
        if (stmt.kind == StmtKind::kIf) {
            process_block(stmt.then_body, used_vars, changed, loop_live_vars);
            process_block(stmt.else_body, used_vars, changed, loop_live_vars);
            collect_expr_vars(stmt.condition, used_vars);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile) {
            // CRITICAL FIX: Loop bodies are highly problematic for DCE because:
            // 1. Variable renaming (x0 vs x0_9 vs x0_ver_245) creates mismatches
            // 2. Temporaries (tmp*) don't match renamed variables
            // 3. Loop-carried dependencies are hard to track correctly
            //
            // Conservative approach: Just collect all variables used in condition and
            // in loop body as "live". Don't eliminate anything inside loops.
            // The HLIR DCE pass already handled loop-internal dead code.
            
            // Collect ALL variables used anywhere in the loop (including nested)
            std::unordered_set<std::string> loop_used;
            collect_used_vars(stmt, loop_used);
            
            // Mark all of them as live
            for (const auto& var : loop_used) {
                used_vars.insert(var);
            }
            
            // Process loop body but pass the full loop_used set as loop_live_vars
            // This prevents any elimination inside the loop
            process_block(stmt.body, used_vars, changed, &loop_used);
            collect_expr_vars(stmt.condition, used_vars);
        } else if (stmt.kind == StmtKind::kFor) {
            // Same conservative approach for for loops
            std::unordered_set<std::string> loop_used;
            collect_used_vars(stmt, loop_used);
            
            // Mark all of them as live
            for (const auto& var : loop_used) {
                used_vars.insert(var);
            }
            
            // Process all parts of the for loop with the full set
            process_block(stmt.body, used_vars, changed, &loop_used);
            process_block(stmt.else_body, used_vars, changed, &loop_used); // Increment
            collect_expr_vars(stmt.condition, used_vars);
            process_block(stmt.then_body, used_vars, changed, loop_live_vars); // Init (outside loop)
        } else if (stmt.kind == StmtKind::kSwitch) {
             for (auto& case_body : stmt.case_bodies) {
                process_block(case_body, used_vars, changed, loop_live_vars);
            }
            process_block(stmt.default_body, used_vars, changed, loop_live_vars);
            collect_expr_vars(stmt.condition, used_vars);
        } else if (stmt.kind == StmtKind::kAssign) {
            // Check if assignment is dead
            bool is_live = used_vars.find(stmt.var.name) != used_vars.end();
            
            // Variables marked as loop-live are always live within the loop
            bool is_loop_live = false;
            if (loop_live_vars) {
                is_loop_live = loop_live_vars->find(stmt.var.name) != loop_live_vars->end();
                if (is_loop_live) {
                    is_live = true;
                }
                // CRITICAL FIX: If we're inside a loop body (loop_live_vars is not null),
                // be very conservative - only eliminate if the var is DEFINITELY not used.
                // Since variable naming is inconsistent (tmp* vs x*_ver_*), just keep
                // all assignments inside loops.
                is_live = true;  // Force all loop assignments to be live
            }
            
            if (!is_live) {
                // Variable not used. Check for side effects.
                if (!has_side_effects(stmt.expr)) {
                    // Dead assignment. Turn into NOP.
                    stmt.kind = StmtKind::kNop;
                    stmt.expr = {};
                    stmt.var = {};
                    changed = true;
                    continue; // Don't collect vars from dead assignment
                }
            }
            // If alive, remove from used set (it's defined here) and collect dependencies
            // BUT: Do NOT erase loop-live variables - they need to stay live for other
            // definitions within the same loop
            if (!is_loop_live && !loop_live_vars) {
                used_vars.erase(stmt.var.name);
            }
            collect_expr_vars(stmt.expr, used_vars);
        } else {
            // Other statements (Call, Store, Return, etc.) are always live
            collect_used_vars(stmt, used_vars);
        }
    }
    
    // Remove NOPs
    auto it = std::remove_if(stmts.begin(), stmts.end(), [](const Stmt& s) {
        return s.kind == StmtKind::kNop;
    });
    if (it != stmts.end()) {
        stmts.erase(it, stmts.end());
        changed = true;
    }
}

} // namespace

void eliminate_dead_code(Function& function) {
    bool changed = true;
    while (changed) {
        changed = false;
        std::unordered_set<std::string> used_vars;
        process_block(function.stmts, used_vars, changed);
    }
}

} // namespace engine::decompiler::passes
