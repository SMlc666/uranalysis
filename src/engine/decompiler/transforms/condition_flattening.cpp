#include "engine/decompiler/transforms/condition_flattening.h"
#include "engine/decompiler/transforms.h"
#include <vector>

namespace engine::decompiler::transforms {

namespace {

// Helper to check if a block contains only a single if statement
bool is_single_if_block(const std::vector<Stmt>& stmts, const Stmt** out_if_stmt) {
    if (stmts.size() != 1) return false;
    if (stmts[0].kind != StmtKind::kIf) return false;
    if (out_if_stmt) *out_if_stmt = &stmts[0];
    return true;
}

// Helper to combine conditions with AND
mlil::MlilExpr combine_and(const mlil::MlilExpr& lhs, const mlil::MlilExpr& rhs) {
    return make_binary_expr(mlil::MlilOp::kAnd, 1, lhs, rhs); // Assuming boolean size 1
}

// Helper to combine conditions with OR
mlil::MlilExpr combine_or(const mlil::MlilExpr& lhs, const mlil::MlilExpr& rhs) {
    return make_binary_expr(mlil::MlilOp::kOr, 1, lhs, rhs);
}

void process_stmts(std::vector<Stmt>& stmts) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto it = stmts.begin(); it != stmts.end(); ++it) {
            if (it->kind == StmtKind::kIf) {
                // Check for nested IF (AND pattern)
                // if (A) { if (B) { ... } } -> if (A && B) { ... }
                // Only if 'else' is empty for both
                const Stmt* inner_if = nullptr;
                if (it->else_body.empty() && is_single_if_block(it->then_body, &inner_if)) {
                    if (inner_if->else_body.empty()) {
                        // Merge
                        it->condition = combine_and(it->condition, inner_if->condition);
                        it->then_body = inner_if->then_body;
                        changed = true;
                        // Restart loop or continue? Restart is safer but slower.
                        // Let's continue but re-check this node?
                        // Decrement iterator to re-process this node
                        --it; 
                        continue;
                    }
                }
                
                // Check for cascaded IF (OR pattern)
                // if (A) { ... } else { if (B) { ... } } -> if (A || B) { ... }
                // Only if 'then' bodies are identical
                // Checking identical bodies is hard.
                // But we can check for: if (A) { goto L; } else { if (B) { goto L; } }
                // Or if (A) { return X; } else { if (B) { return X; } }
                // This is "merge_nested_ifs" which is already in transforms.h?
                // The prompt asks for "Condition flattener".
                // "Flatten nested if statements that should be && or ||"
                
                // Let's implement the AND flattening as primary.
                // Also: if (A) { ... } else if (B) { ... } is standard else-if chain, not necessarily flattening.
                
                // Another pattern:
                // if (A) { if (B) { X } else { Y } } else { Y }
                // -> if (A && B) { X } else { Y }
                // Requires checking if inner else matches outer else.
                
                // Let's stick to the simple AND flattening first.
                
                // Recurse into bodies
                process_stmts(it->then_body);
                process_stmts(it->else_body);
            } else if (it->kind == StmtKind::kWhile || it->kind == StmtKind::kDoWhile) {
                process_stmts(it->body);
            } else if (it->kind == StmtKind::kFor) {
                process_stmts(it->then_body);
                process_stmts(it->else_body);
                process_stmts(it->body);
            } else if (it->kind == StmtKind::kSwitch) {
                for (auto& cb : it->case_bodies) process_stmts(cb);
                process_stmts(it->default_body);
            }
        }
    }
}

} // namespace

void flatten_conditions(Function& function) {
    process_stmts(function.stmts);
}

} // namespace engine::decompiler::transforms
