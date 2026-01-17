#include "engine/hlil_lift.h"
#include "analysis/control_flow_graph.h"

#include <algorithm>
#include <cassert>
#include <unordered_set>
#include <spdlog/spdlog.h>

namespace engine::hlil {

namespace {

using Expr = mlil::MlilExpr;
using VarRef = mlil::VarRef;

// --- Helper Functions ---

bool expr_to_imm_u64(const Expr& expr, std::uint64_t& out) {
    if (expr.kind != mlil::MlilExprKind::kImm) {
        return false;
    }
    out = expr.imm;
    return true;
}

Expr make_imm(std::uint64_t value, std::size_t size) {
    Expr expr;
    expr.kind = mlil::MlilExprKind::kImm;
    expr.size = size;
    expr.imm = value;
    return expr;
}

Expr make_op(mlil::MlilOp op, std::vector<Expr> args, std::size_t size) {
    Expr expr;
    expr.kind = mlil::MlilExprKind::kOp;
    expr.size = size;
    expr.op = op;
    expr.args = std::move(args);
    return expr;
}

Expr invert_condition(Expr cond) {
    if (cond.kind == mlil::MlilExprKind::kImm && cond.size == 1) {
        cond.imm = (cond.imm & 1) ? 0 : 1;
        return cond;
    }
    if (cond.kind == mlil::MlilExprKind::kOp && cond.size == 1) {
        switch (cond.op) {
            case mlil::MlilOp::kEq: cond.op = mlil::MlilOp::kNe; return cond;
            case mlil::MlilOp::kNe: cond.op = mlil::MlilOp::kEq; return cond;
            case mlil::MlilOp::kLt: cond.op = mlil::MlilOp::kGe; return cond;
            case mlil::MlilOp::kLe: cond.op = mlil::MlilOp::kGt; return cond;
            case mlil::MlilOp::kGt: cond.op = mlil::MlilOp::kLe; return cond;
            case mlil::MlilOp::kGe: cond.op = mlil::MlilOp::kLt; return cond;
            default: break;
        }
    }
    return make_op(mlil::MlilOp::kEq, {std::move(cond), make_imm(0, 1)}, 1);
}

class StructureContext {
public:
    StructureContext(const mlil::Function& func) : function_(func), cfg_(func) {}

    std::vector<HlilStmt> lift() {
        PathState path;
        return lift_region(function_.entry, 0, path, 0, 0);
    }

private:
    struct PathState {
        std::vector<std::uint64_t> stack;
        std::unordered_set<std::uint64_t> on_stack;
    };

    const mlil::Function& function_;
    ControlFlowGraph cfg_;

    // Helper to extract the condition and true/false targets from a block
    bool get_branch_info(const mlil::BasicBlock* block, Expr& cond, std::uint64_t& true_tgt, std::uint64_t& false_tgt) {
        if (block->instructions.empty()) return false;
        const auto& last_inst = block->instructions.back();
        for (auto it = last_inst.stmts.rbegin(); it != last_inst.stmts.rend(); ++it) {
            if (it->kind == mlil::MlilStmtKind::kCJump) {
                cond = it->condition;
                if (!expr_to_imm_u64(it->target, true_tgt)) return false;
                
                // Determine false target
                if (block->successors.size() == 2) {
                    false_tgt = (block->successors[0] == true_tgt) ? block->successors[1] : block->successors[0];
                    return true;
                }
            }
        }
        return false;
    }

    void lift_block_stmts(const mlil::BasicBlock* block, std::vector<HlilStmt>& out) {
        for (const auto& inst : block->instructions) {
            for (const auto& stmt : inst.stmts) {
                // Skip control flow statements
                if (stmt.kind == mlil::MlilStmtKind::kJump || 
                    stmt.kind == mlil::MlilStmtKind::kCJump) continue;

                HlilStmt h;
                h.comment = stmt.comment;
                bool keep = true;
                switch (stmt.kind) {
                    case mlil::MlilStmtKind::kAssign:
                        h.kind = HlilStmtKind::kAssign; h.var = stmt.var; h.expr = stmt.expr; break;
                    case mlil::MlilStmtKind::kStore:
                        h.kind = HlilStmtKind::kStore; h.target = stmt.target; h.expr = stmt.expr; break;
                    case mlil::MlilStmtKind::kCall:
                        h.kind = HlilStmtKind::kCall; h.target = stmt.target; h.args = stmt.args; h.returns = stmt.returns; break;
                    case mlil::MlilStmtKind::kRet:
                        h.kind = HlilStmtKind::kRet; h.expr = stmt.expr; break;
                    case mlil::MlilStmtKind::kNop:
                        h.kind = HlilStmtKind::kNop; break;
                    default: keep = false; break;
                }
                if (keep) out.push_back(std::move(h));
            }
        }
    }

    // The Core Recursive Structurer
    std::vector<HlilStmt> lift_region(std::uint64_t current,
                                      std::uint64_t stop_at,
                                      PathState& path,
                                      std::uint64_t loop_header,
                                      std::uint64_t loop_exit) {
        std::vector<HlilStmt> stmts;
        const std::size_t base_depth = path.stack.size();

        while (current != 0 && current != stop_at) {
            if (path.on_stack.count(current)) {
                // Hit a node already on the active path.
                // Check if it's a trivial leaf block (e.g. just 'ret') that we should duplicate
                // for better readability (avoiding 'goto label_return').
                const BlockInfo* info = cfg_.get_info(current);
                bool is_trivial_leaf = false;
                if (info && info->succs.empty()) {
                    // Check instruction count/complexity. For now, just allow leaves.
                    // Verify it doesn't loop back (succs empty implies it doesn't).
                    is_trivial_leaf = true;
                }

                if (is_trivial_leaf && info) {
                    // Duplicate logic: Emit instructions, but stop here (no recursion).
                    lift_block_stmts(info->block, stmts);
                    break;
                }

                // Standard cycle behavior
                if (current == loop_header) {
                    HlilStmt s; s.kind = HlilStmtKind::kContinue;
                    stmts.push_back(std::move(s));
                } else if (current == loop_exit) {
                    HlilStmt s; s.kind = HlilStmtKind::kBreak;
                    stmts.push_back(std::move(s));
                } else {
                    HlilStmt s; s.kind = HlilStmtKind::kGoto; s.address = current;
                    stmts.push_back(std::move(s));
                }
                break;
            }
            path.on_stack.insert(current);
            path.stack.push_back(current);

            const BlockInfo* info = cfg_.get_info(current);
            if (!info) break;

            // Track where statements start for this block (for self-loop handling)
            std::size_t stmts_start_idx = stmts.size();

            // 1. Emit statements
            lift_block_stmts(info->block, stmts);

            // 2. Check for Return
            if (info->succs.empty()) {
                break;
            }

            // 3. Check for Loop
            if (!info->back_edges.empty()) {
                // Determine Loop Info
                // We use the first back edge to define the loop scope for now
                // In robust decompiler, we'd handle multi-entry/multi-backedge loops
                
                // Identify loop exit
                std::uint64_t body_start = 0;
                std::uint64_t exit_target = 0;
                
                Expr loop_cond;
                std::uint64_t t_tgt = 0, f_tgt = 0;
                bool is_cjump = get_branch_info(info->block, loop_cond, t_tgt, f_tgt);

                SPDLOG_DEBUG("HLIL Loop detected at 0x{:x}: is_cjump={} t_tgt=0x{:x} f_tgt=0x{:x}", 
                    current, is_cjump, t_tgt, f_tgt);

                HlilStmt loop_stmt;
                loop_stmt.kind = HlilStmtKind::kWhile;
                
                if (is_cjump) {
                    bool t_in = cfg_.is_in_loop(t_tgt, current);
                    bool f_in = cfg_.is_in_loop(f_tgt, current);
                    
                    if (t_in && !f_in) {
                        loop_stmt.condition = loop_cond;
                        body_start = t_tgt;
                        exit_target = f_tgt;
                    } else if (f_in && !t_in) {
                        loop_stmt.condition = invert_condition(loop_cond);
                        body_start = f_tgt;
                        exit_target = t_tgt;
                    } else if (t_in && f_in) {
                        // Both branches in loop - try to find which leads to eventual exit
                        // Look for a branch that has a path to outside the loop
                        const BlockInfo* t_info = cfg_.get_info(t_tgt);
                        const BlockInfo* f_info = cfg_.get_info(f_tgt);
                        
                        bool t_has_exit_path = false;
                        bool f_has_exit_path = false;
                        
                        // Check if t_tgt eventually exits the loop
                        if (t_info) {
                            for (auto succ : t_info->succs) {
                                if (!cfg_.is_in_loop(succ, current)) {
                                    t_has_exit_path = true;
                                    exit_target = succ;
                                    break;
                                }
                            }
                        }
                        
                        // Check if f_tgt eventually exits the loop
                        if (f_info) {
                            for (auto succ : f_info->succs) {
                                if (!cfg_.is_in_loop(succ, current)) {
                                    f_has_exit_path = true;
                                    if (exit_target == 0) {
                                        exit_target = succ;
                                    }
                                    break;
                                }
                            }
                        }
                        
                        // Use the condition if one path has an exit
                        if (t_has_exit_path && !f_has_exit_path) {
                            // t_tgt leads to exit, so loop continues while NOT condition
                            loop_stmt.condition = invert_condition(loop_cond);
                            body_start = f_tgt;
                        } else if (f_has_exit_path && !t_has_exit_path) {
                            // f_tgt leads to exit, so loop continues while condition
                            loop_stmt.condition = loop_cond;
                            body_start = t_tgt;
                        } else {
                            // Both or neither have exit paths - use condition as-is
                            // The condition likely represents something meaningful
                            loop_stmt.condition = loop_cond;
                            body_start = t_tgt;
                        }
                    } else {
                        // Neither in loop - shouldn't happen for back-edge block
                        loop_stmt.condition = make_imm(1, 1);
                        body_start = t_tgt;
                    }
                } else {
                     loop_stmt.condition = make_imm(1, 1);
                     body_start = info->succs[0];
                }

                // P1 Fix: Handle self-loops (body_start == current)
                // In self-loops, the loop header IS the loop body
                // We need to move statements from outer context into loop body
                //
                // P2 Fix: Handle edge-split self-loops
                // After critical edge splitting, a self-loop like 0x1c68 -> 0x1c68
                // becomes 0x1c68 -> 0x1c82 -> 0x1c68 where 0x1c82 is a synthetic block
                // containing only phi copies. We detect this by checking if body_start
                // is a trampoline block that jumps directly back to the header.
                
                bool is_trampoline_body = false;
                if (body_start != current && body_start != 0) {
                    const BlockInfo* body_info = cfg_.get_info(body_start);
                    if (body_info && body_info->succs.size() == 1 && body_info->succs[0] == current) {
                        // body_start jumps directly back to current - it's a trampoline
                        // Check if it only contains phi copies (comment contains "phi" or "split edge")
                        bool only_phi_copies = true;
                        if (body_info->block) {
                            for (const auto& inst : body_info->block->instructions) {
                                for (const auto& stmt : inst.stmts) {
                                    if (stmt.kind == mlil::MlilStmtKind::kJump) continue;
                                    if (stmt.comment.find("phi") == std::string::npos &&
                                        stmt.comment.find("split edge") == std::string::npos) {
                                        only_phi_copies = false;
                                        break;
                                    }
                                }
                                if (!only_phi_copies) break;
                            }
                        }
                        is_trampoline_body = only_phi_copies;
                        if (is_trampoline_body) {
                            SPDLOG_DEBUG("  Detected trampoline block 0x{:x} -> 0x{:x}, treating as self-loop", body_start, current);
                        }
                    }
                }
                
                if (body_start == current || is_trampoline_body) {
                    SPDLOG_DEBUG("  Self-loop at 0x{:x}, moving {} stmts from index {}", current, stmts.size() - stmts_start_idx, stmts_start_idx);
                    // Self-loop: move previously extracted statements into loop body
                    // These statements were added at stmts_start_idx by lift_block_stmts above
                    for (std::size_t i = stmts_start_idx; i < stmts.size(); ++i) {
                        loop_stmt.body.push_back(std::move(stmts[i]));
                    }
                    // Remove moved statements from outer list
                    stmts.erase(stmts.begin() + static_cast<std::ptrdiff_t>(stmts_start_idx), stmts.end());
                    
                    // If it's a trampoline, also lift the trampoline block's statements
                    if (is_trampoline_body) {
                        const BlockInfo* body_info = cfg_.get_info(body_start);
                        if (body_info) {
                            lift_block_stmts(body_info->block, loop_stmt.body);
                        }
                    }
                } else if (body_start != 0) {
                    SPDLOG_DEBUG("  Loop body_start=0x{:x}, recursing with stop_at=0x{:x}", body_start, current);
                    // Recurse for body
                    // The 'stop_at' for the body is the header itself (current)
                    // We also pass current as loop_header and exit_target as loop_exit
                    loop_stmt.body = lift_region(body_start, current, path, current, exit_target);
                    SPDLOG_DEBUG("  Loop body has {} statements after recursion", loop_stmt.body.size());
                }
                
                // Universal fallback for empty loop bodies
                // Applies to both self-loops and regular loops
                if (loop_stmt.body.empty() && body_start != 0) {
                    SPDLOG_DEBUG("  Empty body fallback for body_start=0x{:x}", body_start);
                    const BlockInfo* body_info = cfg_.get_info(body_start);
                    if (body_info) {
                        lift_block_stmts(body_info->block, loop_stmt.body);
                        SPDLOG_DEBUG("  Fallback lifted {} statements", loop_stmt.body.size());
                    }
                }
                
                stmts.push_back(std::move(loop_stmt));

                if (exit_target != 0) {
                    current = exit_target;
                    continue;
                } else {
                    break;
                }
            }

            // 4. Check for Two-Way Branch (If-Else)
            if (info->succs.size() == 2) {
                Expr cond;
                std::uint64_t t_tgt = 0, f_tgt = 0;
                if (get_branch_info(info->block, cond, t_tgt, f_tgt)) {
                    
                    // Check for Break/Continue structure FIRST
                    if (loop_header != 0) {
                        bool t_in_loop = cfg_.is_in_loop(t_tgt, loop_header);
                        bool f_in_loop = cfg_.is_in_loop(f_tgt, loop_header);
                        // If one exits loop and other stays, it's a break/loop condition
                        // But we handled loop header above. This is for internal blocks.
                    }

                    // Determine Merge Point using IPDOM
                    std::uint64_t merge = info->ipdom;
                    
                    // If IPDOM is 0 (exit) or too far (beyond stop_at), clamp it
                    // Actually, if IPDOM is beyond stop_at, we should stop at stop_at.
                    // If merge is 0, it means the branches likely return or don't meet.
                    
                    // Special Handling: If one branch returns, merge point is effectively the other branch?
                    // IPDOM handles this naturally? 
                    // If T returns, IPDOM(Head) = Exit.
                    // If F -> M -> Exit.
                    // IPDOM(Head) = Exit.
                    // We need to detect that F does not go to Exit immediately?
                    
                    // Let's use a simpler heuristic for 'Merge': 
                    // If one branch dominates the IPDOM? No.
                    
                    // We trust recursive lift to hit 'stop_at' (merge) or return.
                    
                    HlilStmt if_stmt;
                    if_stmt.kind = HlilStmtKind::kIf;
                    if_stmt.condition = cond;
                    
                    // If merge is valid (non-zero) and different from targets
                    if (merge == 0) merge = stop_at; // Bounded by current region

                    if_stmt.then_body = lift_region(t_tgt, merge, path, loop_header, loop_exit);
                    if (f_tgt != merge) {
                         if_stmt.else_body = lift_region(f_tgt, merge, path, loop_header, loop_exit);
                    }
                    
                    stmts.push_back(std::move(if_stmt));
                    
                    current = merge;
                    continue;
                }
            }

            // 5. Linear
            if (info->succs.size() == 1) {
                current = info->succs[0];
                continue;
            }

            break;
        }
        while (path.stack.size() > base_depth) {
            path.on_stack.erase(path.stack.back());
            path.stack.pop_back();
        }
        return stmts;
    }
};

}  // namespace

bool build_hlil_from_mlil(const mlil::Function& mlil_function,
                          Function& hlil_function,
                          std::string& error) {
    error.clear();
    hlil_function = {};
    hlil_function.entry = mlil_function.entry;

    StructureContext ctx(mlil_function);
    hlil_function.stmts = ctx.lift();

    return true;
}

}  // namespace engine::hlil
