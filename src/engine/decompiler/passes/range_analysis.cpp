#include "engine/decompiler/passes/range_analysis.h"
#include "engine/decompiler/passes/constant_propagation.h"
#include <algorithm>
#include <queue>

namespace engine::decompiler::passes {

bool Range::contains(uint64_t val) const {
    if (val < min_val || val > max_val) return false;
    if (stride == 0) return val == min_val;
    if (stride == 1) return true;
    return (val % stride) == offset;
}

namespace {

Range union_ranges(const Range& a, const Range& b) {
    if (a.is_full() || b.is_full()) return Range::full();
    
    uint64_t new_min = std::min(a.min_val, b.min_val);
    uint64_t new_max = std::max(a.max_val, b.max_val);
    
    uint64_t new_stride = 1;
    uint64_t new_offset = 0;

    if (a.stride == b.stride && a.offset == b.offset && a.stride > 0) {
        new_stride = a.stride;
        new_offset = a.offset;
    } 
    else if (a.is_singleton() && b.is_singleton()) {
        uint64_t diff = (a.min_val > b.min_val) ? (a.min_val - b.min_val) : (b.min_val - a.min_val);
        if (diff > 0) {
            new_stride = diff;
            new_offset = a.min_val % diff;
        } else {
            new_stride = 0;
            new_offset = 0;
        }
    }
    else if (a.stride > 0 && b.is_singleton()) {
        if ((b.min_val % a.stride) == a.offset) {
            new_stride = a.stride;
            new_offset = a.offset;
        }
    }
    else if (b.stride > 0 && a.is_singleton()) {
        if ((a.min_val % b.stride) == b.offset) {
            new_stride = b.stride;
            new_offset = b.offset;
        }
    }

    return Range(new_min, new_max, new_stride, new_offset);
}

Range add_range(const Range& r, uint64_t val) {
    if (r.is_full()) return r;
    return Range(r.min_val + val, r.max_val + val, r.stride, (r.offset + val) % (r.stride ? r.stride : 1));
}

Range mul_range(const Range& r, uint64_t val) {
    if (r.is_full()) return r;
    if (val == 0) return Range::singleton(0);
    return Range(r.min_val * val, r.max_val * val, r.stride * val, (r.offset * val) % (r.stride * val ? r.stride * val : 1));
}

Range and_range(const Range& r, uint64_t val) {
    uint64_t new_max = std::min(r.max_val, val);
    
    if (r.stride > 0 && (r.stride % (val + 1) == 0) && ((val + 1) & val) == 0) {
         return Range::singleton(r.offset & val);
    }
    
    return Range(0, new_max, 1, 0); 
}

bool evaluate_range(const mlil::MlilExpr& expr, const std::unordered_map<std::string, Range>& ranges, Range& out) {
    if (expr.kind == mlil::MlilExprKind::kImm) {
        out = Range::singleton(expr.imm);
        return true;
    }
    if (expr.kind == mlil::MlilExprKind::kVar) {
        auto it = ranges.find(expr.var.name);
        if (it != ranges.end()) {
            out = it->second;
            return true;
        }
        return false;
    }
    if (expr.kind == mlil::MlilExprKind::kOp) {
        if (expr.args.size() == 2) {
            Range lhs, rhs;
            if (evaluate_range(expr.args[0], ranges, lhs) && evaluate_range(expr.args[1], ranges, rhs)) {
                if (rhs.is_singleton()) {
                    uint64_t val = rhs.min_val;
                    switch (expr.op) {
                        case mlil::MlilOp::kAdd: out = add_range(lhs, val); return true;
                        case mlil::MlilOp::kMul: out = mul_range(lhs, val); return true;
                        case mlil::MlilOp::kAnd: out = and_range(lhs, val); return true;
                        default: break;
                    }
                }
            }
        }
    }
    out = Range::full();
    return true;
}

void process_stmts(std::vector<Stmt>& stmts, std::unordered_map<std::string, Range>& ranges, bool& changed) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kAssign) {
            Range new_range;
            if (evaluate_range(stmt.expr, ranges, new_range)) {
                ranges[stmt.var.name] = new_range;
            }
        }
        else if (stmt.kind == StmtKind::kIf) {
            auto then_ranges = ranges;
            auto else_ranges = ranges;
            
            process_stmts(stmt.then_body, then_ranges, changed);
            process_stmts(stmt.else_body, else_ranges, changed);
            
            for (auto& [name, r] : ranges) {
                ranges[name] = union_ranges(then_ranges[name], else_ranges[name]);
            }
        }
        else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile) {
            auto loop_ranges = ranges;
            for (int i = 0; i < 3; ++i) {
                process_stmts(stmt.body, loop_ranges, changed);
                bool local_change = false;
                for (auto& [name, r] : ranges) {
                    Range merged = union_ranges(ranges[name], loop_ranges[name]);
                    if (merged.min_val != ranges[name].min_val || merged.max_val != ranges[name].max_val) {
                        ranges[name] = merged;
                        local_change = true;
                    }
                }
                if (!local_change) break;
            }
        }
        else if (stmt.kind == StmtKind::kFor) {
             process_stmts(stmt.then_body, ranges, changed);
             
             auto loop_ranges = ranges;
             for (int i = 0; i < 3; ++i) {
                 process_stmts(stmt.body, loop_ranges, changed);
                 process_stmts(stmt.else_body, loop_ranges, changed);
                 
                 bool local_change = false;
                 for (auto& [name, r] : ranges) {
                     Range merged = union_ranges(ranges[name], loop_ranges[name]);
                     if (merged.min_val != ranges[name].min_val || merged.max_val != ranges[name].max_val) {
                         ranges[name] = merged;
                         local_change = true;
                     }
                 }
                 if (!local_change) break;
             }
        }
    }
}

void resolve_branches(std::vector<Stmt>& stmts, const std::unordered_map<std::string, Range>& ranges) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            if (stmt.condition.kind == mlil::MlilExprKind::kOp) {
                if (stmt.condition.op == mlil::MlilOp::kEq) {
                    Range lhs, rhs;
                    if (evaluate_range(stmt.condition.args[0], ranges, lhs) && 
                        evaluate_range(stmt.condition.args[1], ranges, rhs)) {
                        
                        if (rhs.is_singleton() && rhs.min_val == 0) {
                            if (lhs.max_val == 0) {
                                stmt.condition.kind = mlil::MlilExprKind::kImm;
                                stmt.condition.imm = 1;
                            }
                        }
                    }
                }
            }
            resolve_branches(stmt.then_body, ranges);
            resolve_branches(stmt.else_body, ranges);
        }
        else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile) {
            resolve_branches(stmt.body, ranges);
        }
        else if (stmt.kind == StmtKind::kFor) {
            resolve_branches(stmt.body, ranges);
        }
    }
}

} // namespace

void analyze_ranges(Function& function) {
    std::unordered_map<std::string, Range> ranges;
    bool changed = false;
    process_stmts(function.stmts, ranges, changed);
    resolve_branches(function.stmts, ranges);
}

} // namespace engine::decompiler::passes
