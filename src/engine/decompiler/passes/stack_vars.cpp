#include "engine/decompiler.h"
#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace engine::decompiler {

namespace {

// Represents a stack variable with offset and size information
struct StackVar {
    std::int64_t offset;      // Offset from SP (negative for locals)
    std::size_t size;         // Size in bytes
    std::string name;         // Generated name (e.g., "local_10", "var_20")
    std::string type_hint;    // Type hint based on usage patterns
    bool is_argument;         // True if this is a saved argument (positive offset)
    int access_count;         // How many times accessed
};

// Analyze expression to find SP-relative accesses
// Returns true if found an SP access, fills offset and is_store
bool find_sp_access(const mlil::MlilExpr& expr, std::int64_t& offset, std::size_t& size, bool& is_load) {
    // Pattern 1: Load from (sp + offset)
    if (expr.kind == mlil::MlilExprKind::kLoad && !expr.args.empty()) {
        const auto& addr = expr.args[0];
        
        // Direct: *(sp + offset)
        if (addr.kind == mlil::MlilExprKind::kOp && 
            (addr.op == mlil::MlilOp::kAdd || addr.op == mlil::MlilOp::kSub) &&
            addr.args.size() == 2) {
            
            // Check if LHS is SP variable
            if (addr.args[0].kind == mlil::MlilExprKind::kVar) {
                const std::string& name = addr.args[0].var.name;
                if (name == "sp" || name == "reg.sp" || name.find("sp") != std::string::npos) {
                    // Get offset
                    if (addr.args[1].kind == mlil::MlilExprKind::kImm) {
                        std::int64_t off = static_cast<std::int64_t>(addr.args[1].imm);
                        if (addr.op == mlil::MlilOp::kSub) {
                            off = -off;
                        }
                        offset = off;
                        size = expr.size > 0 ? expr.size : 8;
                        is_load = true;
                        return true;
                    }
                }
            }
        }
        
        // Direct SP var (sp[0])
        if (addr.kind == mlil::MlilExprKind::kVar) {
            const std::string& name = addr.var.name;
            if (name == "sp" || name == "reg.sp") {
                offset = 0;
                size = expr.size > 0 ? expr.size : 8;
                is_load = true;
                return true;
            }
        }
    }
    
    // Pattern 2: var.name contains sp offset pattern like "sp - 0x10"
    // This catches printer output patterns like sp[i - 0xc8]
    
    return false;
}

// Recursively find all SP accesses in an expression
void collect_sp_accesses(const mlil::MlilExpr& expr, 
                         std::map<std::int64_t, StackVar>& vars,
                         bool is_store_context) {
    std::int64_t offset = 0;
    std::size_t size = 0;
    bool is_load = false;
    
    if (find_sp_access(expr, offset, size, is_load)) {
        // Round offset to alignment
        std::int64_t aligned_offset = (offset / 8) * 8;
        
        auto it = vars.find(aligned_offset);
        if (it == vars.end()) {
            StackVar sv;
            sv.offset = aligned_offset;
            sv.size = size;
            sv.is_argument = (offset >= 0);
            sv.access_count = 1;
            
            // Generate name based on offset
            if (offset < 0) {
                // Local variable
                char buf[32];
                std::snprintf(buf, sizeof(buf), "local_%lx", static_cast<unsigned long>(-offset));
                sv.name = buf;
            } else if (offset == 0) {
                sv.name = "saved_fp";
            } else {
                // Saved value or argument
                char buf[32];
                std::snprintf(buf, sizeof(buf), "saved_%lx", static_cast<unsigned long>(offset));
                sv.name = buf;
            }
            
            // Type hints based on size
            switch (size) {
                case 1: sv.type_hint = "int8_t"; break;
                case 2: sv.type_hint = "int16_t"; break;
                case 4: sv.type_hint = "int32_t"; break;
                case 8: sv.type_hint = "int64_t"; break;
                default: sv.type_hint = "void*"; break;
            }
            
            vars[aligned_offset] = sv;
        } else {
            // Update existing
            it->second.access_count++;
            if (size > it->second.size) {
                it->second.size = size;
            }
        }
    }
    
    // Recurse into sub-expressions
    for (const auto& arg : expr.args) {
        collect_sp_accesses(arg, vars, is_store_context);
    }
}

// Collect SP accesses from a statement
void collect_sp_accesses_stmt(const Stmt& stmt, std::map<std::int64_t, StackVar>& vars) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            collect_sp_accesses(stmt.expr, vars, false);
            break;
            
        case StmtKind::kStore:
            collect_sp_accesses(stmt.target, vars, true);
            collect_sp_accesses(stmt.expr, vars, false);
            break;
            
        case StmtKind::kCall:
            collect_sp_accesses(stmt.target, vars, false);
            for (const auto& arg : stmt.args) {
                collect_sp_accesses(arg, vars, false);
            }
            break;
            
        case StmtKind::kReturn:
            collect_sp_accesses(stmt.expr, vars, false);
            break;
            
        case StmtKind::kIf:
            collect_sp_accesses(stmt.condition, vars, false);
            for (const auto& s : stmt.then_body) {
                collect_sp_accesses_stmt(s, vars);
            }
            for (const auto& s : stmt.else_body) {
                collect_sp_accesses_stmt(s, vars);
            }
            break;
            
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
            collect_sp_accesses(stmt.condition, vars, false);
            for (const auto& s : stmt.body) {
                collect_sp_accesses_stmt(s, vars);
            }
            break;
            
        case StmtKind::kSwitch:
            collect_sp_accesses(stmt.condition, vars, false);
            for (const auto& case_body : stmt.case_bodies) {
                for (const auto& s : case_body) {
                    collect_sp_accesses_stmt(s, vars);
                }
            }
            for (const auto& s : stmt.default_body) {
                collect_sp_accesses_stmt(s, vars);
            }
            break;
            
        default:
            break;
    }
}

// Replace SP offset expressions with stack variable references in an expression
void rewrite_sp_expr(mlil::MlilExpr& expr, const std::map<std::int64_t, StackVar>& vars) {
    std::int64_t offset = 0;
    std::size_t size = 0;
    bool is_load = false;
    
    if (find_sp_access(expr, offset, size, is_load)) {
        std::int64_t aligned_offset = (offset / 8) * 8;
        auto it = vars.find(aligned_offset);
        if (it != vars.end()) {
            // Replace with variable reference
            // For loads, we replace the entire Load expression with a Var
            // This creates cleaner output like "local_10" instead of "*((sp - 0x10))"
            expr.kind = mlil::MlilExprKind::kVar;
            expr.var.name = it->second.name;
            expr.var.size = it->second.size;
            expr.var.version = -1;
            expr.args.clear();
            expr.op = mlil::MlilOp::kAdd; // Reset op
            return;
        }
    }
    
    // Recurse into sub-expressions
    for (auto& arg : expr.args) {
        rewrite_sp_expr(arg, vars);
    }
}

// Rewrite SP accesses in a statement
void rewrite_sp_stmt(Stmt& stmt, const std::map<std::int64_t, StackVar>& vars) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            rewrite_sp_expr(stmt.expr, vars);
            break;
            
        case StmtKind::kStore:
            rewrite_sp_expr(stmt.target, vars);
            rewrite_sp_expr(stmt.expr, vars);
            break;
            
        case StmtKind::kCall:
            rewrite_sp_expr(stmt.target, vars);
            for (auto& arg : stmt.args) {
                rewrite_sp_expr(arg, vars);
            }
            break;
            
        case StmtKind::kReturn:
            rewrite_sp_expr(stmt.expr, vars);
            break;
            
        case StmtKind::kIf:
            rewrite_sp_expr(stmt.condition, vars);
            for (auto& s : stmt.then_body) {
                rewrite_sp_stmt(s, vars);
            }
            for (auto& s : stmt.else_body) {
                rewrite_sp_stmt(s, vars);
            }
            break;
            
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
            rewrite_sp_expr(stmt.condition, vars);
            for (auto& s : stmt.body) {
                rewrite_sp_stmt(s, vars);
            }
            break;
            
        case StmtKind::kSwitch:
            rewrite_sp_expr(stmt.condition, vars);
            for (auto& case_body : stmt.case_bodies) {
                for (auto& s : case_body) {
                    rewrite_sp_stmt(s, vars);
                }
            }
            for (auto& s : stmt.default_body) {
                rewrite_sp_stmt(s, vars);
            }
            break;
            
        default:
            break;
    }
}

} // anonymous namespace

void analyze_stack_variables(Function& function) {
    // Phase 1: Collect all SP-relative accesses and build stack layout
    std::map<std::int64_t, StackVar> stack_vars;
    
    for (const auto& stmt : function.stmts) {
        collect_sp_accesses_stmt(stmt, stack_vars);
    }
    
    // Phase 2: Refine variable names based on usage patterns
    // Sort by offset to identify variable regions
    std::vector<std::pair<std::int64_t, StackVar*>> sorted_vars;
    for (auto& [offset, var] : stack_vars) {
        sorted_vars.emplace_back(offset, &var);
    }
    std::sort(sorted_vars.begin(), sorted_vars.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    
    // Assign sequential names for better readability
    int local_index = 0;
    int saved_index = 0;
    for (auto& [offset, var] : sorted_vars) {
        if (offset < 0) {
            char buf[32];
            // Use size suffix for clarity
            const char* suffix = "";
            switch (var->size) {
                case 1: suffix = "b"; break;  // byte
                case 2: suffix = "w"; break;  // word
                case 4: suffix = "d"; break;  // dword
                case 8: suffix = "q"; break;  // qword
                default: break;
            }
            std::snprintf(buf, sizeof(buf), "local_%d%s", local_index++, suffix);
            var->name = buf;
        } else if (offset > 0) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "saved_%d", saved_index++);
            var->name = buf;
        }
    }
    
    // Phase 3: Rewrite SP-relative accesses to use stack variable names
    for (auto& stmt : function.stmts) {
        rewrite_sp_stmt(stmt, stack_vars);
    }
    
    // Phase 4: Add stack variables to function's local variable declarations
    for (const auto& [offset, var] : stack_vars) {
        VarDecl v;
        v.name = var.name;
        v.type = var.type_hint;
        function.locals.push_back(v);
    }
}

} // namespace engine::decompiler