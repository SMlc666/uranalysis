#include "engine/mlil_lift.h"

namespace engine::mlil {

namespace {

std::size_t reg_size_from_name(const std::string& name) {
    if (name.empty()) {
        return 0;
    }
    
    // ARM64 registers (first char prefix)
    switch (name[0]) {
        case 'w': return 4;   // w0-w30 (32-bit)
        case 'x': return 8;   // x0-x30, xzr (64-bit)
        case 'b': return 1;   // b0-b31 (8-bit SIMD)
        case 'h': return 2;   // h0-h31 (16-bit SIMD)
        case 'q':
        case 'v': return 16;  // v0-v31, q0-q31 (128-bit SIMD)
        default: break;
    }
    
    // x86-64 registers
    // 64-bit: rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15, rip
    if (name[0] == 'r') {
        // r8-r15 without suffix are 64-bit
        if (name.size() >= 2) {
            char c1 = name[1];
            // rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, rip
            if (c1 == 'a' || c1 == 'b' || c1 == 'c' || c1 == 'd' ||
                c1 == 's' || c1 == 'i') {
                return 8;
            }
            // r8-r15 and variants
            if (c1 >= '0' && c1 <= '9') {
                // Check for suffix: r8d (32), r8w (16), r8b (8)
                if (name.size() >= 3) {
                    char last = name.back();
                    if (last == 'd') return 4;
                    if (last == 'w') return 2;
                    if (last == 'b') return 1;
                }
                return 8;  // r8, r9, ..., r15
            }
        }
    }
    
    // 32-bit: eax, ebx, ecx, edx, esi, edi, esp, ebp
    if (name[0] == 'e') {
        return 4;
    }
    
    // 16-bit: ax, bx, cx, dx, si, di, sp, bp (2 chars, no 'r' or 'e' prefix)
    // 8-bit: al, bl, cl, dl, ah, bh, ch, dh, sil, dil, spl, bpl
    if (name.size() == 2) {
        char c1 = name[1];
        // al, bl, cl, dl, ah, bh, ch, dh
        if (c1 == 'l' || c1 == 'h') {
            return 1;
        }
        // ax, bx, cx, dx, si, di, sp, bp
        if (c1 == 'x' || c1 == 'i' || c1 == 'p') {
            return 2;
        }
    }
    
    // 8-bit: sil, dil, spl, bpl (3 chars ending in 'l')
    if (name.size() == 3 && name[2] == 'l') {
        if ((name[0] == 's' && (name[1] == 'i' || name[1] == 'p')) ||
            (name[0] == 'd' && name[1] == 'i') ||
            (name[0] == 'b' && name[1] == 'p')) {
            return 1;
        }
    }
    
    // x86-64 SIMD: xmm0-xmm15 (128-bit), ymm0-ymm15 (256-bit)
    if (name.size() >= 4 && name[0] == 'x' && name[1] == 'm' && name[2] == 'm') {
        return 16;
    }
    if (name.size() >= 4 && name[0] == 'y' && name[1] == 'm' && name[2] == 'm') {
        return 32;
    }
    
    // x86-64 flags (1-byte pseudo registers)
    if (name.size() >= 5 && name.rfind("flag_", 0) == 0) {
        return 1;
    }
    
    // ARM64 SIMD single/double precision
    if (name[0] == 's') return 4;   // s0-s31 (32-bit float)
    if (name[0] == 'd') return 8;   // d0-d31 (64-bit float)
    
    return 0;
}

VarRef make_var_from_reg(const llir::RegRef& reg, std::size_t size) {
    VarRef var;
    var.name = "reg." + reg.name;
    var.version = reg.version;
    var.size = size;
    return var;
}

VarRef make_var_from_var(const llir::VarRef& in) {
    VarRef var;
    var.name = in.name;
    var.version = in.version;
    var.size = in.size;
    var.type_name = in.type_name;
    return var;
}

bool map_op(llir::LlilOp op, MlilOp& out) {
    switch (op) {
        case llir::LlilOp::kAdd:
            out = MlilOp::kAdd;
            return true;
        case llir::LlilOp::kSub:
            out = MlilOp::kSub;
            return true;
        case llir::LlilOp::kMul:
            out = MlilOp::kMul;
            return true;
        case llir::LlilOp::kDiv:
            out = MlilOp::kDiv;
            return true;
        case llir::LlilOp::kMod:
            out = MlilOp::kMod;
            return true;
        case llir::LlilOp::kAnd:
            out = MlilOp::kAnd;
            return true;
        case llir::LlilOp::kOr:
            out = MlilOp::kOr;
            return true;
        case llir::LlilOp::kXor:
            out = MlilOp::kXor;
            return true;
        case llir::LlilOp::kShl:
            out = MlilOp::kShl;
            return true;
        case llir::LlilOp::kShr:
            out = MlilOp::kShr;
            return true;
        case llir::LlilOp::kSar:
            out = MlilOp::kSar;
            return true;
        case llir::LlilOp::kRor:
            out = MlilOp::kRor;
            return true;
        case llir::LlilOp::kNot:
            out = MlilOp::kNot;
            return true;
        case llir::LlilOp::kNeg:
            out = MlilOp::kNeg;
            return true;
        case llir::LlilOp::kAbs:
            out = MlilOp::kAbs;
            return true;
        case llir::LlilOp::kMin:
            out = MlilOp::kMin;
            return true;
        case llir::LlilOp::kMax:
            out = MlilOp::kMax;
            return true;
        case llir::LlilOp::kBswap:
            out = MlilOp::kBswap;
            return true;
        case llir::LlilOp::kClz:
            out = MlilOp::kClz;
            return true;
        case llir::LlilOp::kRbit:
            out = MlilOp::kRbit;
            return true;
        case llir::LlilOp::kSqrt:
            out = MlilOp::kSqrt;
            return true;
        case llir::LlilOp::kCast:
            out = MlilOp::kCast;
            return true;
        case llir::LlilOp::kSelect:
            out = MlilOp::kSelect;
            return true;
        case llir::LlilOp::kEq:
            out = MlilOp::kEq;
            return true;
        case llir::LlilOp::kNe:
            out = MlilOp::kNe;
            return true;
        case llir::LlilOp::kLt:
            out = MlilOp::kLt;
            return true;
        case llir::LlilOp::kLe:
            out = MlilOp::kLe;
            return true;
        case llir::LlilOp::kGt:
            out = MlilOp::kGt;
            return true;
        case llir::LlilOp::kGe:
            out = MlilOp::kGe;
            return true;
    }
    return false;
}

bool convert_expr(const llir::LlilExpr& in, MlilExpr& out, std::string& error) {
    out = {};
    out.kind = MlilExprKind::kInvalid;
    out.size = in.size;
    switch (in.kind) {
        case llir::LlilExprKind::kInvalid:
            out.kind = MlilExprKind::kInvalid;
            return true;
        case llir::LlilExprKind::kUnknown:
            out.kind = MlilExprKind::kUndef;
            return true;
        case llir::LlilExprKind::kUndef:
            out.kind = MlilExprKind::kUndef;
            return true;
        case llir::LlilExprKind::kImm:
            out.kind = MlilExprKind::kImm;
            out.imm = in.imm;
            return true;
        case llir::LlilExprKind::kReg:
            out.kind = MlilExprKind::kVar;
            out.var = make_var_from_reg(in.reg, in.size);
            return true;
        case llir::LlilExprKind::kVar:
            out.kind = MlilExprKind::kVar;
            out.var = make_var_from_var(in.var);
            return true;
        case llir::LlilExprKind::kLoad:
            out.kind = MlilExprKind::kLoad;
            for (const auto& arg : in.args) {
                MlilExpr converted;
                if (!convert_expr(arg, converted, error)) {
                    return false;
                }
                out.args.push_back(std::move(converted));
            }
            return true;
        case llir::LlilExprKind::kOp: {
            out.kind = MlilExprKind::kOp;
            if (!map_op(in.op, out.op)) {
                error = "mlil: unsupported llil op";
                return false;
            }
            out.args.reserve(in.args.size());
            for (const auto& arg : in.args) {
                MlilExpr converted;
                if (!convert_expr(arg, converted, error)) {
                    return false;
                }
                out.args.push_back(std::move(converted));
            }
            return true;
        }
    }
    error = "mlil: unhandled llil expr kind";
    return false;
}

bool convert_stmt(const llir::LlilStmt& in, MlilStmt& out, std::string& error) {
    out = {};
    out.comment = in.comment;
    switch (in.kind) {
        case llir::LlilStmtKind::kUnimpl:
            out.kind = MlilStmtKind::kUnimpl;
            return true;
        case llir::LlilStmtKind::kNop:
            out.kind = MlilStmtKind::kNop;
            return true;
        case llir::LlilStmtKind::kSetReg:
            out.kind = MlilStmtKind::kAssign;
            out.var = make_var_from_reg(in.reg, in.expr.size);
            return convert_expr(in.expr, out.expr, error);
        case llir::LlilStmtKind::kSetVar:
            out.kind = MlilStmtKind::kAssign;
            out.var = make_var_from_var(in.var);
            return convert_expr(in.expr, out.expr, error);
        case llir::LlilStmtKind::kStore:
            out.kind = MlilStmtKind::kStore;
            if (!convert_expr(in.target, out.target, error)) {
                return false;
            }
            return convert_expr(in.expr, out.expr, error);
        case llir::LlilStmtKind::kCall:
            out.kind = MlilStmtKind::kCall;
            out.args.clear();
            out.args.reserve(in.args.size());
            for (const auto& arg : in.args) {
                MlilExpr converted;
                if (!convert_expr(arg, converted, error)) {
                    return false;
                }
                out.args.push_back(std::move(converted));
            }
            out.returns.clear();
            out.returns.reserve(in.returns.size());
            for (const auto& ret : in.returns) {
                out.returns.push_back(make_var_from_reg(ret, reg_size_from_name(ret.name)));
            }
            return convert_expr(in.target, out.target, error);
        case llir::LlilStmtKind::kJump:
            out.kind = MlilStmtKind::kJump;
            return convert_expr(in.target, out.target, error);
        case llir::LlilStmtKind::kCJump:
            out.kind = MlilStmtKind::kCJump;
            if (!convert_expr(in.condition, out.condition, error)) {
                return false;
            }
            return convert_expr(in.target, out.target, error);
        case llir::LlilStmtKind::kRet:
            out.kind = MlilStmtKind::kRet;
            return convert_expr(in.expr, out.expr, error);
        case llir::LlilStmtKind::kPhi:
            out.kind = MlilStmtKind::kPhi;
            out.var = make_var_from_reg(in.reg, in.expr.size);
            return convert_expr(in.expr, out.expr, error);
    }
    error = "mlil: unhandled llil stmt kind";
    return false;
}

bool has_llil_ssa(const llir::Function& function) {
    for (const auto& block : function.blocks) {
        for (const auto& inst : block.instructions) {
            if (!inst.llil_ssa.empty()) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace

bool build_mlil_from_llil_ssa(const llir::Function& llil_function,
                              Function& mlil_function,
                              std::string& error) {
    error.clear();
    mlil_function = {};
    if (!has_llil_ssa(llil_function)) {
        error = "mlil: llil_ssa is empty";
        return false;
    }

    mlil_function.entry = llil_function.entry;
    mlil_function.blocks.reserve(llil_function.blocks.size());
    for (const auto& llil_block : llil_function.blocks) {
        BasicBlock block;
        block.start = llil_block.start;
        block.end = llil_block.end;
        block.predecessors = llil_block.predecessors;
        block.successors = llil_block.successors;

        block.phis.reserve(llil_block.phis.size());
        for (const auto& phi : llil_block.phis) {
            MlilStmt converted;
            if (!convert_stmt(phi, converted, error)) {
                return false;
            }
            block.phis.push_back(std::move(converted));
        }

        block.instructions.reserve(llil_block.instructions.size());
        for (const auto& llil_inst : llil_block.instructions) {
            Instruction inst;
            inst.address = llil_inst.address;
            inst.stmts.reserve(llil_inst.llil_ssa.size());
            for (const auto& stmt : llil_inst.llil_ssa) {
                MlilStmt converted;
                if (!convert_stmt(stmt, converted, error)) {
                    return false;
                }
                inst.stmts.push_back(std::move(converted));
            }
            block.instructions.push_back(std::move(inst));
        }
        mlil_function.blocks.push_back(std::move(block));
    }
    return true;
}

}  // namespace engine::mlil
