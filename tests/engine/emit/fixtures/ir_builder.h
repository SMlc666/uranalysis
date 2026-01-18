#pragma once

#include "engine/decompiler.h"
#include "engine/mlil.h"

namespace test::emit {

/// Fluent builder for MLIL expressions.
class ExprBuilder {
public:
    static ExprBuilder var(std::string name, int version = -1) {
        ExprBuilder b;
        b.expr_.kind = engine::mlil::MlilExprKind::kVar;
        b.expr_.var.name = std::move(name);
        b.expr_.var.version = version;
        return b;
    }

    static ExprBuilder imm(std::uint64_t value) {
        ExprBuilder b;
        b.expr_.kind = engine::mlil::MlilExprKind::kImm;
        b.expr_.imm = value;
        return b;
    }

    ExprBuilder add(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kAdd, rhs);
    }

    ExprBuilder sub(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kSub, rhs);
    }

    ExprBuilder mul(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kMul, rhs);
    }

    ExprBuilder div(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kDiv, rhs);
    }

    ExprBuilder eq(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kEq, rhs);
    }

    ExprBuilder ne(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kNe, rhs);
    }

    ExprBuilder lt(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kLt, rhs);
    }

    ExprBuilder le(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kLe, rhs);
    }

    ExprBuilder gt(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kGt, rhs);
    }

    ExprBuilder ge(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kGe, rhs);
    }

    ExprBuilder band(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kAnd, rhs);
    }

    ExprBuilder bor(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kOr, rhs);
    }

    ExprBuilder shl(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kShl, rhs);
    }

    ExprBuilder shr(ExprBuilder rhs) const {
        return binary_op(engine::mlil::MlilOp::kShr, rhs);
    }

    ExprBuilder neg() const {
        ExprBuilder b;
        b.expr_.kind = engine::mlil::MlilExprKind::kOp;
        b.expr_.op = engine::mlil::MlilOp::kNeg;
        b.expr_.args.push_back(expr_);
        return b;
    }

    ExprBuilder bnot() const {
        ExprBuilder b;
        b.expr_.kind = engine::mlil::MlilExprKind::kOp;
        b.expr_.op = engine::mlil::MlilOp::kNot;
        b.expr_.args.push_back(expr_);
        return b;
    }

    ExprBuilder load(std::size_t size = 8) const {
        ExprBuilder b;
        b.expr_.kind = engine::mlil::MlilExprKind::kLoad;
        b.expr_.size = size;
        b.expr_.args.push_back(expr_);
        return b;
    }

    ExprBuilder select(ExprBuilder then_val, ExprBuilder else_val) const {
        ExprBuilder b;
        b.expr_.kind = engine::mlil::MlilExprKind::kOp;
        b.expr_.op = engine::mlil::MlilOp::kSelect;
        b.expr_.args.push_back(expr_);
        b.expr_.args.push_back(then_val.expr_);
        b.expr_.args.push_back(else_val.expr_);
        return b;
    }

    engine::mlil::MlilExpr build() const { return expr_; }
    operator engine::mlil::MlilExpr() const { return expr_; }

private:
    ExprBuilder binary_op(engine::mlil::MlilOp op, const ExprBuilder& rhs) const {
        ExprBuilder b;
        b.expr_.kind = engine::mlil::MlilExprKind::kOp;
        b.expr_.op = op;
        b.expr_.args.push_back(expr_);
        b.expr_.args.push_back(rhs.expr_);
        return b;
    }

    engine::mlil::MlilExpr expr_;
};

/// Fluent builder for decompiler statements.
class StmtBuilder {
public:
    static StmtBuilder assign(std::string var, ExprBuilder expr) {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kAssign;
        b.stmt_.var.name = std::move(var);
        b.stmt_.expr = expr.build();
        return b;
    }

    static StmtBuilder store(ExprBuilder target, ExprBuilder expr) {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kStore;
        b.stmt_.target = target.build();
        b.stmt_.expr = expr.build();
        return b;
    }

    static StmtBuilder ret(ExprBuilder expr) {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kReturn;
        b.stmt_.expr = expr.build();
        return b;
    }

    static StmtBuilder ret() {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kReturn;
        return b;
    }

    static StmtBuilder if_(ExprBuilder cond) {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kIf;
        b.stmt_.condition = cond.build();
        return b;
    }

    static StmtBuilder while_(ExprBuilder cond) {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kWhile;
        b.stmt_.condition = cond.build();
        return b;
    }

    static StmtBuilder break_() {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kBreak;
        return b;
    }

    static StmtBuilder continue_() {
        StmtBuilder b;
        b.stmt_.kind = engine::decompiler::StmtKind::kContinue;
        return b;
    }

    StmtBuilder& then(std::vector<StmtBuilder> body) {
        for (auto& s : body) {
            stmt_.then_body.push_back(s.build());
        }
        return *this;
    }

    StmtBuilder& else_(std::vector<StmtBuilder> body) {
        for (auto& s : body) {
            stmt_.else_body.push_back(s.build());
        }
        return *this;
    }

    StmtBuilder& body(std::vector<StmtBuilder> b) {
        for (auto& s : b) {
            stmt_.body.push_back(s.build());
        }
        return *this;
    }

    StmtBuilder& comment(std::string c) {
        stmt_.comment = std::move(c);
        return *this;
    }

    engine::decompiler::Stmt build() const { return stmt_; }
    operator engine::decompiler::Stmt() const { return stmt_; }

private:
    engine::decompiler::Stmt stmt_;
};

/// Convenience aliases
using E = ExprBuilder;
using S = StmtBuilder;

/// Build a simple test function.
inline engine::decompiler::Function make_function(
    std::string name,
    std::vector<StmtBuilder> stmts,
    std::string ret_type = "int") {
    
    engine::decompiler::Function func;
    func.name = std::move(name);
    func.return_type = std::move(ret_type);
    func.entry = 0x1000;
    
    for (auto& s : stmts) {
        func.stmts.push_back(s.build());
    }
    
    return func;
}

}  // namespace test::emit
