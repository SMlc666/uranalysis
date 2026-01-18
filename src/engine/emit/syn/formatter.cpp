#include "engine/emit/syn/formatter.h"

#include <sstream>

namespace engine::emit::syn {

namespace {

std::string format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

}  // namespace

Formatter::Formatter(lex::Writer& writer, FormatOptions opts)
    : w_(writer), opts_(std::move(opts)) {}

// =============================================================================
// Expressions
// =============================================================================

void Formatter::emit_var(const mlil::VarRef& var) {
    if (var.name.empty()) {
        w_.identifier("var");
    } else {
        w_.identifier(var.name, TokenMeta::variable(var.name, var.version));
    }
}

void Formatter::emit_literal(std::uint64_t value) {
    w_.literal(format_hex(value));
}

void Formatter::emit_binary_op(const mlil::MlilExpr& e, Precedence parent_prec) {
    if (e.args.size() < 2) {
        // Malformed - emit as literal 0
        w_.literal("0");
        return;
    }

    Precedence my_prec = get_precedence(e.op);
    bool need_parens = needs_parens(parent_prec, my_prec);

    if (need_parens) {
        w_.punct('(');
    }

    expr(e.args[0], my_prec);

    if (opts_.space_around_binary_op) {
        w_.space();
    }
    w_.op(op_symbol(e.op));
    if (opts_.space_around_binary_op) {
        w_.space();
    }

    expr(e.args[1], my_prec);

    if (need_parens) {
        w_.punct(')');
    }
}

void Formatter::emit_unary_op(const mlil::MlilExpr& e) {
    if (e.args.empty()) {
        w_.literal("0");
        return;
    }

    w_.op(op_symbol(e.op));
    expr(e.args[0], Precedence::Unary);
}

void Formatter::emit_funclike_op(const mlil::MlilExpr& e) {
    w_.identifier(op_symbol(e.op));
    w_.punct('(');
    for (std::size_t i = 0; i < e.args.size(); ++i) {
        if (i > 0) {
            w_.punct(',');
            w_.space();
        }
        expr(e.args[i], Precedence::None);
    }
    w_.punct(')');
}

void Formatter::emit_ternary(const mlil::MlilExpr& e, Precedence parent_prec) {
    if (e.args.size() < 3) {
        w_.literal("0");
        return;
    }

    bool need_parens = needs_parens(parent_prec, Precedence::Ternary);
    if (need_parens) {
        w_.punct('(');
    }

    expr(e.args[0], Precedence::Ternary);
    w_.space();
    w_.op("?");
    w_.space();
    expr(e.args[1], Precedence::Ternary);
    w_.space();
    w_.op(":");
    w_.space();
    expr(e.args[2], Precedence::Ternary);

    if (need_parens) {
        w_.punct(')');
    }
}

void Formatter::emit_load(const mlil::MlilExpr& e) {
    if (e.args.empty()) {
        w_.raw("*(0)");
        return;
    }

    const auto& addr = e.args[0];

    // Simple variable dereference: *ptr
    if (addr.kind == mlil::MlilExprKind::kVar) {
        w_.op("*");
        emit_var(addr.var);
        return;
    }

    // General case: *(expr)
    w_.op("*");
    w_.punct('(');
    expr(addr, Precedence::None);
    w_.punct(')');
}

void Formatter::emit_call_expr(const mlil::MlilExpr& e) {
    if (e.args.empty()) {
        w_.identifier("<missing_target>");
        w_.punct('(');
        w_.punct(')');
        return;
    }

    // First arg is target
    expr(e.args[0], Precedence::Postfix);
    w_.punct('(');
    for (std::size_t i = 1; i < e.args.size(); ++i) {
        if (i > 1) {
            w_.punct(',');
            w_.space();
        }
        expr(e.args[i], Precedence::None);
    }
    w_.punct(')');
}

void Formatter::expr(const mlil::MlilExpr& e, Precedence parent_prec) {
    switch (e.kind) {
        case mlil::MlilExprKind::kInvalid:
            w_.raw("/*invalid*/");
            w_.literal("0");
            break;

        case mlil::MlilExprKind::kUnknown:
            w_.raw("/*unknown*/");
            w_.literal("0");
            break;

        case mlil::MlilExprKind::kUndef:
            w_.raw("/*undef*/");
            w_.literal("0");
            break;

        case mlil::MlilExprKind::kVar:
            emit_var(e.var);
            break;

        case mlil::MlilExprKind::kImm:
            emit_literal(e.imm);
            break;

        case mlil::MlilExprKind::kLoad:
            emit_load(e);
            break;

        case mlil::MlilExprKind::kCall:
            emit_call_expr(e);
            break;

        case mlil::MlilExprKind::kOp:
            if (e.op == mlil::MlilOp::kSelect) {
                emit_ternary(e, parent_prec);
            } else if (e.op == mlil::MlilOp::kCast && !e.args.empty()) {
                // Skip explicit casts for cleaner output
                expr(e.args[0], parent_prec);
            } else if (is_binary_op(e.op)) {
                emit_binary_op(e, parent_prec);
            } else if (is_unary_op(e.op)) {
                emit_unary_op(e);
            } else if (is_funclike_op(e.op)) {
                emit_funclike_op(e);
            } else {
                // Fallback: function-like
                emit_funclike_op(e);
            }
            break;
    }
}

// =============================================================================
// Statements
// =============================================================================

void Formatter::stmt_assign(const decompiler::Stmt& s) {
    if (s.var.name.empty()) return;

    emit_var(s.var);
    w_.space();
    w_.op("=");
    w_.space();
    expr(s.expr, Precedence::Assignment);
    w_.punct(';');

    if (!s.comment.empty()) {
        w_.space();
        w_.line_comment(s.comment);
    }
    w_.newline();
}

void Formatter::stmt_store(const decompiler::Stmt& s) {
    w_.op("*");
    w_.punct('(');
    expr(s.target, Precedence::None);
    w_.punct(')');
    w_.space();
    w_.op("=");
    w_.space();
    expr(s.expr, Precedence::Assignment);
    w_.punct(';');

    if (!s.comment.empty()) {
        w_.space();
        w_.line_comment(s.comment);
    }
    w_.newline();
}

void Formatter::stmt_call(const decompiler::Stmt& s) {
    // Return values
    if (!s.returns.empty()) {
        for (std::size_t i = 0; i < s.returns.size(); ++i) {
            if (i > 0) {
                w_.punct(',');
                w_.space();
            }
            emit_var(s.returns[i]);
        }
        w_.space();
        w_.op("=");
        w_.space();
    }

    // Target
    expr(s.target, Precedence::Postfix);
    w_.punct('(');
    for (std::size_t i = 0; i < s.args.size(); ++i) {
        if (i > 0) {
            w_.punct(',');
            w_.space();
        }
        expr(s.args[i], Precedence::None);
    }
    w_.punct(')');
    w_.punct(';');

    if (!s.comment.empty()) {
        w_.space();
        w_.line_comment(s.comment);
    }
    w_.newline();
}

void Formatter::stmt_return(const decompiler::Stmt& s) {
    w_.keyword("return");
    if (s.expr.kind != mlil::MlilExprKind::kInvalid) {
        w_.space();
        expr(s.expr, Precedence::None);
    }
    w_.punct(';');

    if (!s.comment.empty()) {
        w_.space();
        w_.line_comment(s.comment);
    }
    w_.newline();
}

void Formatter::stmt_if(const decompiler::Stmt& s) {
    w_.keyword("if");
    if (opts_.space_after_keyword) {
        w_.space();
    }
    w_.punct('(');
    expr(s.condition, Precedence::None);
    w_.punct(')');
    w_.space();
    w_.punct('{');
    w_.newline();

    w_.indent();
    block(s.then_body);
    w_.dedent();

    if (!s.else_body.empty()) {
        if (opts_.compact_else) {
            w_.punct('}');
            w_.space();
            w_.keyword("else");
            w_.space();
            w_.punct('{');
        } else {
            w_.punct('}');
            w_.newline();
            w_.keyword("else");
            w_.space();
            w_.punct('{');
        }
        w_.newline();

        w_.indent();
        block(s.else_body);
        w_.dedent();
    }

    w_.punct('}');
    w_.newline();
}

void Formatter::stmt_while(const decompiler::Stmt& s) {
    w_.keyword("while");
    if (opts_.space_after_keyword) {
        w_.space();
    }
    w_.punct('(');
    expr(s.condition, Precedence::None);
    w_.punct(')');
    w_.space();
    w_.punct('{');
    w_.newline();

    w_.indent();
    block(s.body);
    w_.dedent();

    w_.punct('}');
    w_.newline();
}

void Formatter::stmt_do_while(const decompiler::Stmt& s) {
    w_.keyword("do");
    w_.space();
    w_.punct('{');
    w_.newline();

    w_.indent();
    block(s.body);
    w_.dedent();

    w_.punct('}');
    w_.space();
    w_.keyword("while");
    if (opts_.space_after_keyword) {
        w_.space();
    }
    w_.punct('(');
    expr(s.condition, Precedence::None);
    w_.punct(')');
    w_.punct(';');
    w_.newline();
}

void Formatter::stmt_for(const decompiler::Stmt& s) {
    w_.keyword("for");
    if (opts_.space_after_keyword) {
        w_.space();
    }
    w_.punct('(');

    // Init from then_body[0]
    if (!s.then_body.empty() && s.then_body[0].kind == decompiler::StmtKind::kAssign) {
        const auto& init = s.then_body[0];
        emit_var(init.var);
        w_.space();
        w_.op("=");
        w_.space();
        expr(init.expr, Precedence::Assignment);
    }
    w_.punct(';');
    w_.space();

    // Condition
    expr(s.condition, Precedence::None);
    w_.punct(';');
    w_.space();

    // Step from else_body[0]
    if (!s.else_body.empty() && s.else_body[0].kind == decompiler::StmtKind::kAssign) {
        const auto& step = s.else_body[0];
        emit_var(step.var);
        w_.space();
        w_.op("=");
        w_.space();
        expr(step.expr, Precedence::Assignment);
    }

    w_.punct(')');
    w_.space();
    w_.punct('{');
    w_.newline();

    w_.indent();
    block(s.body);
    w_.dedent();

    w_.punct('}');
    w_.newline();
}

void Formatter::stmt_switch(const decompiler::Stmt& s) {
    w_.keyword("switch");
    if (opts_.space_after_keyword) {
        w_.space();
    }
    w_.punct('(');
    expr(s.condition, Precedence::None);
    w_.punct(')');
    w_.space();
    w_.punct('{');
    w_.newline();

    for (std::size_t c = 0; c < s.case_values.size(); ++c) {
        w_.keyword("case");
        w_.space();
        w_.literal(format_hex(s.case_values[c]));
        w_.punct(':');
        w_.newline();

        if (c < s.case_bodies.size()) {
            w_.indent();
            block(s.case_bodies[c]);

            // Add break if last stmt is not return/break
            if (s.case_bodies[c].empty() ||
                (s.case_bodies[c].back().kind != decompiler::StmtKind::kReturn &&
                 s.case_bodies[c].back().kind != decompiler::StmtKind::kBreak)) {
                w_.keyword("break");
                w_.punct(';');
                w_.newline();
            }
            w_.dedent();
        }
    }

    if (!s.default_body.empty()) {
        w_.keyword("default");
        w_.punct(':');
        w_.newline();

        w_.indent();
        block(s.default_body);
        w_.dedent();
    }

    w_.punct('}');
    w_.newline();
}

void Formatter::stmt_label(const decompiler::Stmt& s) {
    w_.identifier("label_" + format_hex(s.address), TokenMeta::addr(s.address));
    w_.punct(':');
    w_.newline();
}

void Formatter::stmt_goto(const decompiler::Stmt& s) {
    w_.keyword("goto");
    w_.space();
    w_.identifier("label_" + format_hex(s.address), TokenMeta::addr(s.address));
    w_.punct(';');
    w_.newline();
}

void Formatter::stmt(const decompiler::Stmt& s) {
    switch (s.kind) {
        case decompiler::StmtKind::kNop:
            if (!s.comment.empty()) {
                w_.line_comment(s.comment);
                w_.newline();
            }
            break;
        case decompiler::StmtKind::kAssign:
            stmt_assign(s);
            break;
        case decompiler::StmtKind::kStore:
            stmt_store(s);
            break;
        case decompiler::StmtKind::kCall:
            stmt_call(s);
            break;
        case decompiler::StmtKind::kReturn:
            stmt_return(s);
            break;
        case decompiler::StmtKind::kLabel:
            stmt_label(s);
            break;
        case decompiler::StmtKind::kGoto:
            stmt_goto(s);
            break;
        case decompiler::StmtKind::kBreak:
            w_.keyword("break");
            w_.punct(';');
            w_.newline();
            break;
        case decompiler::StmtKind::kContinue:
            w_.keyword("continue");
            w_.punct(';');
            w_.newline();
            break;
        case decompiler::StmtKind::kIf:
            stmt_if(s);
            break;
        case decompiler::StmtKind::kWhile:
            stmt_while(s);
            break;
        case decompiler::StmtKind::kDoWhile:
            stmt_do_while(s);
            break;
        case decompiler::StmtKind::kFor:
            stmt_for(s);
            break;
        case decompiler::StmtKind::kSwitch:
            stmt_switch(s);
            break;
    }
}

void Formatter::block(std::span<const decompiler::Stmt> stmts) {
    for (const auto& s : stmts) {
        stmt(s);
    }
}

// =============================================================================
// Declarations
// =============================================================================

void Formatter::func_signature(std::string_view name,
                               std::string_view ret_type,
                               std::span<const decompiler::VarDecl> params) {
    w_.type(ret_type.empty() ? "void" : ret_type);
    w_.space();
    w_.identifier(name);
    w_.punct('(');

    for (std::size_t i = 0; i < params.size(); ++i) {
        if (i > 0) {
            w_.punct(',');
            w_.space();
        }
        w_.type(params[i].type);
        w_.space();
        w_.identifier(params[i].name);
    }

    w_.punct(')');
}

void Formatter::local_decls(std::span<const decompiler::VarDecl> locals,
                            const std::unordered_map<std::string, std::uint64_t>& init_values) {
    for (const auto& local : locals) {
        w_.type(local.type);
        w_.space();
        w_.identifier(local.name);

        auto it = init_values.find(local.name);
        if (it != init_values.end()) {
            w_.space();
            w_.op("=");
            w_.space();
            w_.literal(format_hex(it->second));
        }

        w_.punct(';');
        w_.newline();
    }

    if (!locals.empty()) {
        w_.newline();
    }
}

void Formatter::function(const decompiler::Function& func) {
    // Signature
    std::string name = func.name;
    if (name.empty()) {
        name = "sub_" + format_hex(func.entry);
    }

    func_signature(name, func.return_type, func.params);
    w_.space();
    w_.punct('{');
    w_.newline();

    w_.indent();

    // Local declarations
    local_decls(func.locals, func.initial_values);

    // Body
    block(func.stmts);

    w_.dedent();
    w_.punct('}');
    w_.newline();
}

}  // namespace engine::emit::syn
