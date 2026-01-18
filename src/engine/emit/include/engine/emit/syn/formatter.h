#pragma once

#include <span>
#include <string>
#include <string_view>

#include "engine/decompiler.h"
#include "engine/emit/lex/writer.h"
#include "engine/emit/syn/precedence.h"

namespace engine::emit::syn {

/// Formatting options.
struct FormatOptions {
    int indent_width = 4;
    bool compact_else = true;      // } else { on same line
    bool space_after_keyword = true;
    bool space_around_binary_op = true;
};

/// Syntax-aware formatter that emits C-like code.
class Formatter {
public:
    explicit Formatter(lex::Writer& writer, FormatOptions opts = {});

    // === Expressions ===
    
    /// Format an expression with automatic precedence-based parenthesization.
    void expr(const mlil::MlilExpr& e, Precedence parent_prec = Precedence::None);

    // === Statements ===
    
    /// Format a single statement.
    void stmt(const decompiler::Stmt& s);

    /// Format a block of statements.
    void block(std::span<const decompiler::Stmt> stmts);

    // === Declarations ===
    
    /// Format a function signature (without body).
    void func_signature(std::string_view name,
                        std::string_view ret_type,
                        std::span<const decompiler::VarDecl> params);

    /// Format local variable declarations.
    void local_decls(std::span<const decompiler::VarDecl> locals,
                     const std::unordered_map<std::string, std::uint64_t>& init_values = {});

    // === Complete function ===
    
    /// Format a complete decompiler function.
    void function(const decompiler::Function& func);

private:
    void emit_var(const mlil::VarRef& var);
    void emit_literal(std::uint64_t value);
    void emit_binary_op(const mlil::MlilExpr& e, Precedence parent_prec);
    void emit_unary_op(const mlil::MlilExpr& e);
    void emit_funclike_op(const mlil::MlilExpr& e);
    void emit_ternary(const mlil::MlilExpr& e, Precedence parent_prec);
    void emit_load(const mlil::MlilExpr& e);
    void emit_call_expr(const mlil::MlilExpr& e);

    void stmt_assign(const decompiler::Stmt& s);
    void stmt_store(const decompiler::Stmt& s);
    void stmt_call(const decompiler::Stmt& s);
    void stmt_return(const decompiler::Stmt& s);
    void stmt_if(const decompiler::Stmt& s);
    void stmt_while(const decompiler::Stmt& s);
    void stmt_do_while(const decompiler::Stmt& s);
    void stmt_for(const decompiler::Stmt& s);
    void stmt_switch(const decompiler::Stmt& s);
    void stmt_label(const decompiler::Stmt& s);
    void stmt_goto(const decompiler::Stmt& s);

    lex::Writer& w_;
    FormatOptions opts_;
};

}  // namespace engine::emit::syn
