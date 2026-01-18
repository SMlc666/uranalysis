#pragma once

#include "engine/mlil.h"

namespace engine::emit::syn {

/// Operator precedence levels (higher = tighter binding).
/// Based on C operator precedence.
enum class Precedence : int {
    None = 0,
    Comma = 1,           // ,
    Assignment = 2,      // =, +=, -=, etc.
    Ternary = 3,         // ?:
    LogicalOr = 4,       // ||
    LogicalAnd = 5,      // &&
    BitwiseOr = 6,       // |
    BitwiseXor = 7,      // ^
    BitwiseAnd = 8,      // &
    Equality = 9,        // ==, !=
    Relational = 10,     // <, <=, >, >=
    Shift = 11,          // <<, >>
    Additive = 12,       // +, -
    Multiplicative = 13, // *, /, %
    Unary = 14,          // !, ~, -, ++, --, *, &
    Postfix = 15,        // [], (), ., ->, ++, --
    Primary = 16,        // literals, identifiers
};

/// Get the precedence of an MLIL operator.
inline Precedence get_precedence(mlil::MlilOp op) {
    switch (op) {
        // Multiplicative
        case mlil::MlilOp::kMul:
        case mlil::MlilOp::kDiv:
        case mlil::MlilOp::kMod:
            return Precedence::Multiplicative;

        // Additive
        case mlil::MlilOp::kAdd:
        case mlil::MlilOp::kSub:
            return Precedence::Additive;

        // Shift
        case mlil::MlilOp::kShl:
        case mlil::MlilOp::kShr:
        case mlil::MlilOp::kSar:
        case mlil::MlilOp::kRor:
            return Precedence::Shift;

        // Relational
        case mlil::MlilOp::kLt:
        case mlil::MlilOp::kLe:
        case mlil::MlilOp::kGt:
        case mlil::MlilOp::kGe:
            return Precedence::Relational;

        // Equality
        case mlil::MlilOp::kEq:
        case mlil::MlilOp::kNe:
            return Precedence::Equality;

        // Bitwise
        case mlil::MlilOp::kAnd:
            return Precedence::BitwiseAnd;
        case mlil::MlilOp::kXor:
            return Precedence::BitwiseXor;
        case mlil::MlilOp::kOr:
            return Precedence::BitwiseOr;

        // Unary
        case mlil::MlilOp::kNot:
        case mlil::MlilOp::kNeg:
            return Precedence::Unary;

        // Ternary
        case mlil::MlilOp::kSelect:
            return Precedence::Ternary;

        // Function-like (always primary, no parenthesization needed)
        case mlil::MlilOp::kAbs:
        case mlil::MlilOp::kMin:
        case mlil::MlilOp::kMax:
        case mlil::MlilOp::kBswap:
        case mlil::MlilOp::kClz:
        case mlil::MlilOp::kRbit:
        case mlil::MlilOp::kSqrt:
        case mlil::MlilOp::kCast:
            return Precedence::Primary;
    }
    return Precedence::Primary;
}

/// Check if we need parentheses around a child expression.
inline bool needs_parens(Precedence parent, Precedence child) {
    return static_cast<int>(child) < static_cast<int>(parent);
}

/// Get the C operator symbol for an MLIL operator.
inline const char* op_symbol(mlil::MlilOp op) {
    switch (op) {
        case mlil::MlilOp::kAdd: return "+";
        case mlil::MlilOp::kSub: return "-";
        case mlil::MlilOp::kMul: return "*";
        case mlil::MlilOp::kDiv: return "/";
        case mlil::MlilOp::kMod: return "%";
        case mlil::MlilOp::kAnd: return "&";
        case mlil::MlilOp::kOr:  return "|";
        case mlil::MlilOp::kXor: return "^";
        case mlil::MlilOp::kShl: return "<<";
        case mlil::MlilOp::kShr: return ">>";
        case mlil::MlilOp::kSar: return ">>";
        case mlil::MlilOp::kRor: return "ror";
        case mlil::MlilOp::kNot: return "~";
        case mlil::MlilOp::kNeg: return "-";
        case mlil::MlilOp::kEq:  return "==";
        case mlil::MlilOp::kNe:  return "!=";
        case mlil::MlilOp::kLt:  return "<";
        case mlil::MlilOp::kLe:  return "<=";
        case mlil::MlilOp::kGt:  return ">";
        case mlil::MlilOp::kGe:  return ">=";
        // Function-like ops
        case mlil::MlilOp::kAbs:   return "abs";
        case mlil::MlilOp::kMin:   return "min";
        case mlil::MlilOp::kMax:   return "max";
        case mlil::MlilOp::kBswap: return "bswap";
        case mlil::MlilOp::kClz:   return "clz";
        case mlil::MlilOp::kRbit:  return "rbit";
        case mlil::MlilOp::kSqrt:  return "sqrt";
        case mlil::MlilOp::kCast:  return "";
        case mlil::MlilOp::kSelect: return "?:";
    }
    return "?";
}

/// Check if an operator is binary (takes two operands with infix notation).
inline bool is_binary_op(mlil::MlilOp op) {
    switch (op) {
        case mlil::MlilOp::kAdd:
        case mlil::MlilOp::kSub:
        case mlil::MlilOp::kMul:
        case mlil::MlilOp::kDiv:
        case mlil::MlilOp::kMod:
        case mlil::MlilOp::kAnd:
        case mlil::MlilOp::kOr:
        case mlil::MlilOp::kXor:
        case mlil::MlilOp::kShl:
        case mlil::MlilOp::kShr:
        case mlil::MlilOp::kSar:
        case mlil::MlilOp::kEq:
        case mlil::MlilOp::kNe:
        case mlil::MlilOp::kLt:
        case mlil::MlilOp::kLe:
        case mlil::MlilOp::kGt:
        case mlil::MlilOp::kGe:
            return true;
        default:
            return false;
    }
}

/// Check if an operator is unary prefix.
inline bool is_unary_op(mlil::MlilOp op) {
    return op == mlil::MlilOp::kNot || op == mlil::MlilOp::kNeg;
}

/// Check if an operator renders as a function call.
inline bool is_funclike_op(mlil::MlilOp op) {
    switch (op) {
        case mlil::MlilOp::kAbs:
        case mlil::MlilOp::kMin:
        case mlil::MlilOp::kMax:
        case mlil::MlilOp::kBswap:
        case mlil::MlilOp::kClz:
        case mlil::MlilOp::kRbit:
        case mlil::MlilOp::kSqrt:
        case mlil::MlilOp::kRor:
            return true;
        default:
            return false;
    }
}

}  // namespace engine::emit::syn
