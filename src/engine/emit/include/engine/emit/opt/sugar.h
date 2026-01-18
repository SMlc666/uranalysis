#pragma once

#include <optional>
#include <string>

#include "engine/mlil.h"

namespace engine::emit::opt {

/// Represents a detected array access pattern.
struct ArrayAccess {
    mlil::MlilExpr base;     // Base pointer
    mlil::MlilExpr index;    // Index expression
    std::int64_t offset = 0; // Constant offset (base[index + offset])
    std::size_t scale = 1;   // Element scale factor
};

/// Try to match a load expression as an array access.
/// Patterns recognized:
///   - *(base + index)
///   - *(base + index * scale)
///   - *(base + index * scale + offset)
std::optional<ArrayAccess> match_array_access(const mlil::MlilExpr& load);

/// Represents a detected compound assignment pattern.
struct CompoundAssign {
    enum class Kind { AddAssign, SubAssign, Increment, Decrement };
    Kind kind;
    std::string var_name;
    mlil::MlilExpr operand;  // For +=, -=
};

/// Try to match an assignment as a compound assignment.
/// Patterns recognized:
///   - x = x + 1  -> x++
///   - x = x - 1  -> x--
///   - x = x + y  -> x += y
///   - x = x - y  -> x -= y
std::optional<CompoundAssign> match_compound_assign(const mlil::VarRef& var,
                                                     const mlil::MlilExpr& expr);

/// Simplify a condition expression for display.
/// Transforms:
///   - (x == 0) -> !x
///   - (x != 0) -> x
///   - ((a && b) && c) -> (a && b && c) (flattening)
mlil::MlilExpr simplify_condition(const mlil::MlilExpr& cond);

/// Check if an expression is a zero immediate.
bool is_zero(const mlil::MlilExpr& e);

/// Get the immediate value from an expression if it is one.
bool get_imm_value(const mlil::MlilExpr& e, std::uint64_t& out);

}  // namespace engine::emit::opt
