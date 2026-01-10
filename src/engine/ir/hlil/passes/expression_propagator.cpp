#include "expression_propagator.h"
#include "engine/hlil_opt.h"

#include <algorithm>

namespace engine::hlil::passes {

using Expr = mlil::MlilExpr;
using VarRef = mlil::VarRef;

namespace {

bool has_any_ssa_versions(const std::vector<HlilStmt> &stmts) {
  for (const auto &stmt : stmts) {
    if (stmt.var.version >= 0) {
      return true;
    }
    for (const auto &ret : stmt.returns) {
      if (ret.version >= 0) {
        return true;
      }
    }
    auto check_expr = [&](const Expr &expr, const auto &self) -> bool {
      if (expr.kind == mlil::MlilExprKind::kVar && expr.var.version >= 0) {
        return true;
      }
      for (const auto &arg : expr.args) {
        if (self(arg, self)) {
          return true;
        }
      }
      return false;
    };
    if (check_expr(stmt.expr, check_expr) ||
        check_expr(stmt.target, check_expr) ||
        check_expr(stmt.condition, check_expr)) {
      return true;
    }
    for (const auto &arg : stmt.args) {
      if (check_expr(arg, check_expr)) {
        return true;
      }
    }
    if (has_any_ssa_versions(stmt.then_body) ||
        has_any_ssa_versions(stmt.else_body) ||
        has_any_ssa_versions(stmt.body)) {
      return true;
    }
  }
  return false;
}

} // namespace

bool ExpressionPropagator::run(Function &function) {
  global_counts_.clear();
  def_counts_.clear();
  has_ssa_ = has_any_ssa_versions(function.stmts);
  if (!has_ssa_) {
    assign_versions(function);
    has_ssa_ = true;
  }
  count_usages(function.stmts);
  count_definitions(function.stmts);

  modified_in_scope_.clear();
  collect_modified_vars(function.stmts, modified_in_scope_);

  bool modified = false;
  available_exprs_.clear();
  propagate_block(function.stmts, modified);
  return modified;
}

std::string ExpressionPropagator::make_key(const VarRef &var) const {
  if (var.name.empty()) {
    return "";
  }
  if (has_ssa_ && var.version >= 0) {
    return var.name + "#" + std::to_string(var.version);
  }
  return var.name;
}

bool ExpressionPropagator::key_matches_name(const std::string &key,
                                            const std::string &name) const {
  if (key == name) {
    return true;
  }
  if (key.size() <= name.size()) {
    return false;
  }
  if (key.compare(0, name.size(), name) != 0) {
    return false;
  }
  return key[name.size()] == '#';
}

void ExpressionPropagator::count_usages(const std::vector<HlilStmt> &stmts) {
  for (const auto &stmt : stmts) {
    auto visit_expr = [&](const Expr &e) {
      auto recursive = [&](const Expr &sub, auto &self) -> void {
        if (sub.kind == mlil::MlilExprKind::kVar) {
          const std::string key = make_key(sub.var);
          if (!key.empty()) {
            global_counts_[key]++;
          }
        }
        for (const auto &arg : sub.args)
          self(arg, self);
      };
      recursive(e, recursive);
    };

    switch (stmt.kind) {
    case HlilStmtKind::kAssign:
      visit_expr(stmt.expr);
      break;
    case HlilStmtKind::kStore:
      visit_expr(stmt.target);
      visit_expr(stmt.expr);
      break;
    case HlilStmtKind::kCall:
      visit_expr(stmt.target);
      for (const auto &a : stmt.args)
        visit_expr(a);
      break;
    case HlilStmtKind::kRet:
      visit_expr(stmt.expr);
      break;
    case HlilStmtKind::kIf:
      visit_expr(stmt.condition);
      count_usages(stmt.then_body);
      count_usages(stmt.else_body);
      break;
    case HlilStmtKind::kWhile:
    case HlilStmtKind::kFor:
      visit_expr(stmt.condition);
      count_usages(stmt.body);
      count_usages(stmt.then_body); // For loop init
      count_usages(stmt.else_body); // For loop step
      break;
    default:
      break;
    }
  }
}

void ExpressionPropagator::count_definitions(
    const std::vector<HlilStmt> &stmts) {
  for (const auto &stmt : stmts) {
    if (stmt.kind == HlilStmtKind::kAssign) {
      if (!stmt.var.name.empty()) {
        def_counts_[stmt.var.name]++;
      }
    } else if (stmt.kind == HlilStmtKind::kCall) {
      for (const auto &ret : stmt.returns) {
        if (!ret.name.empty()) {
          def_counts_[ret.name]++;
        }
      }
    } else if (stmt.kind == HlilStmtKind::kIf) {
      count_definitions(stmt.then_body);
      count_definitions(stmt.else_body);
    } else if (stmt.kind == HlilStmtKind::kWhile ||
               stmt.kind == HlilStmtKind::kFor ||
               stmt.kind == HlilStmtKind::kDoWhile) {
      count_definitions(stmt.body);
      count_definitions(stmt.then_body);
      count_definitions(stmt.else_body);
    }
  }
}

void ExpressionPropagator::collect_modified_vars(
    const std::vector<HlilStmt> &stmts, std::unordered_set<std::string> &out) {
  for (const auto &stmt : stmts) {
    if (stmt.kind == HlilStmtKind::kAssign) {
      out.insert(stmt.var.name);
    } else if (stmt.kind == HlilStmtKind::kIf) {
      collect_modified_vars(stmt.then_body, out);
      collect_modified_vars(stmt.else_body, out);
    } else if (stmt.kind == HlilStmtKind::kWhile ||
               stmt.kind == HlilStmtKind::kFor) {
      collect_modified_vars(stmt.body, out);
      collect_modified_vars(stmt.then_body, out);
      collect_modified_vars(stmt.else_body, out);
    }
  }
}

bool ExpressionPropagator::is_simple_expr(const Expr &expr) {
  // Fast depth check to prevent deep recursion
  if (get_expr_depth(expr) > 20) {
    return false;
  }

  if (!is_well_formed_expr(expr)) {
    return false;
  }

  if (expr.kind == mlil::MlilExprKind::kImm ||
      expr.kind == mlil::MlilExprKind::kVar) {
    return true;
  }
  if (expr.kind == mlil::MlilExprKind::kOp) {
    if (expr.args.empty()) {
      return false;
    }

    for (const auto &arg : expr.args) {
      if (!is_simple_expr(arg))
        return false;
    }
    return true;
  }
  return false;
}

bool ExpressionPropagator::is_well_formed_expr(const Expr &expr) {
  auto is_unary = [](mlil::MlilOp op) {
    return op == mlil::MlilOp::kNot || op == mlil::MlilOp::kNeg;
  };
  auto is_binary = [](mlil::MlilOp op) {
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
  };

  switch (expr.kind) {
  case mlil::MlilExprKind::kInvalid:
  case mlil::MlilExprKind::kUnknown:
  case mlil::MlilExprKind::kUndef:
    return false;
  case mlil::MlilExprKind::kImm:
  case mlil::MlilExprKind::kVar:
    return true;
  case mlil::MlilExprKind::kLoad:
    if (expr.args.size() != 1) {
      return false;
    }
    return is_well_formed_expr(expr.args[0]);
  case mlil::MlilExprKind::kOp:
    if (is_unary(expr.op)) {
      if (expr.args.size() != 1) {
        return false;
      }
    } else if (is_binary(expr.op)) {
      if (expr.args.size() != 2) {
        return false;
      }
    } else if (expr.args.empty()) {
      return false;
    }
    for (const auto &arg : expr.args) {
      if (!is_well_formed_expr(arg)) {
        return false;
      }
    }
    return true;
  }
  return false;
}

int ExpressionPropagator::get_expr_depth(const Expr &expr) {
  if (expr.args.empty()) {
    return 1;
  }
  int max_depth = 0;
  for (const auto &arg : expr.args) {
    int d = get_expr_depth(arg);
    if (d > max_depth)
      max_depth = d;
    // Early exit if too deep to matter (optimization)
    if (max_depth > 100)
      return max_depth + 1;
  }
  return max_depth + 1;
}

bool ExpressionPropagator::uses_var(const Expr &expr, const VarRef &var) {
  if (expr.kind == mlil::MlilExprKind::kVar) {
    return expr.var.name == var.name;
  }
  for (const auto &arg : expr.args) {
    if (uses_var(arg, var))
      return true;
  }
  return false;
}

void ExpressionPropagator::propagate_block(std::vector<HlilStmt> &stmts,
                                           bool &modified) {
  for (auto &stmt : stmts) {
    process_stmt(stmt, modified);
  }
}

bool ExpressionPropagator::uses_any_var(
    const Expr &expr, const std::unordered_set<std::string> &vars) {
  if (expr.kind == mlil::MlilExprKind::kVar) {
    return vars.find(expr.var.name) != vars.end();
  }
  for (const auto &arg : expr.args) {
    if (uses_any_var(arg, vars))
      return true;
  }
  return false;
}

void ExpressionPropagator::invalidate_modified(
    const std::unordered_set<std::string> &modified) {
  if (modified.empty())
    return;

  for (auto it = available_exprs_.begin(); it != available_exprs_.end();) {
    // If the variable holding the expression is modified, kill it.
    bool matched = false;
    for (const auto &name : modified) {
      if (key_matches_name(it->first, name)) {
        matched = true;
        break;
      }
    }
    if (matched) {
      it = available_exprs_.erase(it);
      continue;
    }
    // If the expression *uses* a modified variable, kill it.
    if (uses_any_var(it->second, modified)) {
      it = available_exprs_.erase(it);
      continue;
    }
    ++it;
  }
}

void ExpressionPropagator::process_stmt(HlilStmt &stmt, bool &modified) {
  if (stmt.kind == HlilStmtKind::kWhile ||
      stmt.kind == HlilStmtKind::kDoWhile || stmt.kind == HlilStmtKind::kFor) {
    // Loop: avoid substituting variables that are modified inside the loop into
    // the loop condition.
    std::unordered_set<std::string> loop_mod;
    collect_modified_vars(stmt.body, loop_mod);
    if (stmt.kind == HlilStmtKind::kFor) {
      collect_modified_vars(stmt.then_body, loop_mod); // init
      collect_modified_vars(stmt.else_body, loop_mod); // step
    }

    auto saved_state = available_exprs_;
    for (auto it = available_exprs_.begin(); it != available_exprs_.end();) {
      bool kill = false;
      for (const auto &name : modified_in_scope_) {
        if (key_matches_name(it->first, name)) {
          kill = true;
          break;
        }
      }
      if (!kill) {
        for (const auto &name : loop_mod) {
          if (key_matches_name(it->first, name)) {
            kill = true;
            break;
          }
        }
      }
      if (kill) {
        it = available_exprs_.erase(it);
      } else {
        ++it;
      }
    }

    // Do not substitute into loop condition; it is easy to mis-handle
    // induction variables and collapse the condition.
    fold_expr(stmt.condition);

    available_exprs_ = std::move(saved_state);

    // Now proceed with conservative loop handling.
    invalidate_modified(loop_mod);
    propagate_block(stmt.body, modified);
    if (stmt.kind == HlilStmtKind::kFor) {
      propagate_block(stmt.then_body, modified);
      propagate_block(stmt.else_body, modified);
    }
    return;
  }

  substitute_in_stmt(stmt, modified);

  if (stmt.kind == HlilStmtKind::kAssign) {
    std::string var_name = stmt.var.name;
    const std::string var_key = make_key(stmt.var);

    // Invalidate expressions that use this variable
    for (auto it = available_exprs_.begin(); it != available_exprs_.end();) {
      if (uses_var(it->second, stmt.var) ||
          key_matches_name(it->first, var_name)) {
        it = available_exprs_.erase(it);
      } else {
        ++it;
      }
    }

    bool simple = is_simple_expr(stmt.expr);
    bool single_use = false;
    if (!var_key.empty()) {
      auto it = global_counts_.find(var_key);
      single_use = it != global_counts_.end() && it->second == 1;
    }
    // With smarter invalidation, we can be more aggressive.
    // Even if modified strictly later, we can propagate now if we kill it
    // later.

    // Check depth
    bool safe_depth = get_expr_depth(stmt.expr) < 50;

    const bool single_def = (def_counts_.find(var_name) == def_counts_.end()) ||
                            def_counts_[var_name] <= 1;
    if (single_def && safe_depth && (simple || single_use) &&
        !var_key.empty() && is_well_formed_expr(stmt.expr)) {
      available_exprs_[var_key] = stmt.expr;
    }
  } else if (stmt.kind == HlilStmtKind::kIf) {
    auto pre_state = available_exprs_;

    std::unordered_set<std::string> then_mod;
    collect_modified_vars(stmt.then_body, then_mod);
    propagate_block(stmt.then_body, modified);

    // Restore state for else branch
    available_exprs_ = pre_state;

    std::unordered_set<std::string> else_mod;
    collect_modified_vars(stmt.else_body, else_mod);
    propagate_block(stmt.else_body, modified);

    // Merge states: intersection logic.
    // A variable is available after IF only if:
    // 1. It was available BEFORE (in pre_state).
    // 2. It was NOT killed in THEN.
    // 3. It was NOT killed in ELSE.
    // AND, if it was defined/updated inside branches? We ignore definitions
    // inside branches for now to keep it simple. So we revert to 'pre_state'
    // minus anything killed in either branch.

    available_exprs_ = std::move(pre_state);
    invalidate_modified(then_mod);
    invalidate_modified(else_mod);
  }
}

void ExpressionPropagator::substitute_in_stmt(HlilStmt &stmt, bool &modified) {
  auto apply = [&](Expr &e) {
    substitute_recursive(e, modified);
    fold_expr(e);
  };

  switch (stmt.kind) {
  case HlilStmtKind::kAssign:
    apply(stmt.expr);
    break;
  case HlilStmtKind::kStore:
    apply(stmt.target);
    apply(stmt.expr);
    break;
  case HlilStmtKind::kCall:
    apply(stmt.target);
    for (auto &a : stmt.args)
      apply(a);
    break;
  case HlilStmtKind::kRet:
    apply(stmt.expr);
    break;
  case HlilStmtKind::kIf:
    apply(stmt.condition);
    break;
  case HlilStmtKind::kWhile:
    apply(stmt.condition);
    break;
  case HlilStmtKind::kFor:
    apply(stmt.condition);
    break;
  default:
    break;
  }
}

void ExpressionPropagator::substitute_recursive(Expr &expr, bool &modified) {
  if (expr.kind == mlil::MlilExprKind::kVar) {
    if (def_counts_.find(expr.var.name) != def_counts_.end() &&
        def_counts_[expr.var.name] > 1) {
      return;
    }
    const std::string key = make_key(expr.var);
    if (key.empty()) {
      return;
    }
    auto it = available_exprs_.find(key);
    if (it != available_exprs_.end()) {
      if (!is_well_formed_expr(it->second)) {
        return;
      }
      std::size_t sz = expr.size;
      expr = it->second;
      if (expr.size == 0)
        expr.size = sz;
      if (has_ssa_) {
        global_counts_[it->first]--;
      }
      modified = true;
      // Stop recursion here. Do not descend into the just-substituted
      // expression. This prevents exponential tree growth in a single pass and
      // avoids stack overflow. Subsequent passes will handle any variables
      // remaining in the substituted expression.
      return;
    }
  }
  for (auto &arg : expr.args) {
    substitute_recursive(arg, modified);
  }
}

void ExpressionPropagator::fold_expr(Expr &expr) {
  for (auto &arg : expr.args)
    fold_expr(arg);
  if (expr.kind == mlil::MlilExprKind::kOp && expr.args.size() == 2) {
    if (expr.args[0].kind == mlil::MlilExprKind::kImm &&
        expr.args[1].kind == mlil::MlilExprKind::kImm) {
      std::uint64_t a = expr.args[0].imm;
      std::uint64_t b = expr.args[1].imm;
      bool folded = true;
      switch (expr.op) {
      case mlil::MlilOp::kAdd:
        expr.imm = a + b;
        break;
      case mlil::MlilOp::kSub:
        expr.imm = a - b;
        break;
      case mlil::MlilOp::kMul:
        expr.imm = a * b;
        break;
      case mlil::MlilOp::kAnd:
        expr.imm = a & b;
        break;
      case mlil::MlilOp::kOr:
        expr.imm = a | b;
        break;
      case mlil::MlilOp::kXor:
        expr.imm = a ^ b;
        break;
      case mlil::MlilOp::kShl:
        expr.imm = a << b;
        break;
      case mlil::MlilOp::kShr:
        expr.imm = a >> b;
        break;
      default:
        folded = false;
        break;
      }
      if (folded) {
        expr.kind = mlil::MlilExprKind::kImm;
        expr.args.clear();
      }
    }
  }
}

void ExpressionPropagator::assign_versions(Function &function) {
  VersionState state;
  assign_versions_block(function.stmts, state);
}

void ExpressionPropagator::assign_versions_block(std::vector<HlilStmt> &stmts,
                                                 VersionState &state) {
  for (auto &stmt : stmts) {
    assign_versions_stmt(stmt, state);
  }
}

void ExpressionPropagator::assign_versions_stmt(HlilStmt &stmt,
                                                VersionState &state) {
  switch (stmt.kind) {
  case HlilStmtKind::kAssign: {
    assign_versions_expr(stmt.expr, state);
    if (!stmt.var.name.empty()) {
      int &v = state.versions[stmt.var.name];
      v++;
      stmt.var.version = v;
    }
    break;
  }
  case HlilStmtKind::kStore:
    assign_versions_expr(stmt.target, state);
    assign_versions_expr(stmt.expr, state);
    break;
  case HlilStmtKind::kCall:
    assign_versions_expr(stmt.target, state);
    for (auto &arg : stmt.args) {
      assign_versions_expr(arg, state);
    }
    for (auto &ret : stmt.returns) {
      if (ret.name.empty()) {
        continue;
      }
      int &v = state.versions[ret.name];
      v++;
      ret.version = v;
    }
    break;
  case HlilStmtKind::kRet:
    assign_versions_expr(stmt.expr, state);
    break;
  case HlilStmtKind::kIf: {
    assign_versions_expr(stmt.condition, state);
    VersionState then_state = state;
    VersionState else_state = state;
    assign_versions_block(stmt.then_body, then_state);
    assign_versions_block(stmt.else_body, else_state);
    merge_versions(state, then_state, else_state);
    break;
  }
  case HlilStmtKind::kWhile:
  case HlilStmtKind::kDoWhile:
  case HlilStmtKind::kFor: {
    std::unordered_set<std::string> loop_mod;
    collect_modified_vars(stmt.body, loop_mod);
    if (stmt.kind == HlilStmtKind::kFor) {
      collect_modified_vars(stmt.then_body, loop_mod);
      collect_modified_vars(stmt.else_body, loop_mod);
      assign_versions_block(stmt.then_body, state);
    }
    assign_versions_expr(stmt.condition, state);
    VersionState body_state = state;
    assign_versions_block(stmt.body, body_state);
    if (stmt.kind == HlilStmtKind::kFor) {
      assign_versions_block(stmt.else_body, body_state);
    }
    for (const auto &name : loop_mod) {
      int &v = state.versions[name];
      v++;
    }
    break;
  }
  default:
    break;
  }
}

void ExpressionPropagator::assign_versions_expr(mlil::MlilExpr &expr,
                                                VersionState &state) {
  if (expr.kind == mlil::MlilExprKind::kVar) {
    if (expr.var.name.empty()) {
      return;
    }
    int &v = state.versions[expr.var.name];
    expr.var.version = v;
    return;
  }
  for (auto &arg : expr.args) {
    assign_versions_expr(arg, state);
  }
}

void ExpressionPropagator::merge_versions(VersionState &out,
                                          const VersionState &a,
                                          const VersionState &b) {
  out.versions.clear();
  out.versions.reserve(a.versions.size() + b.versions.size());
  for (const auto &[name, v] : a.versions) {
    out.versions[name] = v;
  }
  for (const auto &[name, v] : b.versions) {
    auto it = out.versions.find(name);
    if (it == out.versions.end()) {
      out.versions[name] = v;
    } else if (it->second != v) {
      it->second = std::max(it->second, v) + 1;
    }
  }
}

} // namespace engine::hlil::passes
