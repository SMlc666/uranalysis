#pragma once

/// @file hlil_expr_propagation_pass.h
/// @brief 表达式传播pass，包装现有的ExpressionPropagator

#include "engine/hlil.h"
#include "hlil/passes/expression_propagator.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::hlil {

/// 表达式传播Pass
///
/// 将简单赋值的右侧表达式传播到使用点，
/// 实现复制传播和常量传播的效果
struct HlilExprPropagationPass : public pass::PassInfoMixin<HlilExprPropagationPass> {
    static const char* name() { return "HlilExprPropagationPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        passes::ExpressionPropagator pass;
        bool changed = pass.run(function);
        
        if (changed) {
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::hlil
