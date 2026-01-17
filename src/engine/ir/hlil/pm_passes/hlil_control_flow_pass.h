#pragma once

/// @file hlil_control_flow_pass.h
/// @brief 控制流简化pass，包装现有的ControlFlowSimplifier

#include "engine/hlil.h"
#include "hlil/passes/control_flow.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::hlil {

/// 控制流简化Pass
///
/// 简化控制流结构：
/// - 移除空的if/else分支
/// - 简化常量条件
/// - 移除无用的goto/label
struct HlilControlFlowSimplifyPass : public pass::PassInfoMixin<HlilControlFlowSimplifyPass> {
    static const char* name() { return "HlilControlFlowSimplifyPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        passes::ControlFlowSimplifier pass;
        bool changed = pass.run(function);
        
        if (changed) {
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::hlil
