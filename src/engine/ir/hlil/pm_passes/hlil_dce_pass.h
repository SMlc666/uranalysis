#pragma once

/// @file hlil_dce_pass.h
/// @brief 死代码消除pass，包装现有的DeadCodeEliminator

#include "engine/hlil.h"
#include "hlil/passes/dce.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::hlil {

/// 死代码消除Pass
///
/// 移除没有被使用的变量赋值
struct HlilDCEPass : public pass::PassInfoMixin<HlilDCEPass> {
    static const char* name() { return "HlilDCEPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        passes::DeadCodeEliminator pass;
        bool changed = pass.run(function);
        
        if (changed) {
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::hlil
