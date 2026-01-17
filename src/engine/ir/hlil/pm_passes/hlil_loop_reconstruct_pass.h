#pragma once

/// @file hlil_loop_reconstruct_pass.h
/// @brief 循环重建pass，包装现有的LoopReconstructor

#include "engine/hlil.h"
#include "hlil/passes/loops.h"
#include "engine/pass/pass.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/analysis_manager.h"

namespace engine::hlil {

/// 循环重建Pass
///
/// 将while循环转换为for循环（如果可能）
struct HlilLoopReconstructPass : public pass::PassInfoMixin<HlilLoopReconstructPass> {
    static const char* name() { return "HlilLoopReconstructPass"; }

    pass::PassResult run(Function& function, pass::AnalysisManager<Function>& /*am*/) {
        passes::LoopReconstructor pass;
        bool changed = pass.run(function);
        
        if (changed) {
            return pass::PassResult::successNone();
        }
        
        return pass::PassResult::successAll();
    }
};

}  // namespace engine::hlil
