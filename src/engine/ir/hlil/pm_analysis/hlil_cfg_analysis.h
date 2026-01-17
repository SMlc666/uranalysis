#pragma once

/// @file hlil_cfg_analysis.h
/// @brief CFG分析，包装现有的ControlFlowGraph类

#include "engine/hlil.h"
#include "engine/mlil.h"
#include "hlil/analysis/control_flow_graph.h"
#include "engine/pass/analysis.h"
#include "engine/pass/analysis_manager.h"

#include <memory>

namespace engine::hlil {

/// HLIL控制流图分析
///
/// 包装现有的ControlFlowGraph类，提供支配树、后支配树和循环信息
struct HlilCFGAnalysis : public pass::AnalysisInfoMixin<HlilCFGAnalysis> {
    /// 结果类型 - ControlFlowGraph需要mlil::Function来构建
    /// 所以这里我们存储一个可选的CFG
    struct Result {
        std::unique_ptr<ControlFlowGraph> cfg;
        
        bool valid() const { return cfg != nullptr; }
    };

    static const char* name() { return "HlilCFGAnalysis"; }

    /// 注意：HLIL的CFG分析需要对应的MLIL函数
    /// 这个分析在HLIL层可能不太适用，因为HLIL已经是结构化的
    /// 保留此分析主要是为了API一致性
    Result run(Function& /*function*/, pass::AnalysisManager<Function>& /*am*/) {
        // HLIL层已经是结构化的，不需要CFG分析
        // 如果需要，可以从MLIL层获取
        return Result{nullptr};
    }

    bool invalidate(Function& /*ir*/,
                    const pass::PreservedAnalyses& pa,
                    pass::Invalidator<Function>& /*inv*/,
                    Result& /*result*/) {
        return !pa.preserved(ID());
    }
};

}  // namespace engine::hlil
