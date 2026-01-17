#pragma once

/// @file hlil_pm.h
/// @brief HLIL PassManager组件的聚合头文件
///
/// 使用示例:
/// @code
/// #include "hlil/hlil_pm.h"
/// 
/// using namespace engine::hlil;
///
/// HlilAnalysisManager am;
///
/// HlilPassManager pm;
/// pm.addPass(HlilControlFlowSimplifyPass{});
/// pm.addPass(HlilExprPropagationPass{});
/// pm.addPass(HlilDCEPass{});
/// pm.addPass(HlilLoopReconstructPass{});
///
/// auto result = pm.run(function, am);
/// @endcode

// 核心框架
#include "engine/pass.h"

// HLIL分析
#include "hlil/pm_analysis/hlil_cfg_analysis.h"

// HLIL优化passes
#include "hlil/pm_passes/hlil_control_flow_pass.h"
#include "hlil/pm_passes/hlil_expr_propagation_pass.h"
#include "hlil/pm_passes/hlil_dce_pass.h"
#include "hlil/pm_passes/hlil_loop_reconstruct_pass.h"

namespace engine::hlil {

// ============================================================================
// 类型别名
// ============================================================================

/// HLIL函数的分析管理器
using HlilAnalysisManager = pass::AnalysisManager<Function>;

/// HLIL函数的Pass管理器
using HlilPassManager = pass::PassManager<Function>;

/// HLIL函数的Pass构建器
using HlilPassBuilder = pass::PassBuilder<Function>;

// ============================================================================
// Pipeline构建助手
// ============================================================================

/// HLIL优化pipeline的选项
struct HlilOptPipelineOptions {
    bool simplify_control_flow = true;
    bool propagate_expressions = true;
    bool eliminate_dead_code = true;
    bool reconstruct_loops = true;
    int max_iterations = 10;
};

/// 构建标准HLIL优化pipeline
///
/// 等价于legacy的optimize_hlil()函数
///
/// @param options Pipeline配置选项
/// @return 配置好的HlilPassManager
inline HlilPassManager buildHlilOptPipeline(const HlilOptPipelineOptions& options = {}) {
    HlilPassManager pm;
    
    if (options.simplify_control_flow) {
        pm.addPass(HlilControlFlowSimplifyPass{});
    }
    if (options.propagate_expressions) {
        pm.addPass(HlilExprPropagationPass{});
    }
    if (options.eliminate_dead_code) {
        pm.addPass(HlilDCEPass{});
    }
    if (options.reconstruct_loops) {
        pm.addPass(HlilLoopReconstructPass{});
    }
    
    return pm;
}

}  // namespace engine::hlil
