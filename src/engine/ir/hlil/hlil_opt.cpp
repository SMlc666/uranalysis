#include "engine/hlil_opt.h"

#include "passes/control_flow.h"
#include "passes/expression_propagator.h"
#include "passes/dce.h"
#include "passes/loops.h"

#include <vector>
#include <memory>

namespace engine::hlil {

bool optimize_hlil(Function& function, const HlilOptOptions& options, std::string& error) {
    error.clear();

    std::vector<std::unique_ptr<HlilPass>> pipeline;

    // Build the optimization pipeline based on options
    if (options.simplify_control_flow) {
        pipeline.push_back(std::make_unique<passes::ControlFlowSimplifier>());
    }
    
    // We can run propagation and DCE in a loop
    if (options.propagate_expressions) {
        pipeline.push_back(std::make_unique<passes::ExpressionPropagator>());
    }
    
    if (options.eliminate_dead_code) {
        pipeline.push_back(std::make_unique<passes::DeadCodeEliminator>());
    }

    // Run the main optimization loop
    bool changed = true;
    int iterations = 0;
    const int kMaxIterations = 10;

    while (changed && iterations < kMaxIterations) {
        changed = false;
        for (const auto& pass : pipeline) {
            if (pass->run(function)) {
                changed = true;
            }
        }
        
        // Re-run control flow simplification if things changed to clean up
        if (changed && options.simplify_control_flow) {
            passes::ControlFlowSimplifier cfs;
            cfs.run(function);
        }
        
        iterations++;
    }

    // Post-optimization structural passes
    if (options.simplify_control_flow) {
        // One final cleanup
        passes::ControlFlowSimplifier cfs;
        cfs.run(function);
    }

    // Loop reconstruction comes last as it depends on clean structure
    passes::LoopReconstructor loop_rec;
    loop_rec.run(function);

    return true;
}

}  // namespace engine::hlil
