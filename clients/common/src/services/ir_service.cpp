#include "client/services/ir_service.h"

#include <unordered_map>
#include <unordered_set>

#include "engine/decompiler/passes/abi_params.h"
#include "engine/hlil_lift.h"
#include "engine/mlil_lift.h"

namespace client::services {

IrService::IrService(engine::Session& session) : session_(session) {
    default_resolver_ = create_default_resolver();
}

NameResolver IrService::create_default_resolver() {
    return [this](std::uint64_t addr) -> std::string {
        const auto* dwarf_fn = session_.dwarf_catalog().find_function_by_address(addr);
        if (dwarf_fn) {
            if (!dwarf_fn->name.empty()) {
                return dwarf_fn->name;
            }
            if (!dwarf_fn->linkage_name.empty()) {
                return dwarf_fn->linkage_name;
            }
        }
        auto symbols = session_.symbol_table().within_range(addr, 1);
        if (!symbols.empty() && symbols.front() && symbols.front()->address == addr) {
            const auto* sym = symbols.front();
            if (!sym->demangled_name.empty()) {
                return sym->demangled_name;
            }
            if (!sym->name.empty()) {
                return sym->name;
            }
        }
        return "";
    };
}

void IrService::set_name_resolver(NameResolver resolver) {
    default_resolver_ = std::move(resolver);
}

void IrService::set_param_provider(ParamCountProvider provider) {
    default_param_provider_ = std::move(provider);
}

LlirResult IrService::build_llir_ssa(std::uint64_t address, std::size_t max_instructions) {
    LlirResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;

    if (machine == engine::BinaryMachine::kAarch64) {
        result.success =
            session_.build_llir_ssa_arm64(address, max_instructions, result.function, result.error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        result.success =
            session_.build_llir_ssa_x86_64(address, max_instructions, result.function, result.error);
    } else {
        result.error = "unsupported architecture for llir";
    }

    return result;
}

MlilResult IrService::build_mlil_ssa(std::uint64_t address, std::size_t max_instructions) {
    MlilResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;

    if (machine == engine::BinaryMachine::kAarch64) {
        result.success =
            session_.build_mlil_ssa_arm64(address, max_instructions, result.function, result.error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        // Build LLIR first, then lift to MLIL
        engine::llir::Function llir_function;
        if (!session_.build_llir_ssa_x86_64(address, max_instructions, llir_function, result.error)) {
            return result;
        }
        result.success =
            engine::mlil::build_mlil_from_llil_ssa(llir_function, result.function, result.error);
    } else {
        result.error = "unsupported architecture for mlil";
    }

    return result;
}

HlilResult IrService::build_hlil(std::uint64_t address,
                                  std::size_t max_instructions,
                                  bool optimize) {
    HlilResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;

    if (machine == engine::BinaryMachine::kAarch64) {
        if (optimize) {
            result.success =
                session_.build_hlil_arm64(address, max_instructions, result.function, result.error);
        } else {
            // Build without optimizations
            engine::mlil::Function mlil_function;
            if (!session_.build_mlil_ssa_arm64(address, max_instructions, mlil_function, result.error)) {
                return result;
            }
            result.success =
                engine::hlil::build_hlil_from_mlil(mlil_function, result.function, result.error);
        }
    } else {
        result.error = "hlil error: only arm64 is supported for now";
    }

    return result;
}

int IrService::analyze_param_count(std::uint64_t addr, std::size_t max_instructions) {
    engine::mlil::Function callee_mlil;
    std::string error;
    if (!session_.build_mlil_ssa_arm64(addr, max_instructions, callee_mlil, error)) {
        return -1;  // Failed to analyze
    }
    auto params = engine::decompiler::passes::collect_abi_params(callee_mlil);
    if (params.empty()) {
        return 0;
    }
    // Find the highest parameter index + 1
    int max_index = -1;
    for (const auto& p : params) {
        if (p.index > max_index) {
            max_index = p.index;
        }
    }
    return max_index + 1;
}

namespace {

// Collect all direct call targets from MLIL function
void collect_call_targets_stmt(const engine::mlil::MlilStmt& stmt,
                               std::unordered_set<std::uint64_t>& targets) {
    if (stmt.kind == engine::mlil::MlilStmtKind::kCall) {
        if (stmt.target.kind == engine::mlil::MlilExprKind::kImm) {
            targets.insert(stmt.target.imm);
        }
    }
}

std::unordered_set<std::uint64_t> collect_call_targets(const engine::mlil::Function& function) {
    std::unordered_set<std::uint64_t> targets;
    for (const auto& block : function.blocks) {
        for (const auto& inst : block.instructions) {
            for (const auto& stmt : inst.stmts) {
                collect_call_targets_stmt(stmt, targets);
            }
        }
    }
    return targets;
}

}  // namespace

PseudocResult IrService::build_pseudoc(std::uint64_t address,
                                        std::size_t max_instructions,
                                        NameResolver resolver,
                                        ParamCountProvider param_provider) {
    PseudocResult result;

    if (!session_.loaded()) {
        result.error = "no file loaded";
        return result;
    }

    const auto machine = session_.binary_info().machine;
    if (machine != engine::BinaryMachine::kAarch64) {
        result.error = "pseudoc error: only arm64 is supported for now";
        return result;
    }

    // Build MLIL SSA
    engine::mlil::Function mlil_function;
    if (!session_.build_mlil_ssa_arm64(address, max_instructions, mlil_function, result.error)) {
        result.error = "pseudoc error: " + (result.error.empty() ? "build failed" : result.error);
        return result;
    }

    // Interprocedural analysis: collect all call targets and analyze their parameter counts
    auto call_targets = collect_call_targets(mlil_function);
    std::unordered_map<std::uint64_t, int> param_count_cache;

    // Don't analyze the current function itself
    call_targets.erase(address);

    // Analyze each call target (with a reasonable limit)
    const std::size_t kMaxTargetsToAnalyze = 32;
    std::size_t analyzed = 0;
    for (std::uint64_t target : call_targets) {
        if (analyzed >= kMaxTargetsToAnalyze) {
            break;
        }
        int count = analyze_param_count(target, max_instructions);
        if (count >= 0) {
            param_count_cache[target] = count;
            ++analyzed;
        }
    }

    // Prepare hints
    engine::decompiler::FunctionHints hints;

    // Get function name from DWARF or symbols
    const auto* dwarf_fn = session_.dwarf_catalog().find_function_by_address(address);
    if (dwarf_fn) {
        if (!dwarf_fn->name.empty()) {
            hints.name = dwarf_fn->name;
        } else if (!dwarf_fn->linkage_name.empty()) {
            hints.name = dwarf_fn->linkage_name;
        }
    }
    if (hints.name.empty()) {
        auto symbols = session_.symbol_table().within_range(address, 1);
        if (!symbols.empty() && symbols.front()) {
            const auto* sym = symbols.front();
            if (!sym->demangled_name.empty()) {
                hints.name = sym->demangled_name;
            } else if (!sym->name.empty()) {
                hints.name = sym->name;
            }
        }
    }

    // Setup parameter count provider
    hints.param_count_provider = [&param_count_cache, &param_provider](std::uint64_t target_addr) -> int {
        // Try user-provided provider first
        if (param_provider) {
            int count = param_provider(target_addr);
            if (count >= 0) {
                return count;
            }
        }
        // Try cache
        auto it = param_count_cache.find(target_addr);
        if (it != param_count_cache.end()) {
            return it->second;
        }
        return -1;  // Unknown
    };

    // Use resolver
    NameResolver effective_resolver = resolver ? resolver : default_resolver_;

    // Build pseudo-C
    if (!engine::decompiler::build_pseudoc_from_mlil_ssa(
            mlil_function, result.function, result.error, &hints, effective_resolver)) {
        result.error = "pseudoc error: " + (result.error.empty() ? "build failed" : result.error);
        return result;
    }

    // Emit lines
    engine::decompiler::emit_pseudoc(result.function, result.lines);
    result.success = true;

    return result;
}

}  // namespace client::services