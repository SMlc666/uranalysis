#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "engine/decompiler.h"
#include "engine/hlil.h"
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/session.h"

namespace client::services {

/// Base result for IR operations
struct IrResult {
    bool success = false;
    std::string error;
};

/// Result of LLIR build
struct LlirResult : IrResult {
    engine::llir::Function function;
};

/// Result of MLIL build
struct MlilResult : IrResult {
    engine::mlil::Function function;
};

/// Result of HLIL build
struct HlilResult : IrResult {
    engine::hlil::Function function;
};

/// Result of Pseudo-C build
struct PseudocResult : IrResult {
    engine::decompiler::Function function;
    std::vector<std::string> lines;
};

/// Name resolver function type
using NameResolver = std::function<std::string(std::uint64_t)>;

/// Parameter count provider function type
using ParamCountProvider = std::function<int(std::uint64_t)>;

/// Service for IR building operations
class IrService {
public:
    explicit IrService(engine::Session& session);

    /// Build LLIR SSA for a function
    LlirResult build_llir_ssa(std::uint64_t address, std::size_t max_instructions);

    /// Build MLIL SSA for a function
    MlilResult build_mlil_ssa(std::uint64_t address, std::size_t max_instructions);

    /// Build HLIL for a function
    HlilResult build_hlil(std::uint64_t address,
                          std::size_t max_instructions,
                          bool optimize = true);

    /// Build Pseudo-C for a function
    PseudocResult build_pseudoc(std::uint64_t address,
                                std::size_t max_instructions,
                                NameResolver resolver = nullptr,
                                ParamCountProvider param_provider = nullptr);

    /// Set default name resolver
    void set_name_resolver(NameResolver resolver);

    /// Set default parameter count provider
    void set_param_provider(ParamCountProvider provider);

private:
    engine::Session& session_;
    NameResolver default_resolver_;
    ParamCountProvider default_param_provider_;

    /// Create default name resolver using session
    NameResolver create_default_resolver();

    /// Analyze a callee function to determine parameter count
    int analyze_param_count(std::uint64_t addr, std::size_t max_instructions);
};

}  // namespace client::services