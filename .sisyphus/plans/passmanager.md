# Implementation Plan: LLVM-style PassManager for uranayzle

This document outlines the plan for implementing a comprehensive, unified PassManager framework for the uranayzle binary analysis engine, inspired by the LLVM New Pass Manager architecture.

## 1. Project Context & Goals

uranayzle uses a 3-tier IR system:
1.  **LLIR (Low-Level IR):** Assembly-like, registers, flags, memory.
2.  **MLIL (Medium-Level IR):** SSA variables, expression trees, side-effect free where possible.
3.  **HLIL (High-Level IR):** Structured control flow (if/while/for), high-level AST.
4.  **Decompiler IR:** C-like pseudocode representation.

**Current State:**
- Passes are implemented as ad-hoc functions or simple classes (`HlilPass`).
- Invalidation of analysis results (like SSA def-use) is manual and error-prone.
- No unified way to log, time, or snapshot IR between passes.

**Goals:**
- **Unification:** Single framework for all IR layers.
- **Lazy Analysis:** Compute analyses only when needed and cache them.
- **Automatic Invalidation:** Track dependencies and invalidate analyses when IR changes.
- **Extensibility:** Easy to add new passes and analyses.
- **Observability:** Built-in support for pass logging, IR diffing, and timing.

---

## 2. Core Architecture

The architecture consists of several template classes parameterized by the `IRUnit` (e.g., `llir::Function`, `mlil::Function`, `hlil::Function`, `decompiler::Function`).

### 2.1 PreservedAnalyses
Tracks which analyses remain valid after a pass execution.

```cpp
class PreservedAnalyses {
public:
    static PreservedAnalyses all();
    static PreservedAnalyses none();
    
    template <typename AnalysisT>
    void preserve();
    
    template <typename AnalysisT>
    bool preserved() const;
    
    bool preserved_all() const;
};
```

### 2.2 AnalysisManager<IRUnit>
Lazy computation and caching of analysis results.

```cpp
template <typename IRUnit>
class AnalysisManager {
public:
    template <typename AnalysisT>
    typename AnalysisT::Result& getResult(IRUnit& unit);
    
    template <typename AnalysisT>
    void invalidate(IRUnit& unit, const PreservedAnalyses& PA);
    
    // Internal cache storage and lookup
};
```

### 2.3 PassManager<IRUnit>
Runs a pipeline of passes, handling invalidation between them.

```cpp
template <typename IRUnit>
class PassManager {
public:
    void addPass(std::unique_ptr<PassConcept<IRUnit>> pass);
    PreservedAnalyses run(IRUnit& unit, AnalysisManager<IRUnit>& AM);
};
```

### 2.4 PassResult
A wrapper for `PreservedAnalyses` and potential error information.

```cpp
struct PassResult {
    PreservedAnalyses preserved;
    std::string error; // Empty if success
    bool success() const { return error.empty(); }
};
```

---

## 3. File Structure

All core framework files will reside in `src/engine/pass/`.

```
src/engine/pass/
├── pass_concept.h          # Internal type erasure for passes
├── analysis_concept.h      # Internal type erasure for analyses
├── pass.h                  # Base CRTP class for Passes
├── analysis.h              # Base CRTP class for Analyses
├── analysis_manager.h      # Core AnalysisManager implementation
├── pass_manager.h          # Core PassManager implementation
├── preserved_analyses.h    # Validity tracking
├── invalidator.h           # Dependency invalidation logic
├── pass_builder.h          # Pipeline construction
└── analysis_manager_proxy.h # Cross-layer analysis access
```

Per-layer passes and analyses:
- `src/engine/ir/llir/analysis/`
- `src/engine/ir/llir/passes/`
- `src/engine/ir/mlil/analysis/`
- `src/engine/ir/mlil/passes/`
- `src/engine/ir/hlil/analysis/`
- `src/engine/ir/hlil/passes/`
- `src/engine/decompiler/analysis/`
- `src/engine/decompiler/passes/`

---

## 4. Implementation Phases

### Phase 1: Core Framework (3-4 Days)
1.  Implement `PreservedAnalyses` and `PassResult`.
2.  Implement `AnalysisManager` with basic caching.
3.  Implement `PassManager` with pass execution loop.
4.  Implement `Invalidator` for basic transitive invalidation.
5.  Add `PassBuilder` for registry and basic pipeline building.

### Phase 2: LLIR Migration (2-3 Days)
1.  **Analyses:**
    - `LlirDefUseAnalysis` (wrapping `build_ssa_def_use`)
2.  **Passes:**
    - `LlirConstantFoldPass`
    - `LlirCopyPropPass`
    - `LlirDcePass`
    - `StackVarsPass`
    - `JumpTablePass`
3.  **Orchestration:** Replace `optimize_llil_ssa` with `LlirPassManager`.

### Phase 3: MLIR Migration (2 Days)
1.  **Analyses:**
    - `MlilDefUseAnalysis`
2.  **Passes:**
    - `MlilConstantFoldPass`
    - `MlilCopyPropPass`
    - `MlilDcePass`
3.  **Orchestration:** Replace `optimize_mlil_ssa` with `MlilPassManager`.

### Phase 4: HLIR Migration (2 Days)
1.  **Analyses:**
    - `HlilCfgAnalysis`
2.  **Passes:**
    - Convert `HlilPass` subclasses to new `Pass` base.
    - `ControlFlowSimplifier`
    - `ExpressionPropagator`
    - `DeadCodeEliminator`
    - `LoopReconstructor`
3.  **Orchestration:** Replace `optimize_hlil` with `HlilPassManager`.

### Phase 5: Decompiler Migration (3 Days)
1.  Migrate all 15+ decompiler transforms and passes.
2.  Implement `DecompilerPassManager`.
3.  Replace the monolithic `build_pseudoc_from_hlil` and `build_pseudoc_from_mlil_ssa_internal` sequences with PassManager runs.

### Phase 6: Integration & Advanced Features (2 Days)
1.  **PassBuilder Extensions:** Register all passes/analyses.
2.  **Debug Support:**
    - `PassInstrumentation`: Log before/after each pass.
    - `Timer`: Measure pass execution time.
    - `Snapshot`: Print IR to log or file before/after passes.
3.  **AM Proxies:** Allow `HlilAnalysis` to query `MlilAnalysis`.

---

## 5. Design Patterns & Examples

### 5.1 Defining a Pass
```cpp
struct LlirCopyPropPass : public PassInfoMixin<LlirCopyPropPass> {
    PassResult run(llir::Function& F, LlirAnalysisManager& AM) {
        auto& DU = AM.getResult<LlirDefUseAnalysis>(F);
        bool changed = propagate_copies(F, DU);
        
        if (changed) {
            auto PA = PreservedAnalyses::none();
            // We know we didn't break CFG
            PA.preserve<LlirCfgAnalysis>(); 
            return {PA};
        }
        return {PreservedAnalyses::all()};
    }
};
```

### 5.2 Defining an Analysis
```cpp
struct LlirDefUseAnalysis : public AnalysisInfoMixin<LlirDefUseAnalysis> {
    using Result = LlilSsaDefUse;
    
    Result run(llir::Function& F, LlirAnalysisManager& AM) {
        Result result;
        std::string error;
        build_ssa_def_use(F, result, error);
        return result;
    }
};
```

### 5.3 Using the PassBuilder
```cpp
PassBuilder PB;
LlirPassManager LPM;
LPM.addPass(LlirCopyPropPass());
LPM.addPass(LlirConstantFoldPass());
 
PB.registerLlirAnalyses(LAM);
LPM.run(func, LAM);
```

---

## 6. Debug & Observability

`PassManagerOptions` will control the level of detail:

- `bool log_passes`: Use `spdlog` to print `Running pass: <Name>`.
- `bool time_passes`: Print execution time for each pass.
- `bool print_ir_diff`: If a pass returns `PreservedAnalyses::none()`, print IR diff.
- `std::string dump_ir_to`: Directory to save IR snapshots (e.g., `func_01_copyprop.llir`).

---

## 7. Testing Strategy

1.  **Framework Tests:** Unit tests for `AnalysisManager` caching and invalidation logic.
2.  **Regression Tests:** Run existing binary analysis samples through the new PassManager and verify the output IR/Pseudocode matches the legacy implementation.
3.  **Invalidation Tests:** Verify that modifying IR correctly triggers re-computation of dependent analyses.

---

## 8. Task Breakdown for Phase 1 (First Implementation Sprint)

- [ ] Create `src/engine/pass/` directory.
- [ ] Implement `PreservedAnalyses`.
- [ ] Implement `AnalysisManager` and its type-erased internal cache.
- [ ] Implement `PassManager` with execution loop.
- [ ] Implement `PassInfoMixin` and `AnalysisInfoMixin` helper templates.
- [ ] Implement `Invalidator`.
- [ ] Create initial `PassBuilder` with registration for core engine analyses.

---

## 9. Invalidator Implementation

The Invalidator handles transitive dependency invalidation with memoization to avoid redundant checks:

```cpp
template <typename IRUnit>
class Invalidator {
public:
    Invalidator(AnalysisManager<IRUnit>& AM, const PreservedAnalyses& PA)
        : AM_(AM), PA_(PA) {}
    
    // Check if analysis is invalidated (with memoization)
    template <typename AnalysisT>
    bool invalidate(IRUnit& IR) {
        auto* Key = AnalysisT::ID();
        
        // Check memoization cache
        auto It = IsInvalidated_.find(Key);
        if (It != IsInvalidated_.end())
            return It->second;
        
        // Query the analysis result's invalidate() method
        auto* Result = AM_.template getCachedResult<AnalysisT>(IR);
        bool Invalidated = true;
        
        if (Result) {
            // Let the analysis decide based on PreservedAnalyses
            Invalidated = Result->invalidate(IR, PA_, *this);
        }
        
        IsInvalidated_[Key] = Invalidated;
        return Invalidated;
    }

private:
    AnalysisManager<IRUnit>& AM_;
    const PreservedAnalyses& PA_;
    std::unordered_map<void*, bool> IsInvalidated_;
};
```

### Analysis Result with Dependencies

```cpp
struct LlirDefUseAnalysis {
    struct Result {
        LlilSsaDefUse def_use;
        
        bool invalidate(llir::Function& F, 
                       const PreservedAnalyses& PA,
                       Invalidator<llir::Function>& Inv) {
            // If explicitly preserved, not invalidated
            if (PA.preserved<LlirDefUseAnalysis>())
                return false;
            
            // If all SSA analyses preserved, not invalidated
            if (PA.preservedSet<SSAAnalyses>())
                return false;
            
            // Check transitive dependencies
            // (DefUse depends on CFG being valid)
            if (Inv.invalidate<LlirCfgAnalysis>(F))
                return true;
                
            return true; // Default: invalidate
        }
    };
};
```

---

## 10. Cross-Layer Analysis Proxy

Enable HLIL passes to access cached MLIL analyses:

```cpp
template <typename OuterAM, typename IRUnit>
class OuterAnalysisManagerProxy {
public:
    struct Result {
        OuterAM* OuterAM_;
        
        template <typename AnalysisT>
        typename AnalysisT::Result* getCachedResult(auto& OuterIR) {
            // Read-only access to cached results only
            return OuterAM_->template getCachedResult<AnalysisT>(OuterIR);
        }
        
        // Cannot trigger new computation from inner layer
        // This prevents circular dependencies
    };
    
    static void* ID() { static char ID; return &ID; }
    
    Result run(IRUnit& IR, AnalysisManager<IRUnit>& AM, OuterAM& Outer) {
        return Result{&Outer};
    }
};

// Usage in PassBuilder
void PassBuilder::crossRegisterProxies(
    AnalysisManager<llir::Function>& LAM,
    AnalysisManager<mlil::Function>& MAM,
    AnalysisManager<hlil::Function>& HAM) {
    
    // MLIL can access LLIR analyses
    MAM.registerPass<OuterAnalysisManagerProxy<
        AnalysisManager<llir::Function>, mlil::Function>>();
    
    // HLIL can access MLIL analyses
    HAM.registerPass<OuterAnalysisManagerProxy<
        AnalysisManager<mlil::Function>, hlil::Function>>();
}
```

---

## 11. PassInstrumentation (Debug Support)

```cpp
class PassInstrumentation {
public:
    virtual ~PassInstrumentation() = default;
    
    virtual void runBeforePass(const char* PassName, void* IR) {
        if (Options_.log_passes) {
            SPDLOG_INFO("Running pass: {}", PassName);
        }
        if (Options_.time_passes) {
            timer_.start();
        }
    }
    
    virtual void runAfterPass(const char* PassName, void* IR, 
                              const PreservedAnalyses& PA) {
        if (Options_.time_passes) {
            auto elapsed = timer_.stop();
            SPDLOG_INFO("  {} took {:.3f}ms", PassName, elapsed);
        }
        if (Options_.print_changed && !PA.preserved_all()) {
            SPDLOG_DEBUG("  {} modified IR", PassName);
        }
    }
    
    virtual void runAfterPassInvalidated(const char* PassName) {
        if (Options_.log_passes) {
            SPDLOG_WARN("Pass {} reported failure", PassName);
        }
    }
    
    void setOptions(const PassInstrumentationOptions& Opts) {
        Options_ = Opts;
    }

private:
    PassInstrumentationOptions Options_;
    Timer timer_;
};

struct PassInstrumentationOptions {
    bool log_passes = false;
    bool time_passes = false;
    bool print_changed = false;
    std::string dump_ir_dir;
};
```

---

## 12. Session Integration

Update `Session` class to use the new PassManager:

```cpp
// session.h additions
class Session {
public:
    // New unified build method
    bool build_decompiled(uint64_t entry, 
                          decompiler::Function& out,
                          std::string& error);
    
    // Access to pass builder for customization
    PassBuilder& pass_builder() { return pass_builder_; }
    
    // Set instrumentation options
    void set_pass_options(const PassInstrumentationOptions& opts);

private:
    PassBuilder pass_builder_;
    
    // Per-function analysis managers (created on demand)
    std::unique_ptr<AnalysisManager<llir::Function>> llir_am_;
    std::unique_ptr<AnalysisManager<mlil::Function>> mlil_am_;
    std::unique_ptr<AnalysisManager<hlil::Function>> hlil_am_;
};

// session.cpp
bool Session::build_decompiled(uint64_t entry,
                               decompiler::Function& out,
                               std::string& error) {
    // 1. Build LLIR
    llir::Function llir_func;
    auto llir_pm = pass_builder_.buildLlirPipeline();
    auto llir_result = llir_pm.run(llir_func, *llir_am_);
    if (!llir_result.success()) {
        error = llir_result.error;
        return false;
    }
    
    // 2. Lift to MLIL
    mlil::Function mlil_func;
    mlil::lift_from_llir(llir_func, mlil_func);
    
    auto mlil_pm = pass_builder_.buildMlilPipeline();
    auto mlil_result = mlil_pm.run(mlil_func, *mlil_am_);
    // ... continue through HLIL and Decompiler
    
    return true;
}
```

---

## 13. Migration Checklist

### Files to Delete After Migration
- `src/engine/ir/llir/opt.cpp` (logic moved to passes/)
- `src/engine/ir/mlil/opt.cpp` (logic moved to passes/)
- `src/engine/ir/hlil/hlil_opt.cpp` (replaced by PassManager)
- `src/engine/include/engine/llir_opt.h`
- `src/engine/include/engine/mlil_opt.h`
- `src/engine/include/engine/hlil_opt.h`

### Files to Heavily Modify
- `src/engine/core/session.cpp` - use PassManager
- `src/engine/decompiler/pseudoc.cpp` - use DecompilerPassManager
- `src/engine/ir/hlil/passes/*.cpp` - inherit new Pass base

### xmake.lua Updates
- Add `src/engine/pass/src/*.cpp` to engine target
- Add include path for `src/engine/pass/include`

---

## 14. Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Large refactor breaks existing functionality | Incremental migration, regression tests after each phase |
| Performance regression from abstraction overhead | Profile before/after, optimize hot paths |
| Complex dependency cycles between analyses | Document dependencies, use Invalidator memoization |
| Merge conflicts with ongoing work | Coordinate with team, use feature branch |

---

## 15. Success Criteria

1. All existing optimization functions replaced with PassManager
2. Analysis results properly cached and invalidated
3. Debug logging shows pass execution flow
4. No regression in decompiler output quality
5. Pass timing data available for profiling
6. Clean separation between analysis and transformation
