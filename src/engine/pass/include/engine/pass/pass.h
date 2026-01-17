#pragma once

#include "engine/pass/analysis_manager.h"
#include "engine/pass/pass_result.h"
#include "engine/pass/preserved_analyses.h"

#include <memory>
#include <string>

namespace engine::pass {

/// Concept interface for type-erased pass storage.
/// This allows PassManager to store passes of different types.
template <typename IRUnit>
class PassConcept {
public:
    virtual ~PassConcept() = default;

    /// Get the name of this pass (for debugging/logging)
    virtual const char* name() const = 0;

    /// Run the pass on the given IR unit
    virtual PassResult run(IRUnit& ir, AnalysisManager<IRUnit>& am) = 0;

    /// Clone the pass (for pipeline copying)
    virtual std::unique_ptr<PassConcept<IRUnit>> clone() const = 0;
};

/// Concrete implementation of PassConcept for a specific pass type.
template <typename PassT, typename IRUnit>
class PassModel : public PassConcept<IRUnit> {
public:
    explicit PassModel(PassT pass) : pass_(std::move(pass)) {}

    const char* name() const override {
        return PassT::name();
    }

    PassResult run(IRUnit& ir, AnalysisManager<IRUnit>& am) override {
        return pass_.run(ir, am);
    }

    std::unique_ptr<PassConcept<IRUnit>> clone() const override {
        return std::make_unique<PassModel<PassT, IRUnit>>(pass_);
    }

private:
    PassT pass_;
};

/// CRTP mixin to provide common pass infrastructure.
/// 
/// Usage:
/// @code
/// struct MyPass : public PassInfoMixin<MyPass> {
///     static const char* name() { return "MyPass"; }
///     PassResult run(IRUnit& ir, AnalysisManager<IRUnit>& am);
/// };
/// @endcode
template <typename DerivedT>
struct PassInfoMixin {
    // The derived class must provide:
    // - static const char* name()
    // - PassResult run(IRUnit& ir, AnalysisManager<IRUnit>& am)
};

}  // namespace engine::pass
