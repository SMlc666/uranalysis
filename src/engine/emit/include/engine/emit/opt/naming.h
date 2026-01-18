#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "engine/decompiler.h"
#include "engine/mlil.h"

namespace engine::emit::opt {

/// Naming strategy options.
struct NamingOptions {
    bool use_short_index_names = true;  // Use i, j, k for loop indices
    bool clean_ssa_suffixes = true;     // Remove _v0, _ver_1 suffixes
    bool normalize_stack_vars = true;   // stack.28 -> v28
    bool normalize_arg_slots = true;    // arg.0 -> a0
};

/// Context for variable naming during emit.
class NamingContext {
public:
    explicit NamingContext(NamingOptions opts = {});

    /// Initialize from a function's variable declarations.
    void init_from_function(const decompiler::Function& func);

    /// Resolve a variable name to its display name.
    std::string resolve(const std::string& name) const;
    std::string resolve(const mlil::VarRef& var) const;

    /// Mark a variable as being used as an index.
    void hint_index_var(const std::string& name);

    /// Mark a variable as being a pointer.
    void hint_pointer_var(const std::string& name);

    /// Get the rename map.
    const std::unordered_map<std::string, std::string>& renames() const { return renames_; }

private:
    std::string clean_ssa_suffix(const std::string& name) const;
    void assign_short_names();

    NamingOptions opts_;
    std::unordered_map<std::string, std::string> renames_;
    std::unordered_set<std::string> used_names_;
    std::unordered_set<std::string> pointer_names_;
    std::unordered_set<std::string> index_candidates_;
    std::vector<std::string> short_names_ = {"i", "j", "k", "n", "m", "t"};
};

/// Collect all variables used in a function's statements.
std::unordered_set<std::string> collect_used_vars(const decompiler::Function& func);

/// Build a naming context from a function with automatic index detection.
NamingContext build_naming_context(const decompiler::Function& func,
                                   NamingOptions opts = {});

}  // namespace engine::emit::opt
