#include "client/commands/commands.h"
#include "client/formatters/address.h"
#include "client/formatters/ir.h"
#include "client/util/address_resolver.h"
#include "engine/decompiler.h"
#include "engine/decompiler/passes/abi_params.h"
#include "engine/hlil.h"
#include "engine/hlil_lift.h"
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/mlil_lift.h"

#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace client::commands {

namespace {

void emit_llir_function(const engine::llir::Function& function, Output& output) {
    std::vector<std::string> lines;
    fmt::format_llir_function(function, lines);
    for (const auto& line : lines) {
        output.write_line(line);
    }
}

void emit_mlil_function(const engine::mlil::Function& function, Output& output) {
    std::vector<std::string> lines;
    fmt::format_mlil_function(function, lines);
    for (const auto& line : lines) {
        output.write_line(line);
    }
}

void emit_hlil_function(const engine::hlil::Function& function, Output& output) {
    std::vector<std::string> lines;
    fmt::format_hlil_function(function, lines);
    for (const auto& line : lines) {
        output.write_line(line);
    }
}

void collect_call_targets_stmt(const engine::mlil::MlilStmt& stmt,
                               std::unordered_set<uint64_t>& targets) {
    if (stmt.kind == engine::mlil::MlilStmtKind::kCall) {
        if (stmt.target.kind == engine::mlil::MlilExprKind::kImm) {
            targets.insert(stmt.target.imm);
        }
    }
}

std::unordered_set<uint64_t> collect_call_targets(const engine::mlil::Function& function) {
    std::unordered_set<uint64_t> targets;
    for (const auto& block : function.blocks) {
        for (const auto& inst : block.instructions) {
            for (const auto& stmt : inst.stmts) {
                collect_call_targets_stmt(stmt, targets);
            }
        }
    }
    return targets;
}

int analyze_param_count(Session& session, uint64_t addr, size_t max_instructions) {
    std::string error;
    engine::mlil::Function callee_mlil;
    if (!session.build_mlil_ssa_arm64(addr, max_instructions, callee_mlil, error)) {
        return -1;
    }
    auto params = engine::decompiler::passes::collect_abi_params(callee_mlil);
    if (params.empty()) return 0;
    int max_index = -1;
    for (const auto& p : params) {
        if (p.index > max_index) max_index = p.index;
    }
    return max_index + 1;
}

}  // namespace

void register_ir_commands(CommandRegistry& registry) {
    // ==========================================================================
    // llir - Show Low-Level IR (SSA)
    // ==========================================================================
    registry.register_command(
        CommandV2("llir", {"il", "lir"})
            .description("Show Low-Level IR (LLIR SSA) for a function")
            .requires_file()
            .positional("address", "Function address or symbol (default: cursor)", false)
            .positional("max", "Max instructions to analyze (default: 1024)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                uint64_t addr = session.cursor();
                if (m.has("address")) {
                    auto result = util::resolve_address(m.get<std::string>("address"), session);
                    if (!result.success) {
                        output.write_line(result.error);
                        return true;
                    }
                    addr = result.address;
                }
                size_t max_instructions = static_cast<size_t>(m.get_or<uint64_t>("max", 1024));
                
                engine::llir::Function function;
                std::string error;
                bool ok = false;
                const auto machine = session.binary_info().machine;
                if (machine == engine::BinaryMachine::kAarch64) {
                    ok = session.build_llir_ssa_arm64(addr, max_instructions, function, error);
                } else if (machine == engine::BinaryMachine::kX86_64) {
                    ok = session.build_llir_ssa_x86_64(addr, max_instructions, function, error);
                } else {
                    error = "unsupported architecture for llir";
                }
                if (!ok) {
                    output.write_line("llir error: " + (error.empty() ? "build failed" : error));
                    return true;
                }
                emit_llir_function(function, output);
                return true;
            }));

    // ==========================================================================
    // mlil - Show Medium-Level IR
    // ==========================================================================
    registry.register_command(
        CommandV2("mlil", {"ml", "mir"})
            .description("Show Medium-Level IR (MLIL) for a function")
            .requires_file()
            .positional("address", "Function address or symbol (default: cursor)", false)
            .positional("max", "Max instructions to analyze (default: 1024)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                uint64_t addr = session.cursor();
                if (m.has("address")) {
                    auto result = util::resolve_address(m.get<std::string>("address"), session);
                    if (!result.success) {
                        output.write_line(result.error);
                        return true;
                    }
                    addr = result.address;
                }
                size_t max_instructions = static_cast<size_t>(m.get_or<uint64_t>("max", 1024));
                
                std::string error;
                const auto machine = session.binary_info().machine;
                
                if (machine == engine::BinaryMachine::kAarch64) {
                    engine::mlil::Function mlil_function;
                    if (!session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error)) {
                        output.write_line("mlil error: " + (error.empty() ? "build failed" : error));
                        return true;
                    }
                    emit_mlil_function(mlil_function, output);
                    return true;
                }
                
                if (machine == engine::BinaryMachine::kX86_64) {
                    engine::llir::Function llir_function;
                    if (!session.build_llir_ssa_x86_64(addr, max_instructions, llir_function, error)) {
                        output.write_line("llir error: " + (error.empty() ? "build failed" : error));
                        return true;
                    }
                    engine::mlil::Function mlil_function;
                    if (!engine::mlil::build_mlil_from_llil_ssa(llir_function, mlil_function, error)) {
                        output.write_line("mlil error: " + (error.empty() ? "build failed" : error));
                        return true;
                    }
                    emit_mlil_function(mlil_function, output);
                    return true;
                }
                
                output.write_line("unsupported architecture for mlil");
                return true;
            }));

    // ==========================================================================
    // hlil - Show High-Level IR
    // ==========================================================================
    registry.register_command(
        CommandV2("hlil", {"hl", "hir"})
            .description("Show High-Level IR (HLIL) for a function")
            .requires_file()
            .positional("address", "Function address or symbol (default: cursor)", false)
            .positional("max", "Max instructions to analyze (default: 1024)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                uint64_t addr = session.cursor();
                if (m.has("address")) {
                    auto result = util::resolve_address(m.get<std::string>("address"), session);
                    if (!result.success) {
                        output.write_line(result.error);
                        return true;
                    }
                    addr = result.address;
                }
                size_t max_instructions = static_cast<size_t>(m.get_or<uint64_t>("max", 1024));
                
                const auto machine = session.binary_info().machine;
                if (machine != engine::BinaryMachine::kAarch64) {
                    output.write_line("hlil error: only arm64 is supported for now");
                    return true;
                }
                
                std::string error;
                engine::hlil::Function hlil_function;
                if (!session.build_hlil_arm64(addr, max_instructions, hlil_function, error)) {
                    output.write_line("hlil error: " + (error.empty() ? "build failed" : error));
                    return true;
                }
                emit_hlil_function(hlil_function, output);
                return true;
            }));

    // ==========================================================================
    // hlilraw - Show raw HLIL without optimizations
    // ==========================================================================
    registry.register_command(
        CommandV2("hlilraw", {"hlil0", "rawhlil"})
            .description("Show raw HLIL without optimizations")
            .requires_file()
            .positional("address", "Function address or symbol (default: cursor)", false)
            .positional("max", "Max instructions to analyze (default: 1024)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                uint64_t addr = session.cursor();
                if (m.has("address")) {
                    auto result = util::resolve_address(m.get<std::string>("address"), session);
                    if (!result.success) {
                        output.write_line(result.error);
                        return true;
                    }
                    addr = result.address;
                }
                size_t max_instructions = static_cast<size_t>(m.get_or<uint64_t>("max", 1024));
                
                const auto machine = session.binary_info().machine;
                if (machine != engine::BinaryMachine::kAarch64) {
                    output.write_line("hlilraw error: only arm64 is supported for now");
                    return true;
                }
                
                std::string error;
                engine::mlil::Function mlil_function;
                if (!session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error)) {
                    output.write_line("hlilraw error: " + (error.empty() ? "mlil build failed" : error));
                    return true;
                }
                engine::hlil::Function hlil_function;
                if (!engine::hlil::build_hlil_from_mlil(mlil_function, hlil_function, error)) {
                    output.write_line("hlilraw error: " + (error.empty() ? "hlil build failed" : error));
                    return true;
                }
                emit_hlil_function(hlil_function, output);
                return true;
            }));

    // ==========================================================================
    // pseudoc - Show pseudo-C decompilation
    // ==========================================================================
    registry.register_command(
        CommandV2("pseudoc", {"pc", "decompile", "dec"})
            .description("Show pseudo-C decompilation")
            .requires_file()
            .positional("address", "Function address or symbol (default: cursor)", false)
            .positional("max", "Max instructions to analyze (default: 1024)", false, args::ValueType::Unsigned)
            .handler([](Session& session, Output& output, const args::ArgMatches& m) {
                uint64_t addr = session.cursor();
                if (m.has("address")) {
                    auto result = util::resolve_address(m.get<std::string>("address"), session);
                    if (!result.success) {
                        output.write_line(result.error);
                        return true;
                    }
                    addr = result.address;
                }
                size_t max_instructions = static_cast<size_t>(m.get_or<uint64_t>("max", 1024));
                
                const auto machine = session.binary_info().machine;
                if (machine != engine::BinaryMachine::kAarch64) {
                    output.write_line("pseudoc error: only arm64 is supported for now");
                    return true;
                }
                
                std::string error;
                engine::decompiler::Function pseudo_function;
                engine::decompiler::FunctionHints hints;
                
                // Try to get function name from DWARF or symbols
                const auto* dwarf_fn = session.dwarf_catalog().find_function_by_address(addr);
                if (dwarf_fn) {
                    hints.name = !dwarf_fn->name.empty() ? dwarf_fn->name : dwarf_fn->linkage_name;
                }
                if (hints.name.empty()) {
                    auto symbols = session.symbol_table().within_range(addr, 1);
                    if (!symbols.empty() && symbols.front()) {
                        const auto* sym = symbols.front();
                        hints.name = !sym->demangled_name.empty() ? sym->demangled_name : sym->name;
                    }
                }
                
                engine::mlil::Function mlil_function;
                if (!session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error)) {
                    output.write_line("pseudoc error: " + (error.empty() ? "build failed" : error));
                    return true;
                }
                
                // Interprocedural analysis
                auto call_targets = collect_call_targets(mlil_function);
                std::unordered_map<uint64_t, int> param_count_cache;
                call_targets.erase(addr);
                const size_t kMaxTargetsToAnalyze = 32;
                size_t analyzed = 0;
                for (uint64_t target : call_targets) {
                    if (analyzed >= kMaxTargetsToAnalyze) break;
                    int count = analyze_param_count(session, target, max_instructions);
                    if (count >= 0) {
                        param_count_cache[target] = count;
                        ++analyzed;
                    }
                }
                
                auto resolver = [&](uint64_t resolve_addr) -> std::string {
                    const auto* dwarf = session.dwarf_catalog().find_function_by_address(resolve_addr);
                    if (dwarf) {
                        if (!dwarf->name.empty()) return dwarf->name;
                        if (!dwarf->linkage_name.empty()) return dwarf->linkage_name;
                    }
                    auto syms = session.symbol_table().within_range(resolve_addr, 1);
                    if (!syms.empty() && syms.front() && syms.front()->address == resolve_addr) {
                        const auto* sym = syms.front();
                        if (!sym->demangled_name.empty()) return sym->demangled_name;
                        if (!sym->name.empty()) return sym->name;
                    }
                    return "";
                };
                
                hints.param_count_provider = [&param_count_cache](uint64_t target_addr) -> int {
                    auto it = param_count_cache.find(target_addr);
                    return it != param_count_cache.end() ? it->second : -1;
                };
                
                if (!engine::decompiler::build_pseudoc_from_mlil_ssa(
                        mlil_function, pseudo_function, error, &hints, resolver)) {
                    output.write_line("pseudoc error: " + (error.empty() ? "build failed" : error));
                    return true;
                }
                
                std::vector<std::string> lines;
                engine::decompiler::emit_pseudoc(pseudo_function, lines);
                for (const auto& line : lines) {
                    output.write_line(line);
                }
                return true;
            }));
}

}  // namespace client::commands
