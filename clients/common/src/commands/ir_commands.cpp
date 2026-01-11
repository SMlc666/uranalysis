#include "client/commands/commands.h"

#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "client/formatters/address.h"
#include "client/formatters/ir.h"
#include "engine/decompiler.h"
#include "engine/decompiler/passes/abi_params.h"
#include "engine/hlil.h"
#include "engine/hlil_lift.h"
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/mlil_lift.h"

namespace client::commands {

namespace {

bool require_loaded(const Session& session, Output& output) {
    if (!session.loaded()) {
        output.write_line("no file loaded, use: open <path>");
        return false;
    }
    return true;
}

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

int analyze_param_count(Session& session, std::uint64_t addr, std::size_t max_instructions) {
    std::string error;
    engine::mlil::Function callee_mlil;
    if (!session.build_mlil_ssa_arm64(addr, max_instructions, callee_mlil, error)) {
        return -1;
    }
    auto params = engine::decompiler::passes::collect_abi_params(callee_mlil);
    if (params.empty()) {
        return 0;
    }
    int max_index = -1;
    for (const auto& p : params) {
        if (p.index > max_index) {
            max_index = p.index;
        }
    }
    return max_index + 1;
}

}  // namespace

void register_ir_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "llir",
        {"il"},
        "llir [addr] [max]  show LLIR SSA",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: llir [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                if (!fmt::parse_u64(args[1], addr)) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[2], parsed)) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
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
        }});

    registry.register_command(Command{
        "mlil",
        {"ml"},
        "mlil [addr] [max]  show MLIL",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: mlil [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                if (!fmt::parse_u64(args[1], addr)) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[2], parsed)) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            engine::llir::Function llir_function;
            std::string error;
            bool ok = false;
            const auto machine = session.binary_info().machine;
            if (machine == engine::BinaryMachine::kAarch64) {
                engine::mlil::Function mlil_function;
                ok = session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error);
                if (!ok) {
                    output.write_line("mlil error: " + (error.empty() ? "build failed" : error));
                    return true;
                }
                emit_mlil_function(mlil_function, output);
                return true;
            } else if (machine == engine::BinaryMachine::kX86_64) {
                ok = session.build_llir_ssa_x86_64(addr, max_instructions, llir_function, error);
            } else {
                error = "unsupported architecture for llir";
            }
            if (!ok) {
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
        }});

    registry.register_command(Command{
        "hlil",
        {"hl"},
        "hlil [addr] [max]  show HLIL (early prototype)",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: hlil [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                if (!fmt::parse_u64(args[1], addr)) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[2], parsed)) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            std::string error;
            const auto machine = session.binary_info().machine;
            if (machine != engine::BinaryMachine::kAarch64) {
                output.write_line("hlil error: only arm64 is supported for now");
                return true;
            }
            engine::hlil::Function hlil_function;
            if (!session.build_hlil_arm64(addr, max_instructions, hlil_function, error)) {
                output.write_line("hlil error: " + (error.empty() ? "build failed" : error));
                return true;
            }
            emit_hlil_function(hlil_function, output);
            return true;
        }});

    registry.register_command(Command{
        "hlilraw",
        {"hlil0"},
        "hlilraw [addr] [max]  show HLIL without optimizations",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: hlilraw [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                if (!fmt::parse_u64(args[1], addr)) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[2], parsed)) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            std::string error;
            const auto machine = session.binary_info().machine;
            if (machine != engine::BinaryMachine::kAarch64) {
                output.write_line("hlilraw error: only arm64 is supported for now");
                return true;
            }
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
        }});

    registry.register_command(Command{
        "pseudoc",
        {"pc"},
        "pseudoc [addr] [max]  show pseudo-C (early prototype)",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: pseudoc [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                if (!fmt::parse_u64(args[1], addr)) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                std::uint64_t parsed = 0;
                if (!fmt::parse_u64(args[2], parsed)) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            std::string error;
            const auto machine = session.binary_info().machine;
            if (machine != engine::BinaryMachine::kAarch64) {
                output.write_line("pseudoc error: only arm64 is supported for now");
                return true;
            }

            engine::decompiler::Function pseudo_function;
            engine::decompiler::FunctionHints hints;
            const auto* dwarf_fn = session.dwarf_catalog().find_function_by_address(addr);
            if (dwarf_fn) {
                if (!dwarf_fn->name.empty()) {
                    hints.name = dwarf_fn->name;
                } else if (!dwarf_fn->linkage_name.empty()) {
                    hints.name = dwarf_fn->linkage_name;
                }
            }
            if (hints.name.empty()) {
                auto symbols = session.symbol_table().within_range(addr, 1);
                if (!symbols.empty() && symbols.front()) {
                    const auto* sym = symbols.front();
                    if (!sym->demangled_name.empty()) {
                        hints.name = sym->demangled_name;
                    } else if (!sym->name.empty()) {
                        hints.name = sym->name;
                    }
                }
            }
            engine::mlil::Function mlil_function;
            if (!session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error)) {
                output.write_line("pseudoc error: " + (error.empty() ? "build failed" : error));
                return true;
            }

            // Interprocedural analysis
            auto call_targets = collect_call_targets(mlil_function);
            std::unordered_map<std::uint64_t, int> param_count_cache;
            call_targets.erase(addr);
            const std::size_t kMaxTargetsToAnalyze = 32;
            std::size_t analyzed = 0;
            for (std::uint64_t target : call_targets) {
                if (analyzed >= kMaxTargetsToAnalyze) {
                    break;
                }
                int count = analyze_param_count(session, target, max_instructions);
                if (count >= 0) {
                    param_count_cache[target] = count;
                    ++analyzed;
                }
            }

            auto resolver = [&](std::uint64_t resolve_addr) -> std::string {
                const auto* dwarf = session.dwarf_catalog().find_function_by_address(resolve_addr);
                if (dwarf) {
                    if (!dwarf->name.empty()) {
                        return dwarf->name;
                    }
                    if (!dwarf->linkage_name.empty()) {
                        return dwarf->linkage_name;
                    }
                }
                auto syms = session.symbol_table().within_range(resolve_addr, 1);
                if (!syms.empty() && syms.front() && syms.front()->address == resolve_addr) {
                    const auto* sym = syms.front();
                    if (!sym->demangled_name.empty()) {
                        return sym->demangled_name;
                    }
                    if (!sym->name.empty()) {
                        return sym->name;
                    }
                }
                return "";
            };

            hints.param_count_provider = [&param_count_cache](std::uint64_t target_addr) -> int {
                auto it = param_count_cache.find(target_addr);
                if (it != param_count_cache.end()) {
                    return it->second;
                }
                return -1;
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
        }});
}

}  // namespace client::commands