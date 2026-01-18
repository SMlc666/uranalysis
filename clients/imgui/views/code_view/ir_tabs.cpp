#include "ir_tabs.h"

#include <vector>
#include <string>

#include "imgui.h"
#include "../../utils/imgui_helpers.h"
#include "client/formatters/ir.h"
#include "client/formatters/address.h"
#include "engine/hlil_opt.h"
#include "engine/decompiler.h"
#include "engine/emit/emit.h"

namespace client {

namespace {

void copy_lines(const std::vector<std::string>& lines) {
    client::imgui::copy_to_clipboard(client::imgui::join_lines(lines));
}

} // namespace

IrTabs::IrTabs(AppContext& context) : context_(context) {}

void IrTabs::render(CodeViewState& state) {
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt("IR max instr", &state.ir_instruction_count);
    if (state.ir_instruction_count < 1) state.ir_instruction_count = 1;
    
    ImGui::SameLine();
    if (ImGui::Button("Build IR") || state.ir_needs_refresh) {
        if (state.address != 0) { // Only build if valid address
            refresh_ir(state, state.address);
        }
        state.ir_needs_refresh = false;
    }

    client::imgui::render_error_text(state.ir_error);

    if (ImGui::BeginTabBar("IrTabs")) {
        render_llir_tab(state);
        render_mlil_tab(state);
        render_hlil_tab(state);
        render_pseudoc_tab(state);
        ImGui::EndTabBar();
    }
}

void IrTabs::refresh_ir(CodeViewState& state, std::uint64_t address) {
    auto& session = context_.state().session();
    state.llir_lines.clear();
    state.mlil_lines.clear();
    state.hlil_lines.clear();
    state.pseudoc_lines.clear();
    state.pseudoc_mlil_lines.clear();
    state.ir_error.clear();
    state.mlil_error.clear();
    state.hlil_error.clear();
    state.pseudoc_error.clear();
    state.pseudoc_mlil_error.clear();
    
    state.ir_last_address = address;
    if (state.ir_instruction_count < 1) state.ir_instruction_count = 1;

    // LLIR
    engine::llir::Function llir_function;
    std::string error;
    bool ok = false;
    const auto machine = session.binary_info().machine;
    
    if (machine == engine::BinaryMachine::kAarch64) {
        ok = session.build_llir_ssa_arm64(address, static_cast<std::size_t>(state.ir_instruction_count), llir_function, error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        ok = session.build_llir_ssa_x86_64(address, static_cast<std::size_t>(state.ir_instruction_count), llir_function, error);
    } else {
        error = "unsupported architecture for llir";
    }

    if (!ok) {
        state.ir_error = error.empty() ? "llir build failed" : error;
        return;
    }

    client::fmt::format_llir_function(llir_function, state.llir_lines);

    // MLIL
    engine::mlil::Function mlil_function;
    if (machine != engine::BinaryMachine::kAarch64) {
        state.mlil_error = "mlil error: only arm64 is supported for now";
        state.hlil_error = "hlil error: only arm64 is supported for now";
        state.pseudoc_error = "pseudoc error: only arm64 is supported for now";
        return;
    }

    if (!session.build_mlil_ssa_arm64(address, static_cast<std::size_t>(state.ir_instruction_count), mlil_function, error)) {
        const std::string msg = error.empty() ? "mlil build failed" : error;
        state.mlil_error = msg;
        state.hlil_error = "hlil error: " + msg;
        state.pseudoc_error = "pseudoc error: " + msg;
        return;
    }
    
    client::fmt::format_mlil_function(mlil_function, state.mlil_lines);

    // HLIL
    engine::hlil::Function hlil_function;
    if (!engine::hlil::build_hlil_from_mlil(mlil_function, hlil_function, error)) {
        state.hlil_error = error.empty() ? "hlil build failed" : error;
    } else if (state.hlil_use_optimizations) {
        engine::hlil::HlilOptOptions opt_options;
        if (!engine::hlil::optimize_hlil(hlil_function, opt_options, error)) {
            state.hlil_error = error.empty() ? "hlil opt failed" : error;
        } else {
            client::fmt::format_hlil_function(hlil_function, state.hlil_lines);
        }
    } else {
        client::fmt::format_hlil_function(hlil_function, state.hlil_lines);
    }

    // Pseudo-C
    if (state.mlil_error.empty()) {
        engine::decompiler::FunctionHints hints;
        const auto* dwarf_fn = session.dwarf_catalog().find_function_by_address(address);
        if (dwarf_fn) {
            if (!dwarf_fn->name.empty()) {
                hints.name = dwarf_fn->name;
            } else if (!dwarf_fn->linkage_name.empty()) {
                hints.name = dwarf_fn->linkage_name;
            }
        }
        if (hints.name.empty()) {
            auto symbols = session.symbol_table().within_range(address, 1);
            if (!symbols.empty() && symbols.front()) {
                const auto* sym = symbols.front();
                if (!sym->demangled_name.empty()) {
                    hints.name = sym->demangled_name;
                } else if (!sym->name.empty()) {
                    hints.name = sym->name;
                }
            }
        }

        engine::decompiler::Function pseudoc_function;
        engine::mlil::Function pseudoc_mlil_lowered;
        if (!engine::decompiler::build_pseudoc_from_mlil_ssa_debug(mlil_function, pseudoc_function, error, &hints, &pseudoc_mlil_lowered)) {
            state.pseudoc_error = error.empty() ? "pseudoc build failed" : error;
            state.pseudoc_mlil_error = state.pseudoc_error;
        } else {
            state.pseudoc_lines = engine::emit::to_lines(pseudoc_function);
            client::fmt::format_mlil_function(pseudoc_mlil_lowered, state.pseudoc_mlil_lines);
            state.pseudoc_mlil_error.clear();
        }
    }
}

void IrTabs::render_llir_tab(CodeViewState& state) {
    if (ImGui::BeginTabItem("LLIR (SSA)")) {
        if (ImGui::Button("Copy LLIR")) {
            copy_lines(state.llir_lines);
        }
        if (!state.llir_lines.empty()) {
            client::imgui::render_readonly_text("##LlirText", client::imgui::join_lines(state.llir_lines), ImVec2(0, ImGui::GetContentRegionAvail().y));
        } else {
            ImGui::TextDisabled("Build IR to populate LLIR.");
        }
        ImGui::EndTabItem();
    }
}

void IrTabs::render_mlil_tab(CodeViewState& state) {
    if (ImGui::BeginTabItem("MLIL")) {
        if (ImGui::Button("Copy MLIL")) {
            copy_lines(state.mlil_lines);
        }
        client::imgui::render_error_text(state.mlil_error);
        if (!state.mlil_lines.empty()) {
            client::imgui::render_readonly_text("##MlilText", client::imgui::join_lines(state.mlil_lines), ImVec2(0, ImGui::GetContentRegionAvail().y));
        } else {
            ImGui::TextDisabled("Build IR to populate MLIL.");
        }
        ImGui::EndTabItem();
    }
}

void IrTabs::render_hlil_tab(CodeViewState& state) {
    if (ImGui::BeginTabItem("HLIL")) {
        if (ImGui::Button("Copy HLIL")) {
            copy_lines(state.hlil_lines);
        }
        ImGui::SameLine();
        if (ImGui::Checkbox("Optimize HLIL", &state.hlil_use_optimizations)) {
            state.ir_needs_refresh = true;
        }
        client::imgui::render_error_text(state.hlil_error);
        if (!state.hlil_lines.empty()) {
            client::imgui::render_readonly_text("##HlilText", client::imgui::join_lines(state.hlil_lines), ImVec2(0, ImGui::GetContentRegionAvail().y));
        } else {
            ImGui::TextDisabled("Build IR to populate HLIL.");
        }
        ImGui::EndTabItem();
    }
}

void IrTabs::render_pseudoc_tab(CodeViewState& state) {
    if (ImGui::BeginTabItem("Pseudo-C")) {
        if (ImGui::Button("Copy Pseudo-C")) {
            copy_lines(state.pseudoc_lines);
        }
        client::imgui::render_error_text(state.pseudoc_error);
        if (!state.pseudoc_lines.empty()) {
            client::imgui::render_readonly_text("##PseudoCText", client::imgui::join_lines(state.pseudoc_lines), ImVec2(0, ImGui::GetContentRegionAvail().y));
        } else {
            ImGui::TextDisabled("Build IR to populate Pseudo-C.");
        }
        ImGui::EndTabItem();
    }
}

}  // namespace client