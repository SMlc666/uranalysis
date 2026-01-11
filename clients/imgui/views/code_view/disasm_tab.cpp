#include "disasm_tab.h"

#include <string>
#include <vector>
#include <iomanip>
#include <sstream>

#include "imgui.h"
#include "../../utils/imgui_helpers.h"
#include "client/formatters/address.h"

namespace client {

namespace {

std::string build_disasm_text(const std::vector<engine::DisasmLine>& disasm) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < disasm.size(); ++i) {
        const auto& line = disasm[i];
        oss << "0x" << std::hex << line.address << std::dec << ": " << line.text;
        if (i + 1 < disasm.size()) {
            oss << "\n";
        }
    }
    return oss.str();
}

std::string build_bytes_text(const std::vector<std::uint8_t>& data, std::uint64_t base) {
    std::ostringstream out;
    const std::size_t per_line = 16;
    for (std::size_t offset = 0; offset < data.size(); offset += per_line) {
        std::ostringstream oss;
        oss << "0x" << std::hex << (base + offset);
        oss << ": ";
        for (std::size_t i = 0; i < per_line; ++i) {
            if (offset + i >= data.size()) {
                oss << "   ";
            } else {
                oss << std::setw(2) << std::setfill('0') << static_cast<int>(data[offset + i]) << " ";
            }
        }
        std::ostringstream ascii;
        ascii << " ";
        for (std::size_t i = 0; i < per_line && offset + i < data.size(); ++i) {
            const unsigned char c = data[offset + i];
            ascii << (std::isprint(c) ? static_cast<char>(c) : '.');
        }
        out << oss.str() << ascii.str();
        if (offset + per_line < data.size()) {
            out << "\n";
        }
    }
    return out.str();
}

std::uint64_t next_disasm_address(const std::vector<engine::DisasmLine>& disasm, std::uint64_t fallback) {
    if (disasm.empty()) {
        return fallback;
    }
    const auto& last = disasm.back();
    const std::uint64_t advance = last.size != 0 ? last.size : 4;
    return last.address + advance;
}

} // namespace

DisasmTab::DisasmTab(AppContext& context) : context_(context) {}

void DisasmTab::render(CodeViewState& state) {
    if (state.needs_refresh) {
        refresh_disasm(state, state.address);
        state.needs_refresh = false;
    }

    if (ImGui::Button("Copy Disasm")) {
        client::imgui::copy_to_clipboard(build_disasm_text(state.disasm_cache));
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy Bytes")) {
        client::imgui::copy_to_clipboard(build_bytes_text(state.bytes_cache, state.address));
    }

    client::imgui::render_error_text(state.last_error);

    ImGui::Separator();

    float avail = ImGui::GetContentRegionAvail().y;
    float disasm_height = avail > 140.0f ? avail * 0.6f : 180.0f;
    
    ImGui::BeginChild("DisasmScroll", ImVec2(0, disasm_height), true, ImGuiWindowFlags_HorizontalScrollbar);
    render_disasm_list(state);
    ImGui::EndChild();

    ImGui::Separator();

    if (!state.bytes_cache.empty()) {
        const std::string text = build_bytes_text(state.bytes_cache, state.address);
        client::imgui::render_readonly_text("##BytesText", text, ImVec2(0, ImGui::GetContentRegionAvail().y));
    } else {
        ImGui::TextDisabled("Byte preview will appear here after refresh.");
    }
}

void DisasmTab::refresh_disasm(CodeViewState& state, std::uint64_t address) {
    auto& session = context_.state().session();
    state.disasm_cache.clear();
    state.last_error.clear();
    
    if (state.instruction_count < 1) state.instruction_count = 1;
    
    state.disasm_start_address = address;
    state.disasm_next_address = address;
    state.disasm_reached_end = false;
    state.disasm_loading = false;
    state.disasm_reset_scroll = true;

    // Initial load
    std::size_t count = static_cast<std::size_t>(state.instruction_count);
    const auto machine = session.binary_info().machine;
    std::size_t max_bytes = count * ((machine == engine::BinaryMachine::kAarch64) ? 4U : 15U);
    
    std::vector<engine::DisasmLine> chunk;
    std::string error;
    bool ok = false;
    
    if (machine == engine::BinaryMachine::kAarch64) {
        ok = session.disasm_arm64(address, max_bytes, count, chunk, error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        ok = session.disasm_x86_64(address, max_bytes, count, chunk, error);
    } else {
        error = "unsupported architecture for disasm";
    }

    if (!ok) {
        state.last_error = error.empty() ? "disasm failed" : error;
        state.disasm_reached_end = true;
    } else if (chunk.empty()) {
        state.disasm_reached_end = true;
    } else {
        state.disasm_cache = std::move(chunk);
        state.disasm_next_address = next_disasm_address(state.disasm_cache, address);
    }

    // Bytes load
    state.bytes_cache.clear();
    if (state.byte_count < 1) state.byte_count = 16;
    session.image().read_bytes(address, static_cast<std::size_t>(state.byte_count), state.bytes_cache);
}

void DisasmTab::render_disasm_list(CodeViewState& state) {
    if (state.disasm_reset_scroll) {
        ImGui::SetScrollY(0.0f);
        state.disasm_reset_scroll = false;
    }

    if (state.disasm_cache.empty()) {
        ImGui::TextDisabled("Disassembly will appear here once you refresh with a valid address.");
        return;
    }

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(state.disasm_cache.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const auto& line = state.disasm_cache[static_cast<std::size_t>(i)];
            ImGui::Text("0x%llx: %s", static_cast<unsigned long long>(line.address), line.text.c_str());
        }
    }

    // Infinite scroll logic (simplified)
    bool request_more = false;
    float scroll_y = ImGui::GetScrollY();
    float scroll_max = ImGui::GetScrollMaxY();
    float win_h = ImGui::GetWindowHeight();
    
    if (!state.disasm_reached_end && scroll_max > 0.0f && scroll_y + win_h >= scroll_max - 80.0f) {
        request_more = true;
    }

    if (state.disasm_reached_end) {
        ImGui::TextDisabled("Reached end of readable bytes.");
    } else {
        if (ImGui::Button("Load more")) {
            request_more = true;
        }
    }

    if (request_more && !state.disasm_loading && !state.disasm_reached_end) {
        state.disasm_loading = true;
        
        auto& session = context_.state().session();
        std::size_t count = static_cast<std::size_t>(state.instruction_count);
        const auto machine = session.binary_info().machine;
        std::size_t max_bytes = count * ((machine == engine::BinaryMachine::kAarch64) ? 4U : 15U);
        
        std::vector<engine::DisasmLine> chunk;
        std::string error;
        bool ok = false;
        
        if (machine == engine::BinaryMachine::kAarch64) {
            ok = session.disasm_arm64(state.disasm_next_address, max_bytes, count, chunk, error);
        } else if (machine == engine::BinaryMachine::kX86_64) {
            ok = session.disasm_x86_64(state.disasm_next_address, max_bytes, count, chunk, error);
        }

        if (!ok || chunk.empty()) {
            state.disasm_reached_end = true;
        } else {
            // Remove overlap if any
            if (!state.disasm_cache.empty() && chunk.front().address == state.disasm_cache.back().address) {
                chunk.erase(chunk.begin());
            }
            
            if (chunk.empty()) {
                state.disasm_reached_end = true;
            } else {
                state.disasm_cache.insert(state.disasm_cache.end(), chunk.begin(), chunk.end());
                state.disasm_next_address = next_disasm_address(state.disasm_cache, state.disasm_next_address);
            }
        }
        
        state.disasm_loading = false;
    }
}

}  // namespace client