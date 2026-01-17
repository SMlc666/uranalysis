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

    // Set up table for aligned rendering
    ImGuiTableFlags flags = ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;
    
    // Calculate approximate height to fill, leaving space for "Load more" button
    float avail_h = ImGui::GetContentRegionAvail().y;
    // If not reached end, reserve space for button
    if (!state.disasm_reached_end) avail_h -= 30.0f;
    if (avail_h < 100.0f) avail_h = 100.0f;

    if (ImGui::BeginTable("DisasmTable", 2, flags, ImVec2(0.0f, avail_h))) {
        ImGui::TableSetupScrollFreeze(0, 1); // Make header row always visible
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        // ImGui::TableHeadersRow(); // Optional: show headers

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(state.disasm_cache.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto& line = state.disasm_cache[static_cast<std::size_t>(i)];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                
                // Address Column (Yellow-ish)
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.4f, 1.0f));
                ImGui::Text("0x%llx", static_cast<unsigned long long>(line.address));
                ImGui::PopStyleColor();

                ImGui::TableNextColumn();
                
                // Render instruction with simple syntax highlighting
                // For now, we manually parse the string. 
                // Ideally, engine should return structured tokens.
                // Format: "mnemonic  op1, op2"
                
                std::string text = line.text;
                size_t first_space = text.find(' ');
                
                if (first_space != std::string::npos) {
                    // Mnemonic (Blue)
                    std::string mnemonic = text.substr(0, first_space);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 0.7f, 1.0f, 1.0f));
                    ImGui::TextUnformatted(mnemonic.c_str());
                    ImGui::PopStyleColor();
                    
                    ImGui::SameLine();
                    ImGui::TextUnformatted(" "); 
                    ImGui::SameLine();
                    
                    // Simple regex-like parsing for operands
                    std::string operands = text.substr(first_space + 1);
                    // Trim leading spaces
                    size_t op_start = operands.find_first_not_of(" ");
                    if (op_start != std::string::npos) {
                        operands = operands.substr(op_start);
                    }
                    
                    // Naive tokenization: split by delimiters
                    // We color registers (r.., e.., x..) in Purple
                    // Immediates (0x.., numbers) in Green
                    
                    // For now, just print it. 
                    // TODO: Implement a proper token loop if we want better highlighting.
                    // Let's try a very simple highlight for commas
                    
                    const char* p = operands.c_str();
                    const char* start = p;
                    while (*p) {
                        if (*p == ',' || *p == '[' || *p == ']' || *p == '+' || *p == '-' || *p == '*') {
                            if (p > start) {
                                std::string token(start, p);
                                // Check if token looks like register or number
                                bool is_reg = (token.size() >= 2 && (token[0] == 'r' || token[0] == 'e' || token[0] == 'x' || token[0] == 'w' || token[0] == 's'));
                                bool is_num = (std::isdigit(token[0]));
                                
                                if (is_reg) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.4f, 1.0f, 1.0f)); // Purple
                                else if (is_num) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f)); // Green
                                else ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.85f, 0.85f, 0.85f, 1.0f));
                                
                                ImGui::TextUnformatted(token.c_str());
                                ImGui::PopStyleColor();
                                ImGui::SameLine(0, 0);
                            }
                            // Punctuation
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
                            ImGui::Text("%c", *p);
                            ImGui::PopStyleColor();
                            ImGui::SameLine(0, 0);
                            start = p + 1;
                        }
                        p++;
                    }
                    if (p > start) {
                         std::string token(start, p);
                         bool is_reg = (token.size() >= 2 && (token[0] == 'r' || token[0] == 'e' || token[0] == 'x' || token[0] == 'w' || token[0] == 's'));
                         bool is_num = (std::isdigit(token[0]));
                         if (is_reg) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.4f, 1.0f, 1.0f));
                         else if (is_num) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
                         else ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.85f, 0.85f, 0.85f, 1.0f));
                         
                         ImGui::TextUnformatted(token.c_str());
                         ImGui::PopStyleColor();
                    }
                } else {
                    // Just mnemonic?
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 0.7f, 1.0f, 1.0f));
                    ImGui::TextUnformatted(text.c_str());
                    ImGui::PopStyleColor();
                }
            }
        }
        ImGui::EndTable();
    }

    // Infinite scroll logic (simplified)
    bool request_more = false;
    // Note: Scroll logic is tricky with Tables. 
    // We check if we are near the end of the item list using the clipper/index logic if possible,
    // or rely on a manual "Load More" button for stability first.
    
    if (state.disasm_reached_end) {
        ImGui::TextDisabled("Reached end of readable bytes.");
    } else {
        if (ImGui::Button("Load more...")) {
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