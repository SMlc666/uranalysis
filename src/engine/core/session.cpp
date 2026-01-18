#include "engine/session.h"

#include "engine/arch/arm64/calling_convention.h"
#include "engine/arch/x86_64/calling_convention.h"
#include "engine/hlil_lift.h"
#include "engine/hlil_opt.h"
#include "engine/llir_passes.h"
#include "engine/llir_opt.h"
#include "engine/mlil_lift.h"
#include "engine/pdb_loader.h"
#include "engine/debug/log_channels.h"
#include "engine/debug/ir_dump.h"

#include <algorithm>
#include <spdlog/spdlog.h>

namespace engine {

namespace {

constexpr std::uint32_t kRelocAarch64Abs64 = 257;
constexpr std::uint32_t kRelocAarch64GlobDat = 1025;
constexpr std::uint32_t kRelocAarch64JumpSlot = 1026;
constexpr std::uint32_t kRelocAarch64Relative = 1027;
constexpr std::uint32_t kRelocAarch64TlsDtpMod64 = 1029;
constexpr std::uint32_t kRelocAarch64TlsDtpRel64 = 1030;
constexpr std::uint32_t kRelocAarch64TlsTpRel64 = 1031;
constexpr std::uint32_t kRelocAarch64IRelative = 1032;
constexpr std::uint32_t kRelocPeHighLow = 3;
constexpr std::uint32_t kRelocPeDir64 = 10;
constexpr std::uint32_t kElfPtTls = 7;

std::uint64_t image_base(const std::vector<BinarySegment>& segments) {
    if (segments.empty()) {
        return 0;
    }
    std::uint64_t base = segments.front().vaddr;
    for (const auto& seg : segments) {
        if (seg.vaddr < base) {
            base = seg.vaddr;
        }
    }
    return base;
}

std::uint64_t tls_base(const std::vector<BinarySegment>& segments, bool& has_tls) {
    has_tls = false;
    std::uint64_t base = 0;
    for (const auto& seg : segments) {
        if (seg.type != kElfPtTls) {
            continue;
        }
        if (!has_tls || seg.vaddr < base) {
            base = seg.vaddr;
        }
        has_tls = true;
    }
    return base;
}

std::vector<std::uint8_t> pack_u64(std::uint64_t value) {
    std::vector<std::uint8_t> out(8);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
    }
    return out;
}

}  // namespace

bool Session::open(const std::string& path, std::string& error) {
    close();
    if (!load_binary_image_with_symbols_and_relocations(path,
                                                        binary_info_,
                                                        segments_,
                                                        sections_,
                                                        symbols_,
                                                        relocations_,
                                                        image_,
                                                        error)) {
        return false;
    }
    path_ = path;
    apply_relocations();
    symbol_table_.populate(symbols_, sections_);
    rtti_catalog_.discover(sections_, segments_, image_, binary_info_);
    dwarf_catalog_.discover(path_, sections_, image_, binary_info_, relocations_);
    eh_frame_catalog_.discover(sections_, image_, binary_info_);
    string_catalog_.discover(sections_, image_);
    string_catalog_.attach_symbols(symbol_table_);

    // Auto-load PDB for PE files
    if (binary_info_.format == BinaryFormat::kPe) {
        try_load_pdb();
    }

    loaded_ = true;
    cursor_ = binary_info_.entry;
    return true;
}

void Session::apply_relocations() {
    if (relocations_.empty()) {
        return;
    }
    const std::uint64_t base = image_base(segments_);
    bool has_tls = false;
    const std::uint64_t tls = tls_base(segments_, has_tls);
    for (const auto& reloc : relocations_) {
        bool apply = false;
        std::uint64_t value = 0;
        switch (reloc.type) {
            case kRelocAarch64Relative: {
                const std::int64_t signed_value = static_cast<std::int64_t>(base) + reloc.addend;
                value = static_cast<std::uint64_t>(signed_value);
                apply = true;
                break;
            }
            case kRelocAarch64Abs64:
            case kRelocAarch64GlobDat:
            case kRelocAarch64JumpSlot: {
                const std::int64_t signed_value =
                    static_cast<std::int64_t>(reloc.symbol_value) + reloc.addend;
                value = static_cast<std::uint64_t>(signed_value);
                apply = true;
                break;
            }
            case kRelocAarch64IRelative: {
                const std::int64_t signed_value = static_cast<std::int64_t>(base) + reloc.addend;
                value = static_cast<std::uint64_t>(signed_value);
                apply = true;
                break;
            }
            case kRelocAarch64TlsDtpMod64: {
                value = has_tls ? 1 : 0;
                apply = true;
                break;
            }
            case kRelocAarch64TlsDtpRel64:
            case kRelocAarch64TlsTpRel64: {
                const std::int64_t signed_value =
                    static_cast<std::int64_t>(reloc.symbol_value) + reloc.addend -
                    static_cast<std::int64_t>(has_tls ? tls : 0);
                value = static_cast<std::uint64_t>(signed_value);
                apply = true;
                break;
            }
            case kRelocPeHighLow:
            case kRelocPeDir64: {
                const std::int64_t signed_value =
                    static_cast<std::int64_t>(base) + reloc.addend;
                value = static_cast<std::uint64_t>(signed_value);
                apply = true;
                break;
            }
            default:
                break;
        }
        if (apply) {
            if (reloc.type == kRelocPeHighLow) {
                std::vector<std::uint8_t> data(4);
                for (std::size_t i = 0; i < data.size(); ++i) {
                    data[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
                }
                image_.write_bytes(reloc.offset, data);
            } else {
                image_.write_bytes(reloc.offset, pack_u64(value));
            }
        }
    }
}

void Session::close() {
    loaded_ = false;
    path_.clear();
    pdb_path_.clear();
    has_pdb_symbols_ = false;
    binary_info_ = {};
    segments_.clear();
    sections_.clear();
    symbols_.clear();
    relocations_.clear();
    symbol_table_.reset();
    rtti_catalog_.reset();
    dwarf_catalog_.reset();
    eh_frame_catalog_.reset();
    string_catalog_.reset();
    image_.segments.clear();
    cursor_ = 0;
}

bool Session::loaded() const {
    return loaded_;
}

const std::string& Session::path() const {
    return path_;
}

const BinaryInfo& Session::binary_info() const {
    return binary_info_;
}

const std::vector<BinarySegment>& Session::segments() const {
    return segments_;
}

const std::vector<BinarySection>& Session::sections() const {
    return sections_;
}

const std::vector<BinarySymbol>& Session::symbols() const {
    return symbols_;
}

const std::vector<BinaryRelocation>& Session::relocations() const {
    return relocations_;
}

const symbols::SymbolTable& Session::symbol_table() const {
    return symbol_table_;
}

const rtti::RttiCatalog& Session::rtti_catalog() const {
    return rtti_catalog_;
}

const dwarf::DwarfCatalog& Session::dwarf_catalog() const {
    return dwarf_catalog_;
}

const ehframe::EhFrameCatalog& Session::eh_frame_catalog() const {
    return eh_frame_catalog_;
}

const strings::StringCatalog& Session::string_catalog() const {
    return string_catalog_;
}

bool Session::find_xrefs_to_address(std::uint64_t target,
                                    std::size_t max_results,
                                    std::vector<xrefs::XrefEntry>& out) const {
    return xrefs::find_xrefs_to_address(image_, relocations_, segments_, target, max_results, out);
}

const LoadedImage& Session::image() const {
    return image_;
}

std::uint64_t Session::cursor() const {
    return cursor_;
}

void Session::set_cursor(std::uint64_t addr) {
    cursor_ = addr;
}

bool Session::disasm_arm64(std::uint64_t start,
                           std::size_t max_bytes,
                           std::size_t max_instructions,
                           std::vector<DisasmLine>& out,
                           std::string& error) const {
    return engine::disasm_arm64(image_, start, max_bytes, max_instructions, out, error);
}

bool Session::disasm_x86_64(std::uint64_t start,
                            std::size_t max_bytes,
                            std::size_t max_instructions,
                            std::vector<DisasmLine>& out,
                            std::string& error) const {
    return engine::disasm_x86_64(image_, start, max_bytes, max_instructions, out, error);
}

bool Session::build_llir_cfg_arm64(std::uint64_t entry,
                                   std::size_t max_instructions,
                                   llir::Function& function,
                                   std::string& error) const {
    return llir::build_cfg_arm64(image_, entry, max_instructions, function, error);
}

bool Session::build_llir_cfg_x86_64(std::uint64_t entry,
                                    std::size_t max_instructions,
                                    llir::Function& function,
                                    std::string& error) const {
    return llir::build_cfg_x86_64(image_, entry, max_instructions, function, error);
}

bool Session::build_llir_ssa_arm64(std::uint64_t entry,
                                   std::size_t max_instructions,
                                   llir::Function& function,
                                   std::string& error) const {
    if (!llir::build_cfg_arm64(image_, entry, max_instructions, function, error)) {
        return false;
    }
    if (!llir::build_ssa_with_call_clobbers(function, arch::arm64::call_clobbers(), error)) {
        return false;
    }
    if (!llir::lift_stack_vars(function, error)) {
        return false;
    }
    llir::LlilOptOptions options;
    if (!llir::optimize_llil_ssa(function, options, error)) {
        return false;
    }
    if (!llir::resolve_indirect_branches(function, error)) {
        return false;
    }
    // Resolve jump tables for switch statement recovery
    if (!llir::resolve_jump_tables(function, image_, segments_, error)) {
        return false;
    }
    return true;
}

bool Session::build_mlil_ssa_arm64(std::uint64_t entry,
                                   std::size_t max_instructions,
                                   mlil::Function& function,
                                   std::string& error) const {
    LOG_CH_DEBUG(log::Channel::kMlil, "build_mlil_ssa_arm64: entry=0x{:x}", entry);
    
    llir::Function llir_function;
    if (!build_llir_ssa_arm64(entry, max_instructions, llir_function, error)) {
        return false;
    }
    
    LOG_CH_TRACE(log::Channel::kMlil, "LLIR complete: {} blocks, {} stmts", 
                 llir_function.blocks.size(), debug::count_stmts(llir_function));
    
    if (!mlil::build_mlil_from_llil_ssa(llir_function, function, error)) {
        return false;
    }
    
    LOG_CH_TRACE(log::Channel::kMlil, "MLIL lift complete: {} blocks, {} stmts",
                 function.blocks.size(), debug::count_stmts(function));
    
    // Note: We skip mlil::build_ssa_with_call_clobbers here because LLIR already
    // has correct SSA information. Rebuilding SSA in MLIL would overwrite the
    // correct version numbers from LLIR, causing issues like xor(a, b) becoming
    // xor(a, a) when both operands are different versions of the same register.
    // The call clobbers are already handled in LLIR SSA construction.
    
    mlil::MlilOptOptions options;
    // Disable copy propagation to prevent incorrect variable merging
    options.copy_propagation = false;
    bool result = mlil::optimize_mlil_ssa(function, options, error);
    
    LOG_CH_DEBUG(log::Channel::kMlil, "MLIL opt complete: {} stmts", debug::count_stmts(function));
    return result;
}

bool Session::build_hlil_arm64(std::uint64_t entry,
                               std::size_t max_instructions,
                               hlil::Function& function,
                               std::string& error) const {
    LOG_CH_DEBUG(log::Channel::kHlil, "build_hlil_arm64: entry=0x{:x}", entry);
    
    mlil::Function mlil_function;
    if (!build_mlil_ssa_arm64(entry, max_instructions, mlil_function, error)) {
        return false;
    }
    if (!hlil::build_hlil_from_mlil(mlil_function, function, error)) {
        return false;
    }
    
    LOG_CH_TRACE(log::Channel::kHlil, "HLIL structure complete: {} stmts", debug::count_stmts(function));
    
    hlil::HlilOptOptions options;
    bool result = hlil::optimize_hlil(function, options, error);
    
    LOG_CH_DEBUG(log::Channel::kHlil, "HLIL complete: {} stmts", debug::count_stmts(function));
    return result;
}

bool Session::build_llir_ssa_x86_64(std::uint64_t entry,
                                    std::size_t max_instructions,
                                    llir::Function& function,
                                    std::string& error) const {
    if (!llir::build_cfg_x86_64(image_, entry, max_instructions, function, error)) {
        return false;
    }
    const bool is_windows = binary_info_.format == BinaryFormat::kPe;
    const auto& clobbers = is_windows ? arch::x86_64::call_clobbers_win64()
                                      : arch::x86_64::call_clobbers_sysv();
    if (!llir::build_ssa_with_call_clobbers(function, clobbers, error)) {
        return false;
    }
    if (!llir::lift_stack_vars(function, error)) {
        return false;
    }
    llir::LlilOptOptions options;
    if (!llir::optimize_llil_ssa(function, options, error)) {
        return false;
    }
    if (!llir::resolve_indirect_branches(function, error)) {
        return false;
    }
    // Resolve jump tables for switch statement recovery
    if (!llir::resolve_jump_tables(function, image_, segments_, error)) {
        return false;
    }
    return true;
}

bool Session::build_mlil_ssa_x86_64(std::uint64_t entry,
                                    std::size_t max_instructions,
                                    mlil::Function& function,
                                    std::string& error) const {
    LOG_CH_DEBUG(log::Channel::kMlil, "build_mlil_ssa_x86_64: entry=0x{:x}", entry);
    
    llir::Function llir_function;
    if (!build_llir_ssa_x86_64(entry, max_instructions, llir_function, error)) {
        return false;
    }
    
    LOG_CH_TRACE(log::Channel::kMlil, "LLIR complete: {} blocks, {} stmts", 
                 llir_function.blocks.size(), debug::count_stmts(llir_function));
    
    if (!mlil::build_mlil_from_llil_ssa(llir_function, function, error)) {
        return false;
    }
    
    LOG_CH_TRACE(log::Channel::kMlil, "MLIL lift complete: {} blocks, {} stmts",
                 function.blocks.size(), debug::count_stmts(function));
    
    // Note: We skip mlil::build_ssa_with_call_clobbers here because LLIR already
    // has correct SSA information. Rebuilding SSA in MLIL would overwrite the
    // correct version numbers from LLIR, causing issues like xor(a, b) becoming
    // xor(a, a) when both operands are different versions of the same register.
    // The call clobbers are already handled in LLIR SSA construction.
    
    mlil::MlilOptOptions options;
    // Disable copy propagation to prevent incorrect variable merging
    options.copy_propagation = false;
    bool result = mlil::optimize_mlil_ssa(function, options, error);
    
    LOG_CH_DEBUG(log::Channel::kMlil, "MLIL opt complete: {} stmts", debug::count_stmts(function));
    return result;
}

bool Session::build_hlil_x86_64(std::uint64_t entry,
                                std::size_t max_instructions,
                                hlil::Function& function,
                                std::string& error) const {
    LOG_CH_DEBUG(log::Channel::kHlil, "build_hlil_x86_64: entry=0x{:x}", entry);
    
    mlil::Function mlil_function;
    if (!build_mlil_ssa_x86_64(entry, max_instructions, mlil_function, error)) {
        return false;
    }
    if (!hlil::build_hlil_from_mlil(mlil_function, function, error)) {
        return false;
    }
    
    LOG_CH_TRACE(log::Channel::kHlil, "HLIL structure complete: {} stmts", debug::count_stmts(function));
    
    hlil::HlilOptOptions options;
    bool result = hlil::optimize_hlil(function, options, error);
    
    LOG_CH_DEBUG(log::Channel::kHlil, "HLIL complete: {} stmts", debug::count_stmts(function));
    return result;
}

bool Session::discover_llir_functions_arm64(std::uint64_t entry,
                                            std::size_t max_instructions_per_function,
                                            const analysis::FunctionDiscoveryOptions& options,
                                            std::vector<llir::Function>& functions,
                                            std::string& error) const {
    analysis::FunctionDiscoveryOptions local_options = options;
    if (!local_options.symbols) {
        local_options.symbols = &symbols_;
    }
    if (!local_options.sections) {
        local_options.sections = &sections_;
    }
    if (!local_options.segments) {
        local_options.segments = &segments_;
    }
    if (!local_options.relocations) {
        local_options.relocations = &relocations_;
    }
    if (!local_options.binary_info) {
        local_options.binary_info = &binary_info_;
    }
    if (!local_options.eh_frame) {
        local_options.eh_frame = &eh_frame_catalog_;
    }
    if (!local_options.dwarf) {
        local_options.dwarf = &dwarf_catalog_;
    }
    return analysis::discover_functions_arm64(image_, entry, max_instructions_per_function, local_options, functions,
                                              error);
}

bool Session::discover_llir_functions_x86_64(std::uint64_t entry,
                                             std::size_t max_instructions_per_function,
                                             const analysis::FunctionDiscoveryOptions& options,
                                             std::vector<llir::Function>& functions,
                                             std::string& error) const {
    analysis::FunctionDiscoveryOptions local_options = options;
    if (!local_options.symbols) {
        local_options.symbols = &symbols_;
    }
    if (!local_options.sections) {
        local_options.sections = &sections_;
    }
    if (!local_options.segments) {
        local_options.segments = &segments_;
    }
    if (!local_options.relocations) {
        local_options.relocations = &relocations_;
    }
    if (!local_options.binary_info) {
        local_options.binary_info = &binary_info_;
    }
    if (!local_options.eh_frame) {
        local_options.eh_frame = &eh_frame_catalog_;
    }
    if (!local_options.dwarf) {
        local_options.dwarf = &dwarf_catalog_;
    }
    return analysis::discover_functions_x86_64(image_, entry, max_instructions_per_function, local_options, functions,
                                               error);
}

bool Session::discover_function_ranges_arm64(std::uint64_t entry,
                                             std::size_t max_instructions_per_function,
                                             const analysis::FunctionDiscoveryOptions& options,
                                             std::vector<analysis::FunctionRange>& ranges,
                                             std::string& error) const {
    analysis::FunctionDiscoveryOptions local_options = options;
    if (!local_options.symbols) {
        local_options.symbols = &symbols_;
    }
    if (!local_options.sections) {
        local_options.sections = &sections_;
    }
    if (!local_options.segments) {
        local_options.segments = &segments_;
    }
    if (!local_options.relocations) {
        local_options.relocations = &relocations_;
    }
    if (!local_options.binary_info) {
        local_options.binary_info = &binary_info_;
    }
    if (!local_options.eh_frame) {
        local_options.eh_frame = &eh_frame_catalog_;
    }
    if (!local_options.dwarf) {
        local_options.dwarf = &dwarf_catalog_;
    }

    return analysis::discover_function_ranges_arm64(image_,
                                                    entry,
                                                    max_instructions_per_function,
                                                    local_options,
                                                    ranges,
                                                    error);
}

bool Session::discover_function_ranges_x86_64(std::uint64_t entry,
                                              std::size_t max_instructions_per_function,
                                              const analysis::FunctionDiscoveryOptions& options,
                                              std::vector<analysis::FunctionRange>& ranges,
                                              std::string& error) const {
    analysis::FunctionDiscoveryOptions local_options = options;
    if (!local_options.symbols) {
        local_options.symbols = &symbols_;
    }
    if (!local_options.sections) {
        local_options.sections = &sections_;
    }
    if (!local_options.segments) {
        local_options.segments = &segments_;
    }
    if (!local_options.relocations) {
        local_options.relocations = &relocations_;
    }
    if (!local_options.binary_info) {
        local_options.binary_info = &binary_info_;
    }
    if (!local_options.eh_frame) {
        local_options.eh_frame = &eh_frame_catalog_;
    }
    if (!local_options.dwarf) {
        local_options.dwarf = &dwarf_catalog_;
    }

    return analysis::discover_function_ranges_x86_64(image_,
                                                     entry,
                                                     max_instructions_per_function,
                                                     local_options,
                                                     ranges,
                                                     error);
}

void Session::try_load_pdb() {
    std::string pdb_candidate;
    if (!find_pdb_for_pe(path_, pdb_candidate)) {
        SPDLOG_DEBUG("No PDB file found for {}", path_);
        return;
    }

    SPDLOG_INFO("Found PDB file: {}", pdb_candidate);

    PdbLoadOptions options;
    PdbLoadResult result = load_pdb_symbols(pdb_candidate, binary_info_.image_base, symbols_, options);
    
    if (!result.success) {
        SPDLOG_WARN("Failed to load PDB: {}", result.error);
        return;
    }

    pdb_path_ = pdb_candidate;
    has_pdb_symbols_ = true;

    // Re-populate symbol table with new symbols
    symbol_table_.populate(symbols_, sections_);

    SPDLOG_INFO("Loaded PDB symbols: {} public, {} global, {} functions, {} from modules",
                result.public_symbols, result.global_symbols,
                result.function_symbols, result.module_symbols);
}

PdbLoadResult Session::load_pdb(const std::string& pdb_path, const PdbLoadOptions& options) {
    PdbLoadResult result = load_pdb_symbols(pdb_path, binary_info_.image_base, symbols_, options);
    
    if (result.success) {
        pdb_path_ = pdb_path;
        has_pdb_symbols_ = true;

        // Re-populate symbol table with new symbols
        symbol_table_.populate(symbols_, sections_);
    }

    return result;
}

bool Session::has_pdb_symbols() const {
    return has_pdb_symbols_;
}

const std::string& Session::pdb_path() const {
    return pdb_path_;
}

}  // namespace engine
