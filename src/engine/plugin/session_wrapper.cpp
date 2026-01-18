#include "session_wrapper.h"
#include "engine/disasm.h"

#include <cstring>
#include <sstream>

namespace engine::plugin {

// =============================================================================
// BinaryInfoWrapper
// =============================================================================

class SessionWrapper::BinaryInfoWrapper : public IBinaryInfo {
public:
    explicit BinaryInfoWrapper(const Session* session) : session_(session) {}

    const char* format() const override {
        if (format_cache_.empty() && session_->loaded()) {
            const auto& info = session_->binary_info();
            switch (info.format) {
                case BinaryFormat::kElf: format_cache_ = "ELF"; break;
                case BinaryFormat::kPe: format_cache_ = "PE"; break;
                default: format_cache_ = "Unknown"; break;
            }
        }
        return format_cache_.c_str();
    }

    const char* machine() const override {
        if (machine_cache_.empty() && session_->loaded()) {
            const auto& info = session_->binary_info();
            switch (info.machine) {
                case BinaryMachine::kAarch64: machine_cache_ = "ARM64"; break;
                case BinaryMachine::kX86_64: machine_cache_ = "X86_64"; break;
                case BinaryMachine::kX86: machine_cache_ = "X86"; break;
                default: machine_cache_ = "Unknown"; break;
            }
        }
        return machine_cache_.c_str();
    }

    std::uint32_t bits() const override {
        if (!session_->loaded()) return 0;
        return session_->binary_info().is_64 ? 64 : 32;
    }

    bool is_little_endian() const override {
        if (!session_->loaded()) return true;
        return session_->binary_info().little_endian;
    }

    std::uint64_t entry_point() const override {
        if (!session_->loaded()) return 0;
        return session_->binary_info().entry;
    }

    std::uint64_t image_base() const override {
        if (!session_->loaded()) return 0;
        return session_->binary_info().image_base;
    }

private:
    const Session* session_;
    mutable std::string format_cache_;
    mutable std::string machine_cache_;
};

// =============================================================================
// ImageWrapper
// =============================================================================

class SessionWrapper::ImageWrapper : public IImage {
public:
    explicit ImageWrapper(const Session* session) : session_(session) {}

    std::size_t read_bytes(std::uint64_t addr, std::size_t size, 
                          std::uint8_t* buffer) const override {
        if (!session_->loaded() || !buffer || size == 0) return 0;
        
        std::vector<std::uint8_t> data;
        if (!session_->image().read_bytes(addr, size, data)) {
            return 0;
        }
        
        std::size_t copied = std::min(size, data.size());
        std::memcpy(buffer, data.data(), copied);
        return copied;
    }

    bool is_mapped(std::uint64_t addr) const override {
        if (!session_->loaded()) return false;
        // Check if address falls within any segment
        for (const auto& seg : session_->segments()) {
            if (addr >= seg.vaddr && addr < seg.vaddr + seg.memsz) {
                return true;
            }
        }
        return false;
    }

    std::uint64_t base_address() const override {
        if (!session_->loaded()) return 0;
        return session_->binary_info().image_base;
    }

    std::size_t size() const override {
        if (!session_->loaded()) return 0;
        // Return the size of loaded image based on segments
        std::uint64_t max_addr = 0;
        std::uint64_t min_addr = UINT64_MAX;
        for (const auto& seg : session_->segments()) {
            if (seg.vaddr < min_addr) min_addr = seg.vaddr;
            if (seg.vaddr + seg.memsz > max_addr) max_addr = seg.vaddr + seg.memsz;
        }
        if (min_addr == UINT64_MAX) return 0;
        return static_cast<std::size_t>(max_addr - min_addr);
    }

private:
    const Session* session_;
};

// =============================================================================
// SymbolTableWrapper
// =============================================================================

class SessionWrapper::SymbolTableWrapper : public ISymbolTable {
public:
    explicit SymbolTableWrapper(const Session* session) : session_(session) {}

    std::size_t count() const override {
        if (!session_->loaded()) return 0;
        return session_->symbols().size();
    }

    const char* name_at(std::size_t index) const override {
        if (!session_->loaded()) return nullptr;
        const auto& syms = session_->symbols();
        if (index >= syms.size()) return nullptr;
        return syms[index].name.c_str();
    }

    std::uint64_t address_at(std::size_t index) const override {
        if (!session_->loaded()) return 0;
        const auto& syms = session_->symbols();
        if (index >= syms.size()) return 0;
        return syms[index].value;
    }

    std::uint64_t find_by_name(const char* name) const override {
        if (!session_->loaded() || !name) return 0;
        for (const auto& sym : session_->symbols()) {
            if (sym.name == name) {
                return sym.value;
            }
        }
        return 0;
    }

    const char* find_by_address(std::uint64_t addr) const override {
        if (!session_->loaded()) return nullptr;
        // Linear search through symbols for exact match
        for (const auto& sym : session_->symbols()) {
            if (sym.value == addr && !sym.name.empty()) {
                // Cache the result since we're returning a pointer
                last_lookup_ = sym.name;
                return last_lookup_.c_str();
            }
        }
        return nullptr;
    }

private:
    const Session* session_;
    mutable std::string last_lookup_;
};

// =============================================================================
// SessionWrapper
// =============================================================================

SessionWrapper::SessionWrapper(Session* session) : session_(session) {}

bool SessionWrapper::is_loaded() const {
    return session_ && session_->loaded();
}

const char* SessionWrapper::file_path() const {
    if (!session_) return "";
    return session_->path().c_str();
}

const IBinaryInfo* SessionWrapper::binary_info() const {
    if (!binary_info_wrapper_) {
        binary_info_wrapper_ = std::make_unique<BinaryInfoWrapper>(session_);
    }
    return binary_info_wrapper_.get();
}

const IImage* SessionWrapper::image() const {
    if (!image_wrapper_) {
        image_wrapper_ = std::make_unique<ImageWrapper>(session_);
    }
    return image_wrapper_.get();
}

const ISymbolTable* SessionWrapper::symbol_table() const {
    if (!symbol_table_wrapper_) {
        symbol_table_wrapper_ = std::make_unique<SymbolTableWrapper>(session_);
    }
    return symbol_table_wrapper_.get();
}

std::uint64_t SessionWrapper::cursor() const {
    if (!session_) return 0;
    return session_->cursor();
}

void SessionWrapper::set_cursor(std::uint64_t addr) {
    if (session_) {
        session_->set_cursor(addr);
    }
}

std::size_t SessionWrapper::disassemble_text(std::uint64_t addr, 
                                             std::size_t max_instructions,
                                             char* buffer, 
                                             std::size_t buffer_size) const {
    if (!session_ || !session_->loaded() || !buffer || buffer_size == 0) {
        return 0;
    }

    std::vector<DisasmLine> lines;
    std::string error;
    bool success = false;

    const auto& info = session_->binary_info();
    if (info.machine == BinaryMachine::kAarch64) {
        success = session_->disasm_arm64(addr, 4 * max_instructions, max_instructions, lines, error);
    } else if (info.machine == BinaryMachine::kX86_64) {
        success = session_->disasm_x86_64(addr, 15 * max_instructions, max_instructions, lines, error);
    }

    if (!success || lines.empty()) {
        return 0;
    }

    // Format output
    std::ostringstream oss;
    for (const auto& line : lines) {
        oss << std::hex << line.address << "  " << line.text << "\n";
    }

    std::string result = oss.str();
    std::size_t copy_size = std::min(result.size(), buffer_size - 1);
    std::memcpy(buffer, result.data(), copy_size);
    buffer[copy_size] = '\0';
    
    return copy_size;
}

}  // namespace engine::plugin
