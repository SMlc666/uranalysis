#pragma once

#include "engine/plugin/object.h"
#include "engine/plugin/types.h"

#include <cstdint>

namespace engine::plugin {

/// ABI-safe interface for accessing binary metadata.
struct IBinaryInfo {
    virtual ~IBinaryInfo() = default;

    virtual const char* format() const = 0;        // "ELF", "PE", etc.
    virtual const char* machine() const = 0;       // "ARM64", "X86_64", etc.
    virtual std::uint32_t bits() const = 0;        // 32 or 64
    virtual bool is_little_endian() const = 0;
    virtual std::uint64_t entry_point() const = 0;
    virtual std::uint64_t image_base() const = 0;
};

/// ABI-safe interface for accessing loaded image memory.
struct IImage {
    virtual ~IImage() = default;

    /// Read bytes from the image at the given virtual address.
    /// @param addr Virtual address to read from
    /// @param size Number of bytes to read
    /// @param buffer Output buffer (must be at least size bytes)
    /// @return Number of bytes actually read (0 on error)
    virtual std::size_t read_bytes(std::uint64_t addr, std::size_t size, 
                                   std::uint8_t* buffer) const = 0;

    /// Check if an address is mapped in the image.
    virtual bool is_mapped(std::uint64_t addr) const = 0;

    /// Get the base address of the loaded image.
    virtual std::uint64_t base_address() const = 0;

    /// Get the size of the loaded image.
    virtual std::size_t size() const = 0;
};

/// ABI-safe interface for accessing symbols.
struct ISymbolTable {
    virtual ~ISymbolTable() = default;

    /// Get the number of symbols
    virtual std::size_t count() const = 0;

    /// Get symbol name by index (nullptr if out of range)
    virtual const char* name_at(std::size_t index) const = 0;

    /// Get symbol address by index (0 if out of range)
    virtual std::uint64_t address_at(std::size_t index) const = 0;

    /// Find symbol by name (returns address, 0 if not found)
    virtual std::uint64_t find_by_name(const char* name) const = 0;

    /// Find symbol by address (returns name, nullptr if not found)
    virtual const char* find_by_address(std::uint64_t addr) const = 0;
};

/// ABI-safe session interface.
/// 
/// Provides plugin access to the analysis session without exposing
/// internal engine types. Methods return simple types or ABI-safe
/// interfaces.
struct ISession : public IObject {
    virtual ~ISession() = default;

    // =========================================================================
    // Session State
    // =========================================================================

    /// Check if a file is currently loaded
    virtual bool is_loaded() const = 0;

    /// Get the path of the loaded file
    virtual const char* file_path() const = 0;

    // =========================================================================
    // Binary Info
    // =========================================================================

    /// Get binary metadata (format, architecture, etc.)
    virtual const IBinaryInfo* binary_info() const = 0;

    // =========================================================================
    // Memory Access
    // =========================================================================

    /// Get image interface for memory reading
    virtual const IImage* image() const = 0;

    // =========================================================================
    // Symbols
    // =========================================================================

    /// Get symbol table interface
    virtual const ISymbolTable* symbol_table() const = 0;

    // =========================================================================
    // Navigation
    // =========================================================================

    /// Get current cursor address
    virtual std::uint64_t cursor() const = 0;

    /// Set current cursor address
    virtual void set_cursor(std::uint64_t addr) = 0;

    // =========================================================================
    // Disassembly (Simple)
    // =========================================================================

    /// Disassemble at address and return formatted text.
    /// 
    /// @param addr Address to disassemble
    /// @param max_instructions Maximum number of instructions
    /// @param buffer Output buffer for text
    /// @param buffer_size Size of output buffer
    /// @return Number of characters written (0 on error)
    virtual std::size_t disassemble_text(std::uint64_t addr, 
                                         std::size_t max_instructions,
                                         char* buffer, 
                                         std::size_t buffer_size) const = 0;
};

}  // namespace engine::plugin
