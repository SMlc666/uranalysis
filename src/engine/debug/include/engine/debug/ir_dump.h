#pragma once

/// @file ir_dump.h
/// @brief IR dumping utilities for debugging.
///
/// Provides text serialization of LLIR/MLIR/HLIR for debugging purposes.
/// All dump functions output to ostream or return strings.

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/hlil.h"

namespace engine::debug {

// ============================================================================
// Formatting Options
// ============================================================================

/// Options for IR dump formatting.
struct DumpOptions {
    /// Include original assembly mnemonic/operands in LLIR output.
    bool include_asm = true;

    /// Include SSA version numbers (e.g., x0#3 instead of x0).
    bool include_ssa_versions = true;

    /// Include block address ranges.
    bool include_block_ranges = true;

    /// Include phi nodes at block start.
    bool include_phis = true;

    /// Include statement comments.
    bool include_comments = true;

    /// Indentation string (default 4 spaces).
    std::string indent = "    ";
};

/// Global default options (can be modified at runtime).
DumpOptions& default_dump_options();

// ============================================================================
// Address Formatting
// ============================================================================

/// Format address as hex string (e.g., "0x1000").
std::string hex(std::uint64_t addr);

// ============================================================================
// LLIR Dump Functions
// ============================================================================

/// Get name string for LLIR operation.
const char* op_name(llir::LlilOp op);

/// Dump LLIR register reference.
std::string dump(const llir::RegRef& reg, const DumpOptions& opts = default_dump_options());

/// Dump LLIR variable reference.
std::string dump(const llir::VarRef& var, const DumpOptions& opts = default_dump_options());

/// Dump LLIR expression.
std::string dump(const llir::LlilExpr& expr, const DumpOptions& opts = default_dump_options());

/// Dump LLIR statement.
std::string dump(const llir::LlilStmt& stmt, const DumpOptions& opts = default_dump_options());

/// Dump LLIR function to lines.
void dump(const llir::Function& func, std::vector<std::string>& lines, 
          const DumpOptions& opts = default_dump_options());

/// Dump LLIR function to string.
std::string dump(const llir::Function& func, const DumpOptions& opts = default_dump_options());

/// Dump LLIR function to ostream.
void dump(const llir::Function& func, std::ostream& os, 
          const DumpOptions& opts = default_dump_options());

// ============================================================================
// MLIL Dump Functions
// ============================================================================

/// Get name string for MLIL operation.
const char* op_name(mlil::MlilOp op);

/// Dump MLIL variable reference.
std::string dump(const mlil::VarRef& var, const DumpOptions& opts = default_dump_options());

/// Dump MLIL expression.
std::string dump(const mlil::MlilExpr& expr, const DumpOptions& opts = default_dump_options());

/// Dump MLIL statement.
std::string dump(const mlil::MlilStmt& stmt, const DumpOptions& opts = default_dump_options());

/// Dump MLIL function to lines.
void dump(const mlil::Function& func, std::vector<std::string>& lines,
          const DumpOptions& opts = default_dump_options());

/// Dump MLIL function to string.
std::string dump(const mlil::Function& func, const DumpOptions& opts = default_dump_options());

/// Dump MLIL function to ostream.
void dump(const mlil::Function& func, std::ostream& os,
          const DumpOptions& opts = default_dump_options());

// ============================================================================
// HLIL Dump Functions
// ============================================================================

/// Dump HLIL statement with indentation level.
std::string dump(const hlil::HlilStmt& stmt, int indent = 0,
                 const DumpOptions& opts = default_dump_options());

/// Dump HLIL statement block to lines.
void dump_block(const std::vector<hlil::HlilStmt>& stmts, int indent,
                std::vector<std::string>& lines,
                const DumpOptions& opts = default_dump_options());

/// Dump HLIL function to lines.
void dump(const hlil::Function& func, std::vector<std::string>& lines,
          const DumpOptions& opts = default_dump_options());

/// Dump HLIL function to string.
std::string dump(const hlil::Function& func, const DumpOptions& opts = default_dump_options());

/// Dump HLIL function to ostream.
void dump(const hlil::Function& func, std::ostream& os,
          const DumpOptions& opts = default_dump_options());

// ============================================================================
// Utility Functions
// ============================================================================

/// Calculate discovered function size from LLIR blocks.
std::uint64_t discovered_size(const llir::Function& func);

/// Count statements in LLIR function.
std::size_t count_stmts(const llir::Function& func);

/// Count statements in MLIL function.
std::size_t count_stmts(const mlil::Function& func);

/// Count statements in HLIL function (recursive).
std::size_t count_stmts(const hlil::Function& func);

}  // namespace engine::debug
