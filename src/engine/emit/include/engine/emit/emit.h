#pragma once

#include <string>
#include <vector>

#include "engine/decompiler.h"
#include "engine/emit/lex/writer.h"
#include "engine/emit/opt/naming.h"
#include "engine/emit/syn/formatter.h"
#include "engine/emit/token.h"

namespace engine::emit {

/// Options for emit operations.
struct EmitOptions {
    syn::FormatOptions format;
    opt::NamingOptions naming;
    bool apply_sugar = true;
};

/// Emit a decompiler function to a writer.
void emit_function(const decompiler::Function& func,
                   lex::Writer& writer,
                   const EmitOptions& opts = {});

/// Emit a decompiler function to a string.
std::string to_string(const decompiler::Function& func,
                      const EmitOptions& opts = {});

/// Emit a decompiler function to lines.
std::vector<std::string> to_lines(const decompiler::Function& func,
                                  const EmitOptions& opts = {});

/// Emit a decompiler function to a token stream.
std::vector<Token> to_tokens(const decompiler::Function& func,
                             const EmitOptions& opts = {});

}  // namespace engine::emit
