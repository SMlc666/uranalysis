#include "engine/emit/emit.h"

namespace engine::emit {

void emit_function(const decompiler::Function& func,
                   lex::Writer& writer,
                   const EmitOptions& opts) {
    syn::Formatter formatter(writer, opts.format);
    formatter.function(func);
}

std::string to_string(const decompiler::Function& func,
                      const EmitOptions& opts) {
    lex::StringWriter writer(opts.format.indent_width);
    emit_function(func, writer, opts);
    return writer.str();
}

std::vector<std::string> to_lines(const decompiler::Function& func,
                                  const EmitOptions& opts) {
    lex::StringWriter writer(opts.format.indent_width);
    emit_function(func, writer, opts);
    return writer.lines();
}

std::vector<Token> to_tokens(const decompiler::Function& func,
                             const EmitOptions& opts) {
    lex::TokenWriter writer;
    emit_function(func, writer, opts);
    return writer.take_tokens();
}

}  // namespace engine::emit
