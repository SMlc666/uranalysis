#pragma once

#include "engine/plugin/session.h"
#include "engine/session.h"

#include <string>

namespace engine::plugin {

/// Implementation of ISession that wraps engine::Session
class SessionWrapper : public ObjectBase, public ISession {
public:
    explicit SessionWrapper(Session* session);
    virtual ~SessionWrapper() = default;

    // IObject
    void retain() override { ObjectBase::retain(); }
    void release() override { ObjectBase::release(); }
    std::int32_t ref_count() const override { return ObjectBase::ref_count(); }

    // ISession - State
    bool is_loaded() const override;
    const char* file_path() const override;

    // ISession - Binary Info
    const IBinaryInfo* binary_info() const override;

    // ISession - Memory
    const IImage* image() const override;

    // ISession - Symbols
    const ISymbolTable* symbol_table() const override;

    // ISession - Navigation
    std::uint64_t cursor() const override;
    void set_cursor(std::uint64_t addr) override;

    // ISession - Disassembly
    std::size_t disassemble_text(std::uint64_t addr, 
                                 std::size_t max_instructions,
                                 char* buffer, 
                                 std::size_t buffer_size) const override;

private:
    Session* session_;

    // Cached wrappers (created on demand)
    class BinaryInfoWrapper;
    class ImageWrapper;
    class SymbolTableWrapper;

    mutable std::unique_ptr<BinaryInfoWrapper> binary_info_wrapper_;
    mutable std::unique_ptr<ImageWrapper> image_wrapper_;
    mutable std::unique_ptr<SymbolTableWrapper> symbol_table_wrapper_;
};

}  // namespace engine::plugin
