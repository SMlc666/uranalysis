#pragma once

#include "engine/plugin/object.h"
#include "engine/plugin/types.h"

namespace engine::plugin {

// Forward declaration
struct ISession;

/// ABI-safe output interface for command results.
/// 
/// Commands write their output through this interface instead of
/// directly to stdout or returning strings.
struct IOutput : public IObject {
    virtual ~IOutput() = default;

    /// Write a line of text output
    virtual void write_line(const char* text) = 0;

    /// Write text without a trailing newline
    virtual void write(const char* text) = 0;

    /// Write an error message
    virtual void write_error(const char* text) = 0;

    /// Write a formatted line (convenience wrapper)
    /// Note: format is a simple %s substitution for ABI safety
    virtual void write_fmt(const char* format, const char* arg) = 0;
};

/// ABI-safe argument accessor for commands.
/// 
/// Provides access to parsed command-line arguments.
struct IArgs : public IObject {
    virtual ~IArgs() = default;

    /// Get the number of positional arguments
    virtual std::size_t positional_count() const = 0;

    /// Get a positional argument by index (nullptr if out of range)
    virtual const char* positional(std::size_t index) const = 0;

    /// Check if a flag is set
    virtual bool has_flag(const char* name) const = 0;

    /// Get an option value (nullptr if not present)
    virtual const char* option(const char* name) const = 0;

    /// Get raw argument string at index
    virtual const char* raw_arg(std::size_t index) const = 0;

    /// Get total raw argument count
    virtual std::size_t raw_count() const = 0;
};

/// Command interface for plugin-provided commands.
/// 
/// Usage:
///     class MyCommand : public CommandBase {
///         const char* name() const override { return "mycmd"; }
///         const char* help() const override { return "Does something"; }
///         
///         Result execute(ISession* session, IOutput* output, IArgs* args) override {
///             output->write_line("Hello from plugin!");
///             return Result::Ok;
///         }
///     };
struct ICommand : public IObject {
    virtual ~ICommand() = default;

    /// Get the command name (used to invoke it)
    virtual const char* name() const = 0;

    /// Get short help text (one line)
    virtual const char* help() const = 0;

    /// Get detailed help text (multi-line, optional)
    virtual const char* detailed_help() const = 0;

    /// Get command aliases (comma-separated, e.g., "s,sk")
    /// Returns nullptr or empty string if no aliases
    virtual const char* aliases() const = 0;

    /// Check if this command requires a file to be loaded
    virtual bool requires_file() const = 0;

    /// Execute the command
    /// 
    /// @param session Current session (may be nullptr if no file loaded)
    /// @param output Output interface for writing results
    /// @param args Parsed arguments
    /// @return Result::Ok on success, error code on failure
    virtual Result execute(ISession* session, IOutput* output, IArgs* args) = 0;
};

/// Helper base class for implementing ICommand.
class CommandBase : public ObjectBase, public ICommand {
public:
    CommandBase() = default;
    virtual ~CommandBase() = default;

    // IObject forwarding
    void retain() override { ObjectBase::retain(); }
    void release() override { ObjectBase::release(); }
    std::int32_t ref_count() const override { return ObjectBase::ref_count(); }

    // Default implementations
    const char* detailed_help() const override { return nullptr; }
    const char* aliases() const override { return nullptr; }
    bool requires_file() const override { return false; }
};

}  // namespace engine::plugin
