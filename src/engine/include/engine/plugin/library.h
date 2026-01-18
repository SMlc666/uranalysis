#pragma once

#include <string>

namespace engine::plugin {

/// Handle to a dynamically loaded library.
/// 
/// Platform-independent abstraction over LoadLibrary/dlopen.
/// RAII - automatically unloads when destroyed.
class Library {
public:
    Library() = default;
    ~Library();

    // Non-copyable
    Library(const Library&) = delete;
    Library& operator=(const Library&) = delete;

    // Movable
    Library(Library&& other) noexcept;
    Library& operator=(Library&& other) noexcept;

    /// Load a dynamic library from the given path.
    /// 
    /// @param path Path to the library (.dll on Windows, .so on Linux)
    /// @return true on success, false on failure (check error())
    bool load(const std::string& path);

    /// Unload the library if loaded.
    void unload();

    /// Check if a library is currently loaded.
    bool is_loaded() const { return handle_ != nullptr; }

    /// Get a symbol (function pointer) from the library.
    /// 
    /// @param name The symbol name to look up
    /// @return Pointer to the symbol, or nullptr if not found
    void* get_symbol(const char* name) const;

    /// Typed version of get_symbol for function pointers.
    /// 
    /// Usage: auto func = lib.get_function<int(*)(const char*)>("my_function");
    template <typename FuncPtr>
    FuncPtr get_function(const char* name) const {
        return reinterpret_cast<FuncPtr>(get_symbol(name));
    }

    /// Get the path of the loaded library.
    const std::string& path() const { return path_; }

    /// Get the last error message (if load() failed).
    const std::string& error() const { return error_; }

    /// Get the file extension for dynamic libraries on this platform.
    static const char* library_extension();

    /// Get the file prefix for dynamic libraries on this platform.
    /// Returns "lib" on Unix, "" on Windows.
    static const char* library_prefix();

private:
    void* handle_ = nullptr;
    std::string path_;
    std::string error_;
};

}  // namespace engine::plugin
