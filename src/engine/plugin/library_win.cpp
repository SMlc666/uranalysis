#include "engine/plugin/library.h"

#if defined(_WIN32) || defined(_WIN64)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace engine::plugin {

Library::~Library() {
    unload();
}

Library::Library(Library&& other) noexcept
    : handle_(other.handle_), path_(std::move(other.path_)), error_(std::move(other.error_)) {
    other.handle_ = nullptr;
}

Library& Library::operator=(Library&& other) noexcept {
    if (this != &other) {
        unload();
        handle_ = other.handle_;
        path_ = std::move(other.path_);
        error_ = std::move(other.error_);
        other.handle_ = nullptr;
    }
    return *this;
}

bool Library::load(const std::string& path) {
    unload();
    
    HMODULE module = LoadLibraryA(path.c_str());
    if (!module) {
        DWORD err = GetLastError();
        char buf[256];
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf, sizeof(buf), nullptr);
        error_ = std::string("Failed to load library: ") + buf;
        return false;
    }
    
    handle_ = static_cast<void*>(module);
    path_ = path;
    error_.clear();
    return true;
}

void Library::unload() {
    if (handle_) {
        FreeLibrary(static_cast<HMODULE>(handle_));
        handle_ = nullptr;
    }
    path_.clear();
}

void* Library::get_symbol(const char* name) const {
    if (!handle_) {
        return nullptr;
    }
    return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(handle_), name));
}

const char* Library::library_extension() {
    return ".dll";
}

const char* Library::library_prefix() {
    return "";
}

}  // namespace engine::plugin

#endif  // _WIN32 || _WIN64
