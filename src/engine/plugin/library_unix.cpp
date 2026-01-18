#include "engine/plugin/library.h"

#if !defined(_WIN32) && !defined(_WIN64)

#include <dlfcn.h>

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
    
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char* err = dlerror();
        error_ = std::string("Failed to load library: ") + (err ? err : "unknown error");
        return false;
    }
    
    handle_ = handle;
    path_ = path;
    error_.clear();
    return true;
}

void Library::unload() {
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    path_.clear();
}

void* Library::get_symbol(const char* name) const {
    if (!handle_) {
        return nullptr;
    }
    // Clear any existing error
    dlerror();
    return dlsym(handle_, name);
}

const char* Library::library_extension() {
#ifdef __APPLE__
    return ".dylib";
#else
    return ".so";
#endif
}

const char* Library::library_prefix() {
    return "lib";
}

}  // namespace engine::plugin

#endif  // !_WIN32 && !_WIN64
