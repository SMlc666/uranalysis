#include "engine/mapped_file.h"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace engine {

MappedFile::~MappedFile() {
    close();
}

bool MappedFile::open(const std::string& path, std::string& error) {
    close();
    error.clear();

#ifdef _WIN32
    const HANDLE file_handle = CreateFileA(path.c_str(), GENERIC_READ,
                                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE) {
        error = "failed to open file";
        return false;
    }



    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file_handle, &size) || size.QuadPart <= 0) {
        CloseHandle(file_handle);
        error = "failed to query file size";
        return false;
    }
    const HANDLE mapping_handle = CreateFileMappingA(file_handle, nullptr, PAGE_READONLY,
                                                     0, 0, nullptr);
    if (!mapping_handle) {
        CloseHandle(file_handle);
        error = "failed to create file mapping";
        return false;
    }
    void* mapped = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
    if (!mapped) {
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        error = "failed to map file";
        return false;
    }
    file_ = file_handle;
    mapping_ = mapping_handle;
    data_ = static_cast<const std::uint8_t*>(mapped);
    size_ = static_cast<std::size_t>(size.QuadPart);
    return true;
#else
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        error = "failed to open file";
        return false;
    }
    struct stat st = {};
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        ::close(fd);
        error = "failed to query file size";
        return false;
    }
    void* mapped = mmap(nullptr, static_cast<std::size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        ::close(fd);
        error = "failed to map file";
        return false;
    }
    fd_ = fd;
    data_ = static_cast<const std::uint8_t*>(mapped);
    size_ = static_cast<std::size_t>(st.st_size);
    return true;
#endif
}

void MappedFile::close() {
#ifdef _WIN32
    if (data_) {
        UnmapViewOfFile(data_);
    }
    if (mapping_) {
        CloseHandle(static_cast<HANDLE>(mapping_));
    }
    if (file_) {
        CloseHandle(static_cast<HANDLE>(file_));
    }
    data_ = nullptr;
    size_ = 0;
    file_ = nullptr;
    mapping_ = nullptr;
#else
    if (data_) {
        munmap(const_cast<std::uint8_t*>(data_), size_);
    }
    if (fd_ >= 0) {
        ::close(fd_);
    }
    data_ = nullptr;
    size_ = 0;
    fd_ = -1;
#endif
}

bool MappedFile::valid() const {
    return data_ != nullptr && size_ > 0;
}

std::span<const std::uint8_t> MappedFile::bytes() const {
    if (!valid()) {
        return {};
    }
    return std::span<const std::uint8_t>(data_, size_);
}

bool MappedFile::slice(std::uint64_t offset, std::size_t size,
                       std::span<const std::uint8_t>& out) const {
    if (!valid() || offset > size_) {
        out = {};
        return false;
    }
    if (offset + size > size_) {
        out = {};
        return false;
    }
    out = std::span<const std::uint8_t>(data_ + static_cast<std::size_t>(offset), size);
    return true;
}

}  // namespace engine
