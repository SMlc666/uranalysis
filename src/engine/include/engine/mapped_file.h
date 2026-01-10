#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace engine {

class MappedFile {
public:
    ~MappedFile();
    bool open(const std::string& path, std::string& error);
    void close();
    bool valid() const;
    std::span<const std::uint8_t> bytes() const;
    bool slice(std::uint64_t offset, std::size_t size, std::span<const std::uint8_t>& out) const;

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;

#ifdef _WIN32
    void* file_ = nullptr;
    void* mapping_ = nullptr;
#else
    int fd_ = -1;
#endif
};

}  // namespace engine
