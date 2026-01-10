#pragma once

#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "engine/binary_format.h"

namespace test_helpers {

inline std::optional<std::filesystem::path> find_sample_path(const std::string& relative) {
    std::filesystem::path base = std::filesystem::current_path();
    while (true) {
        std::filesystem::path candidate = base / relative;
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
        if (!base.has_parent_path() || base.parent_path() == base) {
            break;
        }
        base = base.parent_path();
    }
    return std::nullopt;
}

inline bool addr_in_segment(std::uint64_t addr, const engine::BinarySegment& seg) {
    if (seg.memsz == 0) {
        return false;
    }
    if (addr < seg.vaddr) {
        return false;
    }
    return (addr - seg.vaddr) < seg.memsz;
}

inline bool addr_in_any_segment(std::uint64_t addr,
                                const std::vector<engine::BinarySegment>& segments,
                                std::uint32_t flag_mask = 0) {
    for (const auto& seg : segments) {
        if (flag_mask != 0 && (seg.flags & flag_mask) != flag_mask) {
            continue;
        }
        if (addr_in_segment(addr, seg)) {
            return true;
        }
    }
    return false;
}

inline std::filesystem::path make_temp_path(const std::string& prefix) {
    static std::uint64_t counter = 0;
    const auto stamp =
        static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    const std::string name =
        prefix + "_" + std::to_string(stamp) + "_" + std::to_string(++counter);
    return std::filesystem::temp_directory_path() / name;
}

inline bool write_binary_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return false;
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    return out.good();
}

class ScopedTempFile {
public:
    ScopedTempFile(const std::string& prefix, const std::vector<std::uint8_t>& data)
        : path_(make_temp_path(prefix)) {
        write_binary_file(path_, data);
    }

    ~ScopedTempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

}  // namespace test_helpers
