#pragma once

#include <string>

namespace engine {

struct EngineInfo {
    std::string name;
    std::string version;
};

EngineInfo get_engine_info();

}  // namespace engine
