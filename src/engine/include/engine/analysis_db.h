#pragma once

#include <memory>
#include <string>
#include <vector>

#include "engine/function_discovery.h"
#include "engine/xrefs.h"

namespace engine::analysis_db {

class AnalysisDb {
public:
    virtual ~AnalysisDb() = default;

    virtual bool open(const std::string& path, std::string& error) = 0;
    virtual bool init_schema(std::string& error) = 0;
    virtual bool clear(std::string& error) = 0;
    virtual bool write_meta(const std::string& key, const std::string& value, std::string& error) = 0;
    virtual bool write_seeds(const std::vector<analysis::SeedEntry>& seeds, std::string& error) = 0;
    virtual bool write_xrefs(const std::vector<xrefs::XrefEntry>& xrefs, std::string& error) = 0;
    virtual void close() = 0;
};

std::unique_ptr<AnalysisDb> create_sqlite_db();

}  // namespace engine::analysis_db
