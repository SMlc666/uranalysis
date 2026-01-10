#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "engine/analysis_db.h"
#include "test_helpers.h"

TEST_CASE("SQLite analysis DB initializes and writes data", "[analysis_db]") {
    auto db = engine::analysis_db::create_sqlite_db();
    REQUIRE(db);

    test_helpers::ScopedTempFile file("analysis_db", {});
    std::string error;
    REQUIRE(db->open(file.path().string(), error));
    REQUIRE(db->init_schema(error));

    REQUIRE(db->write_meta("version", "1", error));

    std::vector<engine::analysis::SeedEntry> seeds = {
        {0x1000, engine::analysis::SeedKind::kEntry},
        {0x2000, engine::analysis::SeedKind::kManual},
    };
    REQUIRE(db->write_seeds(seeds, error));

    std::vector<engine::xrefs::XrefEntry> xrefs = {
        {0x1000, 0x2000, engine::xrefs::XrefKind::kCodeCall},
        {0x3000, 0, engine::xrefs::XrefKind::kCodeCallIndirect},
    };
    REQUIRE(db->write_xrefs(xrefs, error));

    REQUIRE(db->clear(error));
    db->close();
}

TEST_CASE("SQLite analysis DB rejects usage before open", "[analysis_db]") {
    auto db = engine::analysis_db::create_sqlite_db();
    REQUIRE(db);

    std::string error;
    CHECK_FALSE(db->init_schema(error));
    CHECK_FALSE(error.empty());
}
