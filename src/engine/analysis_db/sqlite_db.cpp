#include "engine/analysis_db.h"

#include <sqlite3.h>

#include <string>

namespace engine::analysis_db {

namespace {

class SqliteDb final : public AnalysisDb {
public:
    SqliteDb() = default;
    ~SqliteDb() override {
        close();
    }

    bool open(const std::string& path, std::string& error) override {
        close();
        const int rc = sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        if (rc != SQLITE_OK) {
            error = sqlite_error();
            close();
            return false;
        }
        return true;
    }

    bool init_schema(std::string& error) override {
        static const char* kSchema = R"sql(
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS meta(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seeds(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                kind INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_seeds_address ON seeds(address);
            CREATE TABLE IF NOT EXISTS xrefs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source INTEGER NOT NULL,
                target INTEGER,
                kind INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_xrefs_source ON xrefs(source);
            CREATE INDEX IF NOT EXISTS idx_xrefs_target ON xrefs(target);
        )sql";
        return exec(kSchema, error);
    }

    bool clear(std::string& error) override {
        return exec("DELETE FROM seeds; DELETE FROM xrefs;", error);
    }

    bool write_meta(const std::string& key, const std::string& value, std::string& error) override {
        static const char* kSql = "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
            error = sqlite_error();
            return false;
        }
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
        const bool ok = step_and_finalize(stmt, error);
        return ok;
    }

    bool write_seeds(const std::vector<analysis::SeedEntry>& seeds, std::string& error) override {
        if (!exec("BEGIN;", error)) {
            return false;
        }
        static const char* kSql = "INSERT INTO seeds(address, kind) VALUES(?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
            error = sqlite_error();
            exec("ROLLBACK;", error);
            return false;
        }
        for (const auto& seed : seeds) {
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(seed.address));
            sqlite3_bind_int(stmt, 2, static_cast<int>(seed.kind));
            if (!step_and_reset(stmt, error)) {
                sqlite3_finalize(stmt);
                exec("ROLLBACK;", error);
                return false;
            }
        }
        sqlite3_finalize(stmt);
        if (!exec("COMMIT;", error)) {
            exec("ROLLBACK;", error);
            return false;
        }
        return true;
    }

    bool write_xrefs(const std::vector<xrefs::XrefEntry>& xrefs, std::string& error) override {
        if (!exec("BEGIN;", error)) {
            return false;
        }
        static const char* kSql = "INSERT INTO xrefs(source, target, kind) VALUES(?, ?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
            error = sqlite_error();
            exec("ROLLBACK;", error);
            return false;
        }
        for (const auto& xref : xrefs) {
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(xref.source));
            const bool indirect = (xref.kind == xrefs::XrefKind::kCodeCallIndirect ||
                                   xref.kind == xrefs::XrefKind::kCodeJumpIndirect);
            if (!indirect && xref.target != 0) {
                sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(xref.target));
            } else {
                sqlite3_bind_null(stmt, 2);
            }
            sqlite3_bind_int(stmt, 3, static_cast<int>(xref.kind));
            if (!step_and_reset(stmt, error)) {
                sqlite3_finalize(stmt);
                exec("ROLLBACK;", error);
                return false;
            }
        }
        sqlite3_finalize(stmt);
        if (!exec("COMMIT;", error)) {
            exec("ROLLBACK;", error);
            return false;
        }
        return true;
    }

    void close() override {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

private:
    std::string sqlite_error() const {
        if (!db_) {
            return "sqlite not initialized";
        }
        const char* msg = sqlite3_errmsg(db_);
        return msg ? msg : "sqlite error";
    }

    bool exec(const char* sql, std::string& error) {
        if (!db_) {
            error = "sqlite not initialized";
            return false;
        }
        char* err = nullptr;
        const int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            error = err ? err : sqlite_error();
            sqlite3_free(err);
            return false;
        }
        return true;
    }

    bool step_and_reset(sqlite3_stmt* stmt, std::string& error) {
        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            error = sqlite_error();
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
            return false;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        return true;
    }

    bool step_and_finalize(sqlite3_stmt* stmt, std::string& error) {
        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            error = sqlite_error();
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3* db_ = nullptr;
};

}  // namespace

std::unique_ptr<AnalysisDb> create_sqlite_db() {
    return std::make_unique<SqliteDb>();
}

}  // namespace engine::analysis_db
