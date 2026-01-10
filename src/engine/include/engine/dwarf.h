#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "engine/image.h"
#include "engine/mapped_file.h"
#include "engine/binary_format.h"

namespace engine::dwarf {

struct DwarfFunction;
struct DwarfVariable;
struct DwarfLineRow;
struct DwarfLocationRange;
struct DwarfError;

enum class DwarfErrorCode {
    kNone,
    kIo,
    kMissingSection,
    kParse,
    kUnsupportedForm
};

struct DwarfError {
    DwarfErrorCode code = DwarfErrorCode::kNone;
    std::string message;
    std::string section;
    std::uint64_t offset = 0;
};

struct SectionData {
    std::string name;
    std::uint64_t address = 0;
    std::vector<std::uint8_t> data;
    std::span<const std::uint8_t> view{};
};

struct DwarfRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
};

class DwarfCatalog {
public:
    ~DwarfCatalog();
    void reset();
    void discover(const std::string& path,
                  const std::vector<BinarySection>& sections,
                  const LoadedImage& image,
                  const BinaryInfo& binary_info,
                  const std::vector<BinaryRelocation>& relocations);

    const std::vector<SectionData>& sections() const;
    const std::vector<DwarfFunction>& functions() const;
    const std::vector<DwarfVariable>& variables() const;
    const std::vector<DwarfLineRow>& line_rows() const;
    const DwarfFunction* find_function_by_address(std::uint64_t addr) const;
    const DwarfLineRow* find_line_for_address(std::uint64_t addr) const;
    const DwarfError* last_error() const;
    const std::vector<DwarfError>& errors() const;

private:
    struct Unit {
        std::size_t offset = 0;
        std::size_t die_offset = 0;
        std::size_t end = 0;
        bool is_64 = false;
        std::uint16_t version = 0;
        std::uint8_t address_size = 0;
        std::uint64_t abbrev_offset = 0;
        std::uint64_t str_offsets_base = 0;
        std::uint64_t rnglists_base = 0;
        std::uint64_t addr_base = 0;
        std::uint64_t loclists_base = 0;
        bool has_stmt_list = false;
        std::uint64_t stmt_list_offset = 0;
        bool has_low_pc = false;
        bool has_high_pc = false;
        bool high_pc_is_addr = false;
        std::uint64_t low_pc = 0;
        std::uint64_t high_pc = 0;
        bool has_ranges = false;
        std::uint64_t ranges_offset = 0;
        bool ranges_is_index = false;
        std::vector<DwarfRange> ranges;
        bool parsed = false;
        bool lines_parsed = false;
    };
    void record_error(DwarfErrorCode code,
                      const std::string& section,
                      std::uint64_t offset,
                      const std::string& message);
    void build_unit_index();
    void parse_unit(Unit& unit);
    void parse_line_table_for_unit(Unit& unit);
    void ensure_all_units_parsed();
    void ensure_units_for_address(std::uint64_t addr);
    void ensure_all_lines_parsed();
    void ensure_lines_for_address(std::uint64_t addr);
    void ensure_lines_sorted();

    std::unique_ptr<engine::MappedFile> mapped_file_;
    BinaryInfo binary_info_;
    std::span<const std::uint8_t> debug_info_;
    std::span<const std::uint8_t> debug_abbrev_;
    std::span<const std::uint8_t> debug_str_;
    std::span<const std::uint8_t> debug_str_offsets_;
    std::span<const std::uint8_t> debug_line_str_;
    std::span<const std::uint8_t> debug_line_;
    std::span<const std::uint8_t> debug_ranges_;
    std::span<const std::uint8_t> debug_rnglists_;
    std::span<const std::uint8_t> debug_addr_;
    std::span<const std::uint8_t> debug_loc_;
    std::span<const std::uint8_t> debug_loclists_;
    bool lazy_parse_ = true;
    std::vector<Unit> units_;
    std::vector<SectionData> sections_;
    std::vector<DwarfFunction> functions_;
    std::vector<DwarfVariable> variables_;
    std::vector<DwarfLineRow> line_rows_;
    bool lines_sorted_ = false;
    DwarfError last_error_;
    std::vector<DwarfError> errors_;
};

struct DwarfFunction {
    std::string name;
    std::string linkage_name;
    std::uint64_t low_pc = 0;
    std::uint64_t high_pc = 0;
    std::uint64_t type_offset = 0;
    std::uint64_t cu_offset = 0;
    std::uint16_t decl_file = 0;
    std::uint32_t decl_line = 0;
    std::vector<DwarfRange> ranges;
};

struct DwarfVariable {
    std::string name;
    std::string linkage_name;
    std::uint64_t type_offset = 0;
    std::uint64_t cu_offset = 0;
    std::vector<std::uint8_t> location_expr;
    std::vector<DwarfLocationRange> location_list;
};

struct DwarfLocationRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    bool is_default = false;
    std::vector<std::uint8_t> expr;
};

struct DwarfLineRow {
    std::uint64_t address = 0;
    std::uint32_t line = 0;
    std::string file;
    std::uint64_t cu_offset = 0;
};

}  // namespace engine::dwarf
