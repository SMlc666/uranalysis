#include "client/formatters/xrefs.h"

namespace client::fmt {

const char* xref_kind_label(engine::xrefs::XrefKind kind) {
    switch (kind) {
        case engine::xrefs::XrefKind::kDataPointer:
            return "data";
        case engine::xrefs::XrefKind::kCodeCall:
            return "call";
        case engine::xrefs::XrefKind::kCodeJump:
            return "jump";
        case engine::xrefs::XrefKind::kCodeCallIndirect:
            return "call_indirect";
        case engine::xrefs::XrefKind::kCodeJumpIndirect:
            return "jump_indirect";
    }
    return "xref";
}

const char* seed_kind_label(engine::analysis::SeedKind kind) {
    switch (kind) {
        case engine::analysis::SeedKind::kEntry:
            return "entry";
        case engine::analysis::SeedKind::kManual:
            return "manual";
        case engine::analysis::SeedKind::kSymbol:
            return "symbol";
        case engine::analysis::SeedKind::kPlt:
            return "plt";
        case engine::analysis::SeedKind::kInitArray:
            return "init_array";
        case engine::analysis::SeedKind::kEhFrame:
            return "eh_frame";
        case engine::analysis::SeedKind::kPrologue:
            return "prologue";
        case engine::analysis::SeedKind::kDwarf:
            return "dwarf";
        case engine::analysis::SeedKind::kLinearSweep:
            return "linear";
    }
    return "seed";
}

const char* range_kind_label(engine::analysis::FunctionRangeKind kind) {
    switch (kind) {
        case engine::analysis::FunctionRangeKind::kDwarf:
            return "dwarf";
        case engine::analysis::FunctionRangeKind::kEhFrame:
            return "eh_frame";
        case engine::analysis::FunctionRangeKind::kSymbol:
            return "symbol";
        case engine::analysis::FunctionRangeKind::kCfg:
            return "cfg";
    }
    return "range";
}

}  // namespace client::fmt