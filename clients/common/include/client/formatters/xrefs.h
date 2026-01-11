#pragma once

#include "engine/function_boundaries.h"
#include "engine/function_discovery.h"
#include "engine/xrefs.h"

namespace client::fmt {

/// Get label for xref kind
const char* xref_kind_label(engine::xrefs::XrefKind kind);

/// Get label for seed kind
const char* seed_kind_label(engine::analysis::SeedKind kind);

/// Get label for function range kind
const char* range_kind_label(engine::analysis::FunctionRangeKind kind);

}  // namespace client::fmt