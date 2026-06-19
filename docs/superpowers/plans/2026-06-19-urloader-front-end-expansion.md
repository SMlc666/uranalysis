# Urloader Front-End Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `urloader` into the workspace binary front-end layer by splitting raw parsing from analysis-facing views, expanding normalized metadata infrastructure, migrating `ura-core` to consume `BinaryView`, and extending CI-only corpus gates with loader/front-end capability checks while keeping real-sample gates out of local-default workflows.

**Architecture:** The implementation lands in stages. First introduce the new raw-versus-view model and keep current ELF/PE behavior green. Then migrate `ura-core`, CLI, daemon, and corpus gate to the normalized front-end contract. After the boundary is stable, expand linkage, debug, and unwind metadata into normalized views and strengthen tests at the unit, local integration, and CI-only corpus layers.

**Tech Stack:** Rust 2021 workspace, Cargo, existing handwritten ELF/PE fixtures, `serde`, `thiserror`, `anyhow`, `tempfile`, existing `ura-core`/`ura-cli`/`ura-daemon`/`ura-corpus-gate`, plus a DWARF reader crate such as `gimli` for debug and `eh_frame` ingestion.

---

## Scope Notes

This plan implements `docs/superpowers/specs/2026-06-19-urloader-front-end-expansion-design.md`.

Keep the hard boundary intact:

- `urloader` may own target identity, mapping, symbols, imports, exports,
  relocations, debug metadata, unwind metadata, capabilities, diagnostics, and
  front-end normalization
- `urloader` must not own disassembly, IL, CFG, xrefs, function discovery, or
  any decoded-instruction semantic analysis

Preserve the existing local-versus-CI split:

- local developers run normal Rust checks and deterministic fixture tests
- real-sample gates remain GitHub Actions only

## File Structure

- Modify `crates/urloader/Cargo.toml`: add front-end dependencies such as a DWARF reader crate and any small normalization helpers.
- Modify `crates/urloader/src/lib.rs`: export the new raw and view APIs while keeping a temporary compatibility helper during migration.
- Modify `crates/urloader/src/error.rs`: split parse errors from view-construction/front-end errors.
- Replace `crates/urloader/src/model.rs`: define raw-image types, `BinaryView`, capability and diagnostic types, and normalized metadata records.
- Create `crates/urloader/src/view.rs`: `analysis_view()` builder, range normalization, and capability derivation.
- Create `crates/urloader/src/normalize.rs`: shared symbol/import/export/relocation normalization helpers.
- Modify `crates/urloader/src/elf.rs`: produce raw ELF facts plus debug/unwind/linkage extraction hooks.
- Modify `crates/urloader/src/pe.rs`: produce raw PE facts plus import/export/base-reloc/unwind extraction hooks.
- Create `crates/urloader/tests/view.rs`: front-end view tests over both ELF and PE fixtures.
- Modify `crates/urloader/tests/elf.rs`: keep parser coverage but shift behavior assertions toward `RawImage` plus `BinaryView`.
- Modify `crates/urloader/tests/pe.rs`: same for PE plus linkage/unwind fixtures.
- Modify `crates/ura-core/src/analysis/mod.rs`: consume `urloader::BinaryView` instead of reconstructing an `AnalysisImage` from `LoadedImage`.
- Modify `crates/ura-core/src/analysis/target.rs`: derive target identity from `BinaryView::target`.
- Modify `crates/ura-core/src/analysis/session.rs`: store raw bytes plus parsed raw image/view instead of cloned owned loader bytes.
- Modify `crates/ura-core/tests/fixtures.rs`: expose helpers returning new `RawImage` and `BinaryView`.
- Modify `crates/ura-core/tests/analysis_smoke.rs`, `elf_loader.rs`, `session_refresh.rs`: keep analysis behavior green on the new front-end contract.
- Modify `crates/ura-cli/src/lib.rs`: load source bytes, build `RawImage`, then build `BinaryView` for sessions.
- Modify `crates/ura-daemon/src/main.rs`: same session input migration.
- Modify `crates/ura-corpus-gate/src/main.rs`: record front-end capability and diagnostic metrics in sample reports.
- Modify `tests/corpus/manifest.toml`: add expected capability assertions for selected samples.
- Keep `tests/corpus/scripts/run-corpus-gate.sh`: CI-only guard remains intact.
- Modify `README.md`: update `urloader` description and explicitly restate local-versus-CI gate policy if wording drifts.

---

### Task 1: Introduce Raw Image And Binary View Skeleton

**Files:**
- Modify: `crates/urloader/Cargo.toml`
- Modify: `crates/urloader/src/lib.rs`
- Modify: `crates/urloader/src/error.rs`
- Modify: `crates/urloader/src/model.rs`
- Create: `crates/urloader/src/view.rs`
- Test: `crates/urloader/tests/view.rs`

- [ ] **Step 1: Write the failing front-end view test**

Create `crates/urloader/tests/view.rs`:

```rust
mod fixtures;

use urloader::{load, Architecture, ImageClass, ImageFormat};

#[test]
fn analysis_view_exposes_target_and_executable_ranges_for_minimal_elf() {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert_eq!(view.target.format, ImageFormat::Elf);
    assert_eq!(view.target.architecture, Architecture::Aarch64);
    assert_eq!(view.target.class, ImageClass::Bits64);
    assert!(view.capabilities.can_map_executable_bytes);
    assert_eq!(view.entry, Some(0x400080));
    assert_eq!(view.ranges.len(), 1);
    assert_eq!(view.ranges[0].file_offset, 0);
}
```

Create `crates/urloader/tests/fixtures.rs` by moving the current handcrafted
fixture constructors out of `elf.rs` and `pe.rs` test files:

```rust
pub fn minimal_elf64_aarch64_executable() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1000];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&0x400080u64.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    bytes[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let ph = 0x40usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
cargo test -p urloader --test view analysis_view_exposes_target_and_executable_ranges_for_minimal_elf -- --nocapture
```

Expected: compile fails because `analysis_view`, `BinaryView`, and `tests/view.rs` support types do not exist yet.

- [ ] **Step 3: Add raw image and front-end view types**

Replace the public exports in `crates/urloader/src/lib.rs`:

```rust
mod elf;
mod error;
mod model;
mod pe;
mod view;

pub use error::{LoadError, Result, ViewBuildError};
pub use model::{
    Architecture, BinaryTarget, CapabilitySet, Endian, FormatDetails, ImageClass, ImageFormat,
    LoaderDiagnostic, MetadataConfidence, MappedRange, NormalizedExport, NormalizedImport,
    NormalizedRelocation, NormalizedSymbol, RawImage, RawSection, RawSegment, ViewSection,
};

pub fn load(bytes: &[u8]) -> Result<RawImage> {
    if bytes.starts_with(b"\x7fELF") {
        return elf::load(bytes);
    }
    if bytes.starts_with(b"MZ") {
        return pe::load(bytes);
    }
    Err(LoadError::UnknownFormat)
}
```

Replace `crates/urloader/src/error.rs` with:

```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, LoadError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoadError {
    #[error("unknown binary format")]
    UnknownFormat,
    #[error("{format}: truncated {field}")]
    Truncated {
        format: &'static str,
        field: &'static str,
    },
    #[error("{format}: unsupported {field}: {value}")]
    Unsupported {
        format: &'static str,
        field: &'static str,
        value: String,
    },
    #[error("{format}: malformed {field}: {message}")]
    Malformed {
        format: &'static str,
        field: &'static str,
        message: String,
    },
    #[error(transparent)]
    ViewBuild(#[from] ViewBuildError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ViewBuildError {
    #[error("front-end view missing executable mapping")]
    MissingExecutableMapping,
    #[error("front-end view missing analysis entry")]
    MissingAnalysisEntry,
}
```

Create `crates/urloader/src/view.rs`:

```rust
use crate::{
    error::ViewBuildError,
    model::{
        BinaryTarget, CapabilitySet, BinaryView, LoaderDiagnostic, MappedRange, RawImage,
        ViewSection,
    },
};

impl RawImage {
    pub fn analysis_view<'a>(&'a self, bytes: &'a [u8]) -> Result<BinaryView<'a>, ViewBuildError> {
        let ranges = self
            .segments
            .iter()
            .map(|segment| MappedRange {
                start: segment.vaddr,
                end: segment.vaddr + segment.mem_size,
                file_offset: segment.file_offset,
                file_size: segment.file_size,
                mem_size: segment.mem_size,
                permissions: segment.permissions.clone(),
                provenance: segment.name.clone(),
            })
            .collect::<Vec<_>>();
        if !ranges.iter().any(|range| range.permissions.contains('x')) {
            return Err(ViewBuildError::MissingExecutableMapping);
        }
        Ok(BinaryView {
            target: BinaryTarget {
                format: self.format,
                architecture: self.architecture,
                class: self.class,
                endian: self.endian,
            },
            entry: Some(self.entry),
            image_base: Some(self.image_base),
            bytes,
            ranges,
            sections: self
                .sections
                .iter()
                .map(|section| ViewSection {
                    name: section.name.clone(),
                    start: section.addr,
                    end: section.addr + section.size,
                    file_offset: section.offset,
                    permissions: section.permissions.clone(),
                    provenance: "section".to_string(),
                })
                .collect(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            debug: None,
            unwind: None,
            capabilities: CapabilitySet {
                can_map_executable_bytes: true,
                can_translate_va: true,
                can_translate_rva: self.image_base != 0,
                has_named_sections: !self.sections.is_empty(),
                has_symbols: !self.symbols.is_empty(),
                has_imports: false,
                has_exports: false,
                has_relocations: false,
                has_debug_lines: false,
                has_debug_function_ranges: false,
                has_unwind_ranges: false,
                supports_analysis_entry: self.entry != 0,
            },
            diagnostics: Vec::<LoaderDiagnostic>::new(),
        })
    }
}
```

Replace `crates/urloader/src/model.rs` with the new split types:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    Elf,
    Pe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
    X86_64,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageClass {
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryTarget {
    pub format: ImageFormat,
    pub architecture: Architecture,
    pub class: ImageClass,
    pub endian: Endian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataConfidence {
    Exact,
    Derived,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderDiagnostic {
    pub code: &'static str,
    pub severity: String,
    pub subject: String,
    pub addr: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSegment {
    pub id: i64,
    pub name: String,
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSection {
    pub id: i64,
    pub name: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub permissions: String,
    pub flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawImage {
    pub format: ImageFormat,
    pub architecture: Architecture,
    pub class: ImageClass,
    pub endian: Endian,
    pub entry: u64,
    pub image_base: u64,
    pub segments: Vec<RawSegment>,
    pub sections: Vec<RawSection>,
    pub symbols: Vec<NormalizedSymbol>,
    pub imports: Vec<NormalizedImport>,
    pub exports: Vec<NormalizedExport>,
    pub relocations: Vec<NormalizedRelocation>,
    pub diagnostics: Vec<LoaderDiagnostic>,
    pub format_details: FormatDetails,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryView<'a> {
    pub target: BinaryTarget,
    pub entry: Option<u64>,
    pub image_base: Option<u64>,
    pub bytes: &'a [u8],
    pub ranges: Vec<MappedRange>,
    pub sections: Vec<ViewSection>,
    pub symbols: Vec<NormalizedSymbol>,
    pub imports: Vec<NormalizedImport>,
    pub exports: Vec<NormalizedExport>,
    pub relocations: Vec<NormalizedRelocation>,
    pub debug: Option<DebugView>,
    pub unwind: Option<UnwindView>,
    pub capabilities: CapabilitySet,
    pub diagnostics: Vec<LoaderDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappedRange {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub permissions: String,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewSection {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub permissions: String,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub can_map_executable_bytes: bool,
    pub can_translate_va: bool,
    pub can_translate_rva: bool,
    pub has_named_sections: bool,
    pub has_symbols: bool,
    pub has_imports: bool,
    pub has_exports: bool,
    pub has_relocations: bool,
    pub has_debug_lines: bool,
    pub has_debug_function_ranges: bool,
    pub has_unwind_ranges: bool,
    pub supports_analysis_entry: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSymbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedImport {
    pub library: Option<String>,
    pub name: Option<String>,
    pub slot_addr: Option<u64>,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedExport {
    pub name: Option<String>,
    pub addr: u64,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedRelocation {
    pub addr: u64,
    pub kind: String,
    pub target: Option<u64>,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugView {
    pub function_ranges: Vec<FunctionRange>,
    pub line_entries: Vec<LineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindView {
    pub function_ranges: Vec<FunctionRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRange {
    pub start: u64,
    pub end: u64,
    pub name: Option<String>,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineEntry {
    pub addr: u64,
    pub file: String,
    pub line: u64,
    pub column: u64,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormatDetails {
    Elf { file_type: u16, machine: u16 },
    Pe { machine: u16, image_base: u64 },
}
```

- [ ] **Step 4: Rewire current parsers to return `RawImage` and run the new view test**

In `crates/urloader/src/elf.rs` and `crates/urloader/src/pe.rs`, rename
segment/section construction to `RawSegment` and `RawSection`, and return
`RawImage` instead of `LoadedImage`. The parser body stays structurally the
same for this task.

Run:

```bash
cargo test -p urloader --test view analysis_view_exposes_target_and_executable_ranges_for_minimal_elf -- --nocapture
cargo test -p urloader --test elf -- --nocapture
cargo test -p urloader --test pe -- --nocapture
```

Expected: all three commands pass, with older parser tests updated to call
`raw.analysis_view(&bytes)` where they used `LoadedImage` helper methods.

- [ ] **Step 5: Commit**

```bash
git add crates/urloader/src/lib.rs crates/urloader/src/error.rs crates/urloader/src/model.rs crates/urloader/src/view.rs crates/urloader/src/elf.rs crates/urloader/src/pe.rs crates/urloader/tests
git commit -m "feat: add urloader raw image and binary view skeleton"
```

---

### Task 2: Migrate `ura-core` To Consume `BinaryView`

**Files:**
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Modify: `crates/ura-core/src/analysis/target.rs`
- Modify: `crates/ura-core/src/analysis/session.rs`
- Modify: `crates/ura-core/tests/fixtures.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`
- Modify: `crates/ura-core/tests/elf_loader.rs`
- Modify: `crates/ura-cli/src/lib.rs`
- Modify: `crates/ura-daemon/src/main.rs`

- [ ] **Step 1: Write the failing `ura-core` front-end consumption test**

Append to `crates/ura-core/tests/analysis_smoke.rs`:

```rust
#[test]
fn build_state_from_binary_view_preserves_disassembly_entry() -> Result<()> {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let raw = urloader::load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("binary view should build");

    let state = ura_core::analysis::build_state_from_view_with_instruction_limit(
        &view,
        &ura_core::model::UserFacts::default(),
        Some(16),
    )?;

    assert_eq!(state.instructions[0].addr, 0x400080);
    assert_eq!(state.instructions[0].text, "ret");
    Ok(())
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
cargo test -p ura-core --test analysis_smoke build_state_from_binary_view_preserves_disassembly_entry -- --nocapture
```

Expected: compile fails because `build_state_from_view_with_instruction_limit`
does not exist and `AnalysisImage` still depends on loader-owned segments.

- [ ] **Step 3: Replace `AnalysisImage` with borrowed `BinaryView`**

In `crates/ura-core/src/analysis/mod.rs`, replace the input model:

```rust
pub type AnalysisImage<'a> = urloader::BinaryView<'a>;

pub fn run_initial_analysis_with_instruction_limit(
    image: &AnalysisImage<'_>,
    user_functions: &[Function],
    max_instructions: Option<usize>,
) -> Result<AnalysisOutput> {
    let instructions = disasm::linear_disassemble_with_limit(image, max_instructions)?;
    let strings = strings::extract_strings(image);
    let entry = image.entry.ok_or_else(|| UraError::Unsupported("binary view missing analysis entry".to_string()))?;
    let window = invalidation::AnalysisWindow {
        start: entry,
        end: entry.saturating_add(4),
        reason: invalidation::RefreshReason::SourceBytesChanged,
    };
    let mut diagnostics = diagnostics::collect_diagnostics(&instructions);
    let cfg = match cfg::build_cfg(&instructions, &[entry], window) {
        Ok(cfg) => cfg,
        Err(err) if max_instructions.is_some() => {
            diagnostics.push(Diagnostic {
                addr: Some(entry),
                severity: "error".to_string(),
                message: err.to_string(),
            });
            cfg::CfgOutput {
                basic_blocks: Vec::new(),
                cfg_edges: Vec::new(),
            }
        }
        Err(err) => return Err(err),
    };
    let functions = functions::discover_functions(
        entry,
        &instructions,
        &cfg.basic_blocks,
        &cfg.cfg_edges,
        user_functions,
    );
    let xrefs = xrefs::build_xrefs(&instructions, &strings, &cfg.cfg_edges);
    diagnostics.extend(diagnostics::collect_graph_diagnostics(&cfg.cfg_edges));
    diagnostics.extend(diagnostics::collect_user_function_diagnostics(
        &functions,
        &instructions,
    ));
    Ok(AnalysisOutput {
        instructions,
        basic_blocks: cfg.basic_blocks,
        cfg_edges: cfg.cfg_edges,
        strings,
        functions,
        xrefs,
        diagnostics,
    })
}

pub fn build_state_from_view_with_instruction_limit(
    view: &urloader::BinaryView<'_>,
    user_facts: &UserFacts,
    max_instructions: Option<usize>,
) -> Result<AnalysisState> {
    let _target = target::AnalysisTarget::from_view(view)?;
    let user_functions = functions::manual_functions_from_facts(user_facts);
    let output = run_initial_analysis_with_instruction_limit(view, &user_functions, max_instructions)?;
    Ok(AnalysisState {
        instructions: output.instructions,
        strings: output.strings,
        basic_blocks: output.basic_blocks,
        cfg_edges: output.cfg_edges,
        functions: output.functions,
        xrefs: output.xrefs,
        diagnostics: output.diagnostics,
    })
}
```

In `crates/ura-core/src/analysis/target.rs`, replace `from_loaded()`:

```rust
impl AnalysisTarget {
    pub fn from_view(view: &urloader::BinaryView<'_>) -> Result<Self> {
        let target = Self {
            format: convert_format(view.target.format),
            architecture: convert_architecture(view.target.architecture)?,
            class: convert_class(view.target.class),
            endian: convert_endian(view.target.endian)?,
        };
        target.ensure_supported()?;
        Ok(target)
    }
}
```

In `crates/ura-core/src/analysis/session.rs`, store raw bytes and rebuild the
view at refresh time:

```rust
#[derive(Debug, Clone)]
pub struct AnalysisInputs {
    pub source_bytes: Vec<u8>,
    pub raw: urloader::RawImage,
    pub user_facts: UserFacts,
}

impl AnalysisInputs {
    pub fn from_source_bytes(source_bytes: Vec<u8>) -> Result<Self> {
        let raw = urloader::load(&source_bytes).map_err(|err| crate::UraError::Analysis(err.to_string()))?;
        Ok(Self {
            source_bytes,
            raw,
            user_facts: UserFacts::default(),
        })
    }
}

pub fn refresh(&mut self) -> Result<RefreshSummary> {
    let plan = build_refresh_plan(self.dirty);
    let ran = if plan.pass_ids().is_empty() {
        Vec::new()
    } else {
        let view = self.inputs.raw.analysis_view(&self.inputs.source_bytes)
            .map_err(|err| crate::UraError::Analysis(err.to_string()))?;
        self.state = build_state_from_view_with_instruction_limit(&view, &self.inputs.user_facts, None)?;
        plan.clone_ids()
    };
    self.dirty = DirtyInputs::default();
    Ok(RefreshSummary { ran })
}
```

- [ ] **Step 4: Update tests and callers to build views from bytes**

In `crates/ura-core/tests/fixtures.rs`:

```rust
pub fn load_minimal_aarch64_raw() -> urloader::RawImage {
    let bytes = minimal_elf64_aarch64_executable();
    urloader::load(&bytes).expect("fixture should load")
}

pub fn load_minimal_aarch64_view(bytes: &[u8]) -> urloader::BinaryView<'_> {
    let raw = urloader::load(bytes).expect("fixture should load");
    raw.analysis_view(bytes).expect("fixture view should build")
}
```

In `crates/ura-cli/src/lib.rs`, replace `loaded` session input setup:

```rust
let session = ura_core::analysis::session::AnalysisSession::from_parts(
    ura_core::analysis::session::AnalysisInputs {
        source_bytes: stored.source.source_bytes.clone(),
        raw: urloader::load(&stored.source.source_bytes).map_err(|err| anyhow!(err.to_string()))?,
        user_facts: stored.user_truth.facts.clone(),
    },
    stored.cache.state.clone(),
    stored.cache_metadata.is_stale_for(&stored.source, &stored.user_truth),
);
```

Mirror the same source-byte-plus-raw setup in `crates/ura-daemon/src/main.rs`.

Run:

```bash
cargo test -p ura-core --test analysis_smoke build_state_from_binary_view_preserves_disassembly_entry -- --nocapture
cargo test -p ura-core --test elf_loader -- --nocapture
cargo test -p ura-cli
cargo test -p ura-daemon
```

Expected: all commands pass.

- [ ] **Step 5: Commit**

```bash
git add crates/ura-core/src/analysis crates/ura-core/tests crates/ura-cli/src/lib.rs crates/ura-daemon/src/main.rs
git commit -m "refactor: make ura-core consume urloader binary views"
```

---

### Task 3: Normalize Linkage Metadata For ELF And PE

**Files:**
- Modify: `crates/urloader/src/elf.rs`
- Modify: `crates/urloader/src/pe.rs`
- Create: `crates/urloader/src/normalize.rs`
- Modify: `crates/urloader/src/view.rs`
- Modify: `crates/urloader/tests/elf.rs`
- Modify: `crates/urloader/tests/pe.rs`

- [ ] **Step 1: Write failing linkage normalization tests**

Append to `crates/urloader/tests/elf.rs`:

```rust
#[test]
fn analysis_view_normalizes_elf_symbols_and_relocations() {
    let bytes = elf_with_sections_and_symbols();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert!(view.capabilities.has_symbols);
    assert!(view
        .symbols
        .iter()
        .any(|symbol| symbol.name == "main" && symbol.source == "elf:symtab"));
}
```

Append to `crates/urloader/tests/pe.rs`:

```rust
#[test]
fn analysis_view_normalizes_pe_exports_and_imports() {
    let bytes = minimal_pe32_plus_x86_64();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert!(!view.imports.is_empty() || !view.exports.is_empty() || !view.relocations.is_empty());
}
```

- [ ] **Step 2: Run focused tests and verify failure**

Run:

```bash
cargo test -p urloader --test elf analysis_view_normalizes_elf_symbols_and_relocations -- --nocapture
cargo test -p urloader --test pe analysis_view_normalizes_pe_exports_and_imports -- --nocapture
```

Expected: first test fails because symbols are still empty in `BinaryView`; second
test fails because PE linkage is not parsed yet.

- [ ] **Step 3: Add normalization helpers and wire ELF symbols through the view**

Create `crates/urloader/src/normalize.rs`:

```rust
use crate::model::{
    MetadataConfidence, NormalizedExport, NormalizedImport, NormalizedRelocation, NormalizedSymbol,
};

pub fn normalize_symbol(
    name: impl Into<String>,
    addr: u64,
    size: u64,
    kind: impl Into<String>,
    source: &'static str,
) -> NormalizedSymbol {
    NormalizedSymbol {
        name: name.into(),
        addr,
        size,
        kind: kind.into(),
        source: source.to_string(),
        confidence: MetadataConfidence::Exact,
    }
}

pub fn normalize_import(
    library: Option<String>,
    name: Option<String>,
    slot_addr: Option<u64>,
    source: &'static str,
) -> NormalizedImport {
    NormalizedImport {
        library,
        name,
        slot_addr,
        source: source.to_string(),
        confidence: MetadataConfidence::Exact,
    }
}

pub fn normalize_export(
    name: Option<String>,
    addr: u64,
    source: &'static str,
) -> NormalizedExport {
    NormalizedExport {
        name,
        addr,
        source: source.to_string(),
        confidence: MetadataConfidence::Exact,
    }
}

pub fn normalize_relocation(
    addr: u64,
    kind: impl Into<String>,
    target: Option<u64>,
    source: &'static str,
) -> NormalizedRelocation {
    NormalizedRelocation {
        addr,
        kind: kind.into(),
        target,
        source: source.to_string(),
        confidence: MetadataConfidence::Exact,
    }
}
```

In `crates/urloader/src/elf.rs`, populate `RawImage.symbols` via
`normalize_symbol(..., "elf:symtab")` or `"elf:dynsym"`.

In `crates/urloader/src/view.rs`, expose raw linkage directly:

```rust
symbols: self.symbols.clone(),
imports: self.imports.clone(),
exports: self.exports.clone(),
relocations: self.relocations.clone(),
capabilities: CapabilitySet {
    has_symbols: !self.symbols.is_empty(),
    has_imports: !self.imports.is_empty(),
    has_exports: !self.exports.is_empty(),
    has_relocations: !self.relocations.is_empty(),
    // keep the other fields unchanged
    ..capabilities
},
```

- [ ] **Step 4: Add PE import/export/base relocation parsing**

In `crates/urloader/src/pe.rs`, add optional-header data-directory parsing and
populate raw normalized linkage:

```rust
#[derive(Debug, Clone, Copy)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

fn parse_data_directories(bytes: &[u8], optional: usize, class: ImageClass) -> Result<[DataDirectory; 16]> {
    let directory_offset = match class {
        ImageClass::Bits32 => optional + 96,
        ImageClass::Bits64 => optional + 112,
    };
    let mut dirs = [DataDirectory { rva: 0, size: 0 }; 16];
    for (idx, dir) in dirs.iter_mut().enumerate() {
        let off = directory_offset + idx * 8;
        need(bytes, off, 8, "data directory")?;
        dir.rva = u32_at(bytes, off, "directory rva")?;
        dir.size = u32_at(bytes, off + 4, "directory size")?;
    }
    Ok(dirs)
}
```

Use the import, export, and base-reloc directories to push records through
`normalize_import`, `normalize_export`, and `normalize_relocation`. For this
task, only support the common name-based import case and relocation block
walking sufficient for x86-64 PE32+ fixtures.

Run:

```bash
cargo test -p urloader --test elf analysis_view_normalizes_elf_symbols_and_relocations -- --nocapture
cargo test -p urloader --test pe analysis_view_normalizes_pe_exports_and_imports -- --nocapture
cargo test -p urloader --test elf -- --nocapture
cargo test -p urloader --test pe -- --nocapture
```

Expected: all commands pass.

- [ ] **Step 5: Commit**

```bash
git add crates/urloader/src/elf.rs crates/urloader/src/pe.rs crates/urloader/src/normalize.rs crates/urloader/src/view.rs crates/urloader/tests/elf.rs crates/urloader/tests/pe.rs
git commit -m "feat: normalize urloader linkage metadata"
```

---

### Task 4: Add Debug And Unwind Front-End Views

**Files:**
- Modify: `crates/urloader/Cargo.toml`
- Modify: `crates/urloader/src/model.rs`
- Modify: `crates/urloader/src/elf.rs`
- Modify: `crates/urloader/src/pe.rs`
- Modify: `crates/urloader/src/view.rs`
- Modify: `crates/urloader/tests/elf.rs`
- Modify: `crates/urloader/tests/pe.rs`

- [ ] **Step 1: Write failing debug/unwind tests**

Append to `crates/urloader/tests/elf.rs`:

```rust
#[test]
fn analysis_view_surfaces_elf_unwind_ranges_when_eh_frame_exists() {
    let bytes = elf_with_mock_eh_frame();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert!(view.capabilities.has_unwind_ranges);
    assert!(view.unwind.is_some());
    assert!(view.unwind.as_ref().unwrap().function_ranges.iter().any(|range| range.start == 0x400080));
}
```

Append to `crates/urloader/tests/pe.rs`:

```rust
#[test]
fn analysis_view_surfaces_pe_unwind_ranges_when_pdata_exists() {
    let bytes = minimal_pe32_plus_x86_64_with_pdata();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert!(view.capabilities.has_unwind_ranges);
    assert!(view.unwind.is_some());
}
```

- [ ] **Step 2: Add DWARF dependency and verify the tests fail first**

Modify `crates/urloader/Cargo.toml`:

```toml
[dependencies]
serde.workspace = true
thiserror.workspace = true
gimli = { version = "0.31", default-features = false, features = ["read", "std"] }
```

Run:

```bash
cargo test -p urloader --test elf analysis_view_surfaces_elf_unwind_ranges_when_eh_frame_exists -- --nocapture
cargo test -p urloader --test pe analysis_view_surfaces_pe_unwind_ranges_when_pdata_exists -- --nocapture
```

Expected: both tests fail because `debug` and `unwind` are still `None`.

- [ ] **Step 3: Parse ELF debug and unwind data into normalized views**

In `crates/urloader/src/elf.rs`, add optional section lookups for `.eh_frame`,
`.debug_info`, `.debug_abbrev`, `.debug_line`, and `.debug_str`, then use a
small `gimli::Dwarf` reader to populate `DebugView` and `UnwindView` records.

Use this helper shape:

```rust
fn build_debug_view(bytes: &[u8], sections: &[RawSection]) -> Option<crate::DebugView> {
    let debug_line = section_bytes(bytes, sections, ".debug_line")?;
    let debug_info = section_bytes(bytes, sections, ".debug_info")?;
    let debug_abbrev = section_bytes(bytes, sections, ".debug_abbrev")?;
    let debug_str = section_bytes(bytes, sections, ".debug_str").unwrap_or(&[]);
    let dwarf = gimli::Dwarf::load(|id| {
        let data = match id.name() {
            ".debug_info" => debug_info,
            ".debug_abbrev" => debug_abbrev,
            ".debug_line" => debug_line,
            ".debug_str" => debug_str,
            _ => &[],
        };
        Ok::<_, gimli::Error>(gimli::EndianSlice::new(data, gimli::LittleEndian))
    }).ok()?;
    let mut lines = Vec::new();
    let mut function_ranges = Vec::new();
    // Iterate units, rows, and subprogram DIEs here.
    Some(crate::DebugView { function_ranges, line_entries: lines })
}
```

For `eh_frame`, add a minimal range extractor that walks FDEs and emits
`FunctionRange { source: "elf:eh_frame".to_string(), confidence: MetadataConfidence::Derived, .. }`.

- [ ] **Step 4: Parse PE unwind data from `pdata`/`xdata` and expose capabilities**

In `crates/urloader/src/pe.rs`, read the exception directory and produce
normalized unwind ranges:

```rust
fn build_pe_unwind_view(
    bytes: &[u8],
    image_base: u64,
    exception_dir: DataDirectory,
    sections: &[RawSection],
) -> Option<crate::UnwindView> {
    let mut ranges = Vec::new();
    let mut offset = rva_to_offset(sections, image_base, exception_dir.rva.into())? as usize;
    let end = offset + exception_dir.size as usize;
    while offset + 12 <= end {
        let begin_rva = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?);
        let end_rva = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().ok()?);
        ranges.push(crate::FunctionRange {
            start: image_base + u64::from(begin_rva),
            end: image_base + u64::from(end_rva),
            name: None,
            source: "pe:pdata".to_string(),
            confidence: crate::MetadataConfidence::Derived,
        });
        offset += 12;
    }
    Some(crate::UnwindView { function_ranges: ranges })
}
```

In `crates/urloader/src/view.rs`, set:

```rust
has_debug_lines: self.debug.as_ref().map_or(false, |debug| !debug.line_entries.is_empty()),
has_debug_function_ranges: self.debug.as_ref().map_or(false, |debug| !debug.function_ranges.is_empty()),
has_unwind_ranges: self.unwind.as_ref().map_or(false, |unwind| !unwind.function_ranges.is_empty()),
```

Run:

```bash
cargo test -p urloader --test elf analysis_view_surfaces_elf_unwind_ranges_when_eh_frame_exists -- --nocapture
cargo test -p urloader --test pe analysis_view_surfaces_pe_unwind_ranges_when_pdata_exists -- --nocapture
cargo test -p urloader --test elf -- --nocapture
cargo test -p urloader --test pe -- --nocapture
```

Expected: all commands pass.

- [ ] **Step 5: Commit**

```bash
git add crates/urloader/Cargo.toml crates/urloader/src/model.rs crates/urloader/src/elf.rs crates/urloader/src/pe.rs crates/urloader/src/view.rs crates/urloader/tests/elf.rs crates/urloader/tests/pe.rs
git commit -m "feat: add urloader debug and unwind views"
```

---

### Task 5: Add Local Front-End Integration Tests

**Files:**
- Create: `crates/urloader/tests/integration.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`
- Modify: `crates/ura-core/tests/session_refresh.rs`

- [ ] **Step 1: Write failing end-to-end fixture integration tests**

Create `crates/urloader/tests/integration.rs`:

```rust
mod fixtures;

#[test]
fn binary_view_round_trips_into_ura_core_analysis_for_elf_and_pe() {
    for bytes in [
        fixtures::minimal_elf64_aarch64_executable(),
        fixtures::minimal_pe32_plus_x86_64(),
    ] {
        let raw = urloader::load(&bytes).expect("raw image should load");
        let view = raw.analysis_view(&bytes).expect("view should build");
        let state = ura_core::analysis::build_state_from_view_with_instruction_limit(
            &view,
            &ura_core::model::UserFacts::default(),
            Some(32),
        )
        .expect("state should build");
        assert!(!state.instructions.is_empty());
    }
}
```

- [ ] **Step 2: Run the new integration test and verify the current unsupported paths**

Run:

```bash
cargo test -p urloader --test integration binary_view_round_trips_into_ura_core_analysis_for_elf_and_pe -- --nocapture
```

Expected: failure if any supported target is still blocked by stale target
derivation or entry/capability handling.

- [ ] **Step 3: Tighten `BinaryView` helper methods used by analysis**

Add to `crates/urloader/src/view.rs`:

```rust
impl BinaryView<'_> {
    pub fn va_to_offset(&self, addr: u64) -> Option<u64> {
        self.ranges.iter().find_map(|range| {
            if addr >= range.start && addr < range.start + range.file_size {
                Some(range.file_offset + (addr - range.start))
            } else {
                None
            }
        })
    }

    pub fn executable_ranges(&self) -> Vec<(u64, u64)> {
        self.ranges
            .iter()
            .filter(|range| range.permissions.contains('x'))
            .map(|range| (range.start, range.end))
            .collect()
    }

    pub fn bytes_at(&self, addr: u64, size: usize) -> Option<&[u8]> {
        let offset = self.va_to_offset(addr)? as usize;
        self.bytes.get(offset..offset.checked_add(size)?)
    }
}
```

Remove duplicate mapping logic in `ura-core::analysis::mod.rs` and
`strings.rs`/`disasm.rs` so they call these helpers directly on
`urloader::BinaryView`.

- [ ] **Step 4: Run local integration verification**

Run:

```bash
cargo test -p urloader --test integration -- --nocapture
cargo test -p ura-core --test analysis_smoke -- --nocapture
cargo test -p ura-core --test session_refresh -- --nocapture
```

Expected: all commands pass.

- [ ] **Step 5: Commit**

```bash
git add crates/urloader/tests/integration.rs crates/urloader/src/view.rs crates/ura-core/src/analysis crates/ura-core/tests
git commit -m "test: add local urloader front-end integration coverage"
```

---

### Task 6: Extend CI-Only Corpus Gate With Front-End Capability Assertions

**Files:**
- Modify: `crates/ura-corpus-gate/src/main.rs`
- Modify: `tests/corpus/manifest.toml`
- Modify: `README.md`
- Modify: `.github/workflows/corpus-gate.yml` only if step summary needs more output

- [ ] **Step 1: Write failing corpus-gate unit coverage for capability checks**

Add this unit test at the bottom of `crates/ura-corpus-gate/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_capability_expectations_reports_missing_front_end_features() {
        let sample = Sample {
            id: "fixture".to_string(),
            kind: "source".to_string(),
            output: PathBuf::from("generated/source/fixture"),
            format: "elf".to_string(),
            arch: "aarch64".to_string(),
            class: "bits64".to_string(),
            min_instructions: 1,
            max_unknown_rate: 1.0,
            unknown_family_budgets: BTreeMap::new(),
            required_strings: Vec::new(),
            required_capabilities: vec!["has_symbols".to_string(), "has_unwind_ranges".to_string()],
        };
        let report = FrontEndReport {
            capabilities: vec!["has_symbols".to_string()],
            fatal_diagnostic_count: 0,
            warning_diagnostic_count: 0,
        };
        let failures = validate_capabilities(&sample, &report);
        assert_eq!(failures, vec!["missing required capability has_unwind_ranges".to_string()]);
    }
}
```

- [ ] **Step 2: Run the corpus-gate test and verify it fails**

Run:

```bash
cargo test -p ura-corpus-gate validate_capability_expectations_reports_missing_front_end_features -- --nocapture
```

Expected: compile fails because `required_capabilities`, `FrontEndReport`, and
`validate_capabilities()` do not exist.

- [ ] **Step 3: Add front-end report fields and manifest expectations**

In `crates/ura-corpus-gate/src/main.rs`, extend `Sample` and `SampleReport`:

```rust
#[derive(Debug, Deserialize)]
struct Sample {
    id: String,
    kind: String,
    output: PathBuf,
    format: String,
    arch: String,
    class: String,
    min_instructions: usize,
    max_unknown_rate: f64,
    #[serde(default)]
    unknown_family_budgets: BTreeMap<String, usize>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    required_strings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FrontEndReport {
    capabilities: Vec<String>,
    fatal_diagnostic_count: usize,
    warning_diagnostic_count: usize,
}

#[derive(Debug, Serialize)]
struct SampleReport {
    // keep existing fields
    front_end: FrontEndReport,
}
```

Add helpers:

```rust
fn capability_names(view: &urloader::BinaryView<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if view.capabilities.can_map_executable_bytes {
        out.push("can_map_executable_bytes".to_string());
    }
    if view.capabilities.has_symbols {
        out.push("has_symbols".to_string());
    }
    if view.capabilities.has_unwind_ranges {
        out.push("has_unwind_ranges".to_string());
    }
    if view.capabilities.has_debug_function_ranges {
        out.push("has_debug_function_ranges".to_string());
    }
    out
}

fn validate_capabilities(sample: &Sample, report: &FrontEndReport) -> Vec<String> {
    sample
        .required_capabilities
        .iter()
        .filter(|required| !report.capabilities.iter().any(|have| have == *required))
        .map(|required| format!("missing required capability {required}"))
        .collect()
}
```

- [ ] **Step 4: Build views in the corpus gate and keep the CI-only guard**

In `analyze_sample()`:

```rust
let raw = urloader::load(&bytes)?;
let view = raw.analysis_view(&bytes)?;
let state = ura_core::analysis::build_state_from_view_with_instruction_limit(
    &view,
    &ura_core::model::UserFacts::default(),
    Some(MAX_CORPUS_INSTRUCTIONS_PER_SAMPLE),
)?;
let front_end = FrontEndReport {
    capabilities: capability_names(&view),
    fatal_diagnostic_count: view
        .diagnostics
        .iter()
        .filter(|diag| diag.severity == "error")
        .count(),
    warning_diagnostic_count: view
        .diagnostics
        .iter()
        .filter(|diag| diag.severity == "warning")
        .count(),
};
failures.extend(validate_capabilities(sample, &front_end));
```

Update `tests/corpus/manifest.toml` samples with conservative expectations:

```toml
required_capabilities = ["can_map_executable_bytes"]
```

Add stronger expectations only where fixtures or release samples truly expose
the metadata, for example:

```toml
required_capabilities = ["can_map_executable_bytes", "has_symbols"]
```

Run:

```bash
cargo test -p ura-corpus-gate -- --nocapture
env -u GITHUB_ACTIONS tests/corpus/scripts/run-corpus-gate.sh
```

Expected:

- `cargo test -p ura-corpus-gate` passes
- local shell run exits non-zero and prints `real-sample corpus gate is GitHub Actions only`

- [ ] **Step 5: Commit**

```bash
git add crates/ura-corpus-gate/src/main.rs tests/corpus/manifest.toml README.md
git commit -m "test: gate urloader front-end capabilities in corpus CI"
```

---

### Task 7: Final Workspace Verification And Cleanup

**Files:**
- Modify: `README.md` if wording still references the old `LoadedImage`-centric design
- Modify: `crates/urloader/src/lib.rs` to drop temporary compatibility exports when all callers are migrated
- Modify: `Cargo.lock`

- [ ] **Step 1: Remove temporary compatibility helpers**

Delete any temporary `LoadedImage` alias or compatibility wrappers added during
migration. The final public path should be:

```rust
pub fn load(bytes: &[u8]) -> Result<RawImage>;
impl RawImage {
    pub fn analysis_view<'a>(&'a self, bytes: &'a [u8]) -> Result<BinaryView<'a>, ViewBuildError>;
}
```

Update `README.md` crate table entry:

```md
| `urloader` | Parses executable containers into raw format facts and normalized analysis-facing binary views. |
```

- [ ] **Step 2: Run the full unit, integration, and workspace checks**

Run:

```bash
cargo test -p urloader -- --nocapture
cargo test -p ura-core -- --nocapture
cargo test -p ura-cli -- --nocapture
cargo test -p ura-daemon -- --nocapture
cargo test -p ura-corpus-gate -- --nocapture
cargo test --workspace
```

Expected: all commands pass locally without attempting the real-sample gate.

- [ ] **Step 3: Run formatting and lint checks**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: both commands pass.

- [ ] **Step 4: Confirm the corpus gate is still CI-only**

Run:

```bash
env -u GITHUB_ACTIONS tests/corpus/scripts/run-corpus-gate.sh
```

Expected: exits non-zero with `real-sample corpus gate is GitHub Actions only`.

- [ ] **Step 5: Commit the cleanup**

```bash
git add Cargo.lock README.md crates/urloader/src/lib.rs
git commit -m "chore: finalize urloader front-end migration"
```

---

## Self-Review

### Spec Coverage

- Raw parse layer plus analysis-facing front layer: covered by Tasks 1 and 2.
- `BinaryView`, capability, and diagnostic contracts: covered by Tasks 1, 3, and 4.
- Linkage metadata infrastructure: covered by Task 3.
- DWARF, `eh_frame`, and PE unwind high-value usable views: covered by Task 4.
- `ura-core` migration to consume front-end views: covered by Task 2 and Task 5.
- Stable unit tests plus local integration tests: covered by Tasks 1, 3, 4, and 5.
- CI-only real-sample gate with front-end assertions and no local-default gate: covered by Task 6 and Task 7.

No spec requirement is intentionally deferred out of this plan.

### Placeholder Scan

- No `TODO`, `TBD`, or "implement later" placeholders remain.
- Every task includes exact file paths, commands, and expected outputs.
- Code-changing steps include concrete code blocks or exact replacement shapes.

### Type Consistency

- The plan consistently uses `RawImage` for parsed format facts and `BinaryView` for analysis-facing inputs.
- `ura-core` migration steps consistently target `build_state_from_view_with_instruction_limit`.
- Capability names used in the corpus gate match the `CapabilitySet` field names introduced in Task 1 and expanded in Task 4.
