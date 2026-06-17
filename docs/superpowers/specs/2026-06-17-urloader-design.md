# Urloader Design

Date: 2026-06-17

## Purpose

`urloader` is the project-owned binary loader crate for Ura. It replaces the
current `goblin` dependency in the product path and prevents `ura-core` from
owning ELF-specific parsing logic.

The first version is intentionally broader than a direct ELF wrapper. It must
define a real loader abstraction by supporting the existing ELF64 AArch64
workflow and an initial PE loader path. PE support is used to validate the
abstraction boundary, not to claim full PE analysis support in `ura-core`.

## Goals

- Add a new workspace crate named `urloader`.
- Remove `goblin` from `ura-core`.
- Delete `crates/ura-core/src/elf_loader.rs`.
- Make `urloader` the only layer that parses binary container formats.
- Preserve current ELF64 AArch64 project creation and analysis behavior.
- Add initial PE loading support sufficient to validate the shared image model.
- Keep PE loading independently tested without routing PE into the current
  AArch64 analysis pipeline.

## Non-Goals

- No full PE import, export, relocation, resource, or TLS parsing in this
  version.
- No PE disassembly or PE project analysis in `ura-core`.
- No Mach-O support.
- No generic big-endian ELF support.
- No ELF32 support.
- No replacement of `urdisassembly` or `urdis2il`.
- No project-file schema redesign beyond dependency and source-model changes
  needed to remove `ura-core`'s ELF loader.

## Architecture

`urloader` owns format detection and format-specific parsing. Callers pass raw
bytes to the crate and receive a format-neutral loaded image model.

```rust
pub fn load(bytes: &[u8]) -> Result<LoadedImage>;
```

`LoadedImage` is a normalized image view:

- `format`: ELF or PE.
- `architecture`: AArch64, X86-64, or Unknown for unsupported but identified
  machines.
- `class`: 32-bit or 64-bit.
- `endian`: little or big.
- `profile`: executable, shared object, relocatable, kernel-style,
  stripped-like, or unknown.
- `entry`: virtual address entry point when available.
- `segments`: loadable memory ranges with file offsets and permissions.
- `sections`: named file/image sections.
- `symbols`: normalized static and dynamic symbols where implemented.
- `imports` and `exports`: model fields reserved for supported formats.
- `diagnostics`: non-fatal parser observations.
- `format_details`: private-format summary for ELF or PE facts that should not
  pollute the common model.

The model must also support address translation helpers:

- `va_to_offset(addr) -> Option<u64>`
- `rva_to_offset(rva) -> Option<u64>` for PE and formats with relative virtual
  addresses
- `bytes_at(addr, size) -> Option<&[u8]>`
- `executable_ranges() -> Vec<(u64, u64)>`

The helper methods live on `LoadedImage` so analysis code does not need to know
whether the image came from ELF program headers or PE sections.

## ELF Scope

The ELF parser must fully replace the current `goblin` use in `ura-core`.

Supported first-version ELF inputs:

- ELF magic.
- ELF64 class.
- Little-endian encoding.
- AArch64 machine type.
- Executable, shared object, and relocatable object file types.
- Program headers, including `PT_LOAD` segment extraction.
- Section headers.
- Section-name string table.
- `.symtab` plus linked string table.
- `.dynsym` plus linked dynamic string table.
- Virtual-address to file-offset mapping through loadable segments.

ELF output must preserve the data currently persisted by `ura-core`:

- load profile
- entry point
- segments
- sections
- symbols
- original bytes for analysis reads

Unsupported ELF class, endianness, machine type, malformed header sizes, and
out-of-bounds table ranges return typed loader errors.

## PE Scope

The PE parser exists in the first version to force `urloader` to have a real
multi-format abstraction. It does not make PE a supported `ura-core` analysis
target yet.

Supported first-version PE inputs:

- DOS `MZ` header.
- `e_lfanew` pointer validation.
- PE signature.
- COFF header.
- Optional header magic for PE32 and PE32+.
- Machine type detection for at least x86-64.
- Image base.
- Entry point RVA converted to virtual address when possible.
- Section table.
- Section-derived address mapping.
- Basic section permissions from characteristics.

PE output must populate:

- format = PE
- architecture
- class
- profile
- entry
- sections
- loadable ranges derived from sections
- address translation helpers

PE imports, exports, relocations, resources, certificates, debug directories,
and TLS are explicitly deferred. The public model may include fields for them,
but tests must not imply they are implemented.

## `ura-core` Integration

`ura-core` must stop owning a format-specific loader module.

Required changes:

- Remove `pub mod elf_loader`.
- Delete `crates/ura-core/src/elf_loader.rs`.
- Replace `goblin.workspace = true` in `ura-core` with `urloader.workspace =
  true`.
- `commands::new_project` calls `urloader::load(&bytes)`.
- `build_project_file` accepts `urloader::LoadedImage`.
- Existing persisted `ura-core::model` structs remain the project-file model.
- Add a small conversion layer from `urloader` model values into
  `ura-core::model` values.
- Analysis rejects unsupported loaded images with a clear error before
  disassembly.

For this version, the only `ura-core` analysis target remains:

- format = ELF
- architecture = AArch64
- class = 64-bit
- endian = little

PE project creation through `ura-core::commands::new_project` should return a
clear unsupported-analysis-target error. It must not panic, route through ELF
logic, or attempt AArch64 disassembly.

## Testing

Implementation must be test-driven.

### ELF Tests

`urloader` tests use hand-built minimal ELF fixtures. They must prove:

- A minimal ELF64 AArch64 executable loads.
- Entry point, profile, segment permissions, sections, and address mapping are
  correct.
- Symbol table and dynamic symbol table parsing return expected names and
  addresses.
- Invalid magic, unsupported class, unsupported machine, unsupported endian,
  truncated headers, and out-of-bounds table ranges return typed errors.

Existing `ura-core` tests that create projects from minimal ELF inputs must
continue to pass after `elf_loader.rs` is removed.

### PE Tests

`urloader` PE tests use hand-built minimal PE fixtures and no third-party parser
as an oracle. They must prove:

- A minimal PE32+ x86-64 image loads.
- `format`, `architecture`, `class`, `entry`, and image base are correct.
- `.text` and `.rdata` sections are parsed with correct names, virtual
  addresses, raw offsets, sizes, and permissions.
- `rva_to_offset`, `va_to_offset`, and `bytes_at` work for section-backed
  addresses.
- Non-`MZ` input, out-of-bounds `e_lfanew`, missing PE signature, truncated COFF
  header, truncated optional header, unsupported optional-header magic, and
  malformed section tables fail clearly.

### Integration Tests

`ura-core` integration tests must prove:

- ELF project creation, reopen, disassembly, strings, functions, xrefs,
  diagnostics, comments, renames, and user functions preserve current behavior.
- PE input is rejected by `ura-core` with a clear unsupported-analysis-target
  error.
- No `goblin` dependency remains in `ura-core`.

Workspace verification must pass:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Rollout

This is an internal dependency replacement and loader-boundary refactor. The
project-file format should not change semantically. Existing tests are the
compatibility contract for current ELF64 AArch64 behavior.

The first PE loader is intentionally a loader-only feature. Future work can
connect PE to analysis after the project model, architecture dispatch, and
disassembly pipeline support non-ELF targets.
