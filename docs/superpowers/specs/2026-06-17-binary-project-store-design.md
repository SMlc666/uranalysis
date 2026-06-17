# Binary Project Store Design

Date: 2026-06-17

## Purpose

Ura will remove SQLite from the project truth layer and move `*.ura` to a project-owned binary file format. The storage boundary remains abstract through a trait so the engine, CLI, and daemon do not depend directly on the physical project-file encoding.

This design supersedes the SQLite storage decision in `docs/superpowers/specs/2026-06-17-ura-binary-analysis-design.md`. The rest of the MVP scope remains unchanged.

## Goals

- Completely remove the runtime and compile-time dependency on SQLite.
- Keep `ura-core` as the only layer that owns project persistence.
- Preserve the public command behavior used by `ura-cli` and `ura-daemon`.
- Store projects as a single binary `*.ura` file.
- Keep a `ProjectStore` trait so future stores can replace the first binary encoding without changing command callers.
- Keep the first binary format simple enough to implement and test in one focused refactor.

## Non-Goals

- No SQLite-to-binary migration path for existing `*.ura` files.
- No JSON project format.
- No chunk table, mmap layer, compression, encryption, or random-access index in this refactor.
- No analysis-quality changes beyond what is required to preserve current behavior.
- No daemon protocol redesign.

## Architecture

The new storage boundary lives inside `ura-core`.

### Project Model

Introduce a serializable `ProjectFile` model that represents all persisted project truth:

- Metadata: format version, engine version, source hash, binary format, architecture, load profile.
- Loaded image metadata: segments, sections, and symbols.
- Analysis output: instructions, functions, xrefs, strings, and diagnostics.
- User truth: comments and renames.

Current command APIs will load a `ProjectFile`, mutate it in memory when needed, and save the whole file atomically. This keeps the first binary store simple and matches the current small-project MVP scale.

### Store Trait

Add a `ProjectStore` trait:

```rust
pub trait ProjectStore {
    fn load(&self, path: &std::path::Path) -> crate::Result<ProjectFile>;
    fn save(&self, path: &std::path::Path, project: &ProjectFile) -> crate::Result<()>;
}
```

`BinaryProjectStore` is the default implementation. `Project` owns a `ProjectFile` and uses the store for `open` and `save` operations. Command callers should continue to use `ura_core::commands` instead of store internals.

### Binary File Format

The first format is a single file with a small stable header:

```text
offset  size  field
0       4     magic bytes: U R A 0
4       4     container version, little-endian u32
8       8     payload length, little-endian u64
16      N     bincode payload containing ProjectFile
```

Rules:

- Magic must match exactly.
- Container version must be `1`.
- Payload length must equal the remaining file length.
- Payload is encoded with `bincode`.
- Decode failures return a typed `UraError`.

`bincode` is acceptable here because the file is engine-owned, binary, compact, and covered by versioned container metadata. Future compatibility work can add explicit migrations before changing the payload model.

### Atomic Save

`BinaryProjectStore::save` writes to a temporary sibling path first, flushes it, and renames it into place. This prevents a partially written project from replacing a valid project when a process fails mid-write.

### Command Behavior

Command behavior stays functionally aligned with the current SQLite implementation:

- `new_project` parses the input ELF, runs initial analysis, and writes a binary `*.ura`.
- `info`, `disasm`, `strings`, `functions`, `xrefs`, `diagnostics`, and `comments` read from the in-memory project file.
- `rename`, `comment`, `make_function`, and `set_function_range` mutate user truth and save.
- `reanalyze` keeps current behavior: preserve user functions and comments without adding new analysis semantics in this storage refactor.

## Dependency Changes

Remove:

- `rusqlite` from the workspace dependency graph.

Add:

- `bincode` for binary payload encoding.

Keep:

- `serde` for model serialization.
- `serde_json` for CLI JSON output and daemon protocol values.

## Testing

Tests must prove the storage replacement is real and not a thin wrapper over SQLite:

- New project files begin with the binary magic bytes, not a SQLite header.
- Projects can be created, closed, reopened, queried, and mutated.
- User comments, renames, and user-defined function ranges persist after reopening.
- Invalid magic, unsupported container version, truncated header, and mismatched payload length produce errors.
- CLI smoke tests still create a project and print info.
- Daemon smoke tests still open a project and write a comment.
- `cargo test --workspace`, `cargo fmt -- --check`, and `cargo clippy --workspace --all-targets -- -D warnings` must pass.

## Rollout

This is a breaking project-file change. Old SQLite-backed `*.ura` files are not supported after the refactor. The crate version remains `0.1.0`; compatibility guarantees start only after the binary container design stabilizes.
