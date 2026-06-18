# uranalysis

`uranalysis` is an early Rust binary-analysis framework. It currently focuses on loading executable images, decoding instructions, storing project state, and exposing analysis results through a CLI and a simple daemon protocol.

This project is not a mature reverse-engineering suite. The current goal is to build a small, testable core that can grow target support without hiding unknown instructions or unsupported formats.

## Workspace

| Crate | Purpose |
| --- | --- |
| `urloader` | Loads executable image metadata and bytes. |
| `urcodec` | Decodes and encodes AArch64 and x86-64 instruction subsets, owns the shared instruction model, and provides canonical text handling. |
| `urdis2il` | Lifts decoded instructions into a small IL. |
| `ura-core` | Stores projects and runs analysis passes. |
| `ura-cli` | Provides the `ura` command-line interface. |
| `ura-daemon` | Provides a line-delimited JSON daemon protocol. |

## Current Support

| Target | Loader | Core Analysis | Notes |
| --- | --- | --- | --- |
| ELF64 AArch64 little-endian | Supported | Supported | Fixed-width AArch64 disassembly. |
| ELF64 x86-64 little-endian | Supported | Supported | Variable-width x86-64 disassembly. |
| PE32+ x86-64 little-endian | Supported | Supported | PE sections are analyzed as executable ranges. |

Instruction coverage is intentionally partial. Unknown instructions are preserved in analysis output and surfaced through diagnostics.

## Build and Test

```sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## CLI

Create a project:

```sh
cargo run --bin ura -- new sample.elf -o sample.ura
```

Inspect a project:

```sh
cargo run --bin ura -- info sample.ura
cargo run --bin ura -- disasm sample.ura 0x400080 --count 16
cargo run --bin ura -- strings sample.ura --filter hello
cargo run --bin ura -- funcs sample.ura
cargo run --bin ura -- xrefs sample.ura 0x400080
```

Edit user metadata:

```sh
cargo run --bin ura -- rename sample.ura 0x400080 manual_name
cargo run --bin ura -- comment sample.ura 0x400080 "manual note"
cargo run --bin ura -- make-func sample.ura 0x400080
```

## Corpus Gate Policy

The real-sample corpus gate is GitHub Actions only. Local developers should run the normal Rust checks above. Corpus binaries are generated or fetched in CI and are not committed to git.

## License

MIT
