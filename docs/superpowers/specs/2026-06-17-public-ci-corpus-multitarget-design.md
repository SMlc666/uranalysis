# Public Repository, CI Corpus Gate, and Multi-Target Analysis Design

## Summary

The next development stage will turn `uranalysis` from a local Rust workspace into a public GitHub project with CI, a CI-only real-sample corpus gate, and a multi-target `ura-core` analysis pipeline.

The work has three linked goals:

- Publish the repository publicly with enough project metadata for external readers.
- Add GitHub Actions gates that separate normal developer checks from real-sample corpus checks.
- Generalize `ura-core` from `ELF64 + AArch64` to `ELF64 AArch64`, `ELF64 x86-64`, and `PE32+ x86-64`.

## Non-Goals

- Do not check generated binary corpus artifacts into git.
- Do not allow local developers to run the real-sample corpus gate.
- Do not make corpus results depend on unpinned release assets or mutable upstream state.
- Do not replace the current CLI or daemon command surface in this stage.
- Do not attempt broad instruction coverage expansion before the multi-target pipeline and corpus gate exist.

## Open Source Preparation

Before adding GitHub Actions, the repository will be prepared for public release:

- Add `README.md` with project scope, current maturity, build/test commands, CLI examples, and a support matrix.
- Add `LICENSE` matching the existing MIT declaration in `Cargo.toml`.
- State explicitly that the project is an early binary-analysis framework, not a mature reverse-engineering suite.
- Document the initial supported targets and known limitations.

The public GitHub repository will be created with the current authenticated `gh` CLI account:

```sh
gh repo create uranalysis --public --source=. --push
```

An equivalent non-interactive `gh` command is acceptable if needed by the current `gh` authentication state. Public publishing happens before adding workflows so the workflow files can be pushed and evaluated on GitHub.

## Workflow Design

The project will use two separate GitHub Actions workflows.

### `ci.yml`

This is the normal developer-quality gate. It runs on:

- `push`
- `pull_request`
- `workflow_dispatch`

It runs checks that developers may also run locally:

```sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### `corpus-gate.yml`

This is the real-sample gate. It runs on:

- `push` to `main`
- `pull_request` to `main`
- `workflow_dispatch`

It must use plain `pull_request`, not `pull_request_target`, and must not require repository secrets. Release corpus downloads must come from public URLs and be verified by pinned hashes.

The job responsibilities are:

- Install or verify corpus toolchains.
- Build source-defined corpus samples.
- Download pinned GitHub release samples.
- Verify every generated or downloaded sample.
- Build the Rust workspace.
- Run the CI-only corpus gate.
- Upload `corpus-report.json` and a markdown report artifact with `always()`.
- Append a concise gate summary to the GitHub Actions step summary.

The corpus gate must run on pull requests so real-sample regressions are caught before merging into `main`.

## CI Cache Design

Cache is an acceleration layer, not a trust source. Every cache hit must still be verified against manifests, versions, fingerprints, or hashes.

### Rust Cache

Used by both workflows.

Paths:

```text
~/.cargo/registry
~/.cargo/git
target
```

Primary key:

```text
rust-${{ runner.os }}-${{ hashFiles('Cargo.lock') }}-${{ hashFiles('Cargo.toml', 'crates/**/Cargo.toml') }}
```

Restore key:

```text
rust-${{ runner.os }}-
```

This cache only speeds up Rust builds. It does not affect sample correctness.

### Corpus Toolchain Cache

Used by `corpus-gate.yml`.

Path:

```text
tests/corpus/.cache/toolchains/
```

Primary key:

```text
corpus-toolchains-${{ runner.os }}-${{ hashFiles('tests/corpus/toolchains.toml', 'tests/corpus/scripts/install-*.sh') }}
```

Rules:

- Each cached toolchain must have an explicit version and sha256.
- Cache hits must still verify version and sha256.
- If verification fails, the job removes the cached toolchain and reinstalls it.
- If reinstall verification still fails, the job fails.

### Corpus Sample Cache

Used by `corpus-gate.yml`.

Path:

```text
tests/corpus/generated/
```

Primary key:

```text
corpus-samples-${{ runner.os }}-${{ hashFiles('tests/corpus/manifest.toml', 'tests/corpus/src/**', 'tests/corpus/scripts/**') }}
```

Rules:

- `tests/corpus/generated/` is gitignored.
- Cache hits must still verify every sample.
- Release samples must match the manifest sha256.
- Source-built samples must match a generated `.fingerprint.json`.
- A source-built fingerprint includes source hash, compiler id and version, build flags, target triple, and output sha256.
- If a cached source-built sample fingerprint does not match, it is rebuilt.
- If a cached release sample sha256 does not match, the job fails rather than silently using stale or modified data.

The `corpus-gate.yml` order is:

```text
checkout
setup Rust
restore Rust cache
restore corpus toolchain cache
install or verify corpus toolchains
restore corpus sample cache
build, fetch, and verify corpus samples
cargo build --workspace
run CI-only corpus gate
upload corpus reports with always()
```

## Corpus Asset Design

Generated binaries are not committed. Source corpus inputs and corpus metadata are committed.

Directory layout:

```text
tests/corpus/
  manifest.toml
  toolchains.toml
  src/
    elf-aarch64/
    elf-x86_64/
    pe-x86_64/
  scripts/
    build-source-corpus.sh
    fetch-release-corpus.sh
    run-corpus-gate.sh
    install-toolchains.sh
  generated/
```

`generated/` and `.cache/` are ignored by git.

### Source-Built Samples

Source-built samples are mandatory CI inputs. Their source files live under `tests/corpus/src/`.

Initial target classes:

- `ELF64 AArch64`
- `ELF64 x86-64`
- `PE32+ x86-64`

Samples should be small but compiled by real toolchains. They should include enough control flow, strings, symbols, and data references to exercise loader, disassembly, strings, xrefs, and function discovery.

### Release Samples

Pinned release samples provide real-world coverage. Each release sample must define:

- GitHub repository.
- Tag.
- Asset name.
- Download URL or derivable release asset reference.
- sha256.
- License or source note.
- Expected format, architecture, and class.
- Analysis thresholds.

A release sample missing any required pinning or license/source metadata cannot run in the CI gate.

## Corpus Manifest

`tests/corpus/manifest.toml` describes both source-built and release samples.

Example source-built entry:

```toml
[[sample]]
id = "hello_elf_aarch64"
kind = "source"
source = "src/elf-aarch64/hello.S"
format = "elf"
arch = "aarch64"
class = "bits64"
min_instructions = 5
max_unknown_rate = 0.20
required_strings = ["hello"]
```

Release entries use the same expectation keys, plus concrete `repo`, `tag`, `asset`, `sha256`, and `license` values. A release entry with non-concrete metadata is invalid and must be rejected by the corpus scripts.

The manifest is the single source of truth for corpus gate expectations.

## Local Execution Policy

The real-sample corpus gate is GitHub Actions only.

`tests/corpus/scripts/run-corpus-gate.sh` must exit non-zero when `GITHUB_ACTIONS=true` is not present. It must print a direct message that the real-sample gate is CI-only.

The corpus gate must not be called from `cargo test`, `cargo xtask`, or any local-default command. Local developers can run normal Rust checks and small fixture tests only.

## Corpus Report

The corpus gate emits machine-readable and human-readable reports.

`corpus-report.json` records per sample:

- sample id
- source kind
- load result
- detected format
- detected architecture
- detected class
- entry point
- segment and section counts
- decoded instruction count
- unknown instruction count
- unknown rate
- string count
- function count
- xref count
- diagnostic count
- failure reason, when present

The workflow also writes a concise markdown summary to the GitHub Actions step summary.

## `ura-core` Multi-Target Architecture

`ura-core` will stop hardcoding `ELF64 + AArch64`.

Introduce an explicit target model:

```rust
struct AnalysisTarget {
    format: BinaryFormat,
    architecture: Architecture,
    class: ImageClass,
    endian: Endian,
}
```

The project model will be generalized:

- `BinaryFormat`: `Elf`, `Pe`
- `Architecture`: `Aarch64`, `X86_64`
- `ImageClass`: `Bits32`, `Bits64`
- `Endian`: `Little`, and only supported values accepted by analysis

The project schema version will be bumped because serialized model fields change.

`new_project` flow:

```text
read input bytes
urloader::load(bytes)
convert LoadedImage into AnalysisTarget
select analysis backend
run backend disassembly
run shared strings/functions/xrefs/diagnostics passes
save ProjectFile
```

Initial backends:

```text
Aarch64Backend
  supports ELF64 AArch64 little-endian
  uses fixed 4-byte instruction stepping
  reuses the existing AArch64 decoder

X86_64Backend
  supports ELF64 x86-64 little-endian
  supports PE32+ x86-64 little-endian
  uses variable-length stepping from decoder output size
  records unknown or truncated decode diagnostics
```

`urloader` must support ELF machine `EM_X86_64` so ELF64 x86-64 can enter the same pipeline.

## Structured Core Semantics

`ura-core` should stop degrading instruction semantics into strings.

Project instructions will store structured values for:

- instruction kind
- flow kind
- decode status

CLI and daemon output may still serialize these values into readable JSON or debug text, but core analysis must not depend on string comparisons such as `"Call"` or `"Branch"`.

This is required before multi-target analysis grows, because string-matching semantic values would become fragile across architectures.

## Analysis Acceptance Criteria

For each first-stage target:

- `ura new` succeeds.
- `info` records the expected format, architecture, class, and profile where available.
- `disasm` returns at least the manifest `min_instructions`.
- unknown rate is at or below the manifest threshold.
- required strings are present.
- basic function and xref smoke assertions pass when declared in the manifest.
- diagnostics are reported and included in the corpus report.

Gate failures:

- unsupported format or architecture
- all instructions unknown
- unknown rate over threshold
- release download failure
- release sha256 mismatch
- missing release license/source metadata
- source-built sample fingerprint mismatch after rebuild
- local attempt to run the real-sample gate

One sample failure fails the whole corpus gate, but reports must still include all samples that were attempted.

## Implementation Stages

1. Public repository preparation.
   - Add public-facing project metadata.
   - Create and push the public GitHub repository with `gh`.

2. Basic CI.
   - Add `ci.yml`.
   - Verify formatting, tests, and clippy in GitHub Actions.

3. CI-only corpus gate foundation.
   - Add corpus directory, manifest, toolchain metadata, scripts, gitignore entries, cache setup, and report generation.
   - Ensure local corpus gate execution fails.

4. `ura-core` multi-target analysis.
   - Generalize target models.
   - Add backend selection.
   - Add ELF x86-64 loader support.
   - Add x86-64 variable-length disassembly in `ura-core`.
   - Preserve structured instruction semantics.

5. Corpus-backed acceptance.
   - Add source-built samples for all first-stage targets.
   - Add a small number of pinned release samples.
   - Enforce manifest thresholds in `corpus-gate.yml`.
