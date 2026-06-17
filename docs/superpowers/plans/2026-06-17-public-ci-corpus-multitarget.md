# Public CI Corpus Multi-Target Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish `uranalysis` as a public GitHub repository, add normal and CI-only corpus gates, and extend `ura-core` to analyze `ELF64 AArch64`, `ELF64 x86-64`, and `PE32+ x86-64`.

**Architecture:** Keep the existing crate split. Add public metadata and GitHub Actions first, then add corpus assets and scripts, then generalize `ura-core` through explicit target models and backend selection. The real-sample corpus gate stays outside local default commands and runs only when `GITHUB_ACTIONS=true`.

**Tech Stack:** Rust 2021 workspace, GitHub Actions, Bash scripts, pinned Zig `cc` 0.14.1 for source-built corpus samples, pinned ripgrep 14.1.1 GitHub release assets, `gh` CLI for repository publication.

---

## File Structure

Create:

- `README.md`: public project overview, status, support matrix, commands.
- `LICENSE`: MIT license matching workspace metadata.
- `.github/workflows/ci.yml`: local-equivalent Rust quality gate.
- `.github/workflows/corpus-gate.yml`: CI-only real-sample corpus gate.
- `tests/corpus/manifest.toml`: source-built and release sample declarations.
- `tests/corpus/toolchains.toml`: pinned Zig toolchain metadata.
- `tests/corpus/src/common/sample.c`: shared source-built sample.
- `tests/corpus/scripts/install-toolchains.sh`: installs or verifies pinned Zig.
- `tests/corpus/scripts/build-source-corpus.sh`: builds source corpus samples with Zig.
- `tests/corpus/scripts/fetch-release-corpus.sh`: downloads and extracts pinned release samples.
- `tests/corpus/scripts/run-corpus-gate.sh`: CI-only entrypoint.
- `crates/ura-corpus-gate/Cargo.toml`: corpus gate binary crate.
- `crates/ura-corpus-gate/src/main.rs`: manifest-driven analyzer and report writer.
- `crates/ura-core/src/analysis/target.rs`: `AnalysisTarget` model and loader-to-core conversion.

Modify:

- `.gitignore`: ignore corpus generated and cache directories.
- `Cargo.toml`: add `ura-corpus-gate` workspace member and shared dependencies used by that crate.
- `crates/urloader/src/elf.rs`: accept `EM_X86_64` and map it to `Architecture::X86_64`.
- `crates/urloader/tests/elf.rs`: cover ELF64 x86-64 loader metadata.
- `crates/ura-core/src/model.rs`: add `ImageClass`, `Endian`, generalized `BinaryFormat` and `Architecture`, and structured instruction semantics.
- `crates/ura-core/src/store.rs`: bump schema version and update empty project defaults.
- `crates/ura-core/src/commands.rs`: build projects through `AnalysisTarget` and backend selection.
- `crates/ura-core/src/analysis/mod.rs`: pass target information into analysis.
- `crates/ura-core/src/analysis/disasm.rs`: split fixed-width AArch64 and variable-width x86-64 disassembly.
- `crates/ura-core/src/analysis/functions.rs`: use structured `FlowKind`.
- `crates/ura-core/src/analysis/xrefs.rs`: use structured `FlowKind` and `InstructionKind`.
- Existing `ura-core`, `ura-cli`, `ura-daemon`, `urloader`, and `urdisassembly` tests: update expected model enum names.

---

### Task 1: Public Metadata and GitHub Publication

**Files:**
- Create: `README.md`
- Create: `LICENSE`

- [ ] **Step 1: Create `README.md`**

Add this file:

```markdown
# uranalysis

`uranalysis` is an early Rust binary-analysis framework. It currently focuses on loading executable images, decoding instructions, storing project state, and exposing analysis results through a CLI and a simple daemon protocol.

This project is not a mature reverse-engineering suite. The current goal is to build a small, testable core that can grow target support without hiding unknown instructions or unsupported formats.

## Workspace

| Crate | Purpose |
| --- | --- |
| `urloader` | Loads executable image metadata and bytes. |
| `urdisassembly` | Decodes AArch64 and x86-64 instruction subsets. |
| `urdis2il` | Lifts decoded instructions into a small IL. |
| `ura-core` | Stores projects and runs analysis passes. |
| `ura-cli` | Provides the `ura` command-line interface. |
| `ura-daemon` | Provides a line-delimited JSON daemon protocol. |

## Current Support

| Target | Loader | Core Analysis | Notes |
| --- | --- | --- | --- |
| ELF64 AArch64 little-endian | Supported | Supported | Primary current path. |
| ELF64 x86-64 little-endian | Planned | Planned | Part of the next multi-target stage. |
| PE32+ x86-64 little-endian | Supported by loader | Planned | Part of the next multi-target stage. |

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
```

- [ ] **Step 2: Create `LICENSE`**

Add this file:

```text
MIT License

Copyright (c) 2026 uranalysis contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 3: Verify metadata-only change**

Run:

```sh
git diff -- README.md LICENSE
```

Expected: diff only contains the two new public metadata files.

- [ ] **Step 4: Commit public metadata**

Run:

```sh
git add README.md LICENSE
git commit -m "docs: add public project metadata"
```

Expected: commit succeeds.

- [ ] **Step 5: Publish public GitHub repository**

Run:

```sh
gh auth status
gh repo create uranalysis --public --source=. --push
```

Expected:

- `gh auth status` reports a logged-in account.
- `gh repo create` creates a public repository named `uranalysis` under the logged-in account.
- The local branch is pushed to the new remote.

If the repository already exists, run:

```sh
gh repo view uranalysis --json nameWithOwner,visibility
git remote -v
git push -u origin master
```

Expected:

- `visibility` is `PUBLIC`.
- `origin` points at the public `uranalysis` repository.
- The current branch pushes successfully.

---

### Task 2: Normal GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create `.github/workflows/ci.yml`**

Add this file:

```yaml
name: CI

on:
  push:
  pull_request:
  workflow_dispatch:

jobs:
  rust:
    name: Rust checks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Restore Rust cache
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: rust-${{ runner.os }}-${{ hashFiles('Cargo.lock') }}-${{ hashFiles('Cargo.toml', 'crates/**/Cargo.toml') }}
          restore-keys: |
            rust-${{ runner.os }}-

      - name: Check formatting
        run: cargo fmt --check

      - name: Run tests
        run: cargo test --workspace

      - name: Run clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 2: Run normal checks locally**

Run:

```sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 3: Commit CI workflow**

Run:

```sh
git add .github/workflows/ci.yml
git commit -m "ci: add rust workspace checks"
git push
```

Expected: commit and push succeed. GitHub Actions starts the `CI` workflow on the public repository.

---

### Task 3: Corpus Metadata, Sources, and Scripts

**Files:**
- Modify: `.gitignore`
- Create: `tests/corpus/manifest.toml`
- Create: `tests/corpus/toolchains.toml`
- Create: `tests/corpus/src/common/sample.c`
- Create: `tests/corpus/scripts/install-toolchains.sh`
- Create: `tests/corpus/scripts/build-source-corpus.sh`
- Create: `tests/corpus/scripts/fetch-release-corpus.sh`
- Create: `tests/corpus/scripts/run-corpus-gate.sh`

- [ ] **Step 1: Extend `.gitignore`**

Add these lines:

```gitignore
tests/corpus/.cache/
tests/corpus/generated/
```

- [ ] **Step 2: Create `tests/corpus/toolchains.toml`**

Add this file:

```toml
[zig]
version = "0.14.1"
host = "x86_64-linux"
url = "https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz"
sha256 = "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c"
archive_root = "zig-x86_64-linux-0.14.1"
```

- [ ] **Step 3: Create `tests/corpus/manifest.toml`**

Add this file:

```toml
[[sample]]
id = "source_elf_aarch64"
kind = "source"
source = "src/common/sample.c"
output = "generated/source/elf-aarch64/ura-sample"
target = "aarch64-linux-gnu"
format = "elf"
arch = "aarch64"
class = "bits64"
min_instructions = 4
max_unknown_rate = 0.50
required_strings = ["ura-corpus-hello"]

[[sample]]
id = "source_elf_x86_64"
kind = "source"
source = "src/common/sample.c"
output = "generated/source/elf-x86_64/ura-sample"
target = "x86_64-linux-gnu"
format = "elf"
arch = "x86_64"
class = "bits64"
min_instructions = 4
max_unknown_rate = 0.50
required_strings = ["ura-corpus-hello"]

[[sample]]
id = "source_pe_x86_64"
kind = "source"
source = "src/common/sample.c"
output = "generated/source/pe-x86_64/ura-sample.exe"
target = "x86_64-windows-gnu"
format = "pe"
arch = "x86_64"
class = "bits64"
min_instructions = 4
max_unknown_rate = 0.50
required_strings = ["ura-corpus-hello"]

[[sample]]
id = "release_ripgrep_aarch64_linux"
kind = "release"
repo = "BurntSushi/ripgrep"
tag = "14.1.1"
asset = "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz"
url = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz"
sha256 = "c827481c4ff4ea10c9dc7a4022c8de5db34a5737cb74484d62eb94a95841ab2f"
archive_member = "ripgrep-14.1.1-aarch64-unknown-linux-gnu/rg"
output = "generated/release/ripgrep-aarch64-linux/rg"
license = "MIT OR Unlicense"
format = "elf"
arch = "aarch64"
class = "bits64"
min_instructions = 100
max_unknown_rate = 0.98
required_strings = []

[[sample]]
id = "release_ripgrep_x86_64_linux"
kind = "release"
repo = "BurntSushi/ripgrep"
tag = "14.1.1"
asset = "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz"
url = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz"
sha256 = "4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e"
archive_member = "ripgrep-14.1.1-x86_64-unknown-linux-musl/rg"
output = "generated/release/ripgrep-x86_64-linux/rg"
license = "MIT OR Unlicense"
format = "elf"
arch = "x86_64"
class = "bits64"
min_instructions = 100
max_unknown_rate = 0.98
required_strings = []

[[sample]]
id = "release_ripgrep_x86_64_windows"
kind = "release"
repo = "BurntSushi/ripgrep"
tag = "14.1.1"
asset = "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
url = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
sha256 = "d0f534024c42afd6cb4d38907c25cd2b249b79bbe6cc1dbee8e3e37c2b6e25a1"
archive_member = "ripgrep-14.1.1-x86_64-pc-windows-msvc/rg.exe"
output = "generated/release/ripgrep-x86_64-windows/rg.exe"
license = "MIT OR Unlicense"
format = "pe"
arch = "x86_64"
class = "bits64"
min_instructions = 100
max_unknown_rate = 0.98
required_strings = []
```

- [ ] **Step 4: Create `tests/corpus/src/common/sample.c`**

Add this file:

```c
__attribute__((used))
static const char ura_message[] = "ura-corpus-hello";

__attribute__((noinline))
int ura_mix(int value) {
    if (value == 7) {
        return value + ura_message[0];
    }
    return value - 3;
}

#if defined(_WIN32)
void mainCRTStartup(void) {
    volatile int sink = ura_mix(7);
    (void)sink;
}
#else
void _start(void) {
    volatile int sink = ura_mix(7);
    (void)sink;
}
#endif
```

- [ ] **Step 5: Create `tests/corpus/scripts/install-toolchains.sh`**

Add this file and mark it executable:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CACHE_DIR="$ROOT/tests/corpus/.cache/toolchains"
ZIG_DIR="$CACHE_DIR/zig-x86_64-linux-0.14.1"
ZIG_TARBALL="$CACHE_DIR/zig-x86_64-linux-0.14.1.tar.xz"
ZIG_URL="https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz"
ZIG_SHA256="24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c"

mkdir -p "$CACHE_DIR"

verify_file() {
    local path="$1"
    local expected="$2"
    local actual
    actual="$(sha256sum "$path" | awk '{print $1}')"
    test "$actual" = "$expected"
}

if [ -x "$ZIG_DIR/zig" ]; then
    "$ZIG_DIR/zig" version | grep -qx "0.14.1"
    exit 0
fi

rm -rf "$ZIG_DIR"

if [ ! -f "$ZIG_TARBALL" ] || ! verify_file "$ZIG_TARBALL" "$ZIG_SHA256"; then
    rm -f "$ZIG_TARBALL"
    curl -fsSL "$ZIG_URL" -o "$ZIG_TARBALL"
fi

verify_file "$ZIG_TARBALL" "$ZIG_SHA256"
tar -C "$CACHE_DIR" -xf "$ZIG_TARBALL"
"$ZIG_DIR/zig" version | grep -qx "0.14.1"
```

Run:

```sh
chmod +x tests/corpus/scripts/install-toolchains.sh
```

- [ ] **Step 6: Create `tests/corpus/scripts/build-source-corpus.sh`**

Add this file and mark it executable:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ZIG="$ROOT/tests/corpus/.cache/toolchains/zig-x86_64-linux-0.14.1/zig"
SRC="$ROOT/tests/corpus/src/common/sample.c"

if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    echo "source corpus build is GitHub Actions only" >&2
    exit 64
fi

"$ROOT/tests/corpus/scripts/install-toolchains.sh"

build_one() {
    local target="$1"
    local output="$2"
    local entry="$3"
    mkdir -p "$(dirname "$output")"
    "$ZIG" cc -target "$target" -Os -g0 -nostdlib -Wl,-e,"$entry" "$SRC" -o "$output"
}

build_one "aarch64-linux-gnu" "$ROOT/tests/corpus/generated/source/elf-aarch64/ura-sample" "_start"
build_one "x86_64-linux-gnu" "$ROOT/tests/corpus/generated/source/elf-x86_64/ura-sample" "_start"
build_one "x86_64-windows-gnu" "$ROOT/tests/corpus/generated/source/pe-x86_64/ura-sample.exe" "mainCRTStartup"

cat > "$ROOT/tests/corpus/generated/source/.fingerprint.json" <<JSON
{
  "compiler": "zig cc",
  "compiler_version": "$("$ZIG" version)",
  "source_sha256": "$(sha256sum "$SRC" | awk '{print $1}')",
  "elf_aarch64_sha256": "$(sha256sum "$ROOT/tests/corpus/generated/source/elf-aarch64/ura-sample" | awk '{print $1}')",
  "elf_x86_64_sha256": "$(sha256sum "$ROOT/tests/corpus/generated/source/elf-x86_64/ura-sample" | awk '{print $1}')",
  "pe_x86_64_sha256": "$(sha256sum "$ROOT/tests/corpus/generated/source/pe-x86_64/ura-sample.exe" | awk '{print $1}')"
}
JSON
```

Run:

```sh
chmod +x tests/corpus/scripts/build-source-corpus.sh
```

- [ ] **Step 7: Create `tests/corpus/scripts/fetch-release-corpus.sh`**

Add this file and mark it executable:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DOWNLOAD_DIR="$ROOT/tests/corpus/generated/downloads"

if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    echo "release corpus fetch is GitHub Actions only" >&2
    exit 64
fi

mkdir -p "$DOWNLOAD_DIR"

download_and_extract() {
    local id="$1"
    local url="$2"
    local sha256="$3"
    local member="$4"
    local output="$5"
    local asset="$DOWNLOAD_DIR/$id.asset"
    local actual

    if [ ! -f "$asset" ]; then
        curl -fsSL "$url" -o "$asset"
    fi

    actual="$(sha256sum "$asset" | awk '{print $1}')"
    if [ "$actual" != "$sha256" ]; then
        echo "sha256 mismatch for $id: expected $sha256 got $actual" >&2
        exit 65
    fi

    mkdir -p "$(dirname "$ROOT/$output")"
    case "$url" in
        *.tar.gz)
            tar -xzf "$asset" -C "$DOWNLOAD_DIR" "$member"
            cp "$DOWNLOAD_DIR/$member" "$ROOT/$output"
            ;;
        *.zip)
            python3 - "$asset" "$member" "$ROOT/$output" <<'PY'
import pathlib
import sys
import zipfile

asset = pathlib.Path(sys.argv[1])
member = sys.argv[2]
output = pathlib.Path(sys.argv[3])
with zipfile.ZipFile(asset) as archive:
    data = archive.read(member)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(data)
PY
            ;;
        *)
            echo "unsupported release archive type for $url" >&2
            exit 66
            ;;
    esac
}

download_and_extract \
    "ripgrep-aarch64-linux" \
    "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz" \
    "c827481c4ff4ea10c9dc7a4022c8de5db34a5737cb74484d62eb94a95841ab2f" \
    "ripgrep-14.1.1-aarch64-unknown-linux-gnu/rg" \
    "tests/corpus/generated/release/ripgrep-aarch64-linux/rg"

download_and_extract \
    "ripgrep-x86_64-linux" \
    "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz" \
    "4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e" \
    "ripgrep-14.1.1-x86_64-unknown-linux-musl/rg" \
    "tests/corpus/generated/release/ripgrep-x86_64-linux/rg"

download_and_extract \
    "ripgrep-x86_64-windows" \
    "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip" \
    "d0f534024c42afd6cb4d38907c25cd2b249b79bbe6cc1dbee8e3e37c2b6e25a1" \
    "ripgrep-14.1.1-x86_64-pc-windows-msvc/rg.exe" \
    "tests/corpus/generated/release/ripgrep-x86_64-windows/rg.exe"
```

Run:

```sh
chmod +x tests/corpus/scripts/fetch-release-corpus.sh
```

- [ ] **Step 8: Create `tests/corpus/scripts/run-corpus-gate.sh`**

Add this file and mark it executable:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    echo "real-sample corpus gate is GitHub Actions only" >&2
    exit 64
fi

"$ROOT/tests/corpus/scripts/build-source-corpus.sh"
"$ROOT/tests/corpus/scripts/fetch-release-corpus.sh"
cargo run --bin ura-corpus-gate -- \
    --manifest "$ROOT/tests/corpus/manifest.toml" \
    --root "$ROOT" \
    --report "$ROOT/tests/corpus/generated/corpus-report.json" \
    --summary "$ROOT/tests/corpus/generated/corpus-summary.md"
```

Run:

```sh
chmod +x tests/corpus/scripts/run-corpus-gate.sh
```

- [ ] **Step 9: Verify local denial policy**

Run:

```sh
env -u GITHUB_ACTIONS tests/corpus/scripts/run-corpus-gate.sh
```

Expected: command exits non-zero and prints:

```text
real-sample corpus gate is GitHub Actions only
```

- [ ] **Step 10: Commit corpus metadata and scripts**

Run:

```sh
git add .gitignore tests/corpus
git commit -m "test: add ci-only corpus assets and scripts"
```

Expected: commit succeeds and no generated binary appears in `git status --short`.

---

### Task 4: Generalize Loader ELF Architecture Support

**Files:**
- Modify: `crates/urloader/src/elf.rs`
- Modify: `crates/urloader/tests/elf.rs`

- [ ] **Step 1: Write an ELF64 x86-64 loader test**

Append this test to `crates/urloader/tests/elf.rs`. Reuse the existing fixture builders in that file and add the helper shown here if a direct x86-64 fixture does not already exist:

```rust
fn minimal_elf64_x86_64_executable() -> Vec<u8> {
    let mut bytes = minimal_elf64_aarch64_executable();
    bytes[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    bytes
}

#[test]
fn loads_minimal_elf64_x86_64_executable_metadata() {
    let image = load(&minimal_elf64_x86_64_executable()).unwrap();

    assert_eq!(image.format, ImageFormat::Elf);
    assert_eq!(image.architecture, Architecture::X86_64);
    assert_eq!(image.class, ImageClass::Bits64);
    assert_eq!(image.endian, Endian::Little);
    assert_eq!(image.entry, 0x400080);
}
```

- [ ] **Step 2: Run the new test and verify it fails**

Run:

```sh
cargo test -p urloader loads_minimal_elf64_x86_64_executable_metadata
```

Expected: FAIL because `EM_X86_64` is currently unsupported.

- [ ] **Step 3: Implement ELF machine mapping**

In `crates/urloader/src/elf.rs`, add the constant:

```rust
const EM_X86_64: u16 = 62;
```

Replace the machine rejection in `parse_header` with:

```rust
if !matches!(machine, EM_AARCH64 | EM_X86_64) {
    return Err(LoadError::Unsupported {
        format: ELF,
        field: "machine",
        value: machine.to_string(),
    });
}
```

Add this helper:

```rust
fn elf_architecture(machine: u16) -> Architecture {
    match machine {
        EM_AARCH64 => Architecture::Aarch64,
        EM_X86_64 => Architecture::X86_64,
        other => Architecture::Unknown(other),
    }
}
```

In `load`, replace:

```rust
architecture: Architecture::Aarch64,
```

with:

```rust
architecture: elf_architecture(header.machine),
```

- [ ] **Step 4: Run loader tests**

Run:

```sh
cargo test -p urloader
```

Expected: all `urloader` tests pass.

- [ ] **Step 5: Commit loader support**

Run:

```sh
git add crates/urloader/src/elf.rs crates/urloader/tests/elf.rs
git commit -m "feat: load elf64 x86_64 metadata"
```

Expected: commit succeeds.

---

### Task 5: Structured `ura-core` Project Model

**Files:**
- Modify: `crates/ura-core/src/model.rs`
- Modify: `crates/ura-core/src/store.rs`
- Modify: `crates/ura-core/tests/project_roundtrip.rs`
- Modify: `crates/ura-core/tests/project_store.rs`

- [ ] **Step 1: Add a model roundtrip test**

In `crates/ura-core/tests/project_roundtrip.rs`, add a test that creates a project and asserts structured fields:

```rust
#[test]
fn project_schema_v3_records_structured_target_and_decode_semantics() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;

    assert_eq!(info.schema_version, 3);
    assert_eq!(info.format, ura_core::model::BinaryFormat::Elf);
    assert_eq!(info.architecture, ura_core::model::Architecture::Aarch64);
    assert_eq!(info.class, ura_core::model::ImageClass::Bits64);
    assert_eq!(info.endian, ura_core::model::Endian::Little);
    assert_eq!(disasm[0].kind, ura_core::model::InstructionKind::Return);
    assert_eq!(disasm[0].flow, ura_core::model::FlowKind::Return);
    assert_eq!(disasm[0].decode_status, ura_core::model::DecodeStatus::Complete);
    Ok(())
}
```

- [ ] **Step 2: Run the new test and verify it fails**

Run:

```sh
cargo test -p ura-core project_schema_v3_records_structured_target_and_decode_semantics
```

Expected: FAIL because `ImageClass`, `Endian`, `InstructionKind`, `FlowKind`, `DecodeStatus`, and schema version 3 are not present in `ura-core` yet.

- [ ] **Step 3: Update `crates/ura-core/src/model.rs`**

Replace the target and instruction semantic model definitions with:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageClass {
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionKind {
    Branch,
    Call,
    Return,
    Compare,
    Load,
    Store,
    Address,
    Arithmetic,
    Logical,
    Move,
    System,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowKind {
    Fallthrough,
    Branch,
    ConditionalBranch,
    Call,
    Return,
    IndirectBranch,
    IndirectCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodeStatus {
    Complete,
    Partial,
    Unknown,
}
```

Update `ProjectInfo` to include class and endian:

```rust
pub struct ProjectInfo {
    pub schema_version: i64,
    pub engine_version: String,
    pub source_hash: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub class: ImageClass,
    pub endian: Endian,
    pub profile: LoadProfile,
}
```

Update `Instruction` fields:

```rust
pub kind: InstructionKind,
pub flow: FlowKind,
pub decode_status: DecodeStatus,
```

- [ ] **Step 4: Update `crates/ura-core/src/store.rs`**

Change:

```rust
pub const PROJECT_SCHEMA_VERSION: i64 = 2;
```

to:

```rust
pub const PROJECT_SCHEMA_VERSION: i64 = 3;
```

Update `ProjectFile::empty` defaults:

```rust
format: BinaryFormat::Elf,
architecture: Architecture::Aarch64,
class: ImageClass::Bits64,
endian: Endian::Little,
```

- [ ] **Step 5: Fix compile errors from renamed model fields**

Run:

```sh
cargo test -p ura-core project_schema_v3_records_structured_target_and_decode_semantics
```

Expected: compiler errors point to old `Elf64`, string `kind`, string `flow`, or missing `class` and `endian` fields. Update those call sites to use the new enums.

- [ ] **Step 6: Run core project tests**

Run:

```sh
cargo test -p ura-core project_roundtrip project_store
```

Expected: all project roundtrip and store tests pass after updating expected schema and enum names.

- [ ] **Step 7: Commit structured model**

Run:

```sh
git add crates/ura-core/src/model.rs crates/ura-core/src/store.rs crates/ura-core/tests/project_roundtrip.rs crates/ura-core/tests/project_store.rs
git commit -m "feat: store structured project target semantics"
```

Expected: commit succeeds.

---

### Task 6: `ura-core` Target Conversion and Backend Selection

**Files:**
- Create: `crates/ura-core/src/analysis/target.rs`
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Modify: `crates/ura-core/src/analysis/disasm.rs`
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/src/analysis/functions.rs`
- Modify: `crates/ura-core/src/analysis/xrefs.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`
- Modify: `crates/ura-core/tests/elf_loader.rs`

- [ ] **Step 1: Add failing PE acceptance test**

In `crates/ura-core/tests/analysis_smoke.rs`, replace the current PE rejection test with:

```rust
#[test]
fn pe_x86_64_input_creates_project_and_records_target() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.exe");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_pe32_plus_x86_64())?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;

    assert_eq!(info.format, ura_core::model::BinaryFormat::Pe);
    assert_eq!(info.architecture, ura_core::model::Architecture::X86_64);
    assert_eq!(info.class, ura_core::model::ImageClass::Bits64);
    assert_eq!(info.endian, ura_core::model::Endian::Little);
    Ok(())
}
```

- [ ] **Step 2: Add failing ELF x86-64 core test**

In `crates/ura-core/tests/elf_loader.rs`, add:

```rust
#[test]
fn commands_load_minimal_x86_64_executable_through_urloader() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample-x86_64.elf");
    let project = dir.path().join("sample-x86_64.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    bytes[0x80] = 0xc3;
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;

    assert_eq!(info.format, ura_core::model::BinaryFormat::Elf);
    assert_eq!(info.architecture, ura_core::model::Architecture::X86_64);
    assert_eq!(disasm[0].mnemonic, "ret");
    Ok(())
}
```

- [ ] **Step 3: Run new tests and verify they fail**

Run:

```sh
cargo test -p ura-core pe_x86_64_input_creates_project_and_records_target commands_load_minimal_x86_64_executable_through_urloader
```

Expected: FAIL because `ura-core` still gates on AArch64 ELF and disassembly hardcodes AArch64.

- [ ] **Step 4: Create `crates/ura-core/src/analysis/target.rs`**

Add:

```rust
use crate::{
    model::{Architecture, BinaryFormat, Endian, ImageClass},
    Result, UraError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisTarget {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub class: ImageClass,
    pub endian: Endian,
}

impl AnalysisTarget {
    pub fn from_loaded(image: &urloader::LoadedImage) -> Result<Self> {
        let target = Self {
            format: convert_format(image.format),
            architecture: convert_architecture(image.architecture)?,
            class: convert_class(image.class),
            endian: convert_endian(image.endian)?,
        };
        target.ensure_supported()?;
        Ok(target)
    }

    fn ensure_supported(self) -> Result<()> {
        match (self.format, self.architecture, self.class, self.endian) {
            (BinaryFormat::Elf, Architecture::Aarch64, ImageClass::Bits64, Endian::Little)
            | (BinaryFormat::Elf, Architecture::X86_64, ImageClass::Bits64, Endian::Little)
            | (BinaryFormat::Pe, Architecture::X86_64, ImageClass::Bits64, Endian::Little) => Ok(()),
            _ => Err(UraError::Unsupported(format!(
                "unsupported analysis target: format={:?} architecture={:?} class={:?} endian={:?}",
                self.format, self.architecture, self.class, self.endian
            ))),
        }
    }
}

fn convert_format(format: urloader::ImageFormat) -> BinaryFormat {
    match format {
        urloader::ImageFormat::Elf => BinaryFormat::Elf,
        urloader::ImageFormat::Pe => BinaryFormat::Pe,
    }
}

fn convert_architecture(architecture: urloader::Architecture) -> Result<Architecture> {
    match architecture {
        urloader::Architecture::Aarch64 => Ok(Architecture::Aarch64),
        urloader::Architecture::X86_64 => Ok(Architecture::X86_64),
        urloader::Architecture::Unknown(value) => Err(UraError::Unsupported(format!(
            "unsupported architecture: {value}"
        ))),
    }
}

fn convert_class(class: urloader::ImageClass) -> ImageClass {
    match class {
        urloader::ImageClass::Bits32 => ImageClass::Bits32,
        urloader::ImageClass::Bits64 => ImageClass::Bits64,
    }
}

fn convert_endian(endian: urloader::Endian) -> Result<Endian> {
    match endian {
        urloader::Endian::Little => Ok(Endian::Little),
        urloader::Endian::Big => Err(UraError::Unsupported("unsupported big-endian image".to_string())),
    }
}
```

- [ ] **Step 5: Update `analysis/mod.rs`**

Add:

```rust
pub mod target;
```

Add `target: target::AnalysisTarget` to `AnalysisImage`:

```rust
pub struct AnalysisImage<'a> {
    pub target: target::AnalysisTarget,
    pub entry: u64,
    pub bytes: &'a [u8],
    pub segments: &'a [Segment],
}
```

- [ ] **Step 6: Update `analysis/disasm.rs`**

Refactor `linear_disassemble` to dispatch by architecture:

```rust
pub fn linear_disassemble(image: &AnalysisImage<'_>) -> Result<Vec<Instruction>> {
    match image.target.architecture {
        crate::model::Architecture::Aarch64 => disassemble_aarch64(image),
        crate::model::Architecture::X86_64 => disassemble_x86_64(image),
    }
}
```

Keep the existing AArch64 loop in `disassemble_aarch64`. Add x86-64 variable-length stepping:

```rust
fn disassemble_x86_64(image: &AnalysisImage<'_>) -> Result<Vec<Instruction>> {
    let decoder = urdisassembly::Decoder::new(
        urdisassembly::Architecture::X86_64,
        urdisassembly::DecodeOptions::default(),
    )
    .map_err(|err| UraError::Analysis(err.to_string()))?;

    let mut out = Vec::new();
    for (start, end) in image.executable_ranges() {
        let mut addr = start;
        while addr < end {
            let Some(bytes) = image.bytes_at(addr, 15) else {
                break;
            };
            let decoded = decoder
                .decode_one(bytes, addr)
                .map_err(|err| UraError::Analysis(err.to_string()))?;
            let size = u64::from(decoded.size.max(1));
            out.push(convert_instruction(decoded, "urdisassembly/x86_64"));
            addr = addr.saturating_add(size);
        }
    }
    Ok(out)
}
```

Extract a shared `convert_instruction` that maps `urdisassembly` enums into `ura-core` enums without formatting them as strings.

- [ ] **Step 7: Update `commands.rs`**

In `build_project_file`, create target and store it:

```rust
let target = analysis::target::AnalysisTarget::from_loaded(loaded)?;
let analysis_image = AnalysisImage {
    target,
    entry: loaded.entry,
    bytes: &loaded.bytes,
    segments: &segments,
};
```

Set `ProjectInfo` fields:

```rust
format: target.format,
architecture: target.architecture,
class: target.class,
endian: target.endian,
```

Remove `ensure_supported_analysis_target` and its call.

- [ ] **Step 8: Update functions and xrefs to use enums**

In `analysis/functions.rs`, replace string matches with enum matches:

```rust
if matches!(
    insn.flow,
    FlowKind::Call | FlowKind::Branch | FlowKind::ConditionalBranch
) {
    if let Some(target) = insn.branch_target {
        starts.insert((target, FunctionSource::BranchTarget));
    }
}
```

In `analysis/xrefs.rs`, replace string comparisons:

```rust
let kind = if matches!(insn.flow, FlowKind::Call | FlowKind::IndirectCall)
    || insn.kind == InstructionKind::Call
{
    XrefKind::Call
} else {
    XrefKind::Code
};
```

- [ ] **Step 9: Run core tests**

Run:

```sh
cargo test -p ura-core
```

Expected: all `ura-core` tests pass.

- [ ] **Step 10: Run workspace tests**

Run:

```sh
cargo test --workspace
```

Expected: all workspace tests pass.

- [ ] **Step 11: Commit multi-target core**

Run:

```sh
git add crates/ura-core crates/urloader
git commit -m "feat: analyze elf and pe x86_64 targets"
```

Expected: commit succeeds.

---

### Task 7: Corpus Gate Binary

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/ura-corpus-gate/Cargo.toml`
- Create: `crates/ura-corpus-gate/src/main.rs`

- [ ] **Step 1: Add workspace member and dependencies**

In root `Cargo.toml`, add member:

```toml
"crates/ura-corpus-gate",
```

Add workspace dependencies:

```toml
toml = "0.8"
```

- [ ] **Step 2: Create `crates/ura-corpus-gate/Cargo.toml`**

Add:

```toml
[package]
name = "ura-corpus-gate"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
serde.workspace = true
serde_json.workspace = true
tempfile.workspace = true
toml.workspace = true
ura-core = { path = "../ura-core" }
```

- [ ] **Step 3: Create `crates/ura-corpus-gate/src/main.rs`**

Add:

```rust
use std::{fs, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Manifest {
    sample: Vec<Sample>,
}

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
    required_strings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    ok: bool,
    samples: Vec<SampleReport>,
}

#[derive(Debug, Serialize)]
struct SampleReport {
    id: String,
    kind: String,
    ok: bool,
    detected_format: Option<String>,
    detected_architecture: Option<String>,
    detected_class: Option<String>,
    decoded_instruction_count: usize,
    unknown_instruction_count: usize,
    unknown_rate: f64,
    string_count: usize,
    function_count: usize,
    xref_count: usize,
    diagnostic_count: usize,
    failure_reason: Option<String>,
}

fn main() -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        bail!("real-sample corpus gate is GitHub Actions only");
    }

    let args = Args::parse()?;
    let manifest_bytes = fs::read(&args.manifest)
        .with_context(|| format!("read manifest {}", args.manifest.display()))?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)?;
    let manifest: Manifest = toml::from_str(manifest_text)?;

    let mut reports = Vec::new();
    for sample in &manifest.sample {
        reports.push(run_sample(&args.root, sample));
    }

    let ok = reports.iter().all(|report| report.ok);
    let report = Report { ok, samples: reports };
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&args.report, json)?;
    fs::write(&args.summary, render_summary(&report))?;

    if !report.ok {
        bail!("corpus gate failed");
    }
    Ok(())
}

struct Args {
    manifest: PathBuf,
    root: PathBuf,
    report: PathBuf,
    summary: PathBuf,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut manifest = None;
        let mut root = None;
        let mut report = None;
        let mut summary = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| anyhow!("missing value for {arg}"))?;
            match arg.as_str() {
                "--manifest" => manifest = Some(PathBuf::from(value)),
                "--root" => root = Some(PathBuf::from(value)),
                "--report" => report = Some(PathBuf::from(value)),
                "--summary" => summary = Some(PathBuf::from(value)),
                other => bail!("unknown argument {other}"),
            }
        }
        Ok(Self {
            manifest: manifest.ok_or_else(|| anyhow!("missing --manifest"))?,
            root: root.ok_or_else(|| anyhow!("missing --root"))?,
            report: report.ok_or_else(|| anyhow!("missing --report"))?,
            summary: summary.ok_or_else(|| anyhow!("missing --summary"))?,
        })
    }
}

fn run_sample(root: &PathBuf, sample: &Sample) -> SampleReport {
    match analyze_sample(root, sample) {
        Ok(report) => report,
        Err(err) => SampleReport {
            id: sample.id.clone(),
            kind: sample.kind.clone(),
            ok: false,
            detected_format: None,
            detected_architecture: None,
            detected_class: None,
            decoded_instruction_count: 0,
            unknown_instruction_count: 0,
            unknown_rate: 1.0,
            string_count: 0,
            function_count: 0,
            xref_count: 0,
            diagnostic_count: 0,
            failure_reason: Some(err.to_string()),
        },
    }
}

fn analyze_sample(root: &PathBuf, sample: &Sample) -> Result<SampleReport> {
    let input = root.join(&sample.output);
    if !input.exists() {
        bail!("sample output missing: {}", input.display());
    }
    let dir = tempdir()?;
    let project = dir.path().join(format!("{}.ura", sample.id));

    ura_core::commands::new_project(&input, &project)?;
    let info = ura_core::commands::info(&project)?;
    let instructions = ura_core::commands::disasm(&project, 0, usize::MAX)?;
    let strings = ura_core::commands::strings(&project, None)?;
    let functions = ura_core::commands::functions(&project)?;
    let xrefs = ura_core::commands::all_xrefs(&project)?;
    let diagnostics = ura_core::commands::diagnostics(&project)?;

    let detected_format = format!("{:?}", info.format).to_ascii_lowercase();
    let detected_architecture = format!("{:?}", info.architecture).to_ascii_lowercase();
    let detected_class = format!("{:?}", info.class).to_ascii_lowercase();
    let unknown = instructions
        .iter()
        .filter(|insn| insn.decode_status == ura_core::model::DecodeStatus::Unknown)
        .count();
    let unknown_rate = if instructions.is_empty() {
        1.0
    } else {
        unknown as f64 / instructions.len() as f64
    };

    let mut failures = Vec::new();
    if detected_format != sample.format {
        failures.push(format!("format expected {} got {}", sample.format, detected_format));
    }
    if detected_architecture != sample.arch {
        failures.push(format!(
            "architecture expected {} got {}",
            sample.arch, detected_architecture
        ));
    }
    if detected_class != sample.class {
        failures.push(format!("class expected {} got {}", sample.class, detected_class));
    }
    if instructions.len() < sample.min_instructions {
        failures.push(format!(
            "instruction count expected at least {} got {}",
            sample.min_instructions,
            instructions.len()
        ));
    }
    if unknown_rate > sample.max_unknown_rate {
        failures.push(format!(
            "unknown rate expected at most {:.4} got {:.4}",
            sample.max_unknown_rate, unknown_rate
        ));
    }
    for required in &sample.required_strings {
        if !strings.iter().any(|s| s.value.contains(required)) {
            failures.push(format!("required string not found: {required}"));
        }
    }

    let ok = failures.is_empty();
    Ok(SampleReport {
        id: sample.id.clone(),
        kind: sample.kind.clone(),
        ok,
        detected_format: Some(detected_format),
        detected_architecture: Some(detected_architecture),
        detected_class: Some(detected_class),
        decoded_instruction_count: instructions.len(),
        unknown_instruction_count: unknown,
        unknown_rate,
        string_count: strings.len(),
        function_count: functions.len(),
        xref_count: xrefs.len(),
        diagnostic_count: diagnostics.len(),
        failure_reason: if ok { None } else { Some(failures.join("; ")) },
    })
}

fn render_summary(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Corpus Gate\n\n");
    out.push_str("| Sample | OK | Instructions | Unknown Rate | Failure |\n");
    out.push_str("| --- | --- | ---: | ---: | --- |\n");
    for sample in &report.samples {
        out.push_str(&format!(
            "| {} | {} | {} | {:.4} | {} |\n",
            sample.id,
            sample.ok,
            sample.decoded_instruction_count,
            sample.unknown_rate,
            sample.failure_reason.clone().unwrap_or_default()
        ));
    }
    out
}
```

- [ ] **Step 4: Add all-xrefs helper used by the gate**

Add this public helper in `crates/ura-core/src/commands.rs`:

```rust
pub fn all_xrefs(project_path: impl AsRef<Path>) -> Result<Vec<Xref>> {
    Ok(Project::open(project_path)?.file().xrefs.clone())
}
```

The gate crate already calls `ura_core::commands::all_xrefs(&project)?`, so this helper must be present before compiling the new crate.

- [ ] **Step 5: Verify local denial**

Run:

```sh
cargo run --bin ura-corpus-gate -- --manifest tests/corpus/manifest.toml --root . --report /tmp/corpus-report.json --summary /tmp/corpus-summary.md
```

Expected: FAIL with `real-sample corpus gate is GitHub Actions only`.

- [ ] **Step 6: Run workspace checks**

Run:

```sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 7: Commit corpus gate binary**

Run:

```sh
git add Cargo.toml Cargo.lock crates/ura-corpus-gate crates/ura-core/src/commands.rs
git commit -m "test: add ci-only corpus gate runner"
```

Expected: commit succeeds.

---

### Task 8: Corpus Gate GitHub Actions Workflow

**Files:**
- Create: `.github/workflows/corpus-gate.yml`

- [ ] **Step 1: Create `.github/workflows/corpus-gate.yml`**

Add this file:

```yaml
name: Corpus Gate

on:
  push:
    branches:
      - main
      - master
  pull_request:
    branches:
      - main
      - master
  workflow_dispatch:

jobs:
  corpus:
    name: Real-sample corpus gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Restore Rust cache
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: rust-${{ runner.os }}-${{ hashFiles('Cargo.lock') }}-${{ hashFiles('Cargo.toml', 'crates/**/Cargo.toml') }}
          restore-keys: |
            rust-${{ runner.os }}-

      - name: Restore corpus toolchain cache
        uses: actions/cache@v4
        with:
          path: tests/corpus/.cache/toolchains
          key: corpus-toolchains-${{ runner.os }}-${{ hashFiles('tests/corpus/toolchains.toml', 'tests/corpus/scripts/install-*.sh') }}

      - name: Install or verify corpus toolchains
        run: tests/corpus/scripts/install-toolchains.sh

      - name: Restore corpus sample cache
        uses: actions/cache@v4
        with:
          path: tests/corpus/generated
          key: corpus-samples-${{ runner.os }}-${{ hashFiles('tests/corpus/manifest.toml', 'tests/corpus/src/**', 'tests/corpus/scripts/**') }}

      - name: Build source corpus
        run: tests/corpus/scripts/build-source-corpus.sh

      - name: Fetch release corpus
        run: tests/corpus/scripts/fetch-release-corpus.sh

      - name: Build workspace
        run: cargo build --workspace

      - name: Run corpus gate
        run: tests/corpus/scripts/run-corpus-gate.sh

      - name: Write corpus summary
        if: always()
        run: |
          if [ -f tests/corpus/generated/corpus-summary.md ]; then
            cat tests/corpus/generated/corpus-summary.md >> "$GITHUB_STEP_SUMMARY"
          fi

      - name: Upload corpus reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: corpus-report
          path: |
            tests/corpus/generated/corpus-report.json
            tests/corpus/generated/corpus-summary.md
          if-no-files-found: warn
```

- [ ] **Step 2: Verify workflow syntax shape**

Run:

```sh
git diff -- .github/workflows/corpus-gate.yml
```

Expected: workflow uses `pull_request`, not `pull_request_target`, and does not reference `secrets`.

- [ ] **Step 3: Commit and push corpus workflow**

Run:

```sh
git add .github/workflows/corpus-gate.yml
git commit -m "ci: add real-sample corpus gate"
git push
```

Expected: commit and push succeed. GitHub Actions starts the `Corpus Gate` workflow.

---

### Task 9: Final Verification and Documentation Refresh

**Files:**
- Modify: `README.md`
- Modify: `docs/urdisassembly/aarch64-coverage.md`
- Modify: `docs/urdisassembly/x86_64-coverage.md`

- [ ] **Step 1: Refresh support matrix**

Update `README.md` support table to:

```markdown
| Target | Loader | Core Analysis | Notes |
| --- | --- | --- | --- |
| ELF64 AArch64 little-endian | Supported | Supported | Fixed-width AArch64 disassembly. |
| ELF64 x86-64 little-endian | Supported | Supported | Variable-width x86-64 disassembly. |
| PE32+ x86-64 little-endian | Supported | Supported | PE sections are analyzed as executable ranges. |
```

- [ ] **Step 2: Run full local checks**

Run:

```sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 3: Confirm local corpus gate remains blocked**

Run:

```sh
env -u GITHUB_ACTIONS tests/corpus/scripts/run-corpus-gate.sh
```

Expected: command exits non-zero and prints:

```text
real-sample corpus gate is GitHub Actions only
```

- [ ] **Step 4: Check GitHub workflow status**

Run:

```sh
gh run list --limit 10
```

Expected: latest `CI` and `Corpus Gate` runs are visible. For any failed run, inspect it:

```sh
gh run view --log-failed
```

Use the failed log to fix the exact command or test that failed, then rerun the local check that matches the failing step.

- [ ] **Step 5: Commit documentation refresh**

Run:

```sh
git add README.md docs/urdisassembly/aarch64-coverage.md docs/urdisassembly/x86_64-coverage.md
git commit -m "docs: update multitarget support status"
git push
```

Expected: commit and push succeed.
