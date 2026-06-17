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
