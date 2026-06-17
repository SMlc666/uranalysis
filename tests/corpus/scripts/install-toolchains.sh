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
