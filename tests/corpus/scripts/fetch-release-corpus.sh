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
