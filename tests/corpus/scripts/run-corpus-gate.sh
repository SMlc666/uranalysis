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
