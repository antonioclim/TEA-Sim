#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
python "$ROOT/src/teasim_reproduce.py" --root "$ROOT"
python "$ROOT/src/make_checksums.py"
