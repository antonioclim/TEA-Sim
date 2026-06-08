#!/usr/bin/env bash
set -euo pipefail
python src/teasim_reproduce.py --root .
python src/make_checksums.py
