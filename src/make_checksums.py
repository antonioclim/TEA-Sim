#!/usr/bin/env python3
from pathlib import Path
import hashlib

root = Path(__file__).resolve().parents[1]
files = sorted(
    p for p in root.rglob("*")
    if p.is_file() and ".git" not in p.parts and p.name != "SHA256SUMS.txt"
)
with open(root / "SHA256SUMS.txt", "w", encoding="utf-8") as out:
    for p in files:
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        out.write(f"{digest}  {p.relative_to(root).as_posix()}\n")
print("SHA256SUMS.txt written")
