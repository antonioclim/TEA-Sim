#!/usr/bin/env python3
from pathlib import Path
import hashlib

root = Path(__file__).resolve().parents[1]

def include_file(p: Path) -> bool:
    if not p.is_file():
        return False
    if ".git" in p.parts or "__pycache__" in p.parts:
        return False
    if p.suffix == ".pyc" or p.name in {"SHA256SUMS.txt", ".DS_Store"}:
        return False
    return True

files = sorted(p for p in root.rglob("*") if include_file(p))
with open(root / "SHA256SUMS.txt", "w", encoding="utf-8") as out:
    for p in files:
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        out.write(f"{digest}  {p.relative_to(root).as_posix()}\n")
print("SHA256SUMS.txt written")
