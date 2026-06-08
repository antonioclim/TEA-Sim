from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE = {"SHA256SUMS.txt"}

rows = []
for path in sorted(p for p in ROOT.rglob("*") if p.is_file()):
    rel = path.relative_to(ROOT).as_posix()
    if rel in EXCLUDE:
        continue
    if "/.venv/" in rel or rel.startswith(".git/"):
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows.append(f"{digest}  {rel}")
(ROOT / "SHA256SUMS.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
print(f"Wrote {len(rows)} checksums to SHA256SUMS.txt")
