
from pathlib import Path


def load_allowlist(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    out = set()
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            out.add(line)
    return out
