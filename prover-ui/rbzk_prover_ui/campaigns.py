"""Local report inventory. No fixture fallback or inferred verification."""
import hashlib
import json
import os
from pathlib import Path
import time

DEFAULT_ARK_DIR = Path.home() / "Documents/Codex/2026-11-15/new-chat/outputs/zk-rusto-no-bitcoino-ark/Ark"

def load_campaigns(ark_dir=None):
    root = Path(ark_dir or os.environ.get("RBZK_ARK_DIR", DEFAULT_ARK_DIR)) / "results"
    records = []
    for path in sorted(root.glob("*.json"))[:64]:
        try:
            with path.open("rb") as f:
                raw = f.read(2097153)
            if len(raw) > 2097152:
                continue
            data = json.loads(raw)
            summary = {k:v for k,v in data.items() if k in {"schema","status","network","verified","stark_verified","new_mint_funding","full_ark_sp1_bitvm3_complete","proof_sha256","proof_bytes"} and not isinstance(v,(dict,list))}
            records.append(dict(id=str(path),title=path.name,path=str(path),sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),modified_at_unix=path.stat().st_mtime,kind="recorded evidence",summary=summary))
        except (OSError, ValueError, AttributeError):
            continue
    return dict(schema="rbzk-artifact-inventory-v1",sampled_at_unix=time.time(),root=str(root),available=root.is_dir(),campaigns=records)
