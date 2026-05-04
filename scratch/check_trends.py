import os
import json
from pathlib import Path

base_path = Path("F:/Projects/Cloudscape_Project/storage/forensics")
scan_dirs = sorted([d for d in base_path.iterdir() if d.is_dir()], key=lambda x: x.stat().st_mtime)

trends = []
for d in scan_dirs[-30:]:
    snapshots = list(d.glob("STAGE_5_*.json")) or list(d.glob("STAGE_4_*.json"))
    if snapshots:
        with open(snapshots[0], "r") as f:
            data = json.load(f)
            state = data.get("state_snapshot", {})
            assets = state.get("nodes", {}).get("merged", data["metadata"]["node_count"])
            trends.append({
                "scan_id": d.name,
                "assets": assets
            })

print(json.dumps(trends, indent=2))
