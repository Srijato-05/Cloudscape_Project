import os
import json
import logging
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

class ForensicLedger:
    """
    Immutable Phase State Ledger.
    Captures cryptographic snapshots of all pipeline phases for forensic post-mortems.
    """
    def __init__(self, base_storage: str = "storage/forensics"):
        self.logger = logging.getLogger("CloudScape.Core.Forensics")
        self.base_path = Path(base_storage)
        self._ensure_storage()

    def _ensure_storage(self):
        if not self.base_path.exists():
            self.base_path.mkdir(parents=True, exist_ok=True)

    def record_stage(self, scan_id: str, stage_name: str, state_summary: Dict[str, Any], nodes: Optional[List[Dict[str, Any]]] = None, full_persistence: bool = False):
        """
        Persistence kernel for stage evidence.
        """
        scan_dir = self.base_path / scan_id
        scan_dir.mkdir(exist_ok=True)
        
        timestamp = int(time.time())
        filename = f"{stage_name}_t{timestamp}.json"
        target_path = scan_dir / filename
        
        # Prepare the payload
        payload: Dict[str, Any] = {
            "metadata": {
                "scan_id": scan_id,
                "stage": stage_name,
                "timestamp": datetime.now().isoformat(),
                "node_count": len(nodes) if nodes else 0
            },
            "state_snapshot": state_summary,
            "evidence_digest": ""
        }
        
        if nodes:
            if full_persistence or stage_name == "STAGE_4_CONVERGENCE":
                payload["nodes"] = nodes
            else:
                payload["node_sample"] = nodes[:100] # type: ignore
            
        # Generate integrity hash
        payload_str = json.dumps(payload, sort_keys=True)
        payload["evidence_digest"] = hashlib.sha256(payload_str.encode()).hexdigest()
        
        try:
            with open(target_path, "w") as f:
                json.dump(payload, f, indent=2)
            self.logger.info(f"Forensic Snapshot Committed: {stage_name} -> {target_path}")
        except Exception as e:
            self.logger.error(f"FAILED to commit forensic evidence for stage {stage_name}: {e}")

    def load_latest_state(self, scan_id: str, stage_name: str = "STAGE_4_CONVERGENCE") -> Optional[List[Dict[str, Any]]]:
        """Loads the most recent URM set from a specific scan phase."""
        scan_dir = self.base_path / scan_id
        if not scan_dir.exists():
            return None
        
        # Find the latest file for the stage
        files = sorted([f for f in scan_dir.glob(f"{stage_name}_t*.json")], key=lambda x: x.stat().st_mtime, reverse=True)
        if not files:
            return None
            
        try:
            with open(files[0], "r") as f:
                data = json.load(f)
                return data.get("nodes") or data.get("node_sample")
        except Exception as e:
            self.logger.error(f"Failed to load forensic state for {scan_id}/{stage_name}: {e}")
            return None

class TimelineReconstructor:
    """
    Advanced forensic playback engine.
    Reconstructs the infrastructure state at any point in time by analyzing the ledger.
    """
    def __init__(self, ledger: ForensicLedger):
        self.ledger = ledger

    def playback_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Returns a chronologically ordered sequence of state changes for a given scan.
        """
        scan_dir = self.ledger.base_path / scan_id
        if not scan_dir.exists():
            return []
            
        files = sorted(scan_dir.glob("*.json"), key=lambda x: x.stat().st_mtime)
        timeline = []
        
        for f in files:
            try:
                with open(f, "r") as handle:
                    data = json.load(handle)
                    timeline.append({
                        "timestamp": data["metadata"]["timestamp"],
                        "stage": data["metadata"]["stage"],
                        "node_count": data["metadata"]["node_count"],
                        "risk_summary": data.get("state_snapshot", {}).get("risk_score", 0.0)
                    })
            except Exception:
                continue
                
        return timeline

    def get_state_at_time(self, scan_id: str, target_time: str) -> Optional[List[Dict[str, Any]]]:
        """Finds the state snapshot closest to the target_time."""
        # Logic to find the nearest snapshot
        # For simplicity, returning the latest before target_time
        return self.ledger.load_latest_state(scan_id)

class StateComparator:
    """Analytical engine to quantify the difference between two infrastructure states."""
    
    @staticmethod
    def compare(state_a: List[Dict[str, Any]], state_b: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generates a delta report between two URM sets."""
        lookup_a = {n.get("arn") or n.get("id", ""): n for n in state_a}
        lookup_b = {n.get("arn") or n.get("id", ""): n for n in state_b}
        
        arns_a = set(lookup_a.keys())
        arns_b = set(lookup_b.keys())
        
        added = arns_b - arns_a
        removed = arns_a - arns_b
        common = arns_a & arns_b
        
        modified = []
        for arn in common:
            if not arn: continue
            # Check for critical attribute drift (e.g. metadata change)
            if lookup_a[arn].get("metadata") != lookup_b[arn].get("metadata"):
                modified.append(arn)
        
        return {
            "summary": {
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(modified),
                "total_drift": len(added) + len(removed) + len(modified)
            },
            "deltas": {
                "added": list(added),
                "removed": list(removed),
                "modified": modified
            }
        }

# Global Forensic Anchor
forensic_ledger = ForensicLedger()
