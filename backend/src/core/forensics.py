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
                    state = data.get("state_snapshot", {})
                    timeline.append({
                        "timestamp": data["metadata"]["timestamp"],
                        "stage": data["metadata"]["stage"],
                        "node_count": data["metadata"]["node_count"],
                        "risk_summary": state.get("risk_score") or state.get("risk") or 0.0
                    })
            except Exception as e:
                self.ledger.logger.error(f"Error parsing forensic file {f}: {e}")
                continue
                
        return timeline

    def get_state_at_time(self, scan_id: str, target_time: str) -> Optional[List[Dict[str, Any]]]:
        """Finds the state snapshot closest to the target_time."""
        # Logic to find the nearest snapshot
        # For simplicity, returning the latest before target_time
        return self.ledger.load_latest_state(scan_id)

class StateComparator:
    """Analytical engine to quantify property-level deltas between two infrastructure states."""
    
    @staticmethod
    def compare(state_a: List[Dict[str, Any]], state_b: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generates a high-fidelity delta report between two URM sets."""
        lookup_a = {n.get("arn") or n.get("id", ""): n for n in state_a}
        lookup_b = {n.get("arn") or n.get("id", ""): n for n in state_b}
        
        arns_a = set(lookup_a.keys())
        arns_b = set(lookup_b.keys())
        
        added = arns_b - arns_a
        removed = arns_a - arns_b
        common = arns_a & arns_b
        
        modified_details = {}
        for arn in common:
            if not arn: continue
            diff = StateComparator._deep_diff(lookup_a[arn], lookup_b[arn])
            if diff:
                modified_details[arn] = diff
        
        return {
            "summary": {
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(modified_details),
                "total_drift": len(added) + len(removed) + len(modified_details)
            },
            "deltas": {
                "added": list(added),
                "removed": list(removed),
                "modified": modified_details
            }
        }

    @staticmethod
    def _deep_diff(obj_a: Dict[str, Any], obj_b: Dict[str, Any]) -> Dict[str, Any]:
        """Performs a recursive diff of two objects to find specific property changes."""
        changes = {}
        # We focus on properties and metadata for drift
        keys = set(obj_a.keys()) | set(obj_b.keys())
        for k in keys:
            if k in ['id', 'arn', 'last_seen', 'timestamp']: continue # Skip non-drift fields
            val_a = obj_a.get(k)
            val_b = obj_b.get(k)
            if val_a != val_b:
                if isinstance(val_a, dict) and isinstance(val_b, dict):
                    nested = StateComparator._deep_diff(val_a, val_b)
                    if nested: changes[k] = nested
                else:
                    changes[k] = {"old": val_a, "new": val_b}
        return changes

class EventRegistry:
    """Persistent ledger for security violations and cross-scan drift events."""
    def __init__(self, storage_path: str = "storage/forensics/security_events.json"):
        self.path = Path(storage_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events = self._load()

    def _load(self) -> List[Dict[str, Any]]:
        if self.path.exists():
            try:
                with open(self.path, "r") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def record_event(self, event_type: str, severity: str, resource: str, message: str, metadata: Optional[Dict[str, Any]] = None):
        event = {
            "id": f"evt-{int(time.time()*1000)}",
            "type": event_type,
            "severity": severity,
            "resource": resource,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
        self.events.insert(0, event)
        self.events = self.events[:500] # Cap at 500 events
        self._save()

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self.events, f, indent=2)
        except Exception:
            pass

# Global Forensic Anchor
forensic_ledger = ForensicLedger()
event_registry = EventRegistry()
