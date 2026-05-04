import logging
import json
import time
from typing import Any, Dict

class VerboseDiagnosticLogger:
    """
    High-fidelity event tracer for bit-level simulation visibility.
    Captures raw API payloads and internal state transitions.
    """
    
    def __init__(self, log_path: str = "forensics/logs/verbose_trace.jsonl"):
        self.logger = logging.getLogger("CloudScape.Utils.Verbose")
        self.log_path = log_path
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        import os
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def trace_event(self, event_type: str, component: str, payload: Any, metadata: Dict[str, Any] = None):
        """Records a high-fidelity diagnostic event."""
        entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "component": component,
            "payload": payload,
            "metadata": metadata or {}
        }
        
        # Append to JSONL for high-speed streaming
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            
        self.logger.debug(f"[TRACE] {event_type} in {component}")

diagnostic_tracer = VerboseDiagnosticLogger()
