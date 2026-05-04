import logging
import socket
import time
from typing import Dict, Any, List
import requests

class HealthMonitor:
    """
    Enterprise Pre-flight Diagnostic System.
    Validates infrastructure reachability and service readiness.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger("CloudScape.Utils.Health")
        self.config = config

    def run_preflight_checks(self) -> Dict[str, Any]:
        """Executes a suite of connectivity and state checks."""
        self.logger.info("Executing Enterprise Pre-flight Diagnostics...")
        
        results = {
            "timestamp": time.time(),
            "services": {
                "neo4j": self._check_tcp("localhost", 7687),
                "redis": self._check_tcp("localhost", 6379),
                "localstack": self._check_http("http://localhost:4566/_localstack/health"),
                "azurite": self._check_tcp("localhost", 10000)
            },
            "system": {
                "disk_space": self._check_disk(),
                "python_version": socket.gethostname()
            }
        }
        
        status = "HEALTHY" if all(s["status"] == "UP" for s in results["services"].values()) else "DEGRADED"
        results["overall_status"] = status
        
        return results

    def _check_tcp(self, host: str, port: int) -> Dict[str, str]:
        try:
            with socket.create_connection((host, port), timeout=2):
                return {"status": "UP", "message": "Connection established"}
        except Exception as e:
            return {"status": "DOWN", "error": str(e)}

    def _check_http(self, url: str) -> Dict[str, str]:
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                return {"status": "UP", "message": "Service responding"}
            return {"status": "DEGRADED", "code": str(resp.status_code)}
        except Exception as e:
            return {"status": "DOWN", "error": str(e)}

    def _check_disk(self) -> str:
        import shutil
        total, used, free = shutil.disk_usage("/")
        return f"{free // (2**30)} GB free"
