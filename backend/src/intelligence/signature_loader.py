import os
import json
import logging
from typing import Dict, Any

class SignatureLoader:
    """
    Advanced Dynamic Signature Engine (Cloudscape 15.0)
    Loads, processes, and validates threat signatures from external JSON banks 
    to prevent static hardcoding. Includes rigorous error containment and logging.
    """
    def __init__(self, signature_dir: str = None):
        self.logger = logging.getLogger("CloudScape.Intelligence.SignatureLoader")
        if signature_dir is None:
            self.signature_dir = os.path.join(os.path.dirname(__file__), "signatures")
        else:
            self.signature_dir = signature_dir
            
        # Optional: create dir if missing to prevent faults
        try:
            os.makedirs(self.signature_dir, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Failed to ensure signature directory: {e}", exc_info=True)

        self._cache: Dict[str, Dict[str, Any]] = {}

    def load_signature(self, filename: str) -> Dict[str, Any]:
        """Loads a signature JSON dynamically with full exception handling."""
        if filename in self._cache:
            return self._cache[filename]
            
        file_path = os.path.join(self.signature_dir, filename)
        
        try:
            if not os.path.exists(file_path):
                self.logger.warning(f"Signature bank {filename} missing. Returning empty state.")
                return {}
                
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            self._cache[filename] = data
            self.logger.debug(f"Successfully loaded dynamic signature bank: {filename} ({len(data)} root nodes)")
            return data
            
        except json.JSONDecodeError as e:
            self.logger.critical(f"Corrupted JSON format in signature {filename}: {e}", exc_info=True)
            return {}
        except Exception as e:
            self.logger.error(f"Unexpected dynamic load failure for {filename}: {e}", exc_info=True)
            return {}

    def reload_all(self):
        """Flushes the active memory cache to force a live disk reload without server restart."""
        self.logger.info("Flushing dynamic signature cache...")
        self._cache.clear()

signature_engine = SignatureLoader()
