import logging
import json
import time
import asyncio
from typing import Any, Dict, List, Optional
from pathlib import Path

from core.config import config, TenantConfig
from discovery.engines.base_engine import BaseDiscoveryEngine, EngineMode

class MockPlaybackEngine(BaseDiscoveryEngine):
    """
    [CLOUDSCAPE 15.0] DETERMINISTIC FORENSIC MOCK ENGINE.
    Enables playback of discovery datasets from BSON/JSON forensic snapshots.
    Eliminates the need for LocalStack or live AWS/Azure credentials during integration testing.
    """
    
    def __init__(self, tenant: TenantConfig):
        BaseDiscoveryEngine.__init__(self, tenant)
        self.logger = logging.getLogger(f"CloudScape.Engine.Playback.[{tenant.id}]")
        self.playback_source = Path(config.settings.forensics.log_path) / "playback_snapshot.json"
        
        # CLOUDSCAPE 15.0: ADVANCED PLAYBACK CONTROLS
        self.temporal_fidelity = True # Simulate API latency deltas
        # Differential overlay: Load mutations if they exist
        self.overlay_source = Path(config.settings.forensics.log_path) / "playback_mutation.json"
        
    async def test_connection(self) -> bool:
        """Verifies that the playback source file exists."""
        exists = self.playback_source.exists()
        if exists:
            self.logger.info(f"Playback source found: {self.playback_source}")
        else:
            self.logger.warning(f"Playback source NOT found: {self.playback_source}. Fallback to empty discovery.")
        return exists

    async def discover(self) -> List[Dict[str, Any]]:
        """
        [ADVANCED] Replays URM nodes with high-fidelity temporal simulation.
        Supports differential overlays to test StateComparator logic.
        """
        self.logger.info(f"Initiating high-fidelity playback from {self.playback_source}...")
        start_time = time.perf_counter()
        
        nodes = []
        if self.playback_source.exists():
            try:
                with open(self.playback_source, 'r', encoding='utf-8') as f:
                    nodes = json.load(f)
                
                # Apply Differential Overlay if present
                if self.overlay_source.exists():
                    self.logger.info(f"Applying differential mutation overlay from {self.overlay_source}...")
                    with open(self.overlay_source, 'r', encoding='utf-8') as f:
                        mutations = json.load(f)
                        if isinstance(mutations, list):
                            nodes.extend(mutations)
                            self.logger.info(f"Injected {len(mutations)} mutation/differential nodes.")

                if not isinstance(nodes, list):
                    self.logger.error("Playback source must contain a JSON list of URM nodes.")
                    nodes = []
                    
                # CLOUDSCAPE 15.0: TEMPORAL FIDELITY SIMULATION
                if self.temporal_fidelity and nodes:
                    # Simulation of discovery jitter
                    self.logger.info("Engaging Temporal Fidelity simulation (Simulating API discovery jitter)...")
                    for batch_idx in range(0, len(nodes), 20):
                        await asyncio.sleep(0.05) 
                        
            except Exception as e:
                self.logger.error(f"Failed to execute forensic playback: {e}")
        
        self.metrics.total_extraction_time_ms = (time.perf_counter() - start_time) * 1000
        self.metrics.nodes_extracted = len(nodes)
        
        self.logger.info(f"Playback complete. Replayed {len(nodes)} nodes with temporal fidelity.")
        return nodes

    async def teardown(self) -> None:
        """No specific teardown needed for playback."""
        await super().teardown()
