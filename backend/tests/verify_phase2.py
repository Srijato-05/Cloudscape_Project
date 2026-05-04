import os
import sys
import asyncio
import logging
import json
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))

from core.config import ConfigurationManager, settings
from core.orchestrator import CloudScapeOrchestrator, PipelineStage

async def verify_playback_mode():
    print("\n--- Testing Phase 2: Deterministic Forensic Playback ---")
    
    # 1. Force PLAYBACK mode in environments
    os.environ["CLOUDSCAPE_EXECUTION_MODE"] = "PLAYBACK"
    
    # 2. Initialize Config
    config_manager = ConfigurationManager()
    
    # Ensure playback source exists in the expected location
    # In mock_forensic_engine.py: self.playback_source = Path(config.settings.forensics.log_path) / "playback_snapshot.json"
    # ConfigurationManager resolves base_dir to project root.
    # log_path is "forensics/logs"
    
    playback_dir = Path(config_manager.base_dir) / "backend" / "forensics" / "logs"
    playback_dir.mkdir(parents=True, exist_ok=True)
    playback_file = playback_dir / "playback_snapshot.json"
    
    # We already created it in d:\Cloudscape_Project\backend\forensics\logs\playback_snapshot.json
    # Let's verify it's there or move it if needed.
    if not playback_file.exists():
        print(f"ERROR: Playback file not found at {playback_file}")
        return False

    orchestrator = CloudScapeOrchestrator(config_manager)
    
    print(f"Execution Mode: {config_manager.settings.execution_mode}")
    
    # Run a single tenant pipeline
    if not config_manager.tenants:
        print("ERROR: No tenants configured for testing.")
        return False
        
    tenant = config_manager.tenants[0]
    print(f"Testing tenant: {tenant.id}")
    
    state = await orchestrator._execute_tenant_pipeline(tenant)
    
    print(f"Pipeline Outcome: {state.current_stage.value}")
    print(f"Live Nodes Extracted: {state.live_nodes_extracted}")
    
    if state.current_stage == PipelineStage.COMPLETE and state.live_nodes_extracted == 2:
        print("SUCCESS: Forensic Playback loaded 2 nodes deterministically.")
        return True
    else:
        print(f"FAILED: Expected 2 nodes, got {state.live_nodes_extracted}. Stage: {state.current_stage.value}")
        if state.errors:
            print(f"Errors: {state.errors}")
        return False

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    success = loop.run_until_complete(verify_playback_mode())
    if not success:
        sys.exit(1)
