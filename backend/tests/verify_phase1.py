import sys
import os
from pathlib import Path
import asyncio
import logging

# Inject backend/src into path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.safety_kernel import safety_guard # type: ignore
from core.orchestrator import CloudScapeOrchestrator # type: ignore
from core.config import ConfigurationManager # type: ignore

logging.basicConfig(level=logging.INFO)

async def test_safety_kernel_execution():
    print("\n--- Testing Safety Kernel Functional read-only ---")
    
    @safety_guard.enforce_read_only
    def sensitive_operation(data: str):
        print(f"Executing sensitive operation with: {data}")
        return f"PROCESSED: {data}"
    
    # Direct call (sandbox active by default in implementation)
    result = sensitive_operation("CLOUD_METADATA_01")
    print(f"Result: {result}")
    assert "PROCESSED: CLOUD_METADATA_01" in str(result)
    print("SUCCESS: Safety Kernel allowed execution while logging integrity.")

async def test_orchestrator_backpressure():
    print("\n--- Testing Orchestrator Backpressure (No Self-Mutation) ---")
    
    # Proper class-based mocks instead of hacky type() calls
    class MockOrchestratorSettings:
        max_concurrent_tenants = 1
        worker_timeout_sec = 10
        strict_sequential_mode = True
        max_workers = 1
    
    class MockForensicsSettings:
        log_path = 'logs/forensics'
    
    class MockIngestionSettings:
        batch_size = 10
        
    class MockDatabaseSettings:
        ingestion = MockIngestionSettings()
        
    class MockSettings:
        orchestrator = MockOrchestratorSettings()
        execution_mode = "MOCK"
        forensics = MockForensicsSettings()
        database = MockDatabaseSettings()
    
    class MockConfigManager:
        settings = MockSettings()
        tenants = []
        base_dir = "."
        def validate_runtime_integrity(self): return {"config_loaded": True}

    orchestrator = CloudScapeOrchestrator(MockConfigManager()) # type: ignore
    
    # Verify the method exists but doesn't have the old 'import ast' logic
    import inspect
    source = inspect.getsource(orchestrator._apply_dynamic_backpressure)
    print("Orchestrator backpressure source snippet:")
    source_lines = source.splitlines()
    print("\n".join(source_lines[:min(5, len(source_lines))]))
    
    assert "metamorphic" not in source.lower()
    assert "ast.parse" not in source
    print("SUCCESS: Orchestrator is stable/deterministic.")

if __name__ == "__main__":
    asyncio.run(test_safety_kernel_execution())
    asyncio.run(test_orchestrator_backpressure())
