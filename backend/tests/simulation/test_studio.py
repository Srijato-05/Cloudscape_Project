import pytest
import sys
import os
from pathlib import Path

# Fix pathing for test environment
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

from simulation.simulation_studio import SimulationStudio
from core.forensics import forensic_ledger

def test_studio_scenario_registry():
    studio = SimulationStudio()
    scenarios = studio.scenario_library.list_scenarios()
    assert "S3_BUCKET_EXPOSURE" in scenarios
    assert "IAM_PRIVILEGE_HOIST" in scenarios

def test_studio_run_scenario_s3():
    studio = SimulationStudio()
    
    # Create simple mock base state
    base_nodes = [{
        "arn": "arn:aws:s3:::test-bucket",
        "type": "Bucket",
        "metadata": {"IsPublic": False},
        "properties": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}},
        "risk_score": 2.0
    }]
    
    result = studio.run_scenario(base_nodes, "S3_BUCKET_EXPOSURE", "arn:aws:s3:::test-bucket")
    
    mutated_node = next(n for n in result["mutated_nodes"] if n["arn"] == "arn:aws:s3:::test-bucket")
    assert mutated_node["metadata"]["IsPublic"] == True
    assert mutated_node["risk_score"] == 9.5
    assert result["drift_summary"]["risk_delta"] == 7.5

def test_studio_invalid_scenario():
    studio = SimulationStudio()
    base_nodes = [{"arn": "arn:1", "type": "T", "metadata": {}, "properties": {}}]
    
    # Should fallback to basic mutation if scenario not in library
    result = studio.run_scenario(base_nodes, "INVALID", "arn:1")
    assert result["drift_summary"]["scenario"] == "INVALID"
