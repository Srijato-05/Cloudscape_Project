import pytest
import sys
from pathlib import Path

# Fix pathing for test environment
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

from simulation.simulation_studio import MutationEngine

def test_mutation_engine_path_resolution():
    engine = MutationEngine()
    node = {
        "properties": {
            "Network": {"IsPublic": False},
            "Tags": ["Internal"]
        }
    }
    
    # Test setting nested value
    engine.apply_generic_mutation(node, "properties.Network.IsPublic", True)
    assert node["properties"]["Network"]["IsPublic"] == True

def test_mutation_engine_append():
    engine = MutationEngine()
    node = {
        "properties": {
            "IpPermissions": []
        }
    }
    
    rule = {"Port": 80, "Cidr": "0.0.0.0/0"}
    engine.apply_generic_mutation(node, "properties.IpPermissions", rule, append=True)
    
    assert len(node["properties"]["IpPermissions"]) == 1
    assert node["properties"]["IpPermissions"][0]["Port"] == 80

def test_mutation_engine_missing_path():
    engine = MutationEngine()
    node = {}
    
    # Should create missing keys
    engine.apply_generic_mutation(node, "metadata.Status", "Compromised")
    assert node["metadata"]["Status"] == "Compromised"
