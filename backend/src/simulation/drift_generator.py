import logging
import copy
from typing import Dict, Any, List, Tuple
from simulation.state_factory import StateFactory
from simulation.simulation_studio import SimulationStudio
from simulation.scenario_library import scenario_library

class DriftGenerator:
    """
    Automates the generation of (Base, Mutated) URM pairs for testing.
    Used to validate StateComparator and BlastRadiusEngine fidelity.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Simulation.DriftGenerator")
        self.factory = StateFactory()
        self.studio = SimulationStudio()

    def generate_test_pair(self, scenario_name: str, node_count: int = 50) -> Dict[str, Any]:
        """
        1. Generates a base synthetic topology.
        2. Selects a suitable target node.
        3. Applies the named scenario mutation.
        4. Returns both states and the target ARN.
        """
        self.logger.info(f"Generating test drift pair for scenario: {scenario_name}")
        
        # 1. Produce Base Topology
        # Note: In mock mode, we just need a list of nodes
        from core.config import TenantConfig
        dummy_tenant = TenantConfig(id="test-tenant", credentials=None) # type: ignore
        base_nodes = self.factory.produce_full_topology(dummy_tenant)
        
        # 2. Select Target (e.g. if scenario is S3, find an S3 bucket)
        target_arn = self._find_suitable_target(base_nodes, scenario_name)
        if not target_arn:
            # Fallback to first node if specific type not found
            target_arn = base_nodes[0]["arn"]
            
        # 3. Apply Mutation
        result = self.studio.run_scenario(base_nodes, scenario_name, target_arn)
        
        return {
            "scenario": scenario_name,
            "target_arn": target_arn,
            "base_nodes": base_nodes,
            "mutated_nodes": result["mutated_nodes"],
            "expected_drift": result["drift_summary"]
        }

    def _find_suitable_target(self, nodes: List[Dict[str, Any]], scenario: str) -> Optional[str]:
        """Heuristically picks a node that fits the scenario requirements."""
        if "S3" in scenario:
            for n in nodes:
                if n["type"].lower() == "bucket": return n["arn"]
        if "IAM" in scenario:
            for n in nodes:
                if n["type"].lower() == "role": return n["arn"]
        if "NETWORK" in scenario:
            for n in nodes:
                if n["type"].lower() == "securitygroup": return n["arn"]
        if "DATABASE" in scenario:
            for n in nodes:
                if n["type"].lower() == "dbinstance": return n["arn"]
        return None

drift_generator = DriftGenerator()
