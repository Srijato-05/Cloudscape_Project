import logging
import copy
import time
from typing import List, Dict, Any, Optional
from core.forensics import StateComparator
from simulation.scenario_library import scenario_library

class MutationEngine:
    """Enterprise logic for applying hypothetical changes to URM nodes."""
    
    def apply_generic_mutation(self, node: Dict[str, Any], path: str, value: Any, append: bool = False) -> None:
        """
        Traverses a node by path (e.g. 'properties.PublicAccessBlock') and sets or appends a value.
        """
        parts = path.split('.')
        target = node
        
        # Traverse to the parent of the final attribute
        for part in parts[:-1]:
            if part not in target:
                target[part] = {}
            target = target[part]
            
        final_key = parts[-1]
        
        if append:
            if final_key not in target or not isinstance(target[final_key], list):
                target[final_key] = []
            target[final_key].append(value)
        else:
            target[final_key] = value
            
        # Add a simulation tag if metadata is present
        if "tags" in node:
            node["tags"]["simulation_drift"] = "TRUE"

class SimulationStudio:
    """
    Industry-level 'What-if' Security Mutation Lab.
    Higher-order orchestrator for applying attack scenarios to infra snapshots.
    """

    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Sim.Studio")
        self.mutation_engine = MutationEngine()
        self.scenario_library = scenario_library

    def run_scenario(self, base_nodes: List[Dict[str, Any]], scenario_id: str, target_arn: str) -> Dict[str, Any]:
        """
        Executes a security mutation on a set of URM nodes.
        Returns the mutated nodes and a drift summary.
        """
        self.logger.info(f"Applying scenario '{scenario_id}' to target {target_arn}")
        
        # Fresh copy to avoid mutating the base in-place
        mutated_nodes = copy.deepcopy(base_nodes)
        
        # 1. Resolve Target
        target_node = next((n for n in mutated_nodes if n["arn"] == target_arn), None)
        if not target_node:
            self.logger.error(f"Target node {target_arn} not found in base state.")
            return {"mutated_nodes": base_nodes, "drift_summary": {"error": "Target node not found"}}

        # 2. Extract Scenario Mutations
        scenario_def = self.scenario_library.get_scenario(scenario_id)
        original_risk = target_node.get("risk_score", 0.0)
        
        if scenario_def:
            # Apply predefined scenario mutations
            for mut in scenario_def["mutations"]:
                self.mutation_engine.apply_generic_mutation(
                    target_node, 
                    mut["path"], 
                    mut.get("value"), 
                    append=bool(mut.get("append"))
                )
        else:
            # Fallback for dynamic/ad-hoc names
            self.logger.warning(f"Scenario '{scenario_id}' not in library. Using fallback logic.")
            if scenario_id == "MAKE_PUBLIC":
                self.mutation_engine.apply_generic_mutation(target_node, "metadata.IsPublic", True)
                self.mutation_engine.apply_generic_mutation(target_node, "risk_score", 10.0)
            else:
                self.mutation_engine.apply_generic_mutation(target_node, "metadata.SimulatedMutation", scenario_id)

        new_risk = target_node.get("risk_score", 10.0)

        # 3. Quantify Drift (Topological Risk Delta)
        # Note: We compare the mutated list against the original list
        comparison = StateComparator.compare(base_nodes, mutated_nodes)
        
        drift_summary = {
            "scenario": scenario_id,
            "target": target_arn,
            "risk_delta": new_risk - original_risk,
            "comparison": comparison["summary"],
            "timestamp": time.time()
        }

        return {
            "mutated_nodes": mutated_nodes,
            "drift_summary": drift_summary
        }
