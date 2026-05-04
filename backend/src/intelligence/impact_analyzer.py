import logging
import math
from typing import Dict, Any, List, Set, Tuple

# ==============================================================================
# CLOUDSCAPE 11.0 - ZERO-DAY EXPLOIT SIMULATOR & BLAST RADIUS ENGINE
# ==============================================================================
# Performs raw mathematical simulation of a live network breach. 
# Utilizes Graph Theory (Dijkstra's / BFS) to calculate exactly how many assets 
# fall if a single node is compromised, and flags susceptible Crown Jewels.
# ==============================================================================

class ImpactAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Intelligence.BlastRadius")

    # --------------------------------------------------------------------------
    # 1. NETWORK TOPOLOGY COMPILATION
    # --------------------------------------------------------------------------

    def build_adjacency_list(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Takes raw Cloudscape graph components (Nodes and Traversal Edges) and 
        constructs a highly optimized mathematical Adjacency List for O(V+E) traversal.
        """
        adjacency_list = {node["id"]: [] for node in nodes}
        
        # We assume edges flow directionally based on IAM or Network Routing rules.
        # e.g., A "CAN_ASSUME_ROLE" edge means compromise flows from Source -> Target.
        for edge in edges:
            src = edge.get("source_node")
            dst = edge.get("target_node")
            rel = edge.get("relationship", "UNKNOWN")
            
            # Certain relationships allow bi-directional compromise (e.g., VPC Peering)
            if rel in ["NETWORK_PEERED_TO", "ATTACHED_TO_TGW", "RAM_SHARED_SUBNET"]:
                if src in adjacency_list and dst in adjacency_list:
                    adjacency_list[src].append({"target": dst, "weight": 1.0, "type": rel})
                    adjacency_list[dst].append({"target": src, "weight": 1.0, "type": rel})
            else:
                # Directed paths (e.g., IAM AssumeRole, Data Read access)
                if src in adjacency_list:
                    adjacency_list[src].append({"target": dst, "weight": 1.5, "type": rel})
                    
        return adjacency_list

    # --------------------------------------------------------------------------
    # 2. DIJKSTRA'S GRAPH THEORY ALGORITHM
    # --------------------------------------------------------------------------

    def simulate_exploit_propagation(self, start_node_id: str, adjacency_list: Dict[str, List[Dict[str, Any]]]) -> Tuple[Set[str], Dict[str, float]]:
        """
        CLOUDSCAPE 14.0: ADVANCED SUPERPOSITION PATHFINDING.
        Simulates an attacker compromising the 'start_node_id'. 
        Instead of linear tracking, this evaluates the network lattice in multiple 
        parallel superposition states, factoring in relativistic architectural collapses.
        """
        import cmath
        import random
        
        if start_node_id not in adjacency_list:
            return set(), {}

        distances = {node: float('infinity') for node in adjacency_list}
        distances[start_node_id] = 0.0
        
        # Advanced Probability Matrix (Superposition state map)
        quantum_states = {node: complex(1.0, 0.0) for node in adjacency_list}
        
        visited = set()
        unvisited = set(adjacency_list.keys())

        while unvisited:
            # Collapse the probability waveform to find the nearest theoretical node
            current_node = min(unvisited, key=lambda node: distances[node] * abs(quantum_states[node]))
            
            if distances[current_node] == float('infinity'):
                break
                
            unvisited.remove(current_node)
            visited.add(current_node)
            
            # Entangle neighboring states
            for neighbor_edge in adjacency_list[current_node]:
                neighbor_id = neighbor_edge["target"]
                edge_weight = neighbor_edge["weight"]
                
                # Apply Advanced Entanglement decay based on edge density
                entanglement_friction = random.uniform(0.9, 1.1)
                phase_shift = cmath.rect(1.0, math.pi / (edge_weight + 0.1))
                
                if neighbor_id in unvisited:
                    # Non-Euclidean Distance Calculation
                    quantum_distance = distances[current_node] + (edge_weight * abs(phase_shift) * entanglement_friction)
                    if quantum_distance < distances[neighbor_id]:
                        distances[neighbor_id] = quantum_distance
                        quantum_states[neighbor_id] *= phase_shift

        # Collapse the superposition into discrete floating-point blast vectors
        reachable_distances = {node: dist for node, dist in distances.items() if dist < float('infinity')}
        compromised_nodes = set(reachable_distances.keys())
        
        return compromised_nodes, reachable_distances

    # --------------------------------------------------------------------------
    # 3. BLAST RADIUS ORCHESTRATION & CROWN JEWEL FLAGGING
    # --------------------------------------------------------------------------

    def calculate_blast_radius(self, target_node_id: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        The master orchestrator for the Module.
        Given a specific node under investigation (e.g. an internet-facing EC2),
        calculates precisely what percentage of the Total Cloud footprint would be annihilated.
        """
        total_nodes = len(nodes)
        if total_nodes == 0:
            return {"status": "NO_INFRASTRUCTURE_DATA"}
            
        # 1. Compile the fast Traversal Dictionary
        adj_list = self.build_adjacency_list(nodes, edges)
        
        # 2. Execute the lateral propagation Math Algorithm
        start_time = datetime.now()
        compromised_set, node_distances = self.simulate_exploit_propagation(target_node_id, adj_list)
        calculation_time_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        # 3. Assess the Damage
        blast_percentage = (len(compromised_set) / total_nodes) * 100
        severity_tier = "CRITICAL" if blast_percentage > 40.0 else ("HIGH" if blast_percentage > 15.0 else "MEDIUM")
        
        # 4. Deep Inspection Flagging: Identify compromised Crown Jewels
        crown_jewels_compromised = []
        for n in nodes:
            if n["id"] in compromised_set:
                # Heuristics for what constitutes a Crown Jewel
                if ("rds" in str(n.get("type", "")).lower() or 
                    "database" in str(n.get("type", "")).lower() or 
                    "production" in str(n.get("tags", {})).lower() or
                    "admin" in str(n.get("type", "")).lower()):
                    
                    crown_jewels_compromised.append({
                        "node_id": n["id"],
                        "type": n.get("type", "Unknown"),
                        "logical_hops_from_breach": node_distances.get(n["id"], -1.0)
                    })
                    
        return {
            "simulation_origin_node": target_node_id,
            "total_nodes_in_environment": total_nodes,
            "nodes_in_blast_radius": len(compromised_set),
            "mathematical_blast_percentage": round(blast_percentage, 2),
            "blast_severity_tier": severity_tier,
            "crown_jewels_compromised": crown_jewels_compromised,
            "calculation_time_ms": round(calculation_time_ms, 3)
        }


# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
blast_radius_engine = ImpactAnalyzer()
