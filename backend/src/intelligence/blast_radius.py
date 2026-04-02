import logging
from typing import List, Dict, Any, Set, Optional
from collections import deque

class BlastRadiusEngine:
    """
    Enterprise Graph-Theoretic Path Analyzer.
    Calculates the 'Blast Radius Intensity' by traversing the Universal Resource Model (URM)
    relationships to determine cascading compromise impact.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("CloudScape.Intelligence.BlastRadius")

    def analyze_impact(self, target_arn: str, all_nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Performs a deep graph traversal to determine the blast radius of a compromised node.
        Returns:
            - intensity_score: Normalized risk score (0-10)
            - impacted_arns: List of all downstream reachable resources
            - critical_paths: Key high-value nodes or identity bridges reachable
            - summary: Human-readable impact description
        """
        if not target_arn or not all_nodes:
            return {"intensity_score": 0.0, "impacted_arns": [], "summary": "No target or nodes provided."}

        # 1. Build Adjacency Map for fast traversal
        adj_map: Dict[str, List[str]] = {}
        node_map: Dict[str, Dict[str, Any]] = {}
        
        for node in all_nodes:
            arn = node.get("arn")
            if not arn: continue
            node_map[arn] = node
            adj_map[arn] = node.get("relationships", [])

        if target_arn not in node_map:
            return {"intensity_score": 0.0, "impacted_arns": [], "summary": f"Target {target_arn} not found in URM."}

        # 2. Perform BFS to find all reachable nodes
        visited: Set[str] = {target_arn}
        queue = deque([target_arn])
        impacted_arns: List[str] = []
        critical_encounters: List[str] = []

        while queue:
            current_arn = queue.popleft()
            
            for neighbor in adj_map.get(current_arn, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
                    impacted_arns.append(neighbor)
                    
                    # Log high-value infrastructure
                    neighbor_node = node_map.get(neighbor, {})
                    if neighbor_node.get("service") in ["iam", "rds", "s3", "keyvault"]:
                        critical_encounters.append(f"{neighbor_node.get('service').upper()}:{neighbor}")

        # 3. Calculate Weight based on the sensitivity
        total_intensity = 0.0
        for arn in impacted_arns:
            node = node_map.get(arn, {})
            base_val = 1.0
            tags = node.get("tags", {})
            classification = str(tags.get("data_classification", "INTERNAL")).upper()
            
            if "CRITICAL" in classification or "SECRET" in classification:
                base_val *= 3.0
            if node.get("service") in ["iam", "rds", "s3", "keyvault"]:
                base_val *= 2.0
                
            total_intensity += base_val

        # 4. Final Aggregation
        import math
        intensity_score = min(max(math.log1p(total_intensity) * 1.5, 0.0), 10.0)
        
        return {
            "intensity_score": round(intensity_score, 2),
            "impacted_count": len(impacted_arns),
            "impacted_arns": impacted_arns[:50], # Cap for report readability
            "critical_resources": list(set(critical_encounters))[:10],
            "summary": f"Compromise of {target_arn} exposes {len(impacted_arns)} downstream resources, including {len(critical_encounters)} high-value assets."
        }

    def calculate_intensity(self, target_arn: str, all_nodes: List[Dict[str, Any]]) -> float:
        """Legacy wrapper for intensity scoring."""
        res = self.analyze_impact(target_arn, all_nodes)
        return res["intensity_score"]

# Singleton Export
blast_radius_engine = BlastRadiusEngine()
