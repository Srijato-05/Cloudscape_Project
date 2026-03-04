import logging
import traceback
import networkx as nx
from typing import Any, Dict, List, Optional

# ==============================================================================
# HEURISTIC ATTACK PATH DISCOVERY (HAPD) - NEXUS 5.0
# ==============================================================================
# Utilizes in-memory directed graphs (NetworkX) to calculate multi-hop, 
# cross-cloud attack vectors. Identifies lateral movement opportunities 
# by combining Physical Infrastructure with Identity Fabric trusts.
# ==============================================================================

class AttackPathEngine:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.AttackPath")
        
        # Risk Math Constants (Determines edge thickness in Neo4j)
        self.CRITICAL_PATH_WEIGHT = 9.8
        self.LATERAL_MOVE_WEIGHT = 7.5

    def _ensure_dict(self, data: Any) -> Dict[str, Any]:
        """Strict Type-Caster to prevent mapping cascade crashes on rogue arrays."""
        if isinstance(data, dict): return data
        return {}

    def _build_in_memory_graph(self, unified_graph: List[Dict[str, Any]], global_edges: List[Dict[str, Any]]) -> nx.DiGraph:
        """Constructs a mathematical graph representation of the cloud mesh."""
        G = nx.DiGraph()
        
        # 1. INJECT PHYSICAL & SYNTHETIC NODES
        for node in unified_graph:
            if not isinstance(node, dict): continue
            
            arn = node.get("arn") or node.get("metadata", {}).get("arn")
            if not arn: continue
                
            # Safely extract and cast attributes
            tags = self._ensure_dict(node.get("tags"))
            metadata = self._ensure_dict(node.get("metadata"))
            
            # Store essential compute traits for pathfinding math
            G.add_node(
                arn, 
                resource_type=metadata.get("resource_type", "Unknown"),
                is_public=str(tags.get("Exposure", "")).lower() == "public" or str(tags.get("Tier", "")).lower() == "public",
                is_vulnerable=str(tags.get("InjectedVulnerability", "False")).lower() == "true",
                data_class=tags.get("DataClass", "Standard")
            )

        # 2. INJECT IDENTITY FABRIC TRUSTS
        for edge in global_edges:
            if not isinstance(edge, dict): continue
            src = edge.get("source_arn")
            dst = edge.get("target_arn")
            if src and dst:
                G.add_edge(src, dst, relation=edge.get("relation_type", "RELATES_TO"), weight=edge.get("weight", 1.0))
            
        return G

    # ==========================================================================
    # STRATEGIC TARGETING LOGIC
    # ==========================================================================

    def _identify_entry_points(self, G: nx.DiGraph) -> List[str]:
        """Finds externally facing assets (Web Tier VMs, Public Subnets)."""
        return [n for n, d in G.nodes(data=True) if d.get("is_public") or d.get("resource_type") in ["Instance", "Subnet", "SecurityGroup"]]

    def _identify_crown_jewels(self, G: nx.DiGraph) -> List[str]:
        """Finds high-value targets (Vulnerable Databases, PCI Vaults)."""
        return [n for n, d in G.nodes(data=True) if (d.get("resource_type") == "DBInstance" and d.get("is_vulnerable")) or d.get("data_class") == "PCI"]

    def _find_shadow_admins(self, G: nx.DiGraph) -> List[str]:
        """Finds highly privileged identities connecting the environment."""
        return [n for n, d in G.nodes(data=True) if d.get("resource_type") == "Role" and ("Admin" in n or "Federated" in n)]

    # ==========================================================================
    # PATHFINDING EXECUTION
    # ==========================================================================

    def calculate_attack_paths(self, unified_graph: List[Dict[str, Any]], global_edges: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        [AETHER FIX] Matches Orchestrator signature exactly (takes payloads AND edges).
        Executes the master attack path algorithm, generating heuristic links.
        """
        self.logger.info("Commencing Heuristic Attack Path Discovery (HAPD)...")
        attack_edges = []
        global_edges = global_edges or []
        
        try:
            # 1. Initialize NetworkX Graph
            G = self._build_in_memory_graph(unified_graph, global_edges)
            
            # 2. Extract Strategic Nodes
            entry_points = self._identify_entry_points(G)
            targets = self._identify_crown_jewels(G)
            shadow_admins = self._find_shadow_admins(G)
            
            # 3. Heuristic Kill Chain Generation
            for entry in entry_points:
                # Vector A: Web Tier -> Direct Compromise of Database
                for target in targets:
                    attack_edges.append({
                        "type": "explicit_edge",
                        "source_arn": entry,
                        "target_arn": target,
                        "relation_type": "NETWORK_EXPOSURE_PATH",
                        "weight": self.LATERAL_MOVE_WEIGHT,
                        "metadata": {"discovery_engine": "HAPD", "vector": "Network Lateral Movement"}
                    })

                # Vector B: External Compromise -> Role Assumption
                for admin in shadow_admins:
                    attack_edges.append({
                        "type": "explicit_edge",
                        "source_arn": entry,
                        "target_arn": admin,
                        "relation_type": "CAN_ASSUME_ROLE",
                        "weight": self.LATERAL_MOVE_WEIGHT,
                        "metadata": {"discovery_engine": "HAPD", "vector": "IAM Escalation"}
                    })

            # Vector C: Shadow Admin -> Data Exfiltration
            for admin in shadow_admins:
                for target in targets:
                    attack_edges.append({
                        "type": "explicit_edge",
                        "source_arn": admin,
                        "target_arn": target,
                        "relation_type": "CAN_EXFILTRATE",
                        "weight": self.CRITICAL_PATH_WEIGHT,
                        "metadata": {"discovery_engine": "HAPD", "vector": "Data Breach"}
                    })

            # Deduplicate generated edges using a tuple hash constraint
            unique_edges = { (e["source_arn"], e["target_arn"], e["relation_type"]): e for e in attack_edges }
            final_edges = list(unique_edges.values())

            self.logger.info(f"Attack Path Analysis complete. Generated {len(final_edges)} persistent exfiltration routes.")
            return final_edges

        except Exception as e:
            self.logger.error(f"Failed to calculate HAPD graph matrix: {e}\n{traceback.format_exc()}")
            return []

# ==============================================================================
# SINGLETON EXPORT
# ==============================================================================
attack_path_engine = AttackPathEngine()