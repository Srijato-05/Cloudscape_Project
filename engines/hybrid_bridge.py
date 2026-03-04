import copy
import logging
import traceback
from typing import Any, Dict, List

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - HYBRID DATA BRIDGE
# ==============================================================================
# The master convergence point for the Aether Engine.
# Safely merges dynamic, asynchronous Live API streams with deterministic 
# Synthetic State Factory streams. Includes Strict Type Casting to prevent 
# Mapping Cascades in downstream Logic Engines, and exports a Singleton.
# ==============================================================================

class HybridBridge:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Engines.HybridBridge")

    # ==========================================================================
    # DATA SANITIZATION & DEFENSE
    # ==========================================================================

    def _flatten_payloads(self, raw_stream: Any) -> List[Dict[str, Any]]:
        """
        Recursively flattens deeply nested asyncio.gather results.
        Translates [[[node1], [node2]], node3] -> [node1, node2, node3]
        """
        flat_list = []
        
        if not raw_stream:
            return flat_list
            
        if isinstance(raw_stream, dict):
            return [raw_stream]
            
        if isinstance(raw_stream, (list, tuple)):
            for item in raw_stream:
                if isinstance(item, (list, tuple)):
                    # Recursive dive for deeply nested payload gathers
                    flat_list.extend(self._flatten_payloads(item))
                elif isinstance(item, dict):
                    flat_list.append(item)
                elif isinstance(item, Exception):
                    # Silently drop suppressed exceptions from engine gathers
                    pass
                else:
                    self.logger.debug(f"HybridBridge ignored unmergable payload item of type: {type(item)}")
                    
        return flat_list

    def _ensure_dict(self, data: Any, fallback_key: str = "_raw") -> Dict[str, Any]:
        """
        [AETHER FIX] The strict type-caster. 
        Forces rogue lists (like empty tag arrays) or strings into valid 
        dictionaries to prevent TypeError mapping cascades downstream.
        """
        if isinstance(data, dict):
            return data
        elif not data:  # Catches None, [], "", etc.
            return {}
        else:
            return {fallback_key: str(data)}

    # ==========================================================================
    # MASTER CONVERGENCE LOGIC
    # ==========================================================================

    def merge_payload_streams(self, live_stream: Any, synthetic_stream: Any) -> List[Dict[str, Any]]:
        """
        Executes the Hybrid Data Merge.
        1. Sanitizes and flattens both streams.
        2. Injects 'DataOrigin' tags (LiveAPI, Synthetic, or Hybrid).
        3. Resolves ARN collisions (Live takes precedence, Synthetic risks are grafted).
        """
        self.logger.info("Initializing Hybrid Data Merge Sequence...")
        
        try:
            # 1. Neutralize the List-of-Lists anomaly
            live_payloads = self._flatten_payloads(live_stream)
            synth_payloads = self._flatten_payloads(synthetic_stream)
            
            merged_registry = {}
            
            # ------------------------------------------------------------------
            # PHASE 1: PROCESS LIVE DATA (HIGH PRIORITY)
            # ------------------------------------------------------------------
            for payload in live_payloads:
                # Deepcopy prevents memory reference mutation bugs
                safe_payload = copy.deepcopy(payload)
                
                # Defensively cast tags to prevent 'list indices' TypeError
                tags = self._ensure_dict(safe_payload.get("tags"))
                tags["DataOrigin"] = "LiveAPI"
                safe_payload["tags"] = tags
                
                # Extract ARN safely
                arn = safe_payload.get("metadata", {}).get("arn") or safe_payload.get("arn")
                
                if arn:
                    merged_registry[arn] = safe_payload
                else:
                    self.logger.debug("Live payload missing ARN. Appending without collision check.")
                    merged_registry[f"unknown-live-{id(safe_payload)}"] = safe_payload

            # ------------------------------------------------------------------
            # PHASE 2: PROCESS SYNTHETIC DATA (AUGMENTATION & BACKFILL)
            # ------------------------------------------------------------------
            for payload in synth_payloads:
                safe_payload = copy.deepcopy(payload)
                is_edge = safe_payload.get("type") == "explicit_edge"
                
                if is_edge:
                    arn = f"edge::{safe_payload.get('source_arn')}::{safe_payload.get('target_arn')}"
                else:
                    arn = safe_payload.get("metadata", {}).get("arn") or safe_payload.get("arn")
                    
                if not arn:
                    continue
                
                # Defensively cast synthetic tags
                synth_tags = self._ensure_dict(safe_payload.get("tags"))
                    
                if arn in merged_registry and not is_edge:
                    # [THE HYBRID OVERLAY] - Node exists in Reality AND Simulation
                    live_tags = self._ensure_dict(merged_registry[arn].get("tags"))
                    live_tags["DataOrigin"] = "Hybrid"
                    live_tags["SyntheticAugmented"] = "True"
                    
                    # Graft simulated vulnerabilities onto the Live Node
                    synth_risk = safe_payload.get("metadata", {}).get("baseline_risk_score", 0.0)
                    live_risk = merged_registry[arn].get("metadata", {}).get("baseline_risk_score", 0.0)
                    
                    if float(synth_risk) > float(live_risk):
                        merged_registry[arn].setdefault("metadata", {})["baseline_risk_score"] = float(synth_risk)
                        live_tags["InjectedVulnerability"] = "True"
                        
                    merged_registry[arn]["tags"] = live_tags
                else:
                    # Pure Synthetic Node
                    synth_tags["DataOrigin"] = "Synthetic"
                    safe_payload["tags"] = synth_tags
                    merged_registry[arn] = safe_payload

            # ------------------------------------------------------------------
            # PHASE 3: COMPILATION & METRICS
            # ------------------------------------------------------------------
            final_graph = list(merged_registry.values())
            
            # Metrics for the Orchestrator
            live_count = len(live_payloads)
            synth_count = len([p for p in synth_payloads if p.get("type") != "explicit_edge"])
            hybrid_count = len([p for p in final_graph if p.get("tags", {}).get("DataOrigin") == "Hybrid"])
            pure_synth_count = len([p for p in final_graph if p.get("tags", {}).get("DataOrigin") == "Synthetic" and p.get("type") != "explicit_edge"])
            
            self.logger.info(f"Hybrid Merge Complete. Total Unified Nodes: {len(final_graph)} (Live: {live_count}, Pure Synthetic: {pure_synth_count}, Merged/Overlaid: {hybrid_count})")
            
            return final_graph

        except Exception as e:
            self.logger.critical(f"FATAL ERROR during Hybrid Data Merge: {e}\n{traceback.format_exc()}")
            # The Ultimate Failsafe: Return whatever flat dictionaries we can salvage
            safe_fallback = self._flatten_payloads(live_stream) + self._flatten_payloads(synthetic_stream)
            return [p for p in safe_fallback if isinstance(p, dict)]

# ==============================================================================
# SINGLETON EXPORT (THE MISSING LINK)
# ==============================================================================
# The Orchestrator imports this instance directly to ensure the entire Nexus
# pipeline utilizes a single, memory-efficient data bridge.
hybrid_bridge = HybridBridge()