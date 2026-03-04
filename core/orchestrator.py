import time
import json
import gzip
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.config import config, TenantConfig
from engines.aws_engine import AWSEngine
from engines.azure_engine import AzureEngine
from engines.base_engine import BaseDiscoveryEngine

# Standard Logic Engines (v4.0)
from core.logic.risk_scorer import risk_scorer
from core.logic.policy_engine import policy_resolver
from core.processor.ingestor import graph_ingestor

# Advanced Aether Engines (v5.0)
from simulation.state_factory import state_factory
from engines.hybrid_bridge import hybrid_bridge
from core.logic.identity_fabric import identity_fabric
from core.logic.attack_path import attack_path_engine

# ==============================================================================
# ENTERPRISE MASTER ORCHESTRATOR (NEXUS 5.0 AETHER)
# ==============================================================================

class CloudscapeOrchestrator:
    """
    The Central Nervous System of Project Cloudscape.
    Manages multi-tenant live discovery, synthetic state generation, hybrid merging, 
    cross-cloud identity resolution, and heuristic attack path analysis.
    """

    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Core.Orchestrator")
        
        # Concurrency Controls
        self.max_concurrent_tenants = config.settings.orchestrator.max_concurrent_tenants
        self.semaphore = asyncio.Semaphore(self.max_concurrent_tenants)
        
        # Forensics setup
        self.forensics_dir = Path(config.settings.forensics.output_directory)
        self.generate_evidence = config.settings.forensics.generate_json_evidence
        self.compress_evidence = config.settings.forensics.compress_reports
        
        if self.generate_evidence:
            self.forensics_dir.mkdir(parents=True, exist_ok=True)

    def _instantiate_engine(self, tenant: TenantConfig) -> BaseDiscoveryEngine:
        """Dynamically provisions the correct Cloud Engine."""
        provider = tenant.provider.lower()
        if provider == "aws":
            return AWSEngine(tenant)
        elif provider == "azure":
            return AzureEngine(tenant)
        else:
            raise NotImplementedError(f"Provider '{provider}' is not supported.")

    async def _fetch_live_telemetry(self, tenant: TenantConfig) -> List[Dict[str, Any]]:
        """
        Phase 1: Asynchronously crawls a specific tenant for Live API data.
        """
        async with self.semaphore:
            engine = None
            try:
                self.logger.info(f"[{tenant.id}] Starting Live Telemetry Discovery...")
                engine = self._instantiate_engine(tenant)
                
                is_connected = await engine.test_connection()
                if not is_connected:
                    self.logger.warning(f"[{tenant.id}] Live API Connection Failed. Relying solely on Synthetic State.")
                    return []

                raw_payloads = await engine.run_full_discovery()
                self.logger.info(f"[{tenant.id}] Discovered {len(raw_payloads)} live resources.")
                return raw_payloads

            except Exception as e:
                self.logger.error(f"[{tenant.id}] Live Discovery Crashed: {e}", exc_info=True)
                return []
            finally:
                if engine:
                    await engine.cleanup()

    def _enrich_and_resolve_policies(self, payloads: List[Dict[str, Any]], tenants: List[TenantConfig]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Phase 2: Applies Risk Math and mathematically resolves IAM/RBAC JSON.
        Returns the enriched payloads and a flat list of all generated policy edges.
        """
        self.logger.info("Commencing Global Security Enrichment Phase (Risk Math & Policy Resolution)...")
        
        tenant_map = {t.id: t for t in tenants}
        all_policy_edges = []

        for payload in payloads:
            metadata = payload.get("metadata", {})
            properties = payload.get("properties", {})
            tenant_id = metadata.get("tenant_id")
            resource_type = metadata.get("resource_type", "")
            source_arn = metadata.get("arn", "")

            # 1. Apply Blast Radius Scoring
            tenant = tenant_map.get(tenant_id)
            if tenant:
                metadata["baseline_risk_score"] = risk_scorer.calculate_node_risk(payload, tenant)

            # 2. Resolve IAM/Entra Policies into Graph Edges
            secondary_meta = properties.get("_secondary_metadata", {})
            raw_policy = None
            
            if resource_type in ["Role", "User", "Group", "Policy"]:
                raw_policy = secondary_meta.get("get_policy", {})
            elif resource_type in ["Bucket", "Key", "Secret"]:
                raw_policy = secondary_meta.get("get_bucket_policy", secondary_meta.get("get_key_policy", secondary_meta.get("get_resource_policy", {})))

            if raw_policy and isinstance(raw_policy, dict) and not raw_policy.get("error"):
                resolved_edges = policy_resolver.resolve_policy_to_edges(
                    source_arn=source_arn, 
                    policy_document=raw_policy
                )
                if resolved_edges:
                    # Store edges directly on the node for the ingestor, and collect globally for Dijkstra
                    properties.setdefault("_resolved_policy_edges", []).extend(resolved_edges)
                    all_policy_edges.extend(resolved_edges)

        self.logger.info(f"Enrichment Complete. Generated {len(all_policy_edges)} explicit policy edges.")
        return payloads, all_policy_edges

    async def _generate_forensic_evidence(self, payloads: List[Dict[str, Any]]) -> None:
        """Saves a point-in-time state of the unified cloud matrix."""
        if not self.generate_evidence or not payloads:
            return

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        filename = f"aether_global_audit_{timestamp}.json"
        
        try:
            loop = asyncio.get_running_loop()
            
            def write_file():
                report_data = {
                    "audit_metadata": {
                        "scope": "GLOBAL_MATRIX",
                        "timestamp": timestamp,
                        "resource_count": len(payloads),
                        "framework_version": config.settings.app_metadata.version
                    },
                    "resources": payloads
                }
                
                if self.compress_evidence:
                    filepath = self.forensics_dir / f"{filename}.gz"
                    with gzip.open(filepath, 'wt', encoding="utf-8") as f:
                        json.dump(report_data, f, separators=(',', ':'))
                else:
                    filepath = self.forensics_dir / filename
                    with open(filepath, 'w', encoding="utf-8") as f:
                        json.dump(report_data, f, indent=2)
                
                return filepath

            saved_path = await loop.run_in_executor(None, write_file)
            self.logger.debug(f"Global Forensic Evidence locked at {saved_path}")

        except Exception as e:
            self.logger.error(f"Failed to generate global forensic evidence: {e}")

    def _distribute_global_edges(self, payloads: List[Dict[str, Any]], global_edges: List[Dict[str, Any]]) -> None:
        """
        Takes the synthetic edges generated by Identity Fabric and Attack Path engines,
        and injects them back into their respective source node's URM payloads.
        This allows the existing 'transformer.py' to ingest them effortlessly.
        """
        edge_map = {}
        for edge in global_edges:
            src_arn = edge.get("source_arn")
            if src_arn:
                edge_map.setdefault(src_arn, []).append(edge)

        for payload in payloads:
            arn = payload.get("metadata", {}).get("arn")
            if arn in edge_map:
                payload.setdefault("properties", {}).setdefault("_resolved_policy_edges", []).extend(edge_map[arn])

    async def execute_global_scan(self) -> None:
        """
        The Aether Master Pipeline.
        Executes Live Discovery, Synthetic Generation, Hybrid Merging, 
        Global Pathfinding Math, and Distributed Database Ingestion.
        """
        global_start = time.monotonic()
        tenants = config.tenants

        self.logger.info("="*80)
        self.logger.info(f" IGNITING NEXUS 5.0 AETHER PIPELINE ({len(tenants)} Tenants)")
        self.logger.info("="*80)

        if not tenants:
            self.logger.warning("No tenants defined in configuration. Exiting.")
            return

        try:
            # Step 0: Ensure Neo4j schema indexes are present
            await graph_ingestor.setup_schema()

            # Step 1: Concurrent Live Telemetry Fetching
            live_tasks = [self._fetch_live_telemetry(tenant) for tenant in tenants]
            live_results = await asyncio.gather(*live_tasks, return_exceptions=True)
            
            flat_live_payloads = []
            for res in live_results:
                if isinstance(res, list):
                    flat_live_payloads.extend(res)

            # Step 2: Generate the Synthetic Enterprise Universe
            synthetic_payloads = state_factory.generate_universe(tenants)

            # Step 3: The Hybrid Merge (Resolve Collisions)
            unified_payloads = hybrid_bridge.merge_payload_streams(flat_live_payloads, synthetic_payloads)

            if not unified_payloads:
                self.logger.warning("No payloads discovered or generated. Exiting global pipeline.")
                return

            # Step 4: Security Math & IAM Policy Resolution
            enriched_payloads, policy_edges = self._enrich_and_resolve_policies(unified_payloads, tenants)

            # Step 5: Global Identity Fabric (Cross-Cloud & Shadow Admins)
            identity_edges = identity_fabric.extract_identity_edges(enriched_payloads)
            
            # Combine current known edges for Dijkstra's Pathfinding
            current_global_edges = policy_edges + identity_edges

            # Step 6: Heuristic Attack Path Discovery (Dijkstra)
            attack_path_edges = attack_path_engine.calculate_attack_paths(enriched_payloads, current_global_edges)

            # Step 7: Distribute Synthetic Edges back to Source Nodes for standard ingestion
            self._distribute_global_edges(enriched_payloads, identity_edges + attack_path_edges)

            # Step 8: Generate Forensic Snapshot of the unified matrix
            await self._generate_forensic_evidence(enriched_payloads)

            # Step 9: Distributed Database Ingestion (Chunked by Tenant for memory safety)
            self.logger.info("Executing Graph Database Ingestion Phase...")
            
            tenant_payload_map = {}
            for p in enriched_payloads:
                t_id = p.get("metadata", {}).get("tenant_id", "unknown-tenant")
                tenant_payload_map.setdefault(t_id, []).append(p)

            for t_id, t_payloads in tenant_payload_map.items():
                await graph_ingestor.ingest_payloads(t_id, t_payloads)

            # ==================================================================
            # TELEMETRY & REPORTING
            # ==================================================================
            global_duration = round(time.monotonic() - global_start, 2)
            
            print("\n" + "="*80)
            print(" AETHER GLOBAL SCAN COMPLETE ")
            print("="*80)
            print(f" Total Live Nodes Discovered  : {len(flat_live_payloads)}")
            print(f" Total Synthetic Nodes Forged : {len(synthetic_payloads)}")
            print(f" Total Unified Graph Nodes    : {len(unified_payloads)}")
            print("-" * 80)
            print(f" Policy Edges Calculated      : {len(policy_edges)}")
            print(f" Cross-Cloud Identity Bridges : {len(identity_edges)}")
            print(f" Critical Attack Paths Found  : {len(attack_path_edges)}")
            print("-" * 80)
            print(f" Execution Time               : {global_duration} seconds")
            print("="*80 + "\n")

        except Exception as e:
            self.logger.critical(f"Global Scan failed catastrophically: {e}", exc_info=True)
        finally:
            await graph_ingestor.close()

# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
# Instantiated locally in main.py, but structure supports export if needed.