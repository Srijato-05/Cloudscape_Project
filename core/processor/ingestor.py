import json
import asyncio
import logging
import traceback
from typing import Any, Dict, List, Tuple

from neo4j import AsyncGraphDatabase
from neo4j.exceptions import ServiceUnavailable, SessionExpired, ClientError, TransientError

from core.config import config

# ==============================================================================
# ENTERPRISE GRAPH INGESTOR (NEXUS 5.0 AETHER)
# ==============================================================================
# Asynchronous Neo4j Database pipeline. 
# Implements aggressive keep-alives and connection pooling to prevent Windows 
# IPv6 socket handshake drops.
# Utilizes UNWIND batch chunking and Deep Serialization for OOM-safe graph writing.
# ==============================================================================

class GraphIngestor:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Processor.Ingestor")
        
        # ----------------------------------------------------------------------
        # 1. DATABASE CONFIGURATION BINDING
        # ----------------------------------------------------------------------
        try:
            db_cfg = config.settings.database
            self.uri = db_cfg.uri
            
            # Secure credential extraction
            auth_str = getattr(config.settings, 'neo4j_auth', "neo4j/Cloudscape2026!")
            self.user, self.password = auth_str.split('/', 1) if '/' in auth_str else ("neo4j", "password")

            # Batch chunking limit to prevent heap exhaustion during UNWIND
            self.batch_size = getattr(db_cfg.ingestion, 'batch_size', 2500)
            
        except Exception as e:
            self.logger.critical(f"Failed to parse database configuration: {e}")
            raise

        # ----------------------------------------------------------------------
        # 2. DRIVER INSTANTIATION & SOCKET HARDENING
        # ----------------------------------------------------------------------
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_pool_size=getattr(db_cfg, 'connection_pool_size', 100),
                connection_acquisition_timeout=getattr(db_cfg, 'connection_timeout_sec', 15),
                # [AETHER FIX] Force aggressive socket keep-alive to bypass Windows WinError 10053
                keep_alive=True,
                max_connection_lifetime=300 # Recycle sockets every 5 minutes to prevent staleness
            )
        except Exception as e:
            self.logger.critical(f"FATAL: Failed to initialize Neo4j Driver: {e}")
            raise

    async def close(self) -> None:
        """Gracefully tears down the TCP connection pool on system exit."""
        if self.driver:
            self.logger.info("Closing Neo4j Database Driver...")
            await self.driver.close()

    # ==========================================================================
    # SCHEMA ENFORCEMENT & INITIALIZATION
    # ==========================================================================

    async def setup_schema(self) -> None:
        """
        Validates and creates the strict Neo4j 5.x Enterprise graph constraints.
        Ensures O(1) lookup speeds for node merging.
        *Method signature explicitly matched to Orchestrator line 207.*
        """
        self.logger.info("Asynchronous Neo4j Driver Initialized Successfully.")
        self.logger.info("Validating Enterprise Graph Schema & Constraints...")
        
        queries = [
            "CREATE CONSTRAINT unique_cloud_resource_arn IF NOT EXISTS FOR (n:CloudResource) REQUIRE n.arn IS UNIQUE",
            "CREATE INDEX cloud_resource_tenant_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._tenant_id)",
            "CREATE INDEX cloud_resource_type_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._resource_type)",
            "CREATE INDEX cloud_resource_provider_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._provider)"
        ]
        
        async with self.driver.session() as session:
            for query in queries:
                try:
                    await session.run(query)
                except ClientError as e:
                    # Ignore warnings about indexes already existing in newer Neo4j versions
                    if "EquivalentSchemaRuleAlreadyExists" not in str(e):
                        self.logger.error(f"Schema Client Error: {e}")
                except Exception as e:
                    self.logger.error(f"Failed to create schema constraint: {e}\nQuery: {query}")
        
        self.logger.info("Graph Schema Validation Complete.")

    # ==========================================================================
    # DEEP FLATTENING PROTOCOL (THE MAP TRAP BYPASS)
    # ==========================================================================

    def _normalize_properties(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """
        Neo4j strictly rejects nested Maps (dicts) or heterogeneous arrays. 
        This recursive interceptor serializes complex data structures into safe 
        JSON strings before they hit the database transaction.
        """
        normalized = {}
        for k, v in properties.items():
            if v is None:
                continue
                
            # 1. Allowed Primitives (Direct Passthrough)
            if isinstance(v, (str, int, float, bool)):
                normalized[k] = v
                
            # 2. Arrays & Lists
            elif isinstance(v, list):
                # If it's a simple list of primitives (e.g., list of strings), Neo4j natively accepts it
                if all(isinstance(i, (str, int, float, bool)) for i in v):
                    normalized[k] = v
                else:
                    # If it's an array of dicts (e.g. nested security rules), serialize it immediately
                    normalized[k] = json.dumps(v)
                    
            # 3. Dictionaries (Maps) -> Strict Serialization
            elif isinstance(v, dict):
                normalized[k] = json.dumps(v)
                
            # 4. Fallback for unknown objects (e.g. datetime objects)
            else:
                normalized[k] = str(v)
                
        return normalized

    # ==========================================================================
    # MASTER INGESTION PIPELINE
    # ==========================================================================

    async def ingest_payloads(self, tenant_id: str, payloads: List[Dict[str, Any]]) -> None:
        """
        The main ingestion handler. Matches Orchestrator signature exactly.
        Parses Universal Resource Model (URM) payloads, flattens metadata, 
        and batches them to the database via mathematically chunked UNWINDs.
        """
        if not payloads:
            self.logger.debug(f"[{tenant_id}] No payloads provided to ingestion pipeline.")
            return

        self.logger.info(f"[{tenant_id}] Starting Database Ingestion Pipeline for {len(payloads)} payloads...")
        
        nodes_batch = []
        edges_batch = [] 

        for payload in payloads:
            # Type assertion and safety fallbacks
            metadata = payload.get("metadata", {})
            raw_properties = payload.get("properties", {})
            tags = payload.get("tags", {})
            
            # Identify if the payload is an explicit edge (from logic engines) or a standard node
            if payload.get("type") == "explicit_edge":
                edges_batch.append({
                    "source_arn": payload.get("source_arn"),
                    "target_arn": payload.get("target_arn"),
                    "relation_type": payload.get("relation_type", "RELATES_TO"),
                    "weight": float(payload.get("weight", 1.0))
                })
                continue
            
            # [AETHER FIX] Flatten properties to prevent Neo4j ClientError (The Map Trap)
            safe_properties = self._normalize_properties(raw_properties)
            
            # Construct the flat, Cypher-safe dictionary
            flat_node = {
                "arn": str(metadata.get("arn", "unknown-arn")),
                "_tenant_id": str(metadata.get("tenant_id", tenant_id)),
                "_provider": str(metadata.get("provider", "UNKNOWN")),
                "_resource_type": str(metadata.get("resource_type", "GenericResource")),
                "_baseline_risk": float(metadata.get("baseline_risk_score", 0.0)),
                "tags": json.dumps(tags) if tags else "{}", 
                **safe_properties
            }
            
            # Append State Differentials if they exist
            if "_state_hash" in payload:
                flat_node["_state_hash"] = str(payload["_state_hash"])
                
            nodes_batch.append(flat_node)

        # Execute the atomic database writes using Chunking to prevent JVM Heap exhaustion
        nodes_written = 0
        edges_written = 0
        
        try:
            # Chunk and process Nodes
            for i in range(0, len(nodes_batch), self.batch_size):
                chunk = nodes_batch[i:i + self.batch_size]
                nodes_written += await self._merge_nodes_batch(tenant_id, chunk)

            # Chunk and process Edges
            for i in range(0, len(edges_batch), self.batch_size):
                chunk = edges_batch[i:i + self.batch_size]
                edges_written += await self._merge_edges_batch(tenant_id, chunk)
                
            self.logger.info(f"[{tenant_id}] Ingestion Complete. Successfully wrote {nodes_written} Nodes and {edges_written} Edges.")
            
        except Exception as e:
            self.logger.error(f"[{tenant_id}] Critical Failure during ingestion: {e}\n{traceback.format_exc()}")

    # ==========================================================================
    # CYPHER TRANSACTION EXECUTORS
    # ==========================================================================

    async def _merge_nodes_batch(self, tenant_id: str, batch: List[Dict]) -> int:
        """
        Executes a high-speed UNWIND operation to merge nodes safely.
        Uses primary 'arn' constraint to ensure idempotency.
        """
        if not batch:
            return 0

        query = """
        UNWIND $batch AS resource
        MERGE (n:CloudResource {arn: resource.arn})
        SET n += resource,
            n:AetherNode,
            n.last_seen = timestamp()
        RETURN count(n) as updated_nodes
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, batch=batch)
                record = await result.single()
                return record["updated_nodes"] if record else 0
                
        except (ServiceUnavailable, SessionExpired) as e:
            self.logger.error(f"[{tenant_id}] Socket Handshake Drop during Node Ingestion: {e}")
            return 0
        except TransientError as e:
            self.logger.warning(f"[{tenant_id}] Transient Database Error (Deadlock/Memory). Batch skipped: {e}")
            return 0
        except Exception as e:
            self.logger.error(f"[{tenant_id}] Unexpected Error during Node Ingestion: {e}")
            return 0

    async def _merge_edges_batch(self, tenant_id: str, batch: List[Dict]) -> int:
        """
        Executes an UNWIND operation for explicit edge generation.
        Matches source and target ARNs, creates the relational vector.
        """
        if not batch:
            return 0
            
        query = """
        UNWIND $batch AS edge
        MATCH (source:CloudResource {arn: edge.source_arn})
        MATCH (target:CloudResource {arn: edge.target_arn})
        CALL apoc.create.relationship(source, edge.relation_type, {weight: edge.weight, last_seen: timestamp()}, target)
        YIELD rel
        RETURN count(rel) as updated_edges
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, batch=batch)
                record = await result.single()
                return record["updated_edges"] if record else 0
                
        except Exception as e:
            self.logger.error(f"[{tenant_id}] Unexpected Error during Edge Ingestion: {e}")
            return 0

# ==============================================================================
# SINGLETON EXPORT
# ==============================================================================
# The Orchestrator imports this instance directly to ensure only one connection 
# pool is created across the entire lifecycle of the application, avoiding socket rot.
graph_ingestor = GraphIngestor()