import sys
import asyncio
import logging
import argparse
from typing import Any, Dict, List

# Ensure the parent directory is in the path so we can import core modules
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from neo4j import AsyncGraphDatabase, exceptions
from core.config import config

# ==============================================================================
# ENTERPRISE GRAPH DATABASE MAINTENANCE UTILITY
# ==============================================================================
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
)

class GraphMaintenanceManager:
    """
    Standalone administrative tool for managing Neo4j schema states, 
    executing batch-safe database purges, and running Garbage Collection 
    on orphaned infrastructure nodes.
    """

    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.DBAdmin")
        
        db_config = config.settings.database
        self.uri = db_config.uri
        self._auth = ("neo4j", "Cloudscape2026!") # For local simulation

        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri, 
                auth=self._auth,
                max_connection_pool_size=10
            )
        except Exception as e:
            self.logger.critical(f"FATAL: Could not connect to Neo4j at {self.uri}: {e}")
            sys.exit(1)

    async def test_connectivity(self) -> bool:
        """Pings the database to ensure the JVM and Bolt protocol are responding."""
        try:
            async with self.driver.session() as session:
                result = await session.run("RETURN 1 AS ping")
                record = await result.single()
                if record and record["ping"] == 1:
                    self.logger.info(f"Successfully connected to Neo4j Enterprise at {self.uri}")
                    return True
        except exceptions.ServiceUnavailable:
            self.logger.error("Neo4j Service is unavailable. Is the Docker container running?")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected connection error: {e}")
            return False

    async def enforce_enterprise_schema(self) -> None:
        """
        Applies mathematical constraints and B-Tree indexes.
        Crucial for O(1) MERGE performance during asynchronous ingestion.
        """
        self.logger.info("Enforcing Enterprise Graph Constraints & Indexes...")

        # 1. Unique Constraints (Prevents duplicate ARNs)
        constraints = [
            "CREATE CONSTRAINT unique_cloud_resource_arn IF NOT EXISTS FOR (n:CloudResource) REQUIRE n.arn IS UNIQUE"
        ]

        # 2. Performance Indexes (Speeds up WHERE clauses and Dashboard filtering)
        indexes = [
            "CREATE INDEX cloud_resource_tenant_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._tenant_id)",
            "CREATE INDEX cloud_resource_type_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._resource_type)",
            "CREATE INDEX cloud_resource_risk_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._baseline_risk_score)"
        ]

        async with self.driver.session() as session:
            for query in constraints + indexes:
                try:
                    await session.run(query)
                    self.logger.debug(f"Executed Schema Rule: {query.split('IF NOT EXISTS')[0].strip()}")
                except exceptions.ClientError as e:
                    self.logger.warning(f"Schema conflict detected (Ignored): {e.message}")
                except Exception as e:
                    self.logger.error(f"Failed to apply schema: {e}")

        self.logger.info("Schema Enforcement Complete.")

    async def execute_garbage_collection(self) -> None:
        """
        The Orphaned Node Garbage Collector.
        Finds 'Stub' nodes created by implicit relationships that were never 
        enriched by an actual API call, and removes them if they are disconnected.
        """
        self.logger.info("Initiating Orphaned Node Garbage Collection...")

        # Cypher: Find nodes that have NO properties other than 'arn' (indicating they 
        # are unenriched stubs) AND have 0 relationships.
        gc_query = """
        MATCH (n:CloudResource)
        WHERE size(keys(n)) <= 1 AND size((n)--()) = 0
        DELETE n
        RETURN count(n) AS purged_count
        """

        try:
            async with self.driver.session() as session:
                result = await session.run(gc_query)
                record = await result.single()
                purged = record["purged_count"] if record else 0
                self.logger.info(f"Garbage Collection Complete. Purged {purged} orphaned stub nodes.")
        except Exception as e:
            self.logger.error(f"Garbage Collection failed: {e}")

    async def perform_batch_purge(self) -> None:
        """
        OOM-Safe Database Wipe.
        Uses APOC periodic iterate to delete the graph in batches of 10,000.
        A standard 'MATCH (n) DETACH DELETE n' will crash the JVM on large datasets.
        """
        self.logger.warning("COMMENCING BATCH DATABASE PURGE...")

        apoc_purge_query = """
        CALL apoc.periodic.iterate(
            "MATCH (n) RETURN n",
            "DETACH DELETE n",
            {batchSize:10000, parallel:false, retries:3}
        )
        YIELD batches, operations, errorMessages
        RETURN batches, operations.deletedNodes AS deletedNodes, operations.deletedRelationships AS deletedRels, errorMessages
        """

        try:
            async with self.driver.session() as session:
                result = await session.run(apoc_purge_query)
                record = await result.single()
                
                if record:
                    deleted_nodes = record["deletedNodes"]
                    deleted_rels = record["deletedRels"]
                    errors = record["errorMessages"]
                    
                    self.logger.info(f"Purge Complete. Destroyed {deleted_nodes} Nodes and {deleted_rels} Edges.")
                    if errors:
                        self.logger.error(f"Purge encountered errors: {errors}")
        except Exception as e:
            self.logger.error(f"Catastrophic failure during database purge: {e}")

    async def fetch_database_statistics(self) -> None:
        """Retrieves raw graph counts for telemetry reporting."""
        self.logger.info("Calculating Global Graph Topology...")

        stats_query = """
        MATCH (n)
        OPTIONAL MATCH ()-[r]->()
        RETURN count(DISTINCT n) AS total_nodes, count(DISTINCT r) AS total_edges
        """

        try:
            async with self.driver.session() as session:
                result = await session.run(stats_query)
                record = await result.single()
                
                if record:
                    self.logger.info("=" * 50)
                    self.logger.info(f" TOTAL NODES: {record['total_nodes']:,}")
                    self.logger.info(f" TOTAL EDGES: {record['total_edges']:,}")
                    self.logger.info("=" * 50)
        except Exception as e:
            self.logger.error(f"Failed to calculate statistics: {e}")

    async def close(self) -> None:
        """Gracefully terminate the async driver."""
        if self.driver:
            await self.driver.close()

# ==============================================================================
# CLI EXECUTOR
# ==============================================================================
async def main():
    parser = argparse.ArgumentParser(description="Cloudscape Enterprise DB Administrator Tool")
    parser.add_argument("--init", action="store_true", help="Apply enterprise constraints and B-Tree indexes.")
    parser.add_argument("--gc", action="store_true", help="Run the Orphaned Node Garbage Collector.")
    parser.add_argument("--stats", action="store_true", help="Calculate total nodes and edges in the graph.")
    parser.add_argument("--purge", action="store_true", help="Execute an OOM-safe APOC batch wipe of the entire graph.")
    
    args = parser.parse_args()

    if not any([args.init, args.gc, args.stats, args.purge]):
        parser.print_help()
        sys.exit(0)

    manager = GraphMaintenanceManager()
    
    if not await manager.test_connectivity():
        sys.exit(1)

    try:
        if args.init:
            await manager.enforce_enterprise_schema()
        if args.gc:
            await manager.execute_garbage_collection()
        if args.stats:
            await manager.fetch_database_statistics()
        if args.purge:
            # Secondary safety check for manual execution
            confirm = input("WARNING: You are about to wipe the Neo4j database. Type 'YES' to confirm: ")
            if confirm == "YES":
                await manager.perform_batch_purge()
            else:
                print("Purge aborted by user.")

    except Exception as e:
        logging.getLogger("Cloudscape.DBAdmin").critical(f"Unhandled Execution Error: {e}")
    finally:
        await manager.close()

if __name__ == "__main__":
    # Handle Windows specific Proactor event loop errors when closing async network connections
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)