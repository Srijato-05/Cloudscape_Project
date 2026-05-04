"""One-shot script: wipes synthetic/simulated nodes from Neo4j, keeps only LIVE data."""
from neo4j import GraphDatabase

NEO4J_URI  = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Cloudscape2026!"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

with driver.session() as s:
    # Count before
    total_before = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    print(f"Nodes before wipe: {total_before}")

    # Delete everything that is not LIVE origin
    s.run("""
        MATCH (n)
        WHERE n._data_origin IN ['SYNTHETIC', 'SIMULATION', 'PHANTOM']
           OR n._data_origin IS NULL
        DETACH DELETE n
    """)

    # Count after
    total_after = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    print(f"Nodes after wipe : {total_after}")
    print(f"Deleted          : {total_before - total_after}")

driver.close()
print("Done.")
