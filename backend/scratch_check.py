from neo4j import GraphDatabase
driver = GraphDatabase.driver('bolt://127.0.0.1:7687', auth=('neo4j', 'Cloudscape2026!'))
with driver.session() as s:
    result = s.run("MATCH (n) RETURN n.name as name, n.type as type, n.arn as arn")
    for record in result:
        print(f"{record['type']:20s} | {record['name']:50s} | {record['arn']}")
driver.close()
